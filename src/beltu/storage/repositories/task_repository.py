from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from beltu.common.enums import TaskStatus
from beltu.common.types import Task
from beltu.storage.database import Database


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _decode(value: str | None) -> dict[str, Any] | None:
    if value is None:
        return None
    parsed = json.loads(value)
    return parsed if isinstance(parsed, dict) else {"value": parsed}


class TaskRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    @staticmethod
    def _from_row(row) -> Task:
        return Task(
            row["id"], row["scan_id"], row["kind"], row["status"],
            _decode(row["payload"]) or {}, _decode(row["result"]), row["error"],
            row["attempts"], row["priority"], row["max_attempts"], row["next_run_at"], row["created_at"], row["updated_at"],
        )

    def create(self, scan_id: int, kind: str, payload: dict[str, Any] | None = None, *, priority: int = 50, max_attempts: int = 1) -> Task:
        now = utc_now()
        payload = payload or {}
        priority = max(0, min(100, int(priority)))
        max_attempts = max(1, int(max_attempts))
        with self.db.connect() as conn:
            cur = conn.execute(
                "INSERT INTO tasks(scan_id, kind, status, payload, priority, max_attempts, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, kind, TaskStatus.PENDING.value, json.dumps(payload), priority, max_attempts, now, now),
            )
            task_id = int(cur.lastrowid)
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return self._from_row(row)

    def get(self, task_id: int) -> Task | None:
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return self._from_row(row) if row else None

    def list_for_scan(self, scan_id: int) -> list[Task]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM tasks WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
        return [self._from_row(r) for r in rows]

    def recover_interrupted(self) -> int:
        """Move tasks left RUNNING by a process crash back to PENDING."""
        now = utc_now()
        with self.db.connect() as conn:
            cur = conn.execute(
                "UPDATE tasks SET status = ?, updated_at = ? WHERE status = ?",
                (TaskStatus.PENDING.value, now, TaskStatus.RUNNING.value),
            )
        return cur.rowcount

    def list_pending(self) -> list[Task]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM tasks WHERE status = ? ORDER BY priority DESC, id ASC",
                (TaskStatus.PENDING.value,),
            ).fetchall()
        return [self._from_row(r) for r in rows]

    def has_task_for_decision(self, scan_id: int, decision_id: int) -> bool:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM tasks WHERE scan_id = ? AND kind = 'capability.execute'",
                (scan_id,),
            ).fetchall()
        for row in rows:
            try:
                payload = json.loads(row["payload"])
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict) and int(payload.get("decision_id", -1)) == decision_id:
                return True
        return False

    def list_for_decision(self, scan_id: int, decision_id: int) -> list[Task]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM tasks WHERE scan_id = ? AND kind = 'capability.execute' ORDER BY id",
                (scan_id,),
            ).fetchall()
        tasks = [self._from_row(row) for row in rows]
        return [task for task in tasks if int(task.payload.get("decision_id", -1)) == decision_id]

    def cancel_pending_for_decision(self, scan_id: int, decision_id: int) -> int:
        now = utc_now()
        ids: list[int] = []
        for task in self.list_for_decision(scan_id, decision_id):
            if task.status in {TaskStatus.PENDING.value, TaskStatus.WAITING_APPROVAL.value}:
                ids.append(task.id)
        if not ids:
            return 0
        with self.db.connect() as conn:
            conn.executemany(
                "UPDATE tasks SET status = ?, updated_at = ?, finished_at = ? WHERE id = ?",
                [(TaskStatus.CANCELLED.value, now, now, task_id) for task_id in ids],
            )
        return len(ids)

    def list_runnable(self) -> list[Task]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM tasks WHERE status = ? AND (next_run_at IS NULL OR next_run_at <= ?) ORDER BY priority DESC, id ASC",
                (TaskStatus.PENDING.value, utc_now()),
            ).fetchall()
        return [self._from_row(r) for r in rows]

    def schedule_retry(self, task_id: int, next_run_at: str, error: str) -> Task:
        now = utc_now()
        with self.db.connect() as conn:
            conn.execute(
                "UPDATE tasks SET status = ?, error = ?, result = NULL, finished_at = NULL, next_run_at = ?, updated_at = ? WHERE id = ?",
                (TaskStatus.PENDING.value, error, next_run_at, now, task_id),
            )
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return self._from_row(row)

    def mark_running(self, task_id: int) -> Task:
        now = utc_now()
        with self.db.connect() as conn:
            conn.execute(
                "UPDATE tasks SET status = ?, attempts = attempts + 1, started_at = ?, next_run_at = NULL, updated_at = ? WHERE id = ?",
                (TaskStatus.RUNNING.value, now, now, task_id),
            )
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return self._from_row(row)

    def mark_succeeded(self, task_id: int, result: dict[str, Any] | None = None) -> Task:
        return self._finish(task_id, TaskStatus.SUCCEEDED, result=result)

    def mark_failed(self, task_id: int, error: str) -> Task:
        return self._finish(task_id, TaskStatus.FAILED, error=error)

    def set_status(self, task_id: int, status: TaskStatus) -> Task:
        now = utc_now()
        with self.db.connect() as conn:
            conn.execute(
                "UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?",
                (status.value, now, task_id),
            )
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return self._from_row(row)

    def _finish(
        self,
        task_id: int,
        status: TaskStatus,
        *,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> Task:
        now = utc_now()
        with self.db.connect() as conn:
            conn.execute(
                "UPDATE tasks SET status = ?, result = ?, error = ?, finished_at = ?, updated_at = ? WHERE id = ?",
                (status.value, json.dumps(result) if result is not None else None, error, now, now, task_id),
            )
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return self._from_row(row)

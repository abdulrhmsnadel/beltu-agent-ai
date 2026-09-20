from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from beltu.feedback.models import ReasoningCycle
from beltu.storage.database import Database


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ReasoningCycleRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    @staticmethod
    def _from_row(row) -> ReasoningCycle:
        return ReasoningCycle(
            row["id"], row["scan_id"], row["trigger"], row["trigger_task_id"],
            row["context_fingerprint"], row["status"],
            json.loads(row["summary_json"] or "{}"), row["created_at"], row["completed_at"],
        )

    def create(
        self,
        scan_id: int,
        trigger: str,
        trigger_task_id: int,
        context_fingerprint: str,
        *,
        status: str = "running",
        summary: dict[str, Any] | None = None,
    ) -> ReasoningCycle:
        now = utc_now()
        with self.db.connect() as conn:
            cur = conn.execute(
                """INSERT OR IGNORE INTO reasoning_cycles
                   (scan_id, trigger, trigger_task_id, context_fingerprint, status, summary_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, trigger, trigger_task_id, context_fingerprint, status, json.dumps(summary or {}, sort_keys=True), now),
            )
            if cur.rowcount == 1:
                row = conn.execute("SELECT * FROM reasoning_cycles WHERE id = ?", (int(cur.lastrowid),)).fetchone()
            else:
                row = conn.execute(
                    """SELECT * FROM reasoning_cycles
                       WHERE scan_id = ? AND trigger = ? AND trigger_task_id = ? AND context_fingerprint = ?
                       ORDER BY id DESC LIMIT 1""",
                    (scan_id, trigger, trigger_task_id, context_fingerprint),
                ).fetchone()
        if row is None:
            raise RuntimeError("Reasoning cycle insert did not produce a row")
        return self._from_row(row)

    def get(self, cycle_id: int) -> ReasoningCycle | None:
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM reasoning_cycles WHERE id = ?", (cycle_id,)).fetchone()
        return self._from_row(row) if row else None

    def find_existing(self, scan_id: int, trigger: str, trigger_task_id: int, context_fingerprint: str) -> ReasoningCycle | None:
        with self.db.connect() as conn:
            row = conn.execute(
                """SELECT * FROM reasoning_cycles
                   WHERE scan_id = ? AND trigger = ? AND trigger_task_id = ? AND context_fingerprint = ?
                   ORDER BY id DESC LIMIT 1""",
                (scan_id, trigger, trigger_task_id, context_fingerprint),
            ).fetchone()
        return self._from_row(row) if row else None

    def complete(self, cycle_id: int, *, status: str, summary: dict[str, Any]) -> ReasoningCycle:
        if status not in {"succeeded", "failed", "skipped"}:
            raise ValueError("Invalid reasoning cycle terminal status")
        now = utc_now()
        with self.db.connect() as conn:
            conn.execute(
                "UPDATE reasoning_cycles SET status = ?, summary_json = ?, completed_at = ? WHERE id = ?",
                (status, json.dumps(summary, sort_keys=True), now, cycle_id),
            )
            row = conn.execute("SELECT * FROM reasoning_cycles WHERE id = ?", (cycle_id,)).fetchone()
        if row is None:
            raise KeyError(f"Reasoning cycle #{cycle_id} not found")
        return self._from_row(row)

    def count_for_scan(self, scan_id: int) -> int:
        with self.db.connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM reasoning_cycles WHERE scan_id = ?", (scan_id,)).fetchone()
        return int(row["c"])

    def list_for_scan(self, scan_id: int) -> list[ReasoningCycle]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM reasoning_cycles WHERE scan_id = ? ORDER BY id", (scan_id,)
            ).fetchall()
        return [self._from_row(row) for row in rows]

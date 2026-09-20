from __future__ import annotations

from datetime import datetime, timezone

from beltu.common.enums import ScanStatus
from beltu.common.types import Scan
from beltu.storage.database import Database


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def create(self, target_id: int, status: ScanStatus = ScanStatus.PENDING) -> Scan:
        now = utc_now()
        with self.db.connect() as conn:
            cur = conn.execute(
                "INSERT INTO scans(target_id, status, created_at, updated_at) VALUES(?, ?, ?, ?)",
                (target_id, status.value, now, now),
            )
            scan_id = int(cur.lastrowid)
        return Scan(scan_id, target_id, status.value, now, now)

    def get(self, scan_id: int) -> Scan | None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT id, target_id, status, created_at, updated_at FROM scans WHERE id = ?",
                (scan_id,),
            ).fetchone()
        if row is None:
            return None
        return Scan(row["id"], row["target_id"], row["status"], row["created_at"], row["updated_at"])

    def list_for_target(self, target_id: int) -> list[Scan]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT id, target_id, status, created_at, updated_at FROM scans WHERE target_id = ? ORDER BY id",
                (target_id,),
            ).fetchall()
        return [Scan(r["id"], r["target_id"], r["status"], r["created_at"], r["updated_at"]) for r in rows]

    def recover_interrupted(self) -> int:
        """Move scans left RUNNING by a process crash back to PENDING."""
        now = utc_now()
        with self.db.connect() as conn:
            cur = conn.execute(
                "UPDATE scans SET status = ?, updated_at = ? WHERE status = ?",
                (ScanStatus.PENDING.value, now, ScanStatus.RUNNING.value),
            )
        return cur.rowcount

    def list_resumable(self) -> list[Scan]:
        statuses = (ScanStatus.PENDING.value, ScanStatus.RUNNING.value, ScanStatus.PAUSED.value)
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT id, target_id, status, created_at, updated_at FROM scans WHERE status IN (?, ?, ?) ORDER BY id",
                statuses,
            ).fetchall()
        return [Scan(r["id"], r["target_id"], r["status"], r["created_at"], r["updated_at"]) for r in rows]

    def set_status(self, scan_id: int, status: ScanStatus) -> bool:
        now = utc_now()
        with self.db.connect() as conn:
            cur = conn.execute(
                "UPDATE scans SET status = ?, updated_at = ? WHERE id = ?",
                (status.value, now, scan_id),
            )
        return cur.rowcount == 1

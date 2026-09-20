from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from beltu.common.enums import TargetStatus
from beltu.common.types import Target
from beltu.storage.database import Database


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class TargetRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def add(self, value: str) -> Target:
        now = utc_now()
        with self.db.connect() as conn:
            cursor = conn.execute(
                "INSERT INTO targets(value, status, created_at, updated_at) VALUES(?, ?, ?, ?)",
                (value, TargetStatus.NEW.value, now, now),
            )
            target_id = int(cursor.lastrowid)
        return Target(target_id, value, TargetStatus.NEW.value, now)

    def get(self, target_id: int) -> Target | None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT id, value, status, created_at FROM targets WHERE id = ?",
                (target_id,),
            ).fetchone()
        if row is None:
            return None
        return Target(row["id"], row["value"], row["status"], row["created_at"])

    def list_all(self) -> list[Target]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT id, value, status, created_at FROM targets ORDER BY id"
            ).fetchall()
        return [Target(r["id"], r["value"], r["status"], r["created_at"]) for r in rows]

    def set_status(self, target_id: int, status: TargetStatus) -> bool:
        now = utc_now()
        with self.db.connect() as conn:
            cur = conn.execute(
                "UPDATE targets SET status = ?, updated_at = ? WHERE id = ?",
                (status.value, now, target_id),
            )
        return cur.rowcount == 1

    def exists(self, value: str) -> bool:
        with self.db.connect() as conn:
            row = conn.execute("SELECT 1 FROM targets WHERE value = ?", (value,)).fetchone()
        return row is not None

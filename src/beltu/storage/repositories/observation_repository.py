from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from beltu.storage.database import Database
from beltu.storage.models.brain import Observation


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ObservationRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    @staticmethod
    def _from_row(row) -> Observation:
        return Observation(
            row["id"],
            row["scan_id"],
            row["kind"],
            row["subject"],
            json.loads(row["data_json"]),
            row["source"],
            float(row["confidence"]),
            row["created_at"],
        )

    def add(
        self,
        scan_id: int,
        kind: str,
        subject: str,
        data: dict[str, Any],
        source: str,
        confidence: float = 1.0,
    ) -> Observation:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("Observation confidence must be between 0 and 1")
        now = utc_now()
        with self.db.connect() as conn:
            cur = conn.execute(
                """INSERT INTO observations
                   (scan_id, kind, subject, data_json, source, confidence, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, kind, subject, json.dumps(data, sort_keys=True), source, confidence, now),
            )
            row = conn.execute("SELECT * FROM observations WHERE id = ?", (int(cur.lastrowid),)).fetchone()
        return self._from_row(row)

    def list_for_scan(self, scan_id: int) -> list[Observation]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM observations WHERE scan_id = ? ORDER BY id", (scan_id,)
            ).fetchall()
        return [self._from_row(row) for row in rows]

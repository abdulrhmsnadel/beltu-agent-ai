from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable

from beltu.storage.database import Database
from beltu.storage.models.brain import Hypothesis


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class HypothesisRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    @staticmethod
    def _from_row(row) -> Hypothesis:
        return Hypothesis(
            row["id"],
            row["scan_id"],
            row["statement"],
            [int(x) for x in json.loads(row["basis_observation_ids_json"])],
            float(row["confidence"]),
            row["status"],
            row["created_at"],
            row["updated_at"],
        )

    def create(
        self,
        scan_id: int,
        statement: str,
        basis_observation_ids: Iterable[int],
        confidence: float,
        status: str = "open",
    ) -> Hypothesis:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("Hypothesis confidence must be between 0 and 1")
        basis = [int(x) for x in basis_observation_ids]
        now = utc_now()
        with self.db.connect() as conn:
            cur = conn.execute(
                """INSERT INTO hypotheses
                   (scan_id, statement, basis_observation_ids_json, confidence, status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, statement, json.dumps(basis), confidence, status, now, now),
            )
            row = conn.execute("SELECT * FROM hypotheses WHERE id = ?", (int(cur.lastrowid),)).fetchone()
        return self._from_row(row)

    def list_for_scan(self, scan_id: int) -> list[Hypothesis]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM hypotheses WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
        return [self._from_row(row) for row in rows]

    def update_status(self, hypothesis_id: int, status: str, *, confidence: float | None = None) -> Hypothesis:
        if confidence is not None and not 0.0 <= confidence <= 1.0:
            raise ValueError("Hypothesis confidence must be between 0 and 1")
        now = utc_now()
        with self.db.connect() as conn:
            if confidence is None:
                conn.execute(
                    "UPDATE hypotheses SET status = ?, updated_at = ? WHERE id = ?",
                    (status, now, hypothesis_id),
                )
            else:
                conn.execute(
                    "UPDATE hypotheses SET status = ?, confidence = ?, updated_at = ? WHERE id = ?",
                    (status, confidence, now, hypothesis_id),
                )
            row = conn.execute("SELECT * FROM hypotheses WHERE id = ?", (hypothesis_id,)).fetchone()
        if row is None:
            raise KeyError(f"Hypothesis #{hypothesis_id} not found")
        return self._from_row(row)

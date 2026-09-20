from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from beltu.storage.database import Database


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CapabilitySelectionRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def record(
        self,
        scan_id: int,
        cycle_id: int | None,
        decision_id: int | None,
        capability: str,
        tool: str | None,
        score: float,
        expected_information_gain: float,
        cost: float,
        risk_level: str,
        rationale: str,
        candidates: list[dict[str, Any]],
    ) -> int:
        with self.db.connect() as conn:
            cur = conn.execute(
                """INSERT INTO capability_selections
                   (scan_id, cycle_id, decision_id, capability, tool, score,
                    expected_information_gain, cost, risk_level, rationale,
                    candidates_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id, cycle_id, decision_id, capability, tool, float(score),
                    float(expected_information_gain), float(cost), risk_level,
                    rationale, json.dumps(candidates, sort_keys=True), utc_now(),
                ),
            )
            return int(cur.lastrowid)

    def list_for_scan(self, scan_id: int) -> list[dict[str, Any]]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM capability_selections WHERE scan_id = ? ORDER BY id", (scan_id,)
            ).fetchall()
        return [dict(row) for row in rows]

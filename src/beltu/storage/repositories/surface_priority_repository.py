from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from beltu.storage.database import Database
from beltu.storage.models.surface import SurfacePriority

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _json(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {"value": parsed}

class SurfacePriorityRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def upsert(self, *, scan_id: int, entity_type: str, entity_id: int, value: str, score: float, priority: str, exposure: float, novelty: float, sensitivity: float, confidence: float, rationale: str, signals: dict[str, Any] | None = None) -> SurfacePriority:
        vals = [score, exposure, novelty, sensitivity, confidence]
        if any(not 0.0 <= float(v) <= 1.0 for v in vals):
            raise ValueError("surface scores must be between 0 and 1")
        now = utc_now()
        signals_json=json.dumps(signals or {}, sort_keys=True)
        with self.db.connect() as conn:
            conn.execute(
                """INSERT INTO surface_priorities
                   (scan_id, entity_type, entity_id, value, score, priority, exposure, novelty, sensitivity, confidence, rationale, signals_json, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(scan_id, entity_type, entity_id) DO UPDATE SET
                     value=excluded.value, score=excluded.score, priority=excluded.priority,
                     exposure=excluded.exposure, novelty=excluded.novelty, sensitivity=excluded.sensitivity,
                     confidence=excluded.confidence, rationale=excluded.rationale, signals_json=excluded.signals_json, updated_at=excluded.updated_at""",
                (scan_id, entity_type, entity_id, value, score, priority, exposure, novelty, sensitivity, confidence, rationale, signals_json, now),
            )
            row=conn.execute("SELECT * FROM surface_priorities WHERE scan_id=? AND entity_type=? AND entity_id=?",(scan_id,entity_type,entity_id)).fetchone()
        return self._from_row(row)

    def list_for_scan(self, scan_id: int, *, limit: int | None = None) -> list[SurfacePriority]:
        sql="SELECT * FROM surface_priorities WHERE scan_id=? ORDER BY score DESC, entity_type, entity_id"
        params=[scan_id]
        if limit is not None:
            sql += " LIMIT ?"; params.append(max(1,int(limit)))
        with self.db.connect() as conn:
            rows=conn.execute(sql,params).fetchall()
        return [self._from_row(r) for r in rows]

    @staticmethod
    def _from_row(row) -> SurfacePriority:
        return SurfacePriority(row["id"],row["scan_id"],row["entity_type"],row["entity_id"],row["value"],float(row["score"]),row["priority"],float(row["exposure"]),float(row["novelty"]),float(row["sensitivity"]),float(row["confidence"]),row["rationale"],_json(row["signals_json"]),row["updated_at"])

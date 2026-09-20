from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from beltu.storage.database import Database
from beltu.storage.models.brain import Decision


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DecisionRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    @staticmethod
    def _from_row(row) -> Decision:
        return Decision(
            row["id"],
            row["scan_id"],
            row["hypothesis_id"],
            row["action_kind"],
            json.loads(row["action_payload_json"]),
            row["rationale"],
            float(row["confidence"]),
            row["risk_level"],
            bool(row["requires_approval"]),
            row["status"],
            row["created_at"],
        )

    def create(
        self,
        scan_id: int,
        hypothesis_id: int | None,
        action_kind: str,
        action_payload: dict[str, Any],
        rationale: str,
        confidence: float,
        risk_level: str,
        requires_approval: bool,
        status: str = "proposed",
        *,
        cycle_id: int | None = None,
        action_fingerprint: str | None = None,
    ) -> Decision:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("Decision confidence must be between 0 and 1")
        now = utc_now()
        with self.db.connect() as conn:
            cur = conn.execute(
                """INSERT INTO decisions
                   (scan_id, hypothesis_id, action_kind, action_payload_json, rationale,
                    confidence, risk_level, requires_approval, status, created_at, cycle_id, action_fingerprint)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    hypothesis_id,
                    action_kind,
                    json.dumps(action_payload, sort_keys=True),
                    rationale,
                    confidence,
                    risk_level,
                    int(requires_approval),
                    status,
                    now,
                    cycle_id,
                    action_fingerprint,
                ),
            )
            row = conn.execute("SELECT * FROM decisions WHERE id = ?", (int(cur.lastrowid),)).fetchone()
        return self._from_row(row)

    def get(self, decision_id: int) -> Decision | None:
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM decisions WHERE id = ?", (decision_id,)).fetchone()
        return self._from_row(row) if row else None

    def set_status(self, decision_id: int, status: str) -> Decision:
        with self.db.connect() as conn:
            conn.execute("UPDATE decisions SET status = ? WHERE id = ?", (status, decision_id))
            row = conn.execute("SELECT * FROM decisions WHERE id = ?", (decision_id,)).fetchone()
        if row is None:
            raise KeyError(f"Decision #{decision_id} not found")
        return self._from_row(row)

    def list_for_scan(self, scan_id: int) -> list[Decision]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM decisions WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
        return [self._from_row(row) for row in rows]

    def find_by_action_fingerprint(self, scan_id: int, fingerprint: str) -> Decision | None:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM decisions WHERE scan_id = ? AND action_fingerprint = ? ORDER BY id DESC LIMIT 1",
                (scan_id, fingerprint),
            ).fetchone()
        if row is not None:
            return self._from_row(row)
        # Stage-7 decisions may not have the new fingerprint column populated.
        # Recompute fingerprints in Python as a compatibility fallback.
        from beltu.feedback.replanner import action_fingerprint as compute_fingerprint
        for decision in reversed(self.list_for_scan(scan_id)):
            if compute_fingerprint(decision.action_kind, decision.action_payload) == fingerprint:
                return decision
        return None

    def list_for_hypothesis(self, hypothesis_id: int) -> list[Decision]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM decisions WHERE hypothesis_id = ? ORDER BY id", (hypothesis_id,)).fetchall()
        return [self._from_row(row) for row in rows]

    def supersede(self, decision_id: int, reason: str) -> Decision:
        now = utc_now()
        with self.db.connect() as conn:
            conn.execute(
                "UPDATE decisions SET status = 'superseded', superseded_at = ?, superseded_reason = ? WHERE id = ?",
                (now, reason, decision_id),
            )
            row = conn.execute("SELECT * FROM decisions WHERE id = ?", (decision_id,)).fetchone()
        if row is None:
            raise KeyError(f"Decision #{decision_id} not found")
        return self._from_row(row)

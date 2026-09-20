from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from beltu.storage.database import Database
from beltu.storage.models.access_control import AuthorizationAnomaly, AuthorizationMatrixEntry


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _obj(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {"value": parsed}


def _ids(value: str | None) -> tuple[int, ...]:
    if not value:
        return ()
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return ()
    if not isinstance(parsed, list):
        return ()
    out: list[int] = []
    for item in parsed:
        try:
            out.append(int(item))
        except (TypeError, ValueError):
            continue
    return tuple(dict.fromkeys(out))


class AccessControlRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def upsert_matrix_entry(
        self,
        *,
        scan_id: int,
        operation_id: int,
        principal_id: int | None,
        principal_label: str,
        role: str | None,
        access_state: str,
        auth_required: bool,
        confidence: float,
        evidence_ids: tuple[int, ...] = (),
        basis: dict[str, Any] | None = None,
    ) -> AuthorizationMatrixEntry:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("Authorization confidence must be between 0 and 1")
        principal_key = str(principal_id) if principal_id is not None else f"label:{principal_label.strip().lower()}"
        now = utc_now()
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM authorization_matrix WHERE scan_id=? AND operation_id=? AND principal_key=? AND access_state=?",
                (scan_id, operation_id, principal_key, access_state),
            ).fetchone()
            payload = (
                scan_id, operation_id, principal_id, principal_key, principal_label[:200], role[:120] if role else None,
                access_state[:80], int(auth_required), confidence, json.dumps(list(dict.fromkeys(evidence_ids)), sort_keys=True),
                json.dumps(basis or {}, sort_keys=True), now, now,
            )
            if row is None:
                cur = conn.execute(
                    """INSERT INTO authorization_matrix(
                        scan_id, operation_id, principal_id, principal_key, principal_label, role, access_state,
                        auth_required, confidence, evidence_ids_json, basis_json, created_at, updated_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    payload,
                )
                row = conn.execute("SELECT * FROM authorization_matrix WHERE id=?", (int(cur.lastrowid),)).fetchone()
            else:
                conn.execute(
                    """UPDATE authorization_matrix SET principal_id=?, principal_label=?, role=?, auth_required=?,
                       confidence=MAX(confidence, ?), evidence_ids_json=?, basis_json=?, updated_at=?
                       WHERE id=?""",
                    (principal_id, principal_label[:200], role[:120] if role else None, int(auth_required), confidence,
                     json.dumps(list(dict.fromkeys(evidence_ids)), sort_keys=True), json.dumps(basis or {}, sort_keys=True), now, row["id"]),
                )
                row = conn.execute("SELECT * FROM authorization_matrix WHERE id=?", (row["id"],)).fetchone()
        return self._matrix(row)

    def upsert_anomaly(
        self,
        *,
        scan_id: int,
        kind: str,
        severity: str,
        entity_type: str,
        entity_id: int,
        statement: str,
        rationale: str,
        confidence: float,
        basis: dict[str, Any] | None = None,
    ) -> AuthorizationAnomaly:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("Authorization anomaly confidence must be between 0 and 1")
        now = utc_now()
        with self.db.connect() as conn:
            conn.execute(
                """INSERT INTO authorization_anomalies(
                    scan_id, kind, severity, entity_type, entity_id, statement, rationale, confidence, basis_json, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(scan_id, kind, entity_type, entity_id) DO UPDATE SET
                    severity=excluded.severity, statement=excluded.statement, rationale=excluded.rationale,
                    confidence=MAX(authorization_anomalies.confidence, excluded.confidence), basis_json=excluded.basis_json,
                    updated_at=excluded.updated_at""",
                (scan_id, kind[:100], severity[:30], entity_type[:40], entity_id, statement[:500], rationale[:1000], confidence,
                 json.dumps(basis or {}, sort_keys=True), now, now),
            )
            row = conn.execute(
                "SELECT * FROM authorization_anomalies WHERE scan_id=? AND kind=? AND entity_type=? AND entity_id=?",
                (scan_id, kind, entity_type, entity_id),
            ).fetchone()
        return self._anomaly(row)

    def clear_rebuildable_anomalies(self, scan_id: int) -> None:
        with self.db.connect() as conn:
            conn.execute("DELETE FROM authorization_anomalies WHERE scan_id=? AND basis_json LIKE '%\"rebuildable\": true%'", (scan_id,))

    def list_matrix(self, scan_id: int) -> list[AuthorizationMatrixEntry]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM authorization_matrix WHERE scan_id=? ORDER BY operation_id, role, principal_label, access_state, id",
                (scan_id,),
            ).fetchall()
        return [self._matrix(row) for row in rows]

    def list_anomalies(self, scan_id: int) -> list[AuthorizationAnomaly]:
        with self.db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM authorization_anomalies WHERE scan_id=? ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, entity_type, entity_id, id",
                (scan_id,),
            ).fetchall()
        return [self._anomaly(row) for row in rows]

    def summary(self, scan_id: int) -> dict[str, int]:
        with self.db.connect() as conn:
            matrix = int(conn.execute("SELECT COUNT(*) FROM authorization_matrix WHERE scan_id=?", (scan_id,)).fetchone()[0])
            anomalies = int(conn.execute("SELECT COUNT(*) FROM authorization_anomalies WHERE scan_id=?", (scan_id,)).fetchone()[0])
            high = int(conn.execute("SELECT COUNT(*) FROM authorization_anomalies WHERE scan_id=? AND severity='high'", (scan_id,)).fetchone()[0])
            conflicts = int(conn.execute("SELECT COUNT(*) FROM authorization_anomalies WHERE scan_id=? AND kind='principal_state_conflict'", (scan_id,)).fetchone()[0])
            anonymous = int(conn.execute("SELECT COUNT(*) FROM authorization_anomalies WHERE scan_id=? AND kind='anonymous_access_to_protected'", (scan_id,)).fetchone()[0])
            return {"matrix_entries": matrix, "anomalies": anomalies, "high_anomalies": high, "principal_state_conflicts": conflicts, "anonymous_access_candidates": anonymous}

    def context_payload(self, scan_id: int, limit: int = 200) -> dict[str, Any]:
        matrix = self.list_matrix(scan_id)
        anomalies = self.list_anomalies(scan_id)
        return {
            "summary": self.summary(scan_id),
            "matrix": [
                {"id": e.id, "operation_id": e.operation_id, "principal_id": e.principal_id, "principal_label": e.principal_label,
                 "role": e.role, "access_state": e.access_state, "auth_required": e.auth_required, "confidence": e.confidence,
                 "evidence_ids": list(e.evidence_ids), "basis": e.basis}
                for e in matrix[:limit]
            ],
            "anomalies": [
                {"id": a.id, "kind": a.kind, "severity": a.severity, "entity_type": a.entity_type, "entity_id": a.entity_id,
                 "statement": a.statement, "rationale": a.rationale, "confidence": a.confidence, "basis": a.basis}
                for a in anomalies[:limit]
            ],
        }

    @staticmethod
    def _matrix(row) -> AuthorizationMatrixEntry:
        return AuthorizationMatrixEntry(
            row["id"], row["scan_id"], row["operation_id"], row["principal_id"], row["principal_label"], row["role"],
            row["access_state"], bool(row["auth_required"]), float(row["confidence"]), _ids(row["evidence_ids_json"]),
            _obj(row["basis_json"]), row["created_at"], row["updated_at"],
        )

    @staticmethod
    def _anomaly(row) -> AuthorizationAnomaly:
        return AuthorizationAnomaly(
            row["id"], row["scan_id"], row["kind"], row["severity"], row["entity_type"], row["entity_id"],
            row["statement"], row["rationale"], float(row["confidence"]), _obj(row["basis_json"]), row["created_at"], row["updated_at"],
        )

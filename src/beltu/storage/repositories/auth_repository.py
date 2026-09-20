
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from beltu.storage.database import Database
from beltu.storage.models.auth import AuthOperationControl, AuthPrincipal, AuthSession, AuthTransition


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


_SENSITIVE_KEY = __import__("re").compile(r"(?:value|content|secret|token|password|passwd|authorization|cookie|set-cookie|api[-_]?key|credential|jwt)", __import__("re").I)

def _safe_metadata(value: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    def clean(item: Any) -> Any:
        if isinstance(item, dict):
            return {str(k): ("<redacted>" if _SENSITIVE_KEY.search(str(k)) else clean(v)) for k, v in item.items()}
        if isinstance(item, list):
            return [clean(v) for v in item[:100]]
        if isinstance(item, tuple):
            return [clean(v) for v in item[:100]]
        return item
    return clean(value)


def _json_object(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {"value": parsed}


def _json_list(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return ()
    if not isinstance(parsed, list):
        return ()
    return tuple(str(item) for item in parsed if str(item).strip())


class AuthRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def upsert_principal(self, scan_id: int, label: str, kind: str, role: str | None, confidence: float, source: str, metadata: dict[str, Any] | None = None) -> AuthPrincipal:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("Principal confidence must be between 0 and 1")
        label = label.strip()[:200]
        kind = kind.strip().lower()[:50] or "unknown"
        role = role.strip()[:100] if isinstance(role, str) and role.strip() else None
        now = utc_now()
        payload = json.dumps(_safe_metadata(metadata), sort_keys=True)
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM auth_principals WHERE scan_id=? AND label=? AND COALESCE(role,'')=COALESCE(?, '')",
                (scan_id, label, role),
            ).fetchone()
            if row is None:
                cur = conn.execute(
                    """INSERT INTO auth_principals(scan_id,label,kind,role,confidence,source,metadata_json,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (scan_id, label, kind, role, confidence, source, payload, now, now),
                )
                row = conn.execute("SELECT * FROM auth_principals WHERE id=?", (int(cur.lastrowid),)).fetchone()
            else:
                conn.execute(
                    """UPDATE auth_principals SET kind=?, confidence=MAX(confidence, ?), source=?, metadata_json=?, updated_at=?
                       WHERE id=?""",
                    (kind, confidence, source, payload, now, row["id"]),
                )
                row = conn.execute("SELECT * FROM auth_principals WHERE id=?", (row["id"],)).fetchone()
        return self._principal(row)

    def upsert_session(self, scan_id: int, *, label: str, transport: str, mechanism: str, state: str, secure: bool | None,
                       http_only: bool | None, same_site: str | None, domain: str | None, path: str | None,
                       expires_at: str | None, value_present: bool, source: str, confidence: float,
                       metadata: dict[str, Any] | None = None) -> AuthSession:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("Session confidence must be between 0 and 1")
        label = label.strip()[:200] or "unnamed-session"
        transport = transport.strip().lower()[:50] or "unknown"
        mechanism = mechanism.strip().lower()[:80] or "unknown"
        state = state.strip().lower()[:80] or "unknown"
        domain = domain.strip()[:255] if isinstance(domain, str) and domain.strip() else None
        path = path.strip()[:500] if isinstance(path, str) and path.strip() else None
        same_site = same_site.strip().lower()[:30] if isinstance(same_site, str) and same_site.strip() else None
        fingerprint = hashlib.sha256(f"{label}|{transport}|{mechanism}".encode()).hexdigest()
        now = utc_now()
        metadata_json = json.dumps(_safe_metadata(metadata), sort_keys=True)
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM auth_sessions WHERE scan_id=? AND label=? AND transport=? AND mechanism=?",
                (scan_id, label, transport, mechanism),
            ).fetchone()
            if row is None:
                cur = conn.execute(
                    """INSERT INTO auth_sessions(scan_id,label,transport,mechanism,state,secure,http_only,same_site,domain,path,
                       expires_at,value_present,fingerprint_sha256,source,confidence,metadata_json,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (scan_id,label,transport,mechanism,state,secure,http_only,same_site,domain,path,expires_at,int(value_present),fingerprint,source,confidence,metadata_json,now,now),
                )
                row = conn.execute("SELECT * FROM auth_sessions WHERE id=?", (int(cur.lastrowid),)).fetchone()
            else:
                conn.execute(
                    """UPDATE auth_sessions SET state=?, secure=COALESCE(?, secure), http_only=COALESCE(?, http_only),
                       same_site=COALESCE(?, same_site), domain=COALESCE(?, domain), path=COALESCE(?, path),
                       expires_at=COALESCE(?, expires_at), value_present=MAX(value_present, ?), source=?, confidence=MAX(confidence, ?),
                       metadata_json=?, updated_at=? WHERE id=?""",
                    (state,secure,http_only,same_site,domain,path,expires_at,int(value_present),source,confidence,metadata_json,now,row["id"]),
                )
                row = conn.execute("SELECT * FROM auth_sessions WHERE id=?", (row["id"],)).fetchone()
        return self._session(row)

    def upsert_operation_control(self, scan_id: int, operation_id: int, principal_id: int | None, principal_label: str,
                                  access_state: str, auth_required: bool, schemes: tuple[str, ...], confidence: float,
                                  basis: dict[str, Any] | None = None) -> AuthOperationControl:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("Control confidence must be between 0 and 1")
        now = utc_now()
        schemes_json = json.dumps(list(dict.fromkeys(schemes)), sort_keys=True)
        basis_json = json.dumps(basis or {}, sort_keys=True)
        with self.db.connect() as conn:
            row = conn.execute(
                """SELECT * FROM auth_operation_controls WHERE operation_id=? AND COALESCE(principal_id,0)=COALESCE(?,0)
                   AND access_state=?""",
                (operation_id, principal_id, access_state),
            ).fetchone()
            if row is None:
                cur = conn.execute(
                    """INSERT INTO auth_operation_controls(scan_id,operation_id,principal_id,principal_label,access_state,
                       auth_required,schemes_json,confidence,basis_json,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (scan_id,operation_id,principal_id,principal_label[:200],access_state[:80],int(auth_required),schemes_json,confidence,basis_json,now,now),
                )
                row = conn.execute("SELECT * FROM auth_operation_controls WHERE id=?", (int(cur.lastrowid),)).fetchone()
            else:
                conn.execute(
                    """UPDATE auth_operation_controls SET principal_label=?, auth_required=?, schemes_json=?, confidence=MAX(confidence, ?),
                       basis_json=?, updated_at=? WHERE id=?""",
                    (principal_label[:200],int(auth_required),schemes_json,confidence,basis_json,now,row["id"]),
                )
                row = conn.execute("SELECT * FROM auth_operation_controls WHERE id=?", (row["id"],)).fetchone()
        return self._control(row)

    def upsert_transition(self, scan_id: int, from_state: str, to_state: str, operation_id: int | None, relation: str,
                          confidence: float, basis: dict[str, Any] | None = None) -> AuthTransition:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("Transition confidence must be between 0 and 1")
        now = utc_now()
        with self.db.connect() as conn:
            row = conn.execute(
                """SELECT * FROM auth_transitions WHERE scan_id=? AND from_state=? AND to_state=?
                   AND COALESCE(operation_id,0)=COALESCE(?,0) AND relation=?""",
                (scan_id,from_state,to_state,operation_id,relation),
            ).fetchone()
            if row is None:
                cur = conn.execute(
                    """INSERT INTO auth_transitions(scan_id,from_state,to_state,operation_id,relation,confidence,basis_json,created_at)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (scan_id,from_state,to_state,operation_id,relation,confidence,json.dumps(basis or {},sort_keys=True),now),
                )
                row = conn.execute("SELECT * FROM auth_transitions WHERE id=?", (int(cur.lastrowid),)).fetchone()
            else:
                conn.execute("UPDATE auth_transitions SET confidence=MAX(confidence,?), basis_json=? WHERE id=?", (confidence,json.dumps(basis or {},sort_keys=True),row["id"]))
                row = conn.execute("SELECT * FROM auth_transitions WHERE id=?", (row["id"],)).fetchone()
        return self._transition(row)

    def list_principals(self, scan_id: int) -> list[AuthPrincipal]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM auth_principals WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
        return [self._principal(r) for r in rows]

    def list_sessions(self, scan_id: int) -> list[AuthSession]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM auth_sessions WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
        return [self._session(r) for r in rows]

    def list_controls(self, scan_id: int) -> list[AuthOperationControl]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM auth_operation_controls WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
        return [self._control(r) for r in rows]

    def list_transitions(self, scan_id: int) -> list[AuthTransition]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM auth_transitions WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
        return [self._transition(r) for r in rows]

    def summary(self, scan_id: int) -> dict[str, int]:
        with self.db.connect() as conn:
            values = {}
            for key, table in (("principals","auth_principals"),("sessions","auth_sessions"),("controls","auth_operation_controls"),("transitions","auth_transitions")):
                values[key] = int(conn.execute(f"SELECT COUNT(*) FROM {table} WHERE scan_id=?", (scan_id,)).fetchone()[0])
            values["protected_controls"] = int(conn.execute("SELECT COUNT(*) FROM auth_operation_controls WHERE scan_id=? AND auth_required=1", (scan_id,)).fetchone()[0])
            values["session_like_controls"] = int(conn.execute("SELECT COUNT(*) FROM auth_operation_controls WHERE scan_id=? AND access_state LIKE '%session%'", (scan_id,)).fetchone()[0])
            return values

    def context_payload(self, scan_id: int, limit: int = 100) -> dict[str, Any]:
        principals = self.list_principals(scan_id)
        sessions = self.list_sessions(scan_id)
        controls = self.list_controls(scan_id)
        transitions = self.list_transitions(scan_id)
        principal_payload = [
            {"id": p.id, "label": p.label, "kind": p.kind, "role": p.role, "confidence": p.confidence, "source": p.source, "metadata": p.metadata}
            for p in principals[:limit]
        ]
        session_payload = [
            {"id": s.id, "label": s.label, "transport": s.transport, "mechanism": s.mechanism, "state": s.state,
             "secure": s.secure, "http_only": s.http_only, "same_site": s.same_site, "domain": s.domain, "path": s.path,
             "expires_at": s.expires_at, "value_present": s.value_present, "fingerprint_sha256": s.fingerprint_sha256[:16] + "…",
             "confidence": s.confidence, "source": s.source, "metadata": s.metadata}
            for s in sessions[:limit]
        ]
        control_payload = [
            {"id": c.id, "operation_id": c.operation_id, "principal_id": c.principal_id, "principal_label": c.principal_label,
             "access_state": c.access_state, "auth_required": c.auth_required, "schemes": list(c.schemes), "confidence": c.confidence,
             "basis": c.basis}
            for c in controls[:limit]
        ]
        transition_payload = [
            {"id": t.id, "from_state": t.from_state, "to_state": t.to_state, "operation_id": t.operation_id,
             "relation": t.relation, "confidence": t.confidence, "basis": t.basis}
            for t in transitions[:limit]
        ]
        return {"summary": self.summary(scan_id), "principals": principal_payload, "sessions": session_payload,
                "operation_controls": control_payload, "transitions": transition_payload}

    @staticmethod
    def _principal(row) -> AuthPrincipal:
        return AuthPrincipal(row["id"],row["scan_id"],row["label"],row["kind"],row["role"],float(row["confidence"]),row["source"],_json_object(row["metadata_json"]),row["created_at"],row["updated_at"])

    @staticmethod
    def _session(row) -> AuthSession:
        return AuthSession(row["id"],row["scan_id"],row["label"],row["transport"],row["mechanism"],row["state"],None if row["secure"] is None else bool(row["secure"]),None if row["http_only"] is None else bool(row["http_only"]),row["same_site"],row["domain"],row["path"],row["expires_at"],bool(row["value_present"]),row["fingerprint_sha256"],row["source"],float(row["confidence"]),_json_object(row["metadata_json"]),row["created_at"],row["updated_at"])

    @staticmethod
    def _control(row) -> AuthOperationControl:
        return AuthOperationControl(row["id"],row["scan_id"],row["operation_id"],row["principal_id"],row["principal_label"],row["access_state"],bool(row["auth_required"]),_json_list(row["schemes_json"]),float(row["confidence"]),_json_object(row["basis_json"]),row["created_at"],row["updated_at"])

    @staticmethod
    def _transition(row) -> AuthTransition:
        return AuthTransition(row["id"],row["scan_id"],row["from_state"],row["to_state"],row["operation_id"],row["relation"],float(row["confidence"]),_json_object(row["basis_json"]),row["created_at"])

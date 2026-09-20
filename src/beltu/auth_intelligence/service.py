
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from beltu.api_intelligence.service import _redact
from beltu.storage.database import Database
from beltu.storage.models.api import ApiOperation
from beltu.storage.models.brain import Observation
from beltu.storage.repositories.api_repository import ApiRepository
from beltu.storage.repositories.auth_repository import AuthRepository
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository

_SENSITIVE_KEYS = re.compile(r"(?:value|content|secret|token|password|passwd|authorization|cookie|set-cookie|api[-_]?key|credential|jwt)", re.I)
_SESSION_NAME = re.compile(r"(?:session|sess|sid|auth|csrf|xsrf|jwt|refresh|access)[-_]?[a-z0-9_]*", re.I)

@dataclass(frozen=True, slots=True)
class AuthInventoryResult:
    principals: tuple[Any, ...]
    sessions: tuple[Any, ...]
    controls: tuple[Any, ...]
    transitions: tuple[Any, ...]
    summary: dict[str, int]


def _structured(obs: Observation) -> dict[str, Any]:
    data = obs.data if isinstance(obs.data, dict) else {}
    nested = data.get("structured")
    if isinstance(nested, dict):
        merged = dict(data)
        merged.update(nested)
        return merged
    return data


def _values(value: Any, limit: int = 20) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple, set)):
        return []
    out = []
    for item in value:
        text = str(item).strip()
        if text and text not in out:
            out.append(text[:120])
        if len(out) >= limit:
            break
    return out


def _safe_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return _redact({k: v for k, v in value.items() if not _SENSITIVE_KEYS.search(str(k))})


def _bool_or_none(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        low = value.strip().lower()
        if low in {"true","yes","1"}: return True
        if low in {"false","no","0"}: return False
    return None


class AuthIntelligenceService:
    """Derive authentication/session boundaries from stored observations and API inventory only.

    This stage never sends traffic and never persists credential/token values.
    """
    def __init__(self, db: Database) -> None:
        self.db = db
        self.auth = AuthRepository(db)
        self.observations = ObservationRepository(db)
        self.api = ApiRepository(db)
        self.scans = ScanRepository(db)
        self.targets = TargetRepository(db)

    def rebuild(self, scan_id: int) -> AuthInventoryResult:
        scan = self.scans.get(scan_id)
        if scan is None:
            raise ValueError(f"Scan #{scan_id} not found")
        if self.targets.get(scan.target_id) is None:
            raise ValueError(f"Target #{scan.target_id} not found")
        operations = self.api.list_operations(scan_id)
        observations = self.observations.list_for_scan(scan_id)
        op_by_path = {op.path: op for op in operations}
        op_by_id = {op.id: op for op in operations}
        explicit_principal_by_subject: dict[str, tuple[str, str | None, str]] = {}

        for obs in observations:
            d = _structured(obs)
            kind = obs.kind.strip().lower()
            if kind in {"auth", "authentication", "auth_flow", "identity", "access_control"}:
                label = str(d.get("principal") or d.get("identity") or d.get("user") or d.get("principal_label") or "").strip()
                role = str(d.get("role") or d.get("role_name") or "").strip() or None
                state = str(d.get("state") or d.get("auth_state") or "").strip().lower()
                if label:
                    p_kind = str(d.get("principal_kind") or d.get("kind") or ("anonymous" if label.lower() in {"anonymous","guest","unauthenticated"} else "user")).strip().lower()
                    principal = self.auth.upsert_principal(scan_id, label, p_kind, role, obs.confidence, obs.source, _safe_metadata(d))
                    explicit_principal_by_subject[obs.subject] = (principal.label, principal.role, state)
                self._record_transition(scan_id, obs, d, op_by_path, op_by_id)
            if kind in {"session", "authentication", "auth"}:
                self._record_session(scan_id, obs, d)

        # Every API operation gets a neutral control record. Explicit principals can add role-specific records.
        for op in operations:
            access_state = "authentication_required" if op.auth_required else "authentication_not_observed"
            principal_id = None
            principal_label = "unspecified"
            for subject, (label, role, _) in explicit_principal_by_subject.items():
                if subject == op.path or subject == op.operation_id or subject == op.operation_key or subject.endswith(op.path):
                    principal = next((p for p in self.auth.list_principals(scan_id) if p.label == label and p.role == role), None)
                    principal_id = principal.id if principal else None
                    principal_label = label
                    break
            self.auth.upsert_operation_control(scan_id, op.id, principal_id, principal_label, access_state, op.auth_required, op.auth_schemes, op.confidence, {"source": "api_inventory", "operation_key": op.operation_key})

        # Add explicit role-based controls from observations after all operations exist.
        principals = self.auth.list_principals(scan_id)
        by_label_role = {(p.label, p.role): p for p in principals}
        for obs in observations:
            d = _structured(obs)
            kind = obs.kind.strip().lower()
            if kind not in {"auth", "authentication", "auth_flow", "identity", "access_control"}:
                continue
            label = str(d.get("principal") or d.get("identity") or d.get("user") or d.get("principal_label") or "").strip()
            role = str(d.get("role") or d.get("role_name") or "").strip() or None
            if not label:
                continue
            principal = by_label_role.get((label, role))
            target_op = self._match_operation(obs, d, op_by_path, op_by_id)
            if target_op is not None and principal is not None:
                state = str(d.get("access_state") or d.get("state") or "observed").strip().lower() or "observed"
                schemes = tuple(str(x) for x in _values(d.get("schemes") or d.get("auth_schemes"), 20))
                if not schemes:
                    schemes = target_op.auth_schemes
                self.auth.upsert_operation_control(scan_id, target_op.id, principal.id, principal.label, state, target_op.auth_required, schemes, max(obs.confidence, target_op.confidence), {"observation_id": obs.id, "role": role})

        return AuthInventoryResult(tuple(self.auth.list_principals(scan_id)), tuple(self.auth.list_sessions(scan_id)), tuple(self.auth.list_controls(scan_id)), tuple(self.auth.list_transitions(scan_id)), self.auth.summary(scan_id))

    def _match_operation(self, obs: Observation, d: dict[str, Any], by_path: dict[str, ApiOperation], by_id: dict[int, ApiOperation]) -> ApiOperation | None:
        raw_id = d.get("operation_id")
        try:
            if raw_id is not None and int(raw_id) in by_id:
                return by_id[int(raw_id)]
        except (TypeError, ValueError):
            pass
        for key in ("path", "endpoint", "operation", "subject"):
            value = str(d.get(key) or "").strip()
            if value in by_path:
                return by_path[value]
            if value:
                for op in by_id.values():
                    if value == op.operation_id or value == op.operation_key or value.endswith(op.path):
                        return op
        return by_path.get(obs.subject.strip())

    def _record_transition(self, scan_id: int, obs: Observation, d: dict[str, Any], by_path: dict[str, ApiOperation], by_id: dict[int, ApiOperation]) -> None:
        pairs = []
        if d.get("transition_from") and d.get("transition_to"):
            pairs.append((str(d["transition_from"]), str(d["transition_to"]), "observed_transition", float(d.get("transition_confidence", obs.confidence))))
        transitions = d.get("transitions")
        if isinstance(transitions, list):
            for item in transitions[:50]:
                if isinstance(item, dict) and item.get("from") and item.get("to"):
                    try: conf = min(1.0, max(0.0, float(item.get("confidence", obs.confidence))))
                    except (TypeError, ValueError): conf = obs.confidence
                    pairs.append((str(item["from"]), str(item["to"]), str(item.get("relation") or "observed_transition"), conf))
        op = self._match_operation(obs, d, by_path, by_id)
        for src, dst, relation, conf in pairs:
            self.auth.upsert_transition(scan_id, src.strip().lower(), dst.strip().lower(), op.id if op else None, relation, conf, {"observation_id": obs.id})

    def _record_session(self, scan_id: int, obs: Observation, d: dict[str, Any]) -> None:
        candidates = []
        raw = d.get("sessions")
        if isinstance(raw, list): candidates.extend(x for x in raw if isinstance(x, dict))
        if d.get("session") and isinstance(d.get("session"), dict): candidates.append(d["session"])
        if not candidates and any(k in d for k in ("cookie_name","header_name","session_name","mechanism","transport")):
            candidates.append(d)
        for item in candidates[:50]:
            label = str(item.get("name") or item.get("cookie_name") or item.get("header_name") or item.get("session_name") or "session").strip()
            transport = str(item.get("transport") or ("cookie" if item.get("cookie_name") else "header" if item.get("header_name") else "unknown")).strip().lower()
            mechanism = str(item.get("mechanism") or item.get("type") or "session_token").strip().lower()
            state = str(item.get("state") or d.get("state") or "observed").strip().lower()
            # Only presence is retained; raw values are never persisted.
            value_present = any(key in item for key in ("value", "token", "content")) or any(key in d for key in ("value", "token", "content"))
            session = self.auth.upsert_session(
                scan_id, label=label, transport=transport, mechanism=mechanism, state=state,
                secure=_bool_or_none(item.get("secure")), http_only=_bool_or_none(item.get("http_only") or item.get("httponly")),
                same_site=str(item.get("same_site") or item.get("samesite") or "").strip().lower() or None,
                domain=str(item.get("domain") or "").strip() or None, path=str(item.get("path") or "").strip() or None,
                expires_at=str(item.get("expires_at") or item.get("expires") or "").strip() or None,
                value_present=value_present, source=obs.source, confidence=obs.confidence,
                metadata=_safe_metadata(item),
            )
            # A session observation may contain an explicit lifecycle transition.
            src = str(item.get("transition_from") or "").strip().lower()
            dst = str(item.get("transition_to") or "").strip().lower()
            if src and dst:
                self.auth.upsert_transition(scan_id, src, dst, None, "session_lifecycle", obs.confidence, {"observation_id": obs.id, "session_id": session.id})

    def context_payload(self, scan_id: int, limit: int = 100) -> dict[str, Any]:
        self.rebuild(scan_id)
        return self.auth.context_payload(scan_id, limit=limit)

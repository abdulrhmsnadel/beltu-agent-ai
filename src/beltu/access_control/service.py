from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from beltu.api_intelligence.service import ApiIntelligenceService
from beltu.auth_intelligence.service import AuthIntelligenceService
from beltu.storage.database import Database
from beltu.storage.models.api import ApiOperation
from beltu.storage.models.auth import AuthOperationControl, AuthPrincipal
from beltu.storage.models.access_control import AuthorizationAnomaly, AuthorizationMatrixEntry
from beltu.storage.repositories.access_control_repository import AccessControlRepository
from beltu.storage.repositories.api_repository import ApiRepository
from beltu.storage.repositories.auth_repository import AuthRepository
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository


_ALLOWED_STATES = {
    "allowed", "allow", "granted", "success", "observed", "protected", "authentication_required",
    "authenticated", "denied", "deny", "forbidden", "rejected", "public", "unauthenticated", "unknown",
}


def _state(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {"allow": "allowed", "grant": "granted", "deny": "denied", "forbid": "forbidden", "required": "authentication_required"}
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in _ALLOWED_STATES else "unknown"


def _is_anonymous(label: str, role: str | None) -> bool:
    values = {label.strip().lower(), (role or "").strip().lower()}
    return bool(values & {"anonymous", "guest", "unauthenticated", "public"})


def _is_authenticated(label: str, role: str | None) -> bool:
    if _is_anonymous(label, role):
        return False
    return bool(label.strip()) and label.strip().lower() not in {"unspecified", "unknown"}


def _positive_access(state: str) -> bool:
    return state in {"allowed", "granted", "success", "observed", "public", "unauthenticated", "authenticated"}


def _negative_access(state: str) -> bool:
    return state in {"denied", "forbidden", "rejected"}


@dataclass(frozen=True, slots=True)
class AuthorizationInventoryResult:
    matrix: tuple[AuthorizationMatrixEntry, ...]
    anomalies: tuple[AuthorizationAnomaly, ...]
    summary: dict[str, int]


class AccessControlIntelligenceService:
    """Derive an authorization matrix and candidate inconsistencies from stored evidence only.

    This stage is analytical/read-only with respect to the target. It does not create traffic,
    mutate the target, or attempt privilege escalation. Candidate anomalies require validation.
    """

    def __init__(self, db: Database) -> None:
        self.db = db
        self.repo = AccessControlRepository(db)
        self.observations = ObservationRepository(db)
        self.api = ApiRepository(db)
        self.auth = AuthRepository(db)
        self.scans = ScanRepository(db)
        self.targets = TargetRepository(db)
        self.api_intelligence = ApiIntelligenceService(db)
        self.auth_intelligence = AuthIntelligenceService(db)

    def rebuild(self, scan_id: int) -> AuthorizationInventoryResult:
        scan = self.scans.get(scan_id)
        if scan is None:
            raise ValueError(f"Scan #{scan_id} not found")
        if self.targets.get(scan.target_id) is None:
            raise ValueError(f"Target #{scan.target_id} not found")

        # Rebuild upstream analytical views from stored evidence so Stage 15 is self-contained.
        self.api_intelligence.rebuild(scan_id)
        self.auth_intelligence.rebuild(scan_id)
        operations = self.api.list_operations(scan_id)
        controls = self.auth.list_controls(scan_id)
        principals = self.auth.list_principals(scan_id)
        principal_map = {p.id: p for p in principals}
        by_op: dict[int, list[AuthOperationControl]] = defaultdict(list)
        for control in controls:
            by_op[control.operation_id].append(control)

        for op in operations:
            op_controls = by_op.get(op.id, [])
            if not op_controls:
                self.repo.upsert_matrix_entry(
                    scan_id=scan_id, operation_id=op.id, principal_id=None, principal_label="unspecified", role=None,
                    access_state="authentication_required" if op.auth_required else "unknown", auth_required=op.auth_required,
                    confidence=op.confidence, evidence_ids=(), basis={"source": "api_operation", "derived": True},
                )
                continue
            for control in op_controls:
                principal = principal_map.get(control.principal_id) if control.principal_id is not None else None
                role = principal.role if principal else None
                evidence_ids = self._evidence_ids(control)
                self.repo.upsert_matrix_entry(
                    scan_id=scan_id, operation_id=op.id, principal_id=control.principal_id,
                    principal_label=control.principal_label, role=role, access_state=_state(control.access_state),
                    auth_required=control.auth_required, confidence=control.confidence,
                    evidence_ids=evidence_ids, basis={**control.basis, "source": "auth_operation_control"},
                )

        self.repo.clear_rebuildable_anomalies(scan_id)
        matrix = self.repo.list_matrix(scan_id)
        anomalies = self._detect_anomalies(scan_id, operations, matrix)
        return AuthorizationInventoryResult(tuple(matrix), tuple(anomalies), self.repo.summary(scan_id))

    def _evidence_ids(self, control: AuthOperationControl) -> tuple[int, ...]:
        raw = control.basis.get("observation_id") if isinstance(control.basis, dict) else None
        try:
            return (int(raw),) if raw is not None else ()
        except (TypeError, ValueError):
            return ()

    def _detect_anomalies(self, scan_id: int, operations: list[ApiOperation], matrix: list[AuthorizationMatrixEntry]) -> list[AuthorizationAnomaly]:
        by_op: dict[int, list[AuthorizationMatrixEntry]] = defaultdict(list)
        for entry in matrix:
            by_op[entry.operation_id].append(entry)
        anomalies: list[AuthorizationAnomaly] = []

        for op in operations:
            rows = by_op.get(op.id, [])
            if not rows:
                continue

            # Same principal/role observed with incompatible access states.
            by_principal: dict[tuple[str, str | None], list[AuthorizationMatrixEntry]] = defaultdict(list)
            for row in rows:
                by_principal[(row.principal_label.strip().lower(), row.role)] .append(row)
            for (label, role), principal_rows in by_principal.items():
                states = {r.access_state for r in principal_rows}
                has_positive = any(_positive_access(s) for s in states)
                has_negative = any(_negative_access(s) for s in states)
                if has_positive and has_negative:
                    confidence = max(r.confidence for r in principal_rows)
                    anomaly = self.repo.upsert_anomaly(
                        scan_id=scan_id, kind="principal_state_conflict", severity="medium", entity_type="operation", entity_id=op.id,
                        statement=f"Principal '{label}' has both positive and negative access observations for {op.method} {op.path}.",
                        rationale="Conflicting observations for the same principal/operation should be reconciled before treating the authorization boundary as understood.",
                        confidence=confidence, basis={"rebuildable": True, "principal_label": label, "role": role, "states": sorted(states)},
                    )
                    anomalies.append(anomaly)

            if op.auth_required:
                positive_anonymous = [r for r in rows if _is_anonymous(r.principal_label, r.role) and _positive_access(r.access_state)]
                if positive_anonymous:
                    confidence = max(r.confidence for r in positive_anonymous)
                    anomaly = self.repo.upsert_anomaly(
                        scan_id=scan_id, kind="anonymous_access_to_protected", severity="high", entity_type="operation", entity_id=op.id,
                        statement=f"Stored evidence indicates anonymous/guest access to an operation marked authentication-required: {op.method} {op.path}.",
                        rationale="This is a candidate authorization-boundary inconsistency. It needs explicit validation; the analytical model alone does not establish exploitability.",
                        confidence=confidence, basis={"rebuildable": True, "auth_required": True, "rows": [r.id for r in positive_anonymous]},
                    )
                    anomalies.append(anomaly)

                authenticated_rows = [r for r in rows if _is_authenticated(r.principal_label, r.role) and _positive_access(r.access_state)]
                if not authenticated_rows and not positive_anonymous:
                    anomaly = self.repo.upsert_anomaly(
                        scan_id=scan_id, kind="protected_without_authenticated_observation", severity="low", entity_type="operation", entity_id=op.id,
                        statement=f"Operation {op.method} {op.path} is marked authentication-required but no positive authenticated access observation is stored.",
                        rationale="The evidence model is incomplete for this operation; this is a coverage gap, not a vulnerability finding.",
                        confidence=op.confidence, basis={"rebuildable": True, "auth_required": True},
                    )
                    anomalies.append(anomaly)

            roles = defaultdict(lambda: {"positive": False, "negative": False})
            for row in rows:
                key = (row.role or row.principal_label or "unspecified").strip().lower()
                roles[key]["positive"] |= _positive_access(row.access_state)
                roles[key]["negative"] |= _negative_access(row.access_state)
            positive_roles = sorted(k for k, v in roles.items() if v["positive"])
            negative_roles = sorted(k for k, v in roles.items() if v["negative"])
            if positive_roles and negative_roles and set(positive_roles) != set(negative_roles):
                anomaly = self.repo.upsert_anomaly(
                    scan_id=scan_id, kind="role_access_difference", severity="info", entity_type="operation", entity_id=op.id,
                    statement=f"Authorization observations differ across principals/roles for {op.method} {op.path}.",
                    rationale="Role-dependent access differences can be intentional; this record identifies a boundary that merits contextual review rather than asserting a defect.",
                    confidence=max(r.confidence for r in rows), basis={"rebuildable": True, "positive_roles": positive_roles, "negative_roles": negative_roles},
                )
                anomalies.append(anomaly)

        # Deterministic de-duplication by repository identity.
        unique: dict[tuple[str, str, int], AuthorizationAnomaly] = {}
        for anomaly in anomalies:
            unique[(anomaly.kind, anomaly.entity_type, anomaly.entity_id)] = anomaly
        return list(unique.values())

    def context_payload(self, scan_id: int, limit: int = 200) -> dict[str, Any]:
        self.rebuild(scan_id)
        return self.repo.context_payload(scan_id, limit=limit)

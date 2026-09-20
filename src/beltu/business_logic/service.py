from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from beltu.api_intelligence.service import ApiIntelligenceService
from beltu.storage.database import Database
from beltu.storage.models.api import ApiOperation, ApiRelation
from beltu.storage.models.brain import Observation
from beltu.storage.repositories.access_control_repository import AccessControlRepository
from beltu.storage.repositories.api_repository import ApiRepository
from beltu.storage.repositories.business_logic_repository import BusinessLogicRepository
from beltu.storage.repositories.observation_repository import ObservationRepository

_ACTION_STATE_MAP = {
    "create": ("start", "created"),
    "open": ("new", "open"),
    "submit": ("draft", "submitted"),
    "approve": ("pending", "approved"),
    "confirm": ("pending", "confirmed"),
    "complete": ("in_progress", "completed"),
    "cancel": ("pending", "cancelled"),
    "reject": ("pending", "rejected"),
    "delete": ("active", "deleted"),
    "close": ("open", "closed"),
    "refund": ("paid", "refunded"),
    "publish": ("draft", "published"),
}

_IGNORED_PREFIXES = ("health", "metrics", "docs", "schema", "openapi")


def _norm(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def _workflow_key(path: str, operation: ApiOperation | None = None, metadata: dict[str, Any] | None = None) -> str:
    metadata = metadata or {}
    explicit = metadata.get("workflow") or metadata.get("workflow_key")
    if isinstance(explicit, str) and explicit.strip():
        return _norm(explicit)
    parts = [p for p in path.split("/") if p and not p.startswith("{")]
    if not parts:
        return "root"
    first = _norm(parts[0])
    if first in _IGNORED_PREFIXES and len(parts) > 1:
        first = _norm(parts[1])
    return first or "root"


def _action_from_operation(operation: ApiOperation) -> str | None:
    path_tokens = [t for t in operation.path.split("/") if t and not t.startswith("{")]
    for token in reversed(path_tokens):
        clean = _norm(token)
        if clean in _ACTION_STATE_MAP:
            return clean
    if operation.operation_id:
        clean = _norm(operation.operation_id)
        for action in _ACTION_STATE_MAP:
            if clean.endswith(action) or clean.startswith(action) or f"_{action}_" in clean:
                return action
    summary = _norm(operation.summary or "")
    for action in _ACTION_STATE_MAP:
        if action in summary.split("_"):
            return action
    return None


def _explicit_workflow_payload(observation: Observation) -> dict[str, Any] | None:
    data = observation.data if isinstance(observation.data, dict) else {}
    kind = observation.kind.lower()
    if kind not in {"workflow", "workflow.state", "workflow.transition", "state_transition", "order", "cart", "business_logic"} and not any(k in data for k in ("from_state", "to_state", "state")):
        return None
    payload = dict(data)
    payload.setdefault("subject", observation.subject)
    payload.setdefault("source", observation.source)
    payload.setdefault("observation_id", observation.id)
    payload.setdefault("confidence", observation.confidence)
    return payload


@dataclass(frozen=True, slots=True)
class BusinessLogicResult:
    workflows: tuple[Any, ...]
    transitions: tuple[Any, ...]
    anomalies: tuple[Any, ...]
    summary: dict[str, int]


class BusinessLogicIntelligenceService:
    """Build a passive workflow/state model from stored API and workflow evidence.

    This stage does not send requests and does not prove exploitability. It identifies
    state-machine inconsistencies and validation candidates from evidence already stored.
    """

    def __init__(self, db: Database) -> None:
        self.db = db
        self.repo = BusinessLogicRepository(db)
        self.observations = ObservationRepository(db)
        self.api = ApiRepository(db)
        self.api_intelligence = ApiIntelligenceService(db)
        self.authz = AccessControlRepository(db)

    def rebuild(self, scan_id: int) -> BusinessLogicResult:
        # Ensure API relations exist before constructing workflow edges.
        self.api_intelligence.rebuild(scan_id)
        operations = self.api.list_operations(scan_id)
        relations = self.api.list_relations(scan_id)
        observations = self.observations.list_for_scan(scan_id)

        grouped: dict[str, list[ApiOperation]] = defaultdict(list)
        for op in operations:
            grouped[_workflow_key(op.path, op, op.metadata)].append(op)

        # Explicit workflow observations may create more precise workflow keys.
        explicit = [p for obs in observations if (p := _explicit_workflow_payload(obs)) is not None]
        for payload in explicit:
            key = _norm(str(payload.get("workflow") or payload.get("workflow_key") or ""))
            if key and key not in grouped:
                grouped[key] = []

        for key, ops in grouped.items():
            workflow = self.repo.upsert_workflow(
                scan_id=scan_id,
                workflow_key=key,
                label=key.replace("_", " ").title(),
                confidence=max((op.confidence for op in ops), default=0.6),
                source="api+stored_observations",
                metadata={"operation_count": len(ops), "passive": True},
            )
            self._build_states(workflow.id, ops, explicit)

        self._reconcile_explicit_observations(scan_id, grouped, explicit)
        self._build_relation_transitions(scan_id, grouped, relations)
        self._infer_safe_action_transitions(scan_id, grouped)
        self.repo.clear_rebuildable_anomalies(scan_id)
        self._detect_anomalies(scan_id, operations)
        workflows = tuple(self.repo.list_workflows(scan_id))
        transitions = tuple(self.repo.list_transitions(scan_id))
        anomalies = tuple(self.repo.list_anomalies(scan_id))
        return BusinessLogicResult(workflows, transitions, anomalies, self.repo.summary(scan_id))

    def _build_states(self, workflow_id: int, operations: list[ApiOperation], explicit: list[dict[str, Any]]) -> None:
        states: dict[str, tuple[bool, bool, float, str]] = {}
        for op in operations:
            action = _action_from_operation(op)
            if action in _ACTION_STATE_MAP:
                src, dst = _ACTION_STATE_MAP[action]
                states[src] = (states.get(src, (False, False, 0.0, "inference"))[0] or src == "start", False, max(states.get(src, (False, False, 0.0, "inference"))[2], op.confidence), "action_inference")
                states[dst] = (states.get(dst, (False, False, 0.0, "inference"))[0], dst in {"cancelled", "rejected", "completed", "deleted", "refunded", "closed"}, max(states.get(dst, (False, False, 0.0, "inference"))[2], op.confidence), "action_inference")
        for payload in explicit:
            workflow_key = _norm(str(payload.get("workflow") or payload.get("workflow_key") or ""))
            workflow = self.repo.list_workflows(payload.get("scan_id", 0)) if False else None
            if workflow_key:
                # Explicit observations are reconciled below because workflow IDs are known there.
                pass
            state = payload.get("state")
            if isinstance(state, str) and state.strip():
                clean = _norm(state)
                states[clean] = (bool(payload.get("initial", False)), bool(payload.get("terminal", False)), max(float(payload.get("confidence", 0.5) or 0.5), states.get(clean, (False, False, 0.0, "observation"))[2]), "observation")
        for key, (initial, terminal, confidence, source) in states.items():
            self.repo.upsert_state(workflow_id=workflow_id, state_key=key, label=key.replace("_", " ").title(), initial=initial, terminal=terminal, confidence=confidence, source=source, metadata={"derived": True})

    def _reconcile_explicit_observations(self, scan_id: int, grouped: dict[str, list[ApiOperation]], explicit: list[dict[str, Any]]) -> None:
        workflows = {w.workflow_key: w for w in self.repo.list_workflows(scan_id)}
        operation_by_id = {op.id: op for op in self.api.list_operations(scan_id)}
        operation_by_path = {op.path: op for op in operation_by_id.values()}
        for payload in explicit:
            key = _norm(str(payload.get("workflow") or payload.get("workflow_key") or ""))
            if not key or key not in workflows:
                continue
            workflow = workflows[key]
            from_state = payload.get("from_state")
            to_state = payload.get("to_state")
            state = payload.get("state")
            if isinstance(state, str) and state.strip():
                self.repo.upsert_state(workflow_id=workflow.id, state_key=_norm(state), label=_norm(state).replace("_", " ").title(), initial=bool(payload.get("initial", False)), terminal=bool(payload.get("terminal", False)), confidence=float(payload.get("confidence", 0.5) or 0.5), source="observation", metadata={"observation_id": payload.get("observation_id")})
            if isinstance(from_state, str) and isinstance(to_state, str) and from_state.strip() and to_state.strip():
                op_id = payload.get("operation_id")
                if op_id is None and isinstance(payload.get("path"), str):
                    op = operation_by_path.get(payload["path"])
                    op_id = op.id if op else None
                evidence_ids = (int(payload["observation_id"]),) if str(payload.get("observation_id", "")).isdigit() else ()
                self.repo.upsert_state(workflow_id=workflow.id, state_key=_norm(from_state), label=_norm(from_state).replace("_", " ").title(), initial=bool(payload.get("initial", False)), terminal=False, confidence=float(payload.get("confidence", 0.5) or 0.5), source="observation", metadata={"observation_id": payload.get("observation_id")})
                self.repo.upsert_state(workflow_id=workflow.id, state_key=_norm(to_state), label=_norm(to_state).replace("_", " ").title(), initial=False, terminal=bool(payload.get("terminal", False)), confidence=float(payload.get("confidence", 0.5) or 0.5), source="observation", metadata={"observation_id": payload.get("observation_id")})
                try:
                    self.repo.upsert_transition(scan_id=scan_id, workflow_id=workflow.id, from_state=_norm(from_state), to_state=_norm(to_state), operation_id=int(op_id) if op_id is not None else None, relation="observed_transition", action=str(payload.get("action") or "") or None, confidence=float(payload.get("confidence", 0.5) or 0.5), evidence_ids=evidence_ids, basis={"rebuildable": True, "observation_id": payload.get("observation_id")})
                except ValueError:
                    pass

    def _build_relation_transitions(self, scan_id: int, grouped: dict[str, list[ApiOperation]], relations: list[ApiRelation]) -> None:
        by_id = {op.id: op for ops in grouped.values() for op in ops}
        workflows = {w.workflow_key: w for w in self.repo.list_workflows(scan_id)}
        for relation in relations:
            if relation.relation != "workflow_next":
                continue
            src = by_id.get(relation.from_operation_id)
            dst = by_id.get(relation.to_operation_id)
            if not src or not dst:
                continue
            key = _workflow_key(src.path, src, src.metadata)
            workflow = workflows.get(key)
            if not workflow or key != _workflow_key(dst.path, dst, dst.metadata):
                continue
            action = _action_from_operation(dst) or _action_from_operation(src)
            if action in _ACTION_STATE_MAP:
                src_state, _ = _ACTION_STATE_MAP[action]
                _, dst_state = _ACTION_STATE_MAP[action]
            else:
                src_state = _norm(src.operation_id or src.method.lower() + "_step")
                dst_state = _norm(dst.operation_id or dst.method.lower() + "_step")
            self.repo.upsert_state(workflow_id=workflow.id, state_key=src_state, label=src_state.replace("_", " ").title(), initial=src_state == "start", terminal=False, confidence=relation.confidence, source="api_relation", metadata={"relation_id": relation.id})
            self.repo.upsert_state(workflow_id=workflow.id, state_key=dst_state, label=dst_state.replace("_", " ").title(), initial=False, terminal=dst_state in {"cancelled", "rejected", "completed", "deleted", "refunded", "closed"}, confidence=relation.confidence, source="api_relation", metadata={"relation_id": relation.id})
            if src_state != dst_state:
                self.repo.upsert_transition(scan_id=scan_id, workflow_id=workflow.id, from_state=src_state, to_state=dst_state, operation_id=src.id, relation="api_workflow_next", action=action, confidence=relation.confidence, basis={"rebuildable": True, "api_relation_id": relation.id, "to_operation_id": dst.id})

    def _infer_safe_action_transitions(self, scan_id: int, grouped: dict[str, list[ApiOperation]]) -> None:
        workflows = {w.workflow_key: w for w in self.repo.list_workflows(scan_id)}
        for key, ops in grouped.items():
            workflow = workflows.get(key)
            if not workflow:
                continue
            for op in sorted(ops, key=lambda item: (item.path, item.method, item.id)):
                action = _action_from_operation(op)
                if action not in _ACTION_STATE_MAP:
                    continue
                src, dst = _ACTION_STATE_MAP[action]
                try:
                    self.repo.upsert_state(workflow_id=workflow.id, state_key=src, label=src.replace("_", " ").title(), initial=src == "start", terminal=False, confidence=op.confidence, source="action_inference", metadata={"operation_id": op.id})
                    self.repo.upsert_state(workflow_id=workflow.id, state_key=dst, label=dst.replace("_", " ").title(), initial=False, terminal=dst in {"cancelled", "rejected", "completed", "deleted", "refunded", "closed"}, confidence=op.confidence, source="action_inference", metadata={"operation_id": op.id})
                    self.repo.upsert_transition(scan_id=scan_id, workflow_id=workflow.id, from_state=src, to_state=dst, operation_id=op.id, relation="inferred_action", action=action, confidence=min(0.75, op.confidence), basis={"rebuildable": True, "operation_key": op.operation_key})
                except ValueError:
                    continue

    def _detect_anomalies(self, scan_id: int, operations: list[ApiOperation]) -> None:
        workflows = self.repo.list_workflows(scan_id)
        transitions = self.repo.list_transitions(scan_id)
        authz = self.authz.list_matrix(scan_id)
        authz_by_op: dict[int, list[Any]] = defaultdict(list)
        for row in authz:
            authz_by_op[row.operation_id].append(row)
        by_workflow: dict[int, list[Any]] = defaultdict(list)
        for t in transitions:
            by_workflow[t.workflow_id].append(t)
        for workflow in workflows:
            ts = by_workflow.get(workflow.id, [])
            if not ts:
                continue
            states = {s.state_key: s for s in self.repo.list_states(workflow.id)}
            outgoing = defaultdict(list)
            incoming = defaultdict(list)
            for t in ts:
                outgoing[t.from_state].append(t)
                incoming[t.to_state].append(t)
            for state_key, state in states.items():
                if not state.initial and state_key not in incoming:
                    self.repo.upsert_anomaly(
                        scan_id=scan_id, workflow_id=workflow.id, kind="unreachable_state_candidate", severity="low",
                        statement=f"State '{state_key}' has no observed incoming transition in workflow '{workflow.workflow_key}'.",
                        rationale="This may indicate an incomplete model or an invalid/unreachable state; the evidence is insufficient to call it a defect.",
                        confidence=state.confidence, entity_key=state_key, basis={"rebuildable": True, "state_id": state.id},
                    )
                if state.terminal and outgoing.get(state_key):
                    self.repo.upsert_anomaly(
                        scan_id=scan_id, workflow_id=workflow.id, kind="terminal_state_has_outgoing", severity="medium",
                        statement=f"Terminal state '{state_key}' has an observed outgoing transition.",
                        rationale="A terminal state normally ends a workflow branch. An outgoing edge can be intentional, but it is a state-machine consistency candidate that merits review.",
                        confidence=max(t.confidence for t in outgoing[state_key]), entity_key=state_key,
                        basis={"rebuildable": True, "transition_ids": [t.id for t in outgoing[state_key]]},
                    )
            # Candidate: high-impact state-changing actions without authenticated evidence.
            op_map = {op.id: op for op in operations}
            for transition in ts:
                op = op_map.get(transition.operation_id) if transition.operation_id is not None else None
                if not op or transition.action not in {"cancel", "approve", "confirm", "refund", "delete", "publish"}:
                    continue
                rows = authz_by_op.get(op.id, [])
                weak = [r for r in rows if str(r.access_state).lower() in {"public", "unauthenticated", "allowed"} and str(r.principal_label).lower() in {"anonymous", "guest"}]
                if op.auth_required and weak:
                    self.repo.upsert_anomaly(
                        scan_id=scan_id, workflow_id=workflow.id, kind="sensitive_transition_weak_boundary", severity="high",
                        statement=f"Workflow transition '{transition.action}' for {op.method} {op.path} has stored anonymous/public positive-access evidence while the operation is marked authentication-required.",
                        rationale="This combines workflow semantics with an authorization candidate. It is not a confirmed vulnerability and requires explicit validation.",
                        confidence=max(op.confidence, max(r.confidence for r in weak)), entity_key=str(op.id),
                        basis={"rebuildable": True, "operation_id": op.id, "transition_id": transition.id, "matrix_ids": [r.id for r in weak]},
                    )
            branches = defaultdict(set)
            for t in ts:
                branches[t.from_state].add(t.to_state)
            for source, dests in branches.items():
                if len(dests) > 1:
                    self.repo.upsert_anomaly(
                        scan_id=scan_id, workflow_id=workflow.id, kind="branching_state_candidate", severity="info",
                        statement=f"State '{source}' has multiple observed next states: {', '.join(sorted(dests))}.",
                        rationale="Multiple branches can be intentional. The record identifies a decision point for workflow modeling and is not itself a vulnerability.",
                        confidence=max(t.confidence for t in ts if t.from_state == source), entity_key=source,
                        basis={"rebuildable": True, "destinations": sorted(dests)},
                    )

    def context_payload(self, scan_id: int, limit: int = 100) -> dict[str, Any]:
        self.rebuild(scan_id)
        return self.repo.context_payload(scan_id, limit=limit)

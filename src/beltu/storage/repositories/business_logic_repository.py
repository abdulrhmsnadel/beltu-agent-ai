from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from beltu.storage.database import Database
from beltu.storage.models.business_logic import (
    BusinessLogicAnomaly,
    BusinessWorkflow,
    WorkflowState,
    WorkflowTransition,
)


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


class BusinessLogicRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    def upsert_workflow(
        self, *, scan_id: int, workflow_key: str, label: str, confidence: float,
        source: str, metadata: dict[str, Any] | None = None,
    ) -> BusinessWorkflow:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("Workflow confidence must be between 0 and 1")
        key = workflow_key.strip().lower()
        if not key:
            raise ValueError("Workflow key cannot be empty")
        now = utc_now()
        metadata_json = json.dumps(metadata or {}, sort_keys=True)
        with self.db.connect() as conn:
            conn.execute(
                """INSERT INTO business_workflows(
                    scan_id, workflow_key, label, confidence, source, metadata_json, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(scan_id, workflow_key) DO UPDATE SET
                    label=excluded.label,
                    confidence=MAX(business_workflows.confidence, excluded.confidence),
                    source=excluded.source,
                    metadata_json=excluded.metadata_json,
                    updated_at=excluded.updated_at""",
                (scan_id, key, label[:200], confidence, source[:200], metadata_json, now, now),
            )
            row = conn.execute(
                "SELECT * FROM business_workflows WHERE scan_id=? AND workflow_key=?", (scan_id, key)
            ).fetchone()
        return self._workflow(row)

    def upsert_state(
        self, *, workflow_id: int, state_key: str, label: str, initial: bool, terminal: bool,
        confidence: float, source: str, metadata: dict[str, Any] | None = None,
    ) -> WorkflowState:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("State confidence must be between 0 and 1")
        key = state_key.strip().lower()
        if not key:
            raise ValueError("State key cannot be empty")
        now = utc_now()
        with self.db.connect() as conn:
            conn.execute(
                """INSERT INTO workflow_states(
                    workflow_id, state_key, label, initial, terminal, confidence, source, metadata_json, created_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(workflow_id, state_key) DO UPDATE SET
                    label=excluded.label,
                    initial=MAX(workflow_states.initial, excluded.initial),
                    terminal=MAX(workflow_states.terminal, excluded.terminal),
                    confidence=MAX(workflow_states.confidence, excluded.confidence),
                    source=excluded.source,
                    metadata_json=excluded.metadata_json""",
                (workflow_id, key, label[:200], int(initial), int(terminal), confidence, source[:200], json.dumps(metadata or {}, sort_keys=True), now),
            )
            row = conn.execute("SELECT * FROM workflow_states WHERE workflow_id=? AND state_key=?", (workflow_id, key)).fetchone()
        return self._state(row)

    def upsert_transition(
        self, *, scan_id: int, workflow_id: int, from_state: str, to_state: str,
        operation_id: int | None, relation: str, action: str | None, confidence: float,
        evidence_ids: tuple[int, ...] = (), basis: dict[str, Any] | None = None,
    ) -> WorkflowTransition:
        if from_state.strip().lower() == to_state.strip().lower():
            # Self-loops can be legitimate but are excluded from the explicit state-transition graph.
            raise ValueError("Workflow transitions cannot self-reference")
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("Transition confidence must be between 0 and 1")
        now = utc_now()
        with self.db.connect() as conn:
            existing = conn.execute(
                """SELECT * FROM workflow_transitions
                   WHERE workflow_id=? AND from_state=? AND to_state=? AND operation_id IS ? AND relation=?""",
                (workflow_id, from_state.strip().lower(), to_state.strip().lower(), operation_id, relation.strip().lower()),
            ).fetchone()
            payload = (
                scan_id, workflow_id, from_state.strip().lower(), to_state.strip().lower(), operation_id,
                relation.strip().lower(), action[:120] if action else None, confidence,
                json.dumps(list(dict.fromkeys(evidence_ids)), sort_keys=True), json.dumps(basis or {}, sort_keys=True), now,
            )
            if existing is None:
                cur = conn.execute(
                    """INSERT INTO workflow_transitions(
                        scan_id, workflow_id, from_state, to_state, operation_id, relation, action, confidence,
                        evidence_ids_json, basis_json, created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""", payload,
                )
                row = conn.execute("SELECT * FROM workflow_transitions WHERE id=?", (int(cur.lastrowid),)).fetchone()
            else:
                conn.execute(
                    """UPDATE workflow_transitions SET action=?, confidence=MAX(confidence, ?), evidence_ids_json=?, basis_json=? WHERE id=?""",
                    (action[:120] if action else None, confidence, json.dumps(list(dict.fromkeys(evidence_ids)), sort_keys=True), json.dumps(basis or {}, sort_keys=True), existing["id"]),
                )
                row = conn.execute("SELECT * FROM workflow_transitions WHERE id=?", (existing["id"],)).fetchone()
        return self._transition(row)

    def upsert_anomaly(
        self, *, scan_id: int, workflow_id: int, kind: str, severity: str,
        statement: str, rationale: str, confidence: float, entity_key: str,
        basis: dict[str, Any] | None = None, status: str = "candidate",
    ) -> BusinessLogicAnomaly:
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("Anomaly confidence must be between 0 and 1")
        now = utc_now()
        with self.db.connect() as conn:
            conn.execute(
                """INSERT INTO business_logic_anomalies(
                    scan_id, workflow_id, kind, severity, statement, rationale, confidence, entity_key,
                    basis_json, status, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(scan_id, workflow_id, kind, entity_key) DO UPDATE SET
                    severity=excluded.severity,
                    statement=excluded.statement,
                    rationale=excluded.rationale,
                    confidence=MAX(business_logic_anomalies.confidence, excluded.confidence),
                    basis_json=excluded.basis_json,
                    status=excluded.status,
                    updated_at=excluded.updated_at""",
                (scan_id, workflow_id, kind[:100], severity[:30], statement[:600], rationale[:1200], confidence,
                 entity_key[:200], json.dumps(basis or {}, sort_keys=True), status[:30], now, now),
            )
            row = conn.execute(
                "SELECT * FROM business_logic_anomalies WHERE scan_id=? AND workflow_id=? AND kind=? AND entity_key=?",
                (scan_id, workflow_id, kind, entity_key[:200]),
            ).fetchone()
        return self._anomaly(row)

    def clear_rebuildable_anomalies(self, scan_id: int) -> None:
        with self.db.connect() as conn:
            conn.execute(
                "DELETE FROM business_logic_anomalies WHERE scan_id=? AND basis_json LIKE '%\"rebuildable\": true%'",
                (scan_id,),
            )

    def list_workflows(self, scan_id: int) -> list[BusinessWorkflow]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM business_workflows WHERE scan_id=? ORDER BY workflow_key, id", (scan_id,)).fetchall()
        return [self._workflow(row) for row in rows]

    def list_states(self, workflow_id: int) -> list[WorkflowState]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM workflow_states WHERE workflow_id=? ORDER BY state_key, id", (workflow_id,)).fetchall()
        return [self._state(row) for row in rows]

    def list_transitions(self, scan_id: int) -> list[WorkflowTransition]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM workflow_transitions WHERE scan_id=? ORDER BY workflow_id, from_state, to_state, id", (scan_id,)).fetchall()
        return [self._transition(row) for row in rows]

    def list_anomalies(self, scan_id: int) -> list[BusinessLogicAnomaly]:
        with self.db.connect() as conn:
            rows = conn.execute(
                """SELECT * FROM business_logic_anomalies WHERE scan_id=? ORDER BY
                CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END,
                workflow_id, kind, entity_key""", (scan_id,),
            ).fetchall()
        return [self._anomaly(row) for row in rows]

    def summary(self, scan_id: int) -> dict[str, int]:
        with self.db.connect() as conn:
            workflows = int(conn.execute("SELECT COUNT(*) FROM business_workflows WHERE scan_id=?", (scan_id,)).fetchone()[0])
            states = int(conn.execute("SELECT COUNT(*) FROM workflow_states ws JOIN business_workflows bw ON bw.id=ws.workflow_id WHERE bw.scan_id=?", (scan_id,)).fetchone()[0])
            transitions = int(conn.execute("SELECT COUNT(*) FROM workflow_transitions WHERE scan_id=?", (scan_id,)).fetchone()[0])
            anomalies = int(conn.execute("SELECT COUNT(*) FROM business_logic_anomalies WHERE scan_id=?", (scan_id,)).fetchone()[0])
            high = int(conn.execute("SELECT COUNT(*) FROM business_logic_anomalies WHERE scan_id=? AND severity='high'", (scan_id,)).fetchone()[0])
        return {"workflows": workflows, "states": states, "transitions": transitions, "anomalies": anomalies, "high_anomalies": high}

    def context_payload(self, scan_id: int, limit: int = 100) -> dict[str, Any]:
        workflows = self.list_workflows(scan_id)
        states_by_workflow = {w.id: self.list_states(w.id) for w in workflows}
        transitions = self.list_transitions(scan_id)
        anomalies = self.list_anomalies(scan_id)
        transitions_by_workflow: dict[int, list[WorkflowTransition]] = {}
        for item in transitions:
            transitions_by_workflow.setdefault(item.workflow_id, []).append(item)
        workflow_payload = []
        for workflow in workflows[:limit]:
            workflow_payload.append({
                "id": workflow.id,
                "workflow_key": workflow.workflow_key,
                "label": workflow.label,
                "confidence": workflow.confidence,
                "source": workflow.source,
                "states": [
                    {"id": s.id, "state_key": s.state_key, "label": s.label, "initial": s.initial, "terminal": s.terminal, "confidence": s.confidence, "source": s.source, "metadata": s.metadata}
                    for s in states_by_workflow[workflow.id][:limit]
                ],
                "transitions": [
                    {"id": t.id, "from_state": t.from_state, "to_state": t.to_state, "operation_id": t.operation_id, "relation": t.relation, "action": t.action, "confidence": t.confidence, "evidence_ids": list(t.evidence_ids), "basis": t.basis}
                    for t in transitions_by_workflow.get(workflow.id, [])[:limit]
                ],
            })
        return {
            "summary": self.summary(scan_id),
            "workflows": workflow_payload,
            "anomalies": [
                {"id": a.id, "workflow_id": a.workflow_id, "kind": a.kind, "severity": a.severity, "statement": a.statement,
                 "rationale": a.rationale, "confidence": a.confidence, "entity_key": a.entity_key, "basis": a.basis, "status": a.status}
                for a in anomalies[:limit]
            ],
        }

    @staticmethod
    def _workflow(row) -> BusinessWorkflow:
        return BusinessWorkflow(row["id"], row["scan_id"], row["workflow_key"], row["label"], float(row["confidence"]), row["source"], _obj(row["metadata_json"]), row["created_at"], row["updated_at"])

    @staticmethod
    def _state(row) -> WorkflowState:
        return WorkflowState(row["id"], row["workflow_id"], row["state_key"], row["label"], bool(row["initial"]), bool(row["terminal"]), float(row["confidence"]), row["source"], _obj(row["metadata_json"]), row["created_at"])

    @staticmethod
    def _transition(row) -> WorkflowTransition:
        return WorkflowTransition(row["id"], row["scan_id"], row["workflow_id"], row["from_state"], row["to_state"], row["operation_id"], row["relation"], row["action"], float(row["confidence"]), _ids(row["evidence_ids_json"]), _obj(row["basis_json"]), row["created_at"])

    @staticmethod
    def _anomaly(row) -> BusinessLogicAnomaly:
        return BusinessLogicAnomaly(row["id"], row["scan_id"], row["workflow_id"], row["kind"], row["severity"], row["statement"], row["rationale"], float(row["confidence"]), row["entity_key"], _obj(row["basis_json"]), row["status"], row["created_at"], row["updated_at"])

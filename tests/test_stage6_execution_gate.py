
from __future__ import annotations

from beltu.control.approval_service import ApprovalService
from beltu.execution.service import ExecutionService
from beltu.storage.database import Database
from beltu.storage.repositories.approval_repository import ApprovalRepository
from beltu.storage.repositories.decision_repository import DecisionRepository


class FakeDispatcher:
    async def execute(self, request):
        return None


def test_approved_decision_passes_execution_gate(tmp_path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    with db.connect() as conn:
        conn.execute("INSERT INTO targets(value,status,created_at,updated_at) VALUES('authorized.test','new','x','x')")
        conn.execute("INSERT INTO scans(target_id,status,created_at,updated_at) VALUES(1,'running','x','x')")
    decisions = DecisionRepository(db)
    approvals_repo = ApprovalRepository(db)
    decision = decisions.create(
        1, None, "service_enrichment", {"target": "authorized.test"},
        "test", 0.9, "medium", True, "accepted"
    )
    approvals = ApprovalService(decisions, approvals_repo)
    request = approvals.request_for_decision(decision.id, channel="cli", recipient="test")
    service = ExecutionService(decisions, FakeDispatcher(), approvals)
    try:
        service.request_from_decision(decision.id)
    except PermissionError:
        pass
    else:
        raise AssertionError("unapproved decision was executable")
    approvals.approve(request.id, resolved_by="test", token=request.token)
    execution = service.request_from_decision(decision.id)
    assert execution.target == "authorized.test"

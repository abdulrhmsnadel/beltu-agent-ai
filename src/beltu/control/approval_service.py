from __future__ import annotations

from beltu.storage.models.approval import ApprovalRequest
from beltu.storage.repositories.approval_repository import ApprovalRepository, canonical_action_hash
from beltu.storage.repositories.decision_repository import DecisionRepository


class ApprovalService:
    """Persistent human-in-the-loop gate for decisions that require explicit authorization."""

    def __init__(self, decisions: DecisionRepository, approvals: ApprovalRepository) -> None:
        self.decisions = decisions
        self.approvals = approvals

    def request_for_decision(
        self,
        decision_id: int,
        *,
        channel: str,
        recipient: str | None,
        ttl_seconds: int = 600,
    ) -> ApprovalRequest:
        decision = self.decisions.get(decision_id)
        if decision is None:
            raise KeyError(f"Decision #{decision_id} not found")
        if not decision.requires_approval:
            raise ValueError(f"Decision #{decision_id} does not require approval")
        if decision.status not in {"accepted", "pending_approval"}:
            raise ValueError(f"Decision #{decision_id} is not awaiting approval")
        action_hash = canonical_action_hash(decision.id, decision.action_kind, decision.action_payload)
        pending = [
            a for a in self.approvals.list_pending(channel=channel, recipient=recipient)
            if a.decision_id == decision_id
        ]
        if pending:
            return pending[0]
        approval = self.approvals.create(
            decision.id, decision.scan_id, decision.action_kind, action_hash,
            decision.rationale, channel=channel, recipient=recipient, ttl_seconds=ttl_seconds,
        )
        self.decisions.set_status(decision_id, "pending_approval")
        return approval

    def approve(self, approval_id: int, *, resolved_by: str, token: str) -> ApprovalRequest:
        approval = self.approvals.get(approval_id)
        if approval is None:
            raise KeyError(f"Approval #{approval_id} not found")
        decision = self.decisions.get(approval.decision_id)
        if decision is None:
            raise RuntimeError("Approval references missing decision")
        current_hash = canonical_action_hash(decision.id, decision.action_kind, decision.action_payload)
        if current_hash != approval.action_hash:
            raise ValueError("Decision changed after approval was requested")
        resolved = self.approvals.resolve(approval_id, "approved", resolved_by, token=token)
        self.decisions.set_status(approval.decision_id, "approved")
        return resolved

    def reject(self, approval_id: int, *, resolved_by: str, token: str | None = None) -> ApprovalRequest:
        approval = self.approvals.get(approval_id)
        if approval is None:
            raise KeyError(f"Approval #{approval_id} not found")
        resolved = self.approvals.resolve(approval_id, "rejected", resolved_by, token=token)
        self.decisions.set_status(approval.decision_id, "rejected")
        return resolved

    def has_valid_approved_decision(self, decision_id: int) -> bool:
        for approval in self.approvals.list_for_decision(decision_id):
            if approval.status == "approved" and self.revalidate_approval(approval.id):
                return True
        return False

    def revalidate_approval(self, approval_id: int) -> bool:
        approval = self.approvals.get(approval_id)
        if approval is None or approval.status != "approved":
            return False
        decision = self.decisions.get(approval.decision_id)
        if decision is None:
            return False
        return canonical_action_hash(decision.id, decision.action_kind, decision.action_payload) == approval.action_hash

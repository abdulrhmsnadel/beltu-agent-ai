from __future__ import annotations

from dataclasses import dataclass

from beltu.control.approval_service import ApprovalService
from beltu.storage.models.approval import ApprovalRequest


@dataclass(frozen=True, slots=True)
class ControlPlaneStatus:
    pending: int
    approved: int
    rejected: int
    expired: int


class ControlPlane:
    def __init__(self, approvals: ApprovalService) -> None:
        self.approvals = approvals

    def request(self, decision_id: int, *, channel: str, recipient: str | None, ttl_seconds: int = 600) -> ApprovalRequest:
        return self.approvals.request_for_decision(
            decision_id, channel=channel, recipient=recipient, ttl_seconds=ttl_seconds
        )

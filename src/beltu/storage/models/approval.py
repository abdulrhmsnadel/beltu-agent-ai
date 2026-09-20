from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    id: int
    decision_id: int
    scan_id: int
    action_kind: str
    action_hash: str
    status: str
    channel: str
    recipient: str | None
    reason: str
    requested_at: str
    expires_at: str
    resolved_at: str | None
    resolved_by: str | None
    token: str

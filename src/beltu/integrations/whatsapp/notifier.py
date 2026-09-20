from __future__ import annotations

from beltu.integrations.whatsapp.client import WhatsAppCloudClient
from beltu.storage.models.approval import ApprovalRequest


def format_approval_request(approval: ApprovalRequest) -> str:
    return (
        f"BELTU approval required\n"
        f"Approval: #{approval.id}\n"
        f"Decision: #{approval.decision_id}\n"
        f"Action: {approval.action_kind}\n"
        f"Risk rationale: {approval.reason}\n"
        f"Expires: {approval.expires_at}\n\n"
        f"Reply: YES {approval.id} {approval.token}\n"
        f"or: NO {approval.id}"
    )


class WhatsAppApprovalNotifier:
    def __init__(self, client: WhatsAppCloudClient) -> None:
        self.client = client

    def send(self, approval: ApprovalRequest, recipient: str | None = None) -> dict:
        target = recipient or approval.recipient
        if not target:
            raise ValueError("WhatsApp approval requires a recipient")
        return self.client.send_text(target, format_approval_request(approval))

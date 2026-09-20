from __future__ import annotations

import json
from typing import Any

from beltu.control.approval_service import ApprovalService
from beltu.integrations.whatsapp.message_router import parse_approval_command
from beltu.integrations.whatsapp.security import verify_meta_signature


class WhatsAppWebhookHandler:
    def __init__(self, approvals: ApprovalService, *, verify_token: str, app_secret: str, controller_numbers: set[str]) -> None:
        self.approvals = approvals
        self.verify_token = verify_token
        self.app_secret = app_secret
        self.controller_numbers = controller_numbers

    def verify_challenge(self, mode: str | None, token: str | None, challenge: str | None) -> str:
        if mode == "subscribe" and token == self.verify_token and challenge is not None:
            return challenge
        raise PermissionError("Webhook verification failed")

    def handle(self, body: bytes, signature_header: str | None) -> list[dict[str, Any]]:
        if not verify_meta_signature(body, signature_header, self.app_secret):
            raise PermissionError("Invalid WhatsApp webhook signature")
        payload = json.loads(body.decode("utf-8"))
        responses: list[dict[str, Any]] = []
        for message in self._messages(payload):
            sender = message["from"]
            if sender not in self.controller_numbers:
                responses.append({"recipient": sender, "text": "Unauthorized controller."})
                continue
            text = (((message.get("text") or {}).get("body")) or "").strip()
            command = parse_approval_command(text)
            if command is None:
                responses.append({"recipient": sender, "text": "Use: YES <approval_id> <token> or NO <approval_id> [token]."})
                continue
            try:
                if command.action == "approve":
                    approval = self.approvals.approve(command.approval_id, resolved_by=f"whatsapp:{sender}", token=command.token or "")
                    responses.append({"recipient": sender, "text": f"APPROVED #{approval.id} for decision #{approval.decision_id}."})
                else:
                    approval = self.approvals.reject(command.approval_id, resolved_by=f"whatsapp:{sender}", token=command.token)
                    responses.append({"recipient": sender, "text": f"REJECTED #{approval.id} for decision #{approval.decision_id}."})
            except (KeyError, PermissionError, ValueError) as exc:
                responses.append({"recipient": sender, "text": f"Action blocked: {exc}"})
        return responses

    @staticmethod
    def _messages(payload: dict[str, Any]):
        for entry in payload.get("entry", []):
            for change in entry.get("changes", []):
                value = change.get("value") or {}
                for message in value.get("messages", []) or []:
                    yield message

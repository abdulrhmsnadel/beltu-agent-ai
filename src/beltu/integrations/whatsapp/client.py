from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class WhatsAppConfig:
    access_token: str
    phone_number_id: str
    graph_base_url: str = "https://graph.facebook.com"
    api_version: str = ""


class WhatsAppCloudClient:
    """Small stdlib-only client; API version is configurable so Meta changes do not require code edits."""

    def __init__(self, config: WhatsAppConfig) -> None:
        self.config = config

    def send_text(self, recipient: str, text: str) -> dict:
        if not self.config.access_token or not self.config.phone_number_id or not self.config.api_version:
            raise RuntimeError("WhatsApp credentials/API version are not configured")
        url = f"{self.config.graph_base_url.rstrip('/')}/{self.config.api_version}/{self.config.phone_number_id}/messages"
        payload = json.dumps({
            "messaging_product": "whatsapp",
            "to": recipient,
            "type": "text",
            "text": {"body": text},
        }).encode()
        request = urllib.request.Request(
            url,
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.config.access_token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            raise RuntimeError(f"WhatsApp API returned HTTP {exc.code}: {body}") from exc

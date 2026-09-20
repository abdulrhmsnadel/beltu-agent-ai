from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from beltu.integrations.whatsapp.webhook import WhatsAppWebhookHandler


class _WebhookHandler(BaseHTTPRequestHandler):
    webhook: WhatsAppWebhookHandler | None = None

    def _send(self, status: int, body: str, content_type: str = "text/plain") -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        if self.webhook is None:
            self._send(503, "not configured")
            return
        query = parse_qs(urlparse(self.path).query)
        try:
            body = self.webhook.verify_challenge(
                query.get("hub.mode", [None])[0],
                query.get("hub.verify_token", [None])[0],
                query.get("hub.challenge", [None])[0],
            )
        except PermissionError:
            self._send(403, "forbidden")
            return
        self._send(200, body)

    def do_POST(self) -> None:  # noqa: N802
        if self.webhook is None:
            self._send(503, "not configured")
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            responses = self.webhook.handle(body, self.headers.get("X-Hub-Signature-256"))
        except PermissionError:
            self._send(403, "forbidden")
            return
        except (ValueError, json.JSONDecodeError):
            self._send(400, "bad request")
            return
        self._send(200, json.dumps({"responses": responses}), "application/json")

    def log_message(self, *_args) -> None:
        return


def serve(webhook: WhatsAppWebhookHandler, host: str = "127.0.0.1", port: int = 8080) -> None:
    _WebhookHandler.webhook = webhook
    server = ThreadingHTTPServer((host, port), _WebhookHandler)
    server.serve_forever()

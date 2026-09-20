from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _hash_password(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class RemotePrincipal:
    subject: str
    scopes: tuple[str, ...]


class RemoteAuth:
    """Small signed-session scheme for the local control plane.

    It is intentionally dependency-free. In production this gateway should be
    exposed only through TLS, and the configured password/secret must be kept
    outside the repository.
    """

    def __init__(self, *, username: str, password: str, secret: str, ttl_seconds: int = 43200, scopes: tuple[str, ...] = ("read", "chat", "control", "approve")) -> None:
        if not username or not password or not secret:
            raise ValueError("Remote authentication is not configured")
        if len(secret) < 32:
            raise ValueError("Remote auth secret must be at least 32 characters")
        self.username = username
        self.password_sha256 = _hash_password(password)
        self.secret = secret.encode("utf-8")
        self.ttl_seconds = max(300, ttl_seconds)
        allowed = {"read", "chat", "control", "approve"}
        self.scopes = tuple(scope for scope in scopes if scope in allowed) or ("read",)

    def login(self, username: str, password: str) -> str:
        if not (hmac.compare_digest(username, self.username) and hmac.compare_digest(_hash_password(password), self.password_sha256)):
            raise PermissionError("Invalid credentials")
        now = int(time.time())
        payload = {"sub": self.username, "scopes": list(self.scopes), "iat": now, "exp": now + self.ttl_seconds, "nonce": secrets.token_hex(8)}
        raw = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        sig = _b64(hmac.new(self.secret, raw.encode("ascii"), hashlib.sha256).digest())
        return f"v1.{raw}.{sig}"

    def verify(self, token: str) -> RemotePrincipal:
        try:
            version, raw, sig = token.split(".", 2)
        except ValueError as exc:
            raise PermissionError("Invalid session token") from exc
        if version != "v1":
            raise PermissionError("Unsupported session token")
        expected = _b64(hmac.new(self.secret, raw.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            raise PermissionError("Invalid session signature")
        try:
            payload: dict[str, Any] = json.loads(_unb64(raw).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PermissionError("Invalid session payload") from exc
        if int(payload.get("exp", 0)) < int(time.time()):
            raise PermissionError("Session expired")
        subject = str(payload.get("sub", ""))
        scopes = tuple(str(x) for x in payload.get("scopes", []))
        if not subject or not scopes:
            raise PermissionError("Invalid session claims")
        return RemotePrincipal(subject, scopes)

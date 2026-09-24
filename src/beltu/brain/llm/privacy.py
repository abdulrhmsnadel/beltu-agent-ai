from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from beltu.brain.schemas import AgentContext


class CloudSanitizationError(ValueError):
    """Raised when a payload is not permitted to cross the cloud boundary."""


@dataclass(frozen=True, slots=True)
class CloudDataPolicy:
    enabled: bool = True
    max_input_chars: int = 1_500_000
    max_observation_chars: int = 100_000
    allow_final_reports: bool = False
    allow_exploit_payloads: bool = False
    allow_poc_code: bool = False
    allow_session_data: bool = False
    allow_credentials: bool = False


class CloudPrivacyFilter:
    """Build a minimized cloud-safe snapshot before any Gemini request.

    The filter is intentionally conservative: secret-bearing keys are replaced,
    private-key blocks are removed, and explicit final-report/exploit artifact
    fields are excluded from cloud-visible context.
    """

    _SENSITIVE_KEY = re.compile(
        r"(?i)^(?:authorization|cookie|set-cookie|password|passwd|passphrase|secret|"
        r"api[_-]?key|apikey|client[_-]?secret|access[_-]?token|refresh[_-]?token|"
        r"id[_-]?token|session[_-]?(?:id|token)|csrf[_-]?(?:token|secret)|credentials?|"
        r"private[_-]?key|ssh[_-]?key|auth[_-]?header)$"
    )
    _PROHIBITED_KEY = re.compile(
        r"(?i)^(?:final[_-]?report|report[_-]?body|confirmed[_-]?finding|"
        r"exploit[_-]?payload|payload[_-]?proof|proof[_-]?of[_-]?concept|poc[_-]?code)$"
    )
    _PRIVATE_KEY = re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.I | re.S,
    )
    _AUTH_HEADER = re.compile(r"(?i)(\bAuthorization\s*[:=]\s*)(?!Bearer\s+)[^\r\n]+")
    _COOKIE_HEADER = re.compile(r"(?i)(\b(?:Cookie|Set-Cookie)\s*[:=]\s*)[^\r\n]+")
    _BEARER = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]+")
    _JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b")
    _SECRET_PAIR = re.compile(
        r"(?i)(\b(?:api[_-]?key|apikey|client[_-]?secret|access[_-]?token|refresh[_-]?token|"
        r"id[_-]?token|password|passwd|secret|credential)\s*[=:]\s*)"
        r"([\"']?)[^\s,;\"']{6,}\2"
    )

    def __init__(self, policy: CloudDataPolicy | None = None) -> None:
        self.policy = policy or CloudDataPolicy()

    def scrub_text(self, value: str, *, limit: int | None = None) -> str:
        text = str(value)
        text = self._PRIVATE_KEY.sub("<REDACTED_PRIVATE_KEY>", text)
        text = self._BEARER.sub(r"\1<REDACTED_BEARER>", text)
        text = self._AUTH_HEADER.sub(r"\1<REDACTED_AUTHORIZATION>", text)
        text = self._COOKIE_HEADER.sub(r"\1<REDACTED_COOKIE>", text)
        text = self._JWT.sub("<REDACTED_JWT>", text)
        text = self._SECRET_PAIR.sub(r"\1<REDACTED_SECRET>", text)
        maximum = self.policy.max_observation_chars if limit is None else max(256, int(limit))
        if len(text) <= maximum:
            return text
        head = maximum // 2
        tail = maximum - head
        return text[:head] + "\n...[BELTU CLOUD CONTEXT TRUNCATED]...\n" + text[-tail:]

    def scrub_object(self, value: Any, *, key: str = "") -> Any:
        if self._PROHIBITED_KEY.search(str(key)):
            return None
        if self._SENSITIVE_KEY.search(str(key)):
            return "<REDACTED_SENSITIVE_FIELD>"
        if isinstance(value, str):
            return self.scrub_text(value)
        if isinstance(value, dict):
            result: dict[str, Any] = {}
            for item_key, item_value in value.items():
                cleaned = self.scrub_object(item_value, key=str(item_key))
                if cleaned is not None:
                    result[str(item_key)] = cleaned
            return result
        if isinstance(value, (list, tuple)):
            return [item for item in (self.scrub_object(v) for v in value) if item is not None]
        return value

    def ensure_allowed_text(self, value: str) -> None:
        lowered = value.lower()
        markers = (
            ("final vulnerability report", not self.policy.allow_final_reports),
            ("final report", not self.policy.allow_final_reports),
            ("confirmed exploit payload", not self.policy.allow_exploit_payloads),
            ("exploit payload", not self.policy.allow_exploit_payloads),
            ("proof-of-concept code", not self.policy.allow_poc_code),
            ("proof of concept code", not self.policy.allow_poc_code),
        )
        for marker, blocked in markers:
            if blocked and marker in lowered:
                raise CloudSanitizationError(f"Cloud request contains prohibited marker: {marker}")
        if not self.policy.allow_credentials and re.search(r"(?i)\bcleartext\s+credentials?\b", value):
            raise CloudSanitizationError("Cloud request contains a cleartext-credentials marker")

    def context_payload(self, context: AgentContext) -> dict[str, Any]:
        finding_surface = context.finding_surface if isinstance(context.finding_surface, dict) else {}
        finding_summary = finding_surface.get("summary", {})
        payload = {
            "scan_id": context.scan_id,
            "target": context.target,
            "observations": self.scrub_object(list(context.observations)),
            "known_hypotheses": self.scrub_object(list(context.known_hypotheses)),
            "assets": self.scrub_object(list(context.assets)),
            "asset_summary": self.scrub_object(dict(context.asset_summary)),
            "surface_priorities": self.scrub_object(list(context.surface_priorities)),
            "api_surface": self.scrub_object(dict(context.api_surface)),
            "auth_surface": self.scrub_object(dict(context.auth_surface)),
            "authorization_surface": self.scrub_object(dict(context.authorization_surface)),
            "business_logic_surface": self.scrub_object(dict(context.business_logic_surface)),
            "finding_summary": self.scrub_object(finding_summary if isinstance(finding_summary, dict) else {}),
        }
        serialized = json.dumps(payload, ensure_ascii=True, sort_keys=True)
        self.ensure_allowed_text(serialized)
        if len(serialized) <= self.policy.max_input_chars:
            return payload

        observations = payload.get("observations")
        if isinstance(observations, list):
            compacted: list[Any] = []
            used = len(json.dumps({k: v for k, v in payload.items() if k != "observations"}, ensure_ascii=True))
            budget = max(0, self.policy.max_input_chars - used - 1024)
            for item in observations:
                item_size = len(json.dumps(item, ensure_ascii=True))
                if compacted and item_size > budget:
                    break
                compacted.append(item)
                budget -= item_size
                if budget <= 0:
                    break
            payload["observations"] = compacted

        serialized = json.dumps(payload, ensure_ascii=True, sort_keys=True)
        self.ensure_allowed_text(serialized)
        if len(serialized) > self.policy.max_input_chars:
            raise CloudSanitizationError("Cloud context exceeds configured maximum after minimization")
        return payload

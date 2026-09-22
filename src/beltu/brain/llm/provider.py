from __future__ import annotations

import json
import os
import re
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Protocol
from urllib import error as urlerror
from urllib import request

from beltu.brain.llm.config import LLMConfig
from beltu.brain.llm.privacy import CloudDataPolicy, CloudPrivacyFilter, CloudSanitizationError


class LLMProvider(Protocol):
    name: str
    model: str

    def complete(self, *, system_prompt: str, user_prompt: str) -> tuple[str, float]:
        """Return raw model text and latency in milliseconds."""


@dataclass(frozen=True, slots=True)
class Altar1RequestProfile:
    """Per-task decoding profile selected by BELTU's router."""

    name: str
    temperature: float
    max_tokens: int
    top_p: float = 0.95


class _ActivityLease:
    """Filesystem lease marking one or more Altar-1 requests as active."""

    def __init__(self, directory: Path, metadata: dict[str, Any]) -> None:
        self.directory = directory
        self.metadata = metadata
        self.path: Path | None = None

    def __enter__(self) -> "_ActivityLease":
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / f"request-{os.getpid()}-{uuid.uuid4().hex}.json"
        fd, temp_path = tempfile.mkstemp(prefix=".lease-", dir=self.directory, text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self.metadata, handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self.path)
        except Exception:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise
        return self

    def __exit__(self, *_exc: object) -> None:
        if self.path is not None:
            try:
                self.path.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            if self.directory.exists() and not any(self.directory.iterdir()):
                self.directory.rmdir()
        except OSError:
            pass


@dataclass(frozen=True, slots=True)
class OpenAICompatibleProvider:
    """Generic compatibility provider retained for tests/advanced deployments."""

    config: LLMConfig
    name: str = "openai_compatible"

    @property
    def model(self) -> str:
        return self.config.model

    def complete(self, *, system_prompt: str, user_prompt: str) -> tuple[str, float]:
        api_key = self.config.api_key()
        if self.config.api_key_required and not api_key:
            raise RuntimeError(f"LLM API key is missing; set {self.config.api_key_env}")
        url = f"{self.config.base_url}/chat/completions"
        body: dict[str, Any] = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": False,
        }
        if self.config.use_json_mode:
            body["response_format"] = {"type": "json_object"}
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "BELTU/1.3",
        }
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        req = request.Request(url, data=payload, method="POST", headers=headers)
        started = time.perf_counter()
        try:
            with request.urlopen(req, timeout=self.config.timeout_seconds) as response:
                raw = response.read().decode("utf-8")
        except urlerror.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:1200]
            raise RuntimeError(f"LLM HTTP {exc.code}: {detail}") from exc
        except urlerror.URLError as exc:
            raise RuntimeError(f"LLM network error: {exc.reason}") from exc
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        try:
            parsed = json.loads(raw)
            text = parsed["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError("LLM provider returned an unexpected response shape") from exc
        if not isinstance(text, str) or not text.strip():
            raise RuntimeError("LLM provider returned empty content")
        return text, elapsed_ms


@dataclass(frozen=True, slots=True)
class FreeTokenLocalProvider:
    """FreeToken local-only OpenAI-compatible provider with SSE handling."""

    config: LLMConfig
    name: str = "freetoken_local"

    def __post_init__(self) -> None:
        if self.config.local_only and not self.config.is_loopback:
            raise ValueError(f"FreeToken provider must use a loopback URL, got {self.config.base_url!r}")

    @property
    def model(self) -> str:
        return self.config.model

    def _models_url(self) -> str:
        return f"{self.config.base_url}/models"

    def _chat_url(self) -> str:
        return f"{self.config.base_url}/chat/completions"

    def _request(self, *, body: dict[str, Any], accept: str) -> Any:
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        req = request.Request(
            self._chat_url(),
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": accept,
                "User-Agent": "BELTU/1.3-local-freetoken",
            },
        )
        try:
            return request.urlopen(req, timeout=self.config.timeout_seconds)
        except urlerror.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:1600]
            raise RuntimeError(f"FreeToken HTTP {exc.code}: {detail}") from exc
        except urlerror.URLError as exc:
            raise RuntimeError(f"FreeToken connection failed: {exc.reason}") from exc

    def _resolve_model(self) -> str:
        configured = self.config.model.strip()
        if configured and configured.lower() != "auto":
            return configured
        req = request.Request(self._models_url(), method="GET", headers={"Accept": "application/json", "User-Agent": "BELTU/1.2-local-freetoken"})
        try:
            with request.urlopen(req, timeout=min(self.config.timeout_seconds, 10.0)) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (urlerror.HTTPError, urlerror.URLError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Unable to discover FreeToken model: {exc}") from exc
        items = payload.get("data", []) if isinstance(payload, dict) else []
        if not isinstance(items, list) or not items or not isinstance(items[0], dict) or not items[0].get("id"):
            raise RuntimeError("FreeToken /v1/models returned no served model")
        return str(items[0]["id"])

    @staticmethod
    def _iter_sse_lines(response: Any) -> Iterable[str]:
        while True:
            line = response.readline()
            if not line:
                break
            yield line.decode("utf-8", errors="replace").rstrip("\r\n")

    @staticmethod
    def _chunk_text(chunk: dict[str, Any]) -> str:
        try:
            choice = chunk.get("choices", [])[0]
            delta = choice.get("delta") or {}
        except (IndexError, AttributeError, TypeError):
            return ""
        content = delta.get("content")
        return content if isinstance(content, str) else ""

    def complete(self, *, system_prompt: str, user_prompt: str) -> tuple[str, float]:
        model = self._resolve_model()
        body: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": bool(self.config.stream),
        }
        if self.config.use_json_mode:
            body["response_format"] = {"type": "json_object"}
        started = time.perf_counter()
        if not self.config.stream:
            response = self._request(body=body, accept="application/json")
            with response:
                raw = response.read().decode("utf-8")
            try:
                payload = json.loads(raw)
                text = payload["choices"][0]["message"]["content"]
            except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
                raise RuntimeError("FreeToken returned an unexpected non-streaming response") from exc
        else:
            response = self._request(body=body, accept="text/event-stream")
            pieces: list[str] = []
            with response:
                for line in self._iter_sse_lines(response):
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if not data:
                        continue
                    if data == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    token = self._chunk_text(chunk)
                    if token:
                        pieces.append(token)
            text = "".join(pieces)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        if not isinstance(text, str) or not text.strip():
            raise RuntimeError("FreeToken returned empty content")
        return text, elapsed_ms


@dataclass(frozen=True, slots=True)
class Altar1LocalProvider:
    """Local OpenAI-compatible client for Aikido Altar-1.

    Altar-1 is a large local security model. BELTU keeps its endpoint
    loopback-only when `local_only` is enabled and exposes a request-profile API
    so the router can switch decoding parameters by task class without changing
    the configured model node.
    """

    config: LLMConfig
    name: str = "altar1_local"

    def __post_init__(self) -> None:
        if self.config.local_only and not self.config.altar_is_loopback:
            raise ValueError(f"Altar-1 provider must use a loopback URL, got {self.config.altar_base_url!r}")

    @property
    def model(self) -> str:
        return self.config.altar_model

    @property
    def base_url(self) -> str:
        return self.config.altar_base_url.rstrip("/")

    @property
    def activity_dir(self) -> Path:
        return Path(self.config.altar_activity_dir)

    def _models_url(self) -> str:
        return f"{self.base_url}/models"

    def _chat_url(self) -> str:
        return f"{self.base_url}/chat/completions"

    def _resolve_model(self) -> str:
        configured = self.model.strip()
        if configured and configured.lower() != "auto":
            return configured
        req = request.Request(self._models_url(), method="GET", headers={"Accept": "application/json", "User-Agent": "BELTU/1.3-local-altar1"})
        try:
            with request.urlopen(req, timeout=min(self.config.altar_timeout_seconds, 15.0)) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (urlerror.HTTPError, urlerror.URLError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Unable to discover Altar-1 model: {exc}") from exc
        items = payload.get("data", []) if isinstance(payload, dict) else []
        if not isinstance(items, list) or not items or not isinstance(items[0], dict) or not items[0].get("id"):
            raise RuntimeError("Altar-1 /v1/models returned no served model")
        return str(items[0]["id"])

    def _request_body(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        profile: Altar1RequestProfile,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": self._resolve_model(),
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": profile.temperature,
            "max_tokens": profile.max_tokens,
            "top_p": profile.top_p,
            "stream": bool(self.config.altar_stream),
        }
        if self.config.altar_use_json_mode:
            body["response_format"] = {"type": "json_object"}
        return body

    def _request(self, body: dict[str, Any]) -> Any:
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        req = request.Request(
            self._chat_url(),
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "text/event-stream, application/json",
                "User-Agent": "BELTU/1.2-local-altar1",
            },
        )
        api_key = self.config.altar_api_key()
        if self.config.altar_api_key_required and not api_key:
            raise RuntimeError(f"Altar-1 API key is missing; set {self.config.altar_api_key_env}")
        if api_key:
            req.add_header("Authorization", f"Bearer {api_key}")
        try:
            return request.urlopen(req, timeout=self.config.altar_timeout_seconds)
        except urlerror.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:2000]
            raise RuntimeError(f"Altar-1 HTTP {exc.code}: {detail}") from exc
        except urlerror.URLError as exc:
            raise RuntimeError(f"Altar-1 connection failed: {exc.reason}") from exc

    @staticmethod
    def _sse_content(response: Any) -> Iterable[str]:
        while True:
            raw = response.readline()
            if not raw:
                break
            line = raw.decode("utf-8", errors="replace").strip()
            if not line or not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                chunk = json.loads(data)
            except json.JSONDecodeError:
                continue
            try:
                delta = (chunk.get("choices") or [])[0].get("delta") or {}
            except (IndexError, AttributeError, TypeError):
                continue
            text = delta.get("content")
            if isinstance(text, str) and text:
                yield text

    def complete_with_profile(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        profile: Altar1RequestProfile,
        route: str,
    ) -> tuple[str, float]:
        body = self._request_body(system_prompt=system_prompt, user_prompt=user_prompt, profile=profile)
        started = time.perf_counter()
        metadata = {"route": route, "profile": profile.name, "pid": os.getpid(), "model": body["model"]}
        with _ActivityLease(self.activity_dir, metadata):
            response = self._request(body)
            with response:
                content_type = response.headers.get("Content-Type", "").lower()
                if "text/event-stream" in content_type:
                    text = "".join(self._sse_content(response))
                else:
                    raw = response.read().decode("utf-8", errors="replace")
                    try:
                        payload = json.loads(raw)
                        text = payload["choices"][0]["message"]["content"]
                    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
                        raise RuntimeError("Altar-1 returned an unexpected response shape") from exc
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        if not isinstance(text, str) or not text.strip():
            raise RuntimeError("Altar-1 returned empty content")
        return text, elapsed_ms

    def complete(self, *, system_prompt: str, user_prompt: str) -> tuple[str, float]:
        profile = Altar1RequestProfile(
            name="default",
            temperature=self.config.altar_temperature,
            max_tokens=self.config.altar_max_tokens,
        )
        return self.complete_with_profile(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            profile=profile,
            route="altar1_default",
        )



class GeminiRateLimitError(RuntimeError):
    """BELTU-local rate limiter or Gemini API 429 response."""


class GeminiSafetyBlockedError(RuntimeError):
    """Gemini rejected or safety-blocked a request."""


class GeminiCloudError(RuntimeError):
    """Non-retryable Gemini cloud provider error."""


class GeminiRateLimiter:
    """Thread-safe sliding-window limiter used before cloud requests."""

    def __init__(self, requests_per_minute: int, burst: int = 1) -> None:
        import threading
        from collections import deque

        self.requests_per_minute = max(1, int(requests_per_minute))
        self.burst = max(1, min(int(burst), self.requests_per_minute))
        self._window = 60.0
        self._timestamps: deque[float] = deque()
        self._lock = threading.Lock()

    def try_acquire(self) -> bool:
        now = time.monotonic()
        with self._lock:
            while self._timestamps and now - self._timestamps[0] >= self._window:
                self._timestamps.popleft()
            if len(self._timestamps) >= self.requests_per_minute:
                return False
            # Burst is a safety valve for startup/reconnect without allowing
            # more than the configured RPM over the rolling minute.
            self._timestamps.append(now)
            return len(self._timestamps) <= self.requests_per_minute

    def seconds_until_slot(self) -> float:
        now = time.monotonic()
        with self._lock:
            if len(self._timestamps) < self.requests_per_minute:
                return 0.0
            return max(0.0, self._window - (now - self._timestamps[0]))


@dataclass(slots=True)
class GeminiCloudProvider:
    """Google Gemini cloud provider used only as a sanitized BELTU co-pilot.

    The provider never receives final reports, confirmed exploit payloads, PoC
    code, credentials, or session secrets. It is advisory: BELTU's local model
    remains responsible for the final reasoning and tool execution decision.
    """

    config: LLMConfig
    name: str = "gemini_cloud"
    _filter: CloudPrivacyFilter = field(init=False, repr=False)
    _limiter: GeminiRateLimiter = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.config.gemini_api_key_env.strip():
            raise ValueError("Gemini API key environment variable name cannot be empty")
        policy = CloudDataPolicy(
            enabled=self.config.gemini_scrub_before_send,
            max_input_chars=self.config.gemini_max_input_chars,
            max_observation_chars=self.config.gemini_max_observation_chars,
            allow_final_reports=self.config.gemini_allow_final_reports,
            allow_exploit_payloads=self.config.gemini_allow_exploit_payloads,
            allow_poc_code=self.config.gemini_allow_poc_code,
            allow_session_data=self.config.gemini_allow_session_data,
            allow_credentials=self.config.gemini_allow_credentials,
        )
        object.__setattr__(self, "_filter", CloudPrivacyFilter(policy))
        object.__setattr__(
            self,
            "_limiter",
            GeminiRateLimiter(self.config.gemini_requests_per_minute, self.config.gemini_burst),
        )

    @property
    def model(self) -> str:
        return self.config.gemini_model

    @property
    def base_url(self) -> str:
        return self.config.gemini_base_url.rstrip("/")

    def api_key(self) -> str | None:
        value = os.getenv(self.config.gemini_api_key_env)
        return value.strip() if value and value.strip() else None

    def _endpoint(self) -> str:
        from urllib.parse import quote
        model = quote(self.model.strip(), safe="-_.~")
        return f"{self.base_url}/models/{model}:generateContent"

    def _sanitize_prompt(self, value: str) -> str:
        if not self.config.gemini_scrub_before_send:
            self._filter.ensure_allowed_text(value)
            return value
        scrubbed = self._filter.scrub_text(value, limit=self.config.gemini_max_input_chars)
        self._filter.ensure_allowed_text(scrubbed)
        return scrubbed

    @staticmethod
    def _extract_text(payload: dict[str, Any]) -> str:
        feedback = payload.get("promptFeedback")
        if isinstance(feedback, dict) and str(feedback.get("blockReason", "")).strip():
            raise GeminiSafetyBlockedError(f"Gemini safety block: {feedback['blockReason']}")
        candidates = payload.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise GeminiCloudError("Gemini returned no candidates")
        texts: list[str] = []
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            finish_reason = str(candidate.get("finishReason", "")).upper()
            if finish_reason in {"SAFETY", "BLOCKLIST", "PROHIBITED_CONTENT"}:
                raise GeminiSafetyBlockedError(f"Gemini safety block: {finish_reason}")
            content = candidate.get("content", {})
            parts = content.get("parts", []) if isinstance(content, dict) else []
            for part in parts:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    texts.append(part["text"])
        text = "".join(texts).strip()
        if not text:
            raise GeminiCloudError("Gemini returned empty content")
        return text

    def _post(self, *, system_prompt: str, user_prompt: str) -> tuple[str, float]:
        api_key = self.api_key()
        if not api_key:
            raise GeminiCloudError(f"Gemini API key is missing; set {self.config.gemini_api_key_env}")

        # Privacy filtering must complete before a cloud-rate-limit slot is consumed.
        system_safe = self._sanitize_prompt(system_prompt)
        user_safe = self._sanitize_prompt(user_prompt)

        if not self._limiter.try_acquire():
            delay = self._limiter.seconds_until_slot()
            raise GeminiRateLimitError(
                f"BELTU Gemini rate limiter reached {self.config.gemini_requests_per_minute} RPM; "
                f"next slot in {delay:.1f}s"
            )
        body: dict[str, Any] = {
            "systemInstruction": {"parts": [{"text": system_safe}]},
            "contents": [{"role": "user", "parts": [{"text": user_safe}]}],
            "generationConfig": {
                "maxOutputTokens": self.config.gemini_max_output_tokens,
                "responseMimeType": "application/json",
            },
        }
        payload = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        req = request.Request(
            self._endpoint(),
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "x-goog-api-key": api_key,
                "User-Agent": "BELTU/1.3-gemini-copilot",
            },
        )
        started = time.perf_counter()
        try:
            with request.urlopen(req, timeout=self.config.gemini_timeout_seconds) as response:
                raw = response.read().decode("utf-8", errors="replace")
                http_status = int(response.status)
        except urlerror.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:1600]
            if exc.code == 429:
                raise GeminiRateLimitError("Gemini API returned HTTP 429 Too Many Requests") from exc
            if exc.code in {400, 403} and re.search(r"(?i)safety|blocked|prohibited", detail):
                raise GeminiSafetyBlockedError(f"Gemini request blocked: HTTP {exc.code}") from exc
            raise GeminiCloudError(f"Gemini HTTP {exc.code}: {detail}") from exc
        except urlerror.URLError as exc:
            raise GeminiCloudError(f"Gemini connection failed: {exc.reason}") from exc

        elapsed_ms = (time.perf_counter() - started) * 1000.0
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GeminiCloudError("Gemini returned invalid JSON") from exc
        if http_status >= 400:
            raise GeminiCloudError(f"Gemini returned HTTP {http_status}")
        return self._extract_text(parsed), elapsed_ms

    def complete(self, *, system_prompt: str, user_prompt: str) -> tuple[str, float]:
        return self._post(system_prompt=system_prompt, user_prompt=user_prompt)

    def advise(self, *, context: AgentContext, local_draft: str, mode: str, goal: str) -> tuple[str, float, dict[str, Any]]:
        payload = self._filter.context_payload(context)
        operator_snapshot: dict[str, Any]
        try:
            draft_payload = json.loads(local_draft.strip())
        except json.JSONDecodeError:
            draft_payload = None
        if isinstance(draft_payload, dict):
            operator_snapshot = {
                "summary": self._filter.scrub_text(str(draft_payload.get("summary", "")), limit=4000),
                "hypotheses": [
                    {
                        "statement": self._filter.scrub_text(str(item.get("statement", "")), limit=1200),
                        "confidence": item.get("confidence"),
                    }
                    for item in draft_payload.get("hypotheses", [])[:8]
                    if isinstance(item, dict)
                ],
                "actions": [
                    {
                        "action_kind": item.get("action_kind"),
                        "rationale": self._filter.scrub_text(str(item.get("rationale", "")), limit=1200),
                        "confidence": item.get("confidence"),
                        "risk_level": item.get("risk_level"),
                        "requires_approval": item.get("requires_approval"),
                        "action_payload": {
                            key: self._filter.scrub_text(str(item.get("action_payload", {}).get(key, "")), limit=600)
                            for key in ("target", "capability", "tool", "hypothesis", "observation_ids")
                            if isinstance(item.get("action_payload", {}), dict) and key in item.get("action_payload", {})
                        },
                    }
                    for item in draft_payload.get("actions", [])[:8]
                    if isinstance(item, dict)
                ],
            }
        else:
            operator_snapshot = {"summary": self._filter.scrub_text(local_draft, limit=12_000)}
        serialized_operator = json.dumps(operator_snapshot, ensure_ascii=True, sort_keys=True)
        self._filter.ensure_allowed_text(serialized_operator)
        user_payload = {
            "mode": mode,
            "goal": self._filter.scrub_text(goal, limit=4000),
            "local_operator_snapshot": operator_snapshot,
            "context": payload,
            "advisory_contract": {
                "role": "BELTU cloud co-pilot",
                "observe": "inspect sanitized telemetry and the local operator state",
                "advise": "identify mistakes, missing evidence, useful next checks, retries, corrections, or escalation",
                "authority": "advisory only; the local operator chooses and executes tools",
                "forbidden": ["final reports", "confirmed exploit payloads", "PoC code", "credentials", "session secrets", "direct tool invocation", "shell commands"],
            },
        }
        serialized = json.dumps(user_payload, ensure_ascii=True, sort_keys=True)
        self._filter.ensure_allowed_text(serialized)
        system = (
            "You are BELTU cloud co-pilot. You monitor the local security agent using only the supplied sanitized telemetry. "
            "You never execute tools and never become the final decision authority. "
            "Diagnose weak reasoning, failed steps, missing evidence, useful next checks, and when to continue, retry, correct, escalate, or stop escalation. "
            "Return JSON only with decision, confidence, reason, focus, recommended_capability, and notes. "
            "Never output final vulnerability reports, exploit payloads, PoC code, credentials, or shell commands."
        )
        text, latency = self._post(system_prompt=system, user_prompt=serialized)
        meta = {
            "mode": mode,
            "input_chars": len(serialized),
            "sent_fields": ["sanitized_context", "local_operator_snapshot", "goal", "mode"],
            "execution_authority": "local_operator_only",
            "tool_execution": "local_only",
            "downstream": "standard_local_final_pass",
            "provider": self.name,
            "model": self.model,
        }
        return text, latency, meta


class DisabledLLMProvider:
    name = "disabled"
    model = "disabled"

    def complete(self, *, system_prompt: str, user_prompt: str) -> tuple[str, float]:
        del system_prompt, user_prompt
        raise RuntimeError("LLM reasoning is disabled")
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from urllib import error as urlerror
from urllib import request
from urllib.parse import urlparse
from typing import Any, Iterable, Protocol

from beltu.brain.llm.config import LLMConfig


class LLMProvider(Protocol):
    name: str
    model: str

    def complete(self, *, system_prompt: str, user_prompt: str) -> tuple[str, float]:
        """Return raw model text and latency in milliseconds."""


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
            "User-Agent": "BELTU/1.1",
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
    """FreeToken local-only OpenAI-compatible provider with SSE token handling.

    FreeToken exposes `/v1/chat/completions` and supports streamed OpenAI-style
    responses. BELTU deliberately accepts only loopback base URLs here, so a
    cloud endpoint cannot be selected accidentally.
    """

    config: LLMConfig
    name: str = "freetoken_local"

    def __post_init__(self) -> None:
        if not self.config.is_loopback:
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
                "User-Agent": "BELTU/1.1-local-freetoken",
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
        req = request.Request(self._models_url(), method="GET", headers={"Accept": "application/json", "User-Agent": "BELTU/1.1-local-freetoken"})
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
        # FreeToken/OpenAI-compatible reasoning parsers may place hidden reasoning
        # in `reasoning_content`. BELTU consumes only public `content` here so the
        # response validator never treats internal reasoning text as executable data.
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
            buffered: list[str] = []
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
                        buffered.append(data)
                        continue
                    token = self._chunk_text(chunk)
                    if token:
                        pieces.append(token)
            if buffered and not pieces:
                joined = "".join(buffered).strip()
                if joined:
                    try:
                        payload = json.loads(joined)
                        pieces.append(str(payload.get("choices", [{}])[0].get("message", {}).get("content", "")))
                    except (json.JSONDecodeError, AttributeError, IndexError, TypeError):
                        pass
            text = "".join(pieces)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        if not isinstance(text, str) or not text.strip():
            raise RuntimeError("FreeToken returned empty content")
        return text, elapsed_ms


class DisabledLLMProvider:
    name = "disabled"
    model = "disabled"

    def complete(self, *, system_prompt: str, user_prompt: str) -> tuple[str, float]:
        del system_prompt, user_prompt
        raise RuntimeError("LLM reasoning is disabled")

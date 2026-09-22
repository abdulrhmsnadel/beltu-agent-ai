from __future__ import annotations

import json
import os
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Protocol
from urllib import error as urlerror
from urllib import request

from beltu.brain.llm.config import LLMConfig


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
            "User-Agent": "BELTU/1.2",
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
                "User-Agent": "BELTU/1.2-local-freetoken",
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
        req = request.Request(self._models_url(), method="GET", headers={"Accept": "application/json", "User-Agent": "BELTU/1.2-local-altar1"})
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


class DisabledLLMProvider:
    name = "disabled"
    model = "disabled"

    def complete(self, *, system_prompt: str, user_prompt: str) -> tuple[str, float]:
        del system_prompt, user_prompt
        raise RuntimeError("LLM reasoning is disabled")
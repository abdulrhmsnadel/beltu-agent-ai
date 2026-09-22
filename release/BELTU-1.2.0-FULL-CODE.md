# BELTU 1.2.0 — Full Updated Code

This file contains the complete v1.2.0 core source files and support files added/updated for the multi-model local brain.

## `src/beltu/brain/llm/config.py`

```python
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


@dataclass(frozen=True, slots=True)
class LLMConfig:
    """BELTU local multi-model LLM configuration.

    The existing top-level fields remain the standard reasoning backend for
    backward compatibility. v1.2 adds an optional Altar-1 local backend and a
    deterministic router. Both local providers are loopback-only by default.
    """

    enabled: bool = True
    provider: str = "freetoken_local"
    base_url: str = "http://127.0.0.1:8000/v1"
    model: str = "auto"
    api_key_env: str = "BELTU_LLM_API_KEY"
    api_key_required: bool = False
    use_json_mode: bool = True
    stream: bool = True
    local_only: bool = True
    timeout_seconds: float = 60.0
    max_tokens: int = 1800
    temperature: float = 0.1
    fallback_to_heuristic: bool = True
    max_hypotheses: int = 3
    max_actions: int = 3
    system_prompt_path: str = "prompts/llm/system.md"
    reasoning_prompt_path: str = "prompts/llm/reasoning.md"

    # v1.2 multi-model router.
    router_enabled: bool = True
    altar_enabled: bool = False
    altar_base_url: str = "http://127.0.0.1:8001/v1"
    altar_model: str = "aikido/altar-1"
    altar_api_key_env: str = "BELTU_ALTAR1_API_KEY"
    altar_api_key_required: bool = False
    altar_use_json_mode: bool = False
    altar_stream: bool = True
    altar_local_only: bool = True
    altar_timeout_seconds: float = 180.0
    altar_max_tokens: int = 3200
    altar_temperature: float = 0.1
    altar_activity_dir: str = "data/runtime/altar1.active"

    @classmethod
    def from_mapping(cls, mapping: dict[str, Any]) -> "LLMConfig":
        data = mapping if isinstance(mapping, dict) else {}
        altar = data.get("altar1", data.get("altar", {}))
        altar = altar if isinstance(altar, dict) else {}
        routing = data.get("routing", {})
        routing = routing if isinstance(routing, dict) else {}
        return cls(
            enabled=bool(data.get("enabled", True)),
            provider=str(data.get("provider", "freetoken_local")),
            base_url=str(data.get("base_url", "http://127.0.0.1:8000/v1")).rstrip("/"),
            model=str(data.get("model", "auto")),
            api_key_env=str(data.get("api_key_env", "BELTU_LLM_API_KEY")),
            api_key_required=bool(data.get("api_key_required", False)),
            use_json_mode=bool(data.get("use_json_mode", True)),
            stream=bool(data.get("stream", True)),
            local_only=bool(data.get("local_only", True)),
            timeout_seconds=max(1.0, float(data.get("timeout_seconds", 60.0))),
            max_tokens=max(256, int(data.get("max_tokens", 1800))),
            temperature=max(0.0, min(1.0, float(data.get("temperature", 0.1)))),
            fallback_to_heuristic=bool(data.get("fallback_to_heuristic", True)),
            max_hypotheses=max(1, int(data.get("max_hypotheses", 3))),
            max_actions=max(1, int(data.get("max_actions", 3))),
            system_prompt_path=str(data.get("system_prompt_path", "prompts/llm/system.md")),
            reasoning_prompt_path=str(data.get("reasoning_prompt_path", "prompts/llm/reasoning.md")),
            router_enabled=bool(routing.get("enabled", data.get("router_enabled", True))),
            altar_enabled=bool(altar.get("enabled", False)),
            altar_base_url=str(altar.get("base_url", "http://127.0.0.1:8001/v1")).rstrip("/"),
            altar_model=str(altar.get("model", "aikido/altar-1")),
            altar_api_key_env=str(altar.get("api_key_env", "BELTU_ALTAR1_API_KEY")),
            altar_api_key_required=bool(altar.get("api_key_required", False)),
            altar_use_json_mode=bool(altar.get("use_json_mode", False)),
            altar_stream=bool(altar.get("stream", True)),
            altar_local_only=bool(altar.get("local_only", True)),
            altar_timeout_seconds=max(1.0, float(altar.get("timeout_seconds", 180.0))),
            altar_max_tokens=max(256, int(altar.get("max_tokens", 3200))),
            altar_temperature=max(0.0, min(1.0, float(altar.get("temperature", 0.1)))),
            altar_activity_dir=str(altar.get("activity_dir", "data/runtime/altar1.active")),
        )

    def api_key(self) -> str | None:
        value = os.getenv(self.api_key_env)
        return value.strip() if value and value.strip() else None

    def altar_api_key(self) -> str | None:
        value = os.getenv(self.altar_api_key_env)
        return value.strip() if value and value.strip() else None

    @property
    def is_loopback(self) -> bool:
        host = (urlparse(self.base_url).hostname or "").lower()
        return host in LOOPBACK_HOSTS

    @property
    def altar_is_loopback(self) -> bool:
        host = (urlparse(self.altar_base_url).hostname or "").lower()
        return host in LOOPBACK_HOSTS

    def altar_config(self) -> "LLMConfig":
        """Return a provider config representing the Altar-1 local node."""
        return LLMConfig(
            enabled=self.altar_enabled,
            provider="altar1_local",
            base_url=self.altar_base_url,
            model=self.altar_model,
            api_key_env=self.altar_api_key_env,
            api_key_required=self.altar_api_key_required,
            use_json_mode=self.altar_use_json_mode,
            stream=self.altar_stream,
            local_only=self.altar_local_only,
            timeout_seconds=self.altar_timeout_seconds,
            max_tokens=self.altar_max_tokens,
            temperature=self.altar_temperature,
            fallback_to_heuristic=self.fallback_to_heuristic,
            max_hypotheses=self.max_hypotheses,
            max_actions=self.max_actions,
            system_prompt_path=self.system_prompt_path,
            reasoning_prompt_path=self.reasoning_prompt_path,
            router_enabled=self.router_enabled,
            altar_enabled=self.altar_enabled,
            altar_base_url=self.altar_base_url,
            altar_model=self.altar_model,
            altar_api_key_env=self.altar_api_key_env,
            altar_api_key_required=self.altar_api_key_required,
            altar_use_json_mode=self.altar_use_json_mode,
            altar_stream=self.altar_stream,
            altar_local_only=self.altar_local_only,
            altar_timeout_seconds=self.altar_timeout_seconds,
            altar_max_tokens=self.altar_max_tokens,
            altar_temperature=self.altar_temperature,
            altar_activity_dir=self.altar_activity_dir,
        )

    @classmethod
    def from_project(cls, root: Path) -> "LLMConfig":
        path = root / "config" / "agent.yaml"
        if not path.exists():
            return cls()
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid config/agent.yaml: {exc}") from exc
        brain = data.get("brain", {}) if isinstance(data, dict) else {}
        llm = brain.get("llm", {}) if isinstance(brain, dict) else {}
        if not isinstance(llm, dict):
            llm = {}
        merged = dict(llm)
        merged.setdefault("enabled", bool(brain.get("llm_enabled", True)) if isinstance(brain, dict) else True)
        return cls.from_mapping(merged)
```

## `src/beltu/brain/llm/provider.py`

```python
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
```

## `src/beltu/brain/llm/router.py`

```python
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from beltu.brain.llm.provider import (
    Altar1LocalProvider,
    Altar1RequestProfile,
    DisabledLLMProvider,
    LLMProvider,
)
from beltu.brain.schemas import AgentContext


RouteName = Literal["standard", "altar1"]


@dataclass(frozen=True, slots=True)
class RouteDecision:
    route: RouteName
    score: float
    reasons: tuple[str, ...]
    profile: Altar1RequestProfile | None = None


@dataclass(frozen=True, slots=True)
class RoutedCompletion:
    text: str
    latency_ms: float
    provider_name: str
    model: str
    decision: RouteDecision


class LLMRouter:
    """Classify BELTU contexts and route specialized work to Altar-1.

    Routing is deterministic and context-driven. General reconnaissance and raw
    tool output stay on the standard local model. Code review, exploit-proof
    generation/review, and authorization-matrix anomaly verification go to
    Altar-1 when that node is enabled. A disabled/unavailable Altar node does not
    create a cloud fallback; the caller can use the normal heuristic fallback.
    """

    _CODE_REVIEW = re.compile(
        r"\b(?:code[ _-]?review|source[ _-]?review|static[ _-]?analysis|secure[ _-]?code|patch[ _-]?review|code[ _-]?audit|source[ _-]?audit)\b",
        re.I,
    )
    _EXPLOIT_PROOF = re.compile(
        r"\b(?:exploit[ _-]?proof|proof[ _-]?of[ _-]?concept|poc|reproduction|repro[ _-]?case|exploit[ _-]?validation|vuln(?:erability)?[ _-]?proof)\b",
        re.I,
    )
    _AUTHZ_MATRIX = re.compile(
        r"\b(?:authorization[ _-]?matrix|access[ _-]?control[ _-]?matrix|permission[ _-]?matrix|authz[ _-]?matrix|role[ _-]?permission|privilege[ _-]?matrix|authorization[ _-]?anomal(?:y|ies)|authz[ _-]?anomal(?:y|ies))\b",
        re.I,
    )
    _RECON = re.compile(
        r"\b(?:recon|reconnaissance|subdomain|asset[ _-]?discovery|http[ _-]?probe|tool[ _-]?output|nmap|nuclei|subfinder|httpx|endpoint[ _-]?mapping|service[ _-]?discovery)\b",
        re.I,
    )

    def __init__(
        self,
        standard_provider: LLMProvider | None = None,
        altar_provider: Altar1LocalProvider | None = None,
        *,
        enabled: bool = True,
    ) -> None:
        self.standard_provider = standard_provider or DisabledLLMProvider()
        self.altar_provider = altar_provider or DisabledLLMProvider()  # type: ignore[assignment]
        self.enabled = enabled
        self.last_decision: RouteDecision | None = None

    def available(self) -> bool:
        providers = (self.standard_provider, self.altar_provider)
        return self.enabled and any(not isinstance(p, DisabledLLMProvider) for p in providers)

    @staticmethod
    def _flatten_values(value: Any) -> list[str]:
        out: list[str] = []
        if isinstance(value, str):
            out.append(value)
        elif isinstance(value, dict):
            for key, item in value.items():
                out.append(str(key))
                out.extend(LLMRouter._flatten_values(item))
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                out.extend(LLMRouter._flatten_values(item))
        elif value is not None:
            out.append(str(value))
        return out

    @classmethod
    def _context_text(cls, context: AgentContext) -> str:
        pieces: list[str] = [context.target]
        pieces.extend(cls._flatten_values(context.observations))
        pieces.extend(cls._flatten_values(context.known_hypotheses))
        pieces.extend(cls._flatten_values(context.api_surface))
        pieces.extend(cls._flatten_values(context.auth_surface))
        pieces.extend(cls._flatten_values(context.authorization_surface))
        pieces.extend(cls._flatten_values(context.business_logic_surface))
        pieces.extend(cls._flatten_values(context.finding_surface))
        pieces.extend(cls._flatten_values(context.surface_priorities))
        return " ".join(pieces)

    @staticmethod
    def _contains_structured_signal(container: dict[str, Any], names: tuple[str, ...]) -> bool:
        needles = {item.lower().replace("-", "_").replace(" ", "_") for item in names}
        for key in container:
            normalized = str(key).lower().replace("-", "_").replace(" ", "_")
            if normalized in needles:
                return True
        return False

    def classify(self, context: AgentContext) -> RouteDecision:
        text = self._context_text(context)
        reasons: list[str] = []
        score = 0.0
        profile: Altar1RequestProfile | None = None

        structured_code = self._contains_structured_signal(
            context.finding_surface,
            ("code_review", "source_review", "static_analysis", "code_audit"),
        )
        structured_proof = self._contains_structured_signal(
            context.finding_surface,
            ("exploit_proof", "proof_of_concept", "reproduction", "poc"),
        )
        structured_authz = any(
            self._contains_structured_signal(container, ("authorization_matrix", "access_control_matrix", "permission_matrix", "anomalies"))
            for container in (context.authorization_surface, context.finding_surface)
        )

        if structured_code or self._CODE_REVIEW.search(text):
            score += 1.0
            reasons.append("code-review signal")
            profile = Altar1RequestProfile("code_review", temperature=0.05, max_tokens=2600, top_p=0.90)
        if structured_proof or self._EXPLOIT_PROOF.search(text):
            score += 1.2
            reasons.append("exploit-proof/reproduction signal")
            profile = Altar1RequestProfile("exploit_proof", temperature=0.10, max_tokens=3200, top_p=0.92)
        if structured_authz or self._AUTHZ_MATRIX.search(text):
            score += 1.1
            reasons.append("authorization-matrix anomaly signal")
            profile = Altar1RequestProfile("authz_matrix", temperature=0.05, max_tokens=2400, top_p=0.90)

        if not reasons and self._RECON.search(text):
            reasons.append("general recon/tool-output signal")

        route: RouteName = "altar1" if score >= 1.0 else "standard"
        if route == "altar1" and profile is None:
            profile = Altar1RequestProfile("altar1_specialized", temperature=0.08, max_tokens=2600, top_p=0.90)
        if route == "standard" and not reasons:
            reasons.append("no specialized signal; standard reasoning")
        return RouteDecision(route, round(score, 3), tuple(reasons), profile)

    def complete_for_context(
        self,
        *,
        context: AgentContext,
        system_prompt: str,
        user_prompt: str,
    ) -> RoutedCompletion:
        decision = self.classify(context)
        self.last_decision = decision

        if decision.route == "altar1" and not isinstance(self.altar_provider, DisabledLLMProvider):
            profile = decision.profile or Altar1RequestProfile("altar1_specialized", 0.08, 2600, 0.90)
            text, latency = self.altar_provider.complete_with_profile(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                profile=profile,
                route=decision.route,
            )
            return RoutedCompletion(text, latency, self.altar_provider.name, self.altar_provider.model, decision)

        text, latency = self.standard_provider.complete(system_prompt=system_prompt, user_prompt=user_prompt)
        return RoutedCompletion(text, latency, self.standard_provider.name, self.standard_provider.model, decision)

    # Backward-compatible provider-shaped interface for callers that don't pass context.
    def complete(self, *, system_prompt: str, user_prompt: str) -> tuple[str, float]:
        text, latency = self.standard_provider.complete(system_prompt=system_prompt, user_prompt=user_prompt)
        self.last_decision = RouteDecision("standard", 0.0, ("no context supplied",), None)
        return text, latency
```

## `src/beltu/brain/llm/reasoner.py`

```python
from __future__ import annotations

import hashlib
import time
from pathlib import Path

from beltu.brain.llm.config import LLMConfig
from beltu.brain.llm.prompting import build_user_prompt, load_prompt
from beltu.brain.llm.provider import LLMProvider
from beltu.brain.llm.router import LLMRouter
from beltu.brain.llm.schemas import LLMRunResult
from beltu.brain.llm.validator import extract_json, validate_response
from beltu.brain.schemas import AgentContext


class LLMReasoningEngine:
    """LLM-backed proposal generator with optional context-aware routing."""

    def __init__(self, root: Path, config: LLMConfig, provider: LLMProvider | LLMRouter) -> None:
        self.root = root
        self.config = config
        self.provider = provider
        self.last_route = None

    def run(self, context: AgentContext) -> LLMRunResult:
        system_prompt = load_prompt(
            self.root,
            self.config.system_prompt_path,
            "You are BELTU's reasoning module. Return JSON only. Propose hypotheses and declarative action objects. Never emit commands, shell syntax, URLs outside the supplied target, credentials, or execution instructions.",
        )
        user_prompt = build_user_prompt(
            self.root,
            self.config.reasoning_prompt_path,
            context,
            self.config.max_hypotheses,
            self.config.max_actions,
        )
        prompt_bytes = (system_prompt + "\n\n" + user_prompt).encode("utf-8")
        prompt_hash = hashlib.sha256(prompt_bytes).hexdigest()
        started = time.perf_counter()
        raw = ""
        provider_name = getattr(self.provider, "name", "router")
        provider_model = getattr(self.provider, "model", "router")
        try:
            if isinstance(self.provider, LLMRouter):
                routed = self.provider.complete_for_context(
                    context=context,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                )
                raw = routed.text
                provider_latency = routed.latency_ms
                provider_name = routed.provider_name
                provider_model = routed.model
                self.last_route = routed.decision
            else:
                raw, provider_latency = self.provider.complete(system_prompt=system_prompt, user_prompt=user_prompt)
                self.last_route = None

            payload = extract_json(raw)
            response = validate_response(
                payload,
                context,
                provider=provider_name,
                model=provider_model,
                max_hypotheses=self.config.max_hypotheses,
                max_actions=self.config.max_actions,
            )
            response_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            return LLMRunResult(
                True,
                response,
                raw,
                None,
                max(provider_latency, (time.perf_counter() - started) * 1000.0),
                prompt_hash,
                response_hash,
            )
        except Exception as exc:
            response_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest() if raw else hashlib.sha256(b"").hexdigest()
            return LLMRunResult(
                False,
                None,
                raw,
                f"{provider_name}: {exc}",
                (time.perf_counter() - started) * 1000.0,
                prompt_hash,
                response_hash,
            )


class StaticProvider:
    """Offline deterministic provider used by tests and local development."""

    name = "static"
    model = "fixture"

    def __init__(self, response: str, latency_ms: float = 0.0) -> None:
        self.response = response
        self.latency_ms = latency_ms

    def complete(self, *, system_prompt: str, user_prompt: str) -> tuple[str, float]:
        del system_prompt, user_prompt
        return self.response, self.latency_ms
```

## `src/beltu/brain/llm/__init__.py`

```python
from beltu.brain.llm.config import LLMConfig
from beltu.brain.llm.provider import (
    Altar1LocalProvider,
    Altar1RequestProfile,
    DisabledLLMProvider,
    FreeTokenLocalProvider,
    LLMProvider,
    OpenAICompatibleProvider,
)
from beltu.brain.llm.reasoner import LLMReasoningEngine, StaticProvider
from beltu.brain.llm.router import LLMRouter, RouteDecision, RoutedCompletion
from beltu.brain.llm.schemas import LLMReasoningResponse, LLMRunResult

__all__ = [
    "LLMConfig",
    "LLMProvider",
    "OpenAICompatibleProvider",
    "FreeTokenLocalProvider",
    "Altar1LocalProvider",
    "Altar1RequestProfile",
    "DisabledLLMProvider",
    "LLMRouter",
    "RouteDecision",
    "RoutedCompletion",
    "LLMReasoningEngine",
    "StaticProvider",
    "LLMReasoningResponse",
    "LLMRunResult",
]
```

## `src/beltu/execution/resource_governor.py`

```python
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error as urlerror
from urllib import request


@dataclass(frozen=True, slots=True)
class GpuSnapshot:
    available: bool
    name: str | None
    total_bytes: int
    used_bytes: int
    free_bytes: int
    utilization_percent: float
    freetoken_used_bytes: int
    altar1_used_bytes: int = 0

    @property
    def used_percent(self) -> float:
        if self.total_bytes <= 0:
            return 0.0
        return (self.used_bytes / self.total_bytes) * 100.0

    @property
    def freetoken_percent(self) -> float:
        if self.total_bytes <= 0:
            return 0.0
        return (self.freetoken_used_bytes / self.total_bytes) * 100.0

    @property
    def altar1_percent(self) -> float:
        if self.total_bytes <= 0:
            return 0.0
        return (self.altar1_used_bytes / self.total_bytes) * 100.0


@dataclass(frozen=True, slots=True)
class FreeTokenSnapshot:
    configured: bool
    reachable: bool
    pid: int | None
    model: str | None
    cpu_percent: float
    rss_bytes: int
    vram_bytes: int
    moe_backend: str | None
    requests: int | None


@dataclass(frozen=True, slots=True)
class Altar1Snapshot:
    configured: bool
    reachable: bool
    active: bool
    pid: int | None
    model: str | None
    cpu_percent: float
    rss_bytes: int
    vram_bytes: int
    active_requests: int


@dataclass(frozen=True, slots=True)
class ToolRuntimeLimits:
    tool: str
    thread_limit: int
    max_parallel_processes: int
    affinity_cpus: tuple[int, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class ResourceSnapshot:
    timestamp: float
    beltu_cpu_percent: float
    beltu_memory_percent: float
    host_cpu_percent: float
    host_memory_percent: float
    memory_total_bytes: int
    memory_available_bytes: int
    load1: float
    cpu_count: int
    beltu_rss_bytes: int
    active_processes: int
    gpu: GpuSnapshot | None = None
    freetoken: FreeTokenSnapshot | None = None
    altar1: Altar1Snapshot | None = None


class LinuxResourceMonitor:
    """Linux telemetry using /proc plus optional NVIDIA, FreeToken and Altar-1 telemetry."""

    def __init__(
        self,
        *,
        freetoken_pid_file: str | Path = "data/runtime/freetoken.pid",
        freetoken_url: str = "http://127.0.0.1:8000",
        altar1_pid_file: str | Path = "data/runtime/altar1.pid",
        altar1_activity_dir: str | Path = "data/runtime/altar1.active",
        altar1_url: str = "http://127.0.0.1:8001",
    ) -> None:
        self.cpu_count = max(1, os.cpu_count() or 1)
        self.freetoken_pid_file = Path(freetoken_pid_file)
        self.freetoken_url = freetoken_url.rstrip("/")
        self.altar1_pid_file = Path(altar1_pid_file)
        self.altar1_activity_dir = Path(altar1_activity_dir)
        self.altar1_url = altar1_url.rstrip("/")
        self._prev_proc: tuple[int, float] | None = None
        self._prev_host: tuple[int, int] | None = None

    def snapshot(self, active_processes: int = 0) -> ResourceSnapshot:
        now = time.monotonic()
        proc_cpu = self._process_cpu_percent(now)
        host_cpu = self._host_cpu_percent()
        total, available = self._memory()
        beltu_rss = self._process_rss()
        beltu_memory = 0.0 if total <= 0 else (beltu_rss / total) * 100.0
        host_memory = 0.0 if total <= 0 else ((total - available) / total) * 100.0
        try:
            load1 = os.getloadavg()[0]
        except (AttributeError, OSError):
            load1 = 0.0
        gpu, apps = self._gpu_snapshot()
        freetoken = self._freetoken_snapshot(gpu, apps)
        altar1 = self._altar1_snapshot(gpu, apps)
        return ResourceSnapshot(
            timestamp=time.time(),
            beltu_cpu_percent=round(max(0.0, min(100.0, proc_cpu)), 2),
            beltu_memory_percent=round(max(0.0, min(100.0, beltu_memory)), 2),
            host_cpu_percent=round(max(0.0, min(100.0, host_cpu)), 2),
            host_memory_percent=round(max(0.0, min(100.0, host_memory)), 2),
            memory_total_bytes=total,
            memory_available_bytes=available,
            load1=round(load1, 2),
            cpu_count=self.cpu_count,
            beltu_rss_bytes=beltu_rss,
            active_processes=active_processes,
            gpu=gpu,
            freetoken=freetoken,
            altar1=altar1,
        )

    def _process_cpu_percent(self, now: float) -> float:
        try:
            with open("/proc/self/stat", "r", encoding="utf-8") as handle:
                parts = handle.read().split()
            ticks = int(parts[13]) + int(parts[14])
        except (OSError, ValueError, IndexError):
            return 0.0
        if self._prev_proc is None:
            self._prev_proc = (ticks, now)
            return 0.0
        prev_ticks, prev_time = self._prev_proc
        self._prev_proc = (ticks, now)
        dt = max(now - prev_time, 1e-6)
        try:
            hz = max(1, int(os.sysconf("SC_CLK_TCK")))
        except (OSError, ValueError):
            hz = 100
        return ((ticks - prev_ticks) / hz) / dt * 100.0

    def _pid_cpu_percent(self, pid: int | None) -> float:
        if not pid:
            return 0.0
        try:
            uptime = float(open("/proc/uptime", "r", encoding="utf-8").read().split()[0])
            stat = open(f"/proc/{pid}/stat", "r", encoding="utf-8").read().split()
            ticks = int(stat[13]) + int(stat[14])
            start_ticks = int(stat[21])
            hz = max(1, int(os.sysconf("SC_CLK_TCK")))
            process_age = max(1e-3, uptime - (start_ticks / hz))
            return max(0.0, min(100.0 * self.cpu_count, (ticks / hz) / process_age * 100.0))
        except (OSError, ValueError, IndexError):
            return 0.0

    def _host_cpu_percent(self) -> float:
        try:
            parts = [int(x) for x in open("/proc/stat", "r", encoding="utf-8").readline().split()[1:8]]
            total = sum(parts)
            idle = parts[3] + parts[4]
        except (OSError, ValueError, IndexError):
            return 0.0
        if self._prev_host is None:
            self._prev_host = (total, idle)
            return 0.0
        prev_total, prev_idle = self._prev_host
        self._prev_host = (total, idle)
        dt_total = total - prev_total
        dt_idle = idle - prev_idle
        if dt_total <= 0:
            return 0.0
        return (1.0 - dt_idle / dt_total) * 100.0

    @staticmethod
    def _memory() -> tuple[int, int]:
        try:
            values: dict[str, int] = {}
            with open("/proc/meminfo", "r", encoding="utf-8") as handle:
                for line in handle:
                    key, value, *_ = line.split()
                    if key in {"MemTotal:", "MemAvailable:"}:
                        values[key] = int(value) * 1024
            return values.get("MemTotal:", 0), values.get("MemAvailable:", 0)
        except (OSError, ValueError):
            return 0, 0

    @staticmethod
    def _process_rss(pid: int | None = None) -> int:
        target = pid or "self"
        try:
            with open(f"/proc/{target}/status", "r", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("VmRSS:"):
                        return int(line.split()[1]) * 1024
        except (OSError, ValueError):
            pass
        return 0

    @staticmethod
    def _read_pid_file(path: Path) -> int | None:
        try:
            pid = int(path.read_text(encoding="utf-8").strip())
            return pid if pid > 1 and Path(f"/proc/{pid}").exists() else None
        except (OSError, ValueError):
            return None

    def _read_freetoken_pid(self) -> int | None:
        return self._read_pid_file(self.freetoken_pid_file)

    def _read_altar1_pid(self) -> int | None:
        return self._read_pid_file(self.altar1_pid_file)

    def _query_nvidia(self) -> tuple[GpuSnapshot, dict[int, int]] | None:
        try:
            info = subprocess.run(
                [
                    "nvidia-smi",
                    "--query-gpu=name,memory.total,memory.used,memory.free,utilization.gpu",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                timeout=2.0,
                check=False,
            )
            apps = subprocess.run(
                [
                    "nvidia-smi",
                    "--query-compute-apps=pid,used_gpu_memory",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                timeout=2.0,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if info.returncode != 0 or not info.stdout.strip():
            return None
        pieces = [p.strip() for p in info.stdout.splitlines()[0].split(",")]
        if len(pieces) < 5:
            return None

        def mib(value: str) -> int:
            try:
                return max(0, int(float(value))) * 1024 * 1024
            except ValueError:
                return 0

        try:
            gpu = GpuSnapshot(
                True,
                pieces[0],
                mib(pieces[1]),
                mib(pieces[2]),
                mib(pieces[3]),
                float(pieces[4]),
                0,
                0,
            )
        except ValueError:
            return None
        apps_by_pid: dict[int, int] = {}
        for row in apps.stdout.splitlines():
            parts = [p.strip() for p in row.split(",")]
            if len(parts) < 2:
                continue
            try:
                apps_by_pid[int(parts[0])] = mib(parts[1])
            except ValueError:
                continue
        return gpu, apps_by_pid

    def _gpu_snapshot(self) -> tuple[GpuSnapshot | None, dict[int, int]]:
        result = self._query_nvidia()
        if result is None:
            return None, {}
        gpu, apps = result
        freetoken_pid = self._read_freetoken_pid()
        altar1_pid = self._read_altar1_pid()
        return (
            GpuSnapshot(
                gpu.available,
                gpu.name,
                gpu.total_bytes,
                gpu.used_bytes,
                gpu.free_bytes,
                gpu.utilization_percent,
                apps.get(freetoken_pid, 0) if freetoken_pid else 0,
                apps.get(altar1_pid, 0) if altar1_pid else 0,
            ),
            apps,
        )

    def _freetoken_snapshot(self, gpu: GpuSnapshot | None, apps: dict[int, int]) -> FreeTokenSnapshot | None:
        pid = self._read_freetoken_pid()
        configured = bool(self.freetoken_url)
        reachable = False
        model = None
        backend = None
        requests = None
        if configured:
            try:
                with request.urlopen(f"{self.freetoken_url}/v1/models", timeout=0.8) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                items = payload.get("data", []) if isinstance(payload, dict) else []
                if isinstance(items, list) and items and isinstance(items[0], dict):
                    model = items[0].get("id")
                reachable = True
            except (OSError, ValueError, urlerror.URLError, urlerror.HTTPError):
                reachable = False
            if reachable:
                try:
                    with request.urlopen(f"{self.freetoken_url}/v1/stats", timeout=0.8) as response:
                        stats = json.loads(response.read().decode("utf-8"))
                    if isinstance(stats, dict):
                        backend = str(stats.get("moe_backend") or stats.get("moe_backend_name") or "") or None
                        requests_raw = stats.get("running_requests") or stats.get("active_requests")
                        requests = int(requests_raw) if requests_raw is not None else None
                except (OSError, ValueError, urlerror.URLError, urlerror.HTTPError, TypeError):
                    pass
        if not configured and pid is None:
            return None
        return FreeTokenSnapshot(
            configured=configured,
            reachable=reachable,
            pid=pid,
            model=str(model) if model is not None else None,
            cpu_percent=round(self._pid_cpu_percent(pid), 2) if pid else 0.0,
            rss_bytes=self._process_rss(pid) if pid else 0,
            vram_bytes=gpu.freetoken_used_bytes if gpu is not None else apps.get(pid, 0) if pid else 0,
            moe_backend=backend,
            requests=requests,
        )

    def _altar1_snapshot(self, gpu: GpuSnapshot | None, apps: dict[int, int]) -> Altar1Snapshot | None:
        pid = self._read_altar1_pid()
        active_files = []
        try:
            if self.altar1_activity_dir.exists():
                active_files = [p for p in self.altar1_activity_dir.glob("*.json") if p.is_file()]
        except OSError:
            active_files = []
        active = bool(active_files)
        configured = bool(self.altar1_url)
        reachable = False
        model = None
        if configured:
            try:
                with request.urlopen(f"{self.altar1_url}/v1/models", timeout=0.8) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                items = payload.get("data", []) if isinstance(payload, dict) else []
                if isinstance(items, list) and items and isinstance(items[0], dict):
                    model = items[0].get("id")
                reachable = True
            except (OSError, ValueError, urlerror.URLError, urlerror.HTTPError):
                reachable = False
        if not configured and pid is None and not active:
            return None
        return Altar1Snapshot(
            configured=configured,
            reachable=reachable,
            active=active,
            pid=pid,
            model=str(model) if model is not None else None,
            cpu_percent=round(self._pid_cpu_percent(pid), 2) if pid else 0.0,
            rss_bytes=self._process_rss(pid) if pid else 0,
            vram_bytes=gpu.altar1_used_bytes if gpu is not None else apps.get(pid, 0) if pid else 0,
            active_requests=len(active_files),
        )


class ResourceGovernor:
    """Adaptive CPU/RAM/GPU governor with an Altar-1 heavy-model clamp.

    During an active Altar-1 request, the governor treats the security model as
    VRAM-critical even when NVIDIA telemetry is unavailable: new external tools
    are reduced to a single concurrent process and one requested thread, while
    managed child processes are restricted to one CPU where supported.
    """

    def __init__(
        self,
        max_concurrent_processes: int = 2,
        cpu_budget_percent: float = 30.0,
        memory_budget_percent: float = 30.0,
        min_concurrent_processes: int = 1,
        poll_interval: float = 0.5,
        *,
        freetoken_pid_file: str | Path = "data/runtime/freetoken.pid",
        freetoken_url: str = "http://127.0.0.1:8000",
        altar1_pid_file: str | Path = "data/runtime/altar1.pid",
        altar1_activity_dir: str | Path = "data/runtime/altar1.active",
        altar1_url: str = "http://127.0.0.1:8001",
        gpu_vram_budget_percent: float = 45.0,
    ) -> None:
        self.max_concurrent_processes = max(1, int(max_concurrent_processes))
        self.min_concurrent_processes = max(1, min(int(min_concurrent_processes), self.max_concurrent_processes))
        self.cpu_budget_percent = max(1.0, min(100.0, float(cpu_budget_percent)))
        self.memory_budget_percent = max(1.0, min(100.0, float(memory_budget_percent)))
        self.gpu_vram_budget_percent = max(10.0, min(100.0, float(gpu_vram_budget_percent)))
        self.poll_interval = max(0.05, float(poll_interval))
        self.monitor = LinuxResourceMonitor(
            freetoken_pid_file=freetoken_pid_file,
            freetoken_url=freetoken_url,
            altar1_pid_file=altar1_pid_file,
            altar1_activity_dir=altar1_activity_dir,
            altar1_url=altar1_url,
        )
        self._active = 0
        self._condition = asyncio.Condition()
        self._last_snapshot = self.monitor.snapshot()
        self._watch_task: asyncio.Task[None] | None = None
        self._managed_pids: dict[int, str] = {}

    async def start(self) -> None:
        if self._watch_task is None or self._watch_task.done():
            self._watch_task = asyncio.create_task(self._watch_loop())

    async def stop(self) -> None:
        task = self._watch_task
        self._watch_task = None
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self._managed_pids.clear()

    async def _watch_loop(self) -> None:
        while True:
            await asyncio.sleep(self.poll_interval)
            self._last_snapshot = self.monitor.snapshot(self._active)
            self._apply_affinity_limits(self._last_snapshot)
            async with self._condition:
                self._condition.notify_all()

    def _pressure(self, snap: ResourceSnapshot) -> tuple[float, float, float]:
        beltu_pressure = max(
            snap.beltu_cpu_percent / max(self.cpu_budget_percent, 1.0),
            snap.beltu_memory_percent / max(self.memory_budget_percent, 1.0),
        )
        host_pressure = max(snap.host_cpu_percent / 90.0, snap.host_memory_percent / 90.0)
        gpu_pressure = 0.0
        if snap.gpu is not None:
            gpu_pressure = max(gpu_pressure, snap.gpu.used_percent / 95.0)
            gpu_pressure = max(gpu_pressure, snap.gpu.freetoken_percent / max(self.gpu_vram_budget_percent, 1.0))
            gpu_pressure = max(gpu_pressure, snap.gpu.altar1_percent / max(self.gpu_vram_budget_percent, 1.0))
        if snap.altar1 is not None and snap.altar1.active:
            gpu_pressure = max(gpu_pressure, 1.50)
        return beltu_pressure, host_pressure, gpu_pressure

    def effective_capacity(self, snapshot: ResourceSnapshot | None = None) -> int:
        snap = snapshot or self._last_snapshot
        if snap.altar1 is not None and snap.altar1.active:
            return self.min_concurrent_processes
        beltu_pressure, host_pressure, gpu_pressure = self._pressure(snap)
        if beltu_pressure >= 1.25 or host_pressure >= 1.0 or gpu_pressure >= 1.15:
            return self.min_concurrent_processes
        if beltu_pressure >= 1.0 or host_pressure >= 0.85 or gpu_pressure >= 1.0:
            return max(self.min_concurrent_processes, self.max_concurrent_processes // 2)
        return self.max_concurrent_processes

    def tool_runtime_limits(self, tool: str) -> ToolRuntimeLimits:
        snap = self._last_snapshot
        if snap.altar1 is not None and snap.altar1.active:
            cpus = 1
            return ToolRuntimeLimits(
                tool,
                thread_limit=1,
                max_parallel_processes=self.min_concurrent_processes,
                affinity_cpus=(0,),
                reason="Altar-1 active; aggressive VRAM protection clamp",
            )
        beltu_pressure, host_pressure, gpu_pressure = self._pressure(snap)
        hard = max(beltu_pressure, host_pressure, gpu_pressure)
        if hard >= 1.25:
            thread_limit = 1
            reason = "critical resource pressure"
        elif hard >= 1.0:
            thread_limit = 2
            reason = "high resource pressure"
        elif hard >= 0.85:
            thread_limit = 4
            reason = "elevated resource pressure"
        else:
            thread_limit = 8
            reason = "normal resource pressure"
        if tool in {"nuclei", "nmap", "httpx", "subfinder"} and gpu_pressure >= 1.0:
            thread_limit = min(thread_limit, 2)
            reason += "; local LLM VRAM pressure clamp"
        cpus = max(1, min(self.monitor.cpu_count, thread_limit))
        return ToolRuntimeLimits(tool, thread_limit, self.effective_capacity(snap), tuple(range(cpus)), reason)

    def register_process(self, pid: int, tool: str) -> None:
        if pid > 1:
            self._managed_pids[pid] = tool
            self._apply_affinity_limits(self._last_snapshot)

    def unregister_process(self, pid: int) -> None:
        self._managed_pids.pop(pid, None)

    def _apply_affinity_limits(self, snap: ResourceSnapshot) -> None:
        _, _, gpu_pressure = self._pressure(snap)
        altar_active = bool(snap.altar1 is not None and snap.altar1.active)
        for pid, tool in list(self._managed_pids.items()):
            if not Path(f"/proc/{pid}").exists():
                self._managed_pids.pop(pid, None)
                continue
            limits = self.tool_runtime_limits(tool)
            if altar_active or gpu_pressure >= 1.0 or snap.host_cpu_percent >= 85.0:
                try:
                    os.sched_setaffinity(pid, set(limits.affinity_cpus))
                except (OSError, PermissionError):
                    pass

    async def acquire_process(self, priority: int = 50) -> ResourceSnapshot:
        del priority
        await self.start()
        while True:
            async with self._condition:
                self._last_snapshot = self.monitor.snapshot(self._active)
                capacity = self.effective_capacity(self._last_snapshot)
                if self._active < capacity:
                    self._active += 1
                    return self.monitor.snapshot(self._active)
            await asyncio.sleep(self.poll_interval)

    def release_process(self) -> None:
        self._active = max(0, self._active - 1)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(self._notify_waiters())

    async def _notify_waiters(self) -> None:
        async with self._condition:
            self._condition.notify_all()

    def snapshot(self) -> ResourceSnapshot:
        self._last_snapshot = self.monitor.snapshot(self._active)
        return self._last_snapshot
```

## `src/beltu/version.py`

```python
__version__ = "1.2.0"
```

## `config/agent.yaml`

```yaml
brain:
  mode: local_llm
  llm_enabled: true
  max_hypotheses_per_cycle: 3
  max_actions_per_cycle: 3
  llm:
    enabled: true
    provider: freetoken_local
    base_url: http://127.0.0.1:8000/v1
    model: auto
    api_key_env: BELTU_LLM_API_KEY
    api_key_required: false
    local_only: true
    use_json_mode: false
    stream: true
    timeout_seconds: 60
    max_tokens: 1800
    temperature: 0.1
    fallback_to_heuristic: true
    max_hypotheses: 3
    max_actions: 3
    system_prompt_path: prompts/llm/system.md
    reasoning_prompt_path: prompts/llm/reasoning.md

    routing:
      enabled: true

    # Optional heavy local security specialist. Disabled by default because
    # Altar-1 is a 328 GB W4A16 model intended for a multi-GPU local node.
    altar1:
      enabled: false
      base_url: http://127.0.0.1:8001/v1
      model: aikido/altar-1
      api_key_env: BELTU_ALTAR1_API_KEY
      api_key_required: false
      local_only: true
      use_json_mode: false
      stream: true
      timeout_seconds: 180
      max_tokens: 3200
      temperature: 0.1
      activity_dir: data/runtime/altar1.active

execution:
  external_tools_enabled: false

policy:
  high_risk_requires_approval: true

resource_policy:
  cpu_budget_percent: 30
  memory_budget_percent: 30
  gpu_vram_budget_percent: 45
  min_concurrent_processes: 1
  max_concurrent_processes: 2
  poll_interval_seconds: 0.5

retry_policy:
  base_delay_seconds: 0.25
  max_delay_seconds: 5
  jitter: 0

scheduler:
  workers: 4
```

## `tests/stage22/test_stage22_multi_model.py`

```python
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from beltu.brain.llm.config import LLMConfig
from beltu.brain.llm.provider import Altar1LocalProvider
from beltu.brain.llm.router import LLMRouter
from beltu.brain.schemas import AgentContext
from beltu.execution.resource_governor import Altar1Snapshot, ResourceGovernor, ResourceSnapshot


class AltarHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/v1/models":
            body = json.dumps({"data": [{"id": "aikido/altar-1"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            self.send_response(404)
            self.end_headers()
            return
        _ = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        payload = {"choices": [{"message": {"content": '{"summary":"ok","hypotheses":[],"actions":[]}'}}]}
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        return


def test_router_keeps_general_recon_on_standard_provider():
    class FixtureProvider:
        name = "standard"
        model = "standard-model"

        def complete(self, *, system_prompt: str, user_prompt: str):
            return '{"summary":"ok","hypotheses":[],"actions":[]}', 1.0

    router = LLMRouter(standard_provider=FixtureProvider(), enabled=True)
    decision = router.classify(
        AgentContext(
            scan_id=1,
            target="example.com",
            observations=({"kind": "nmap_tool_output", "subject": "host scan"},),
        )
    )
    assert decision.route == "standard"


def test_router_selects_altar_for_code_review():
    class FixtureProvider:
        name = "standard"
        model = "standard-model"

        def complete(self, *, system_prompt: str, user_prompt: str):
            return "standard", 1.0

    altar = object.__new__(Altar1LocalProvider)
    router = LLMRouter(standard_provider=FixtureProvider(), altar_provider=altar, enabled=True)
    decision = router.classify(
        AgentContext(
            scan_id=1,
            target="example.com",
            finding_surface={"code_review": {"files": ["app.py"]}},
        )
    )
    assert decision.route == "altar1"
    assert decision.profile is not None
    assert decision.profile.name == "code_review"


def test_altar_provider_creates_activity_lease(tmp_path: Path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), AltarHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    activity_dir = tmp_path / "altar1.active"
    try:
        config = LLMConfig.from_mapping(
            {
                "enabled": True,
                "altar1": {
                    "enabled": True,
                    "base_url": f"http://127.0.0.1:{server.server_port}/v1",
                    "model": "aikido/altar-1",
                    "local_only": True,
                    "stream": False,
                    "activity_dir": str(activity_dir),
                },
            }
        )
        provider = Altar1LocalProvider(config)
        text, latency = provider.complete(system_prompt="s", user_prompt="u")
        assert '"summary":"ok"' in text
        assert latency >= 0
        assert not activity_dir.exists() or not list(activity_dir.glob("*.json"))
    finally:
        server.shutdown()
        thread.join()


def test_governor_clamps_during_active_altar_request(tmp_path: Path):
    activity_dir = tmp_path / "altar1.active"
    activity_dir.mkdir()
    (activity_dir / "request.json").write_text("{\"route\":\"exploit_proof\"}\n", encoding="utf-8")
    governor = ResourceGovernor(
        max_concurrent_processes=4,
        min_concurrent_processes=1,
        poll_interval=0.1,
        altar1_activity_dir=activity_dir,
        altar1_url="http://127.0.0.1:65530",
    )
    snap = governor.snapshot()
    assert snap.altar1 is not None
    assert snap.altar1.active is True
    assert governor.effective_capacity(snap) == 1
    limits = governor.tool_runtime_limits("nuclei")
    assert limits.thread_limit == 1
    assert limits.max_parallel_processes == 1
    assert "Altar-1 active" in limits.reason


def test_resource_snapshot_altar_field_is_optional():
    snap = ResourceSnapshot(
        timestamp=0.0,
        beltu_cpu_percent=0.0,
        beltu_memory_percent=0.0,
        host_cpu_percent=0.0,
        host_memory_percent=0.0,
        memory_total_bytes=1,
        memory_available_bytes=1,
        load1=0.0,
        cpu_count=1,
        beltu_rss_bytes=0,
        active_processes=0,
        altar1=Altar1Snapshot(False, False, False, None, None, 0.0, 0, 0, 0),
    )
    assert snap.altar1 is not None
    assert not snap.altar1.active
```

## `scripts/start_altar1.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${BELTU_ALTAR1_VENV:-$HOME/.local/share/beltu/altar1/.venv}"
MODEL="${BELTU_ALTAR1_MODEL:-aikido/altar-1}"
HOST="${BELTU_ALTAR1_HOST:-127.0.0.1}"
PORT="${BELTU_ALTAR1_PORT:-8001}"
TENSOR_PARALLEL="${BELTU_ALTAR1_TENSOR_PARALLEL_SIZE:-4}"
MAX_MODEL_LEN="${BELTU_ALTAR1_MAX_MODEL_LEN:-131072}"
PID_FILE="$ROOT/data/runtime/altar1.pid"
LOG_FILE="$ROOT/data/runtime/altar1.log"

VLLM_BIN="$VENV_DIR/bin/vllm"
[[ -x "$VLLM_BIN" ]] || {
  echo "vLLM not found at $VLLM_BIN. Install vLLM in the Altar-1 serving environment first." >&2
  exit 2
}

mkdir -p "$ROOT/data/runtime"
if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE" 2>/dev/null || echo 0)" 2>/dev/null; then
  echo "Altar-1 already running (pid $(cat "$PID_FILE"))."
  exit 0
fi

CMD=(
  "$VLLM_BIN" serve "$MODEL"
  --tensor-parallel-size "$TENSOR_PARALLEL"
  --trust-remote-code
  --max-model-len "$MAX_MODEL_LEN"
  --host "$HOST"
  --port "$PORT"
)

nohup "${CMD[@]}" >>"$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
chmod 600 "$PID_FILE"

echo "Altar-1 started: http://$HOST:$PORT/v1"
echo "PID: $(cat "$PID_FILE")"
echo "Log: $LOG_FILE"
```

## `scripts/stop_altar1.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="$ROOT/data/runtime/altar1.pid"
if [[ ! -f "$PID_FILE" ]]; then
  echo "Altar-1 is not running."
  exit 0
fi
PID="$(cat "$PID_FILE" 2>/dev/null || true)"
if [[ "$PID" =~ ^[0-9]+$ ]] && kill -0 "$PID" 2>/dev/null; then
  kill "$PID" || true
  for _ in {1..20}; do
    kill -0 "$PID" 2>/dev/null || break
    sleep 0.25
  done
fi
rm -f "$PID_FILE"
echo "Altar-1 stopped."
```

## `src/beltu/interface/cli/app.py` — exact v1.2 integration changes

The full 1099-line application file is already included in `BELTU-1.2.0-source.zip`. The following are the complete blocks that replace the old v1.1 LLM wiring.

### Import block

```python
from beltu.brain.llm import Altar1LocalProvider, DisabledLLMProvider, FreeTokenLocalProvider, LLMConfig, LLMReasoningEngine, LLMRouter, OpenAICompatibleProvider
```

### LLM construction block inside `build_components()`

```python
    llm_config = LLMConfig.from_project(Path.cwd())
    standard_provider = FreeTokenLocalProvider(llm_config) if llm_config.enabled else DisabledLLMProvider()
    altar_provider = Altar1LocalProvider(llm_config) if llm_config.altar_enabled else DisabledLLMProvider()
    llm_router = LLMRouter(
        standard_provider=standard_provider,
        altar_provider=altar_provider,
        enabled=llm_config.router_enabled,
    )
    llm_reasoner = LLMReasoningEngine(Path.cwd(), llm_config, llm_router)
```

### ResourceGovernor construction parameters

```python
            freetoken_pid_file=Path.cwd() / "data" / "runtime" / "freetoken.pid",
            freetoken_url="http://127.0.0.1:8000",
            altar1_pid_file=Path.cwd() / "data" / "runtime" / "altar1.pid",
            altar1_activity_dir=Path.cwd() / "data" / "runtime" / "altar1.active",
            altar1_url="http://127.0.0.1:8001",
            gpu_vram_budget_percent=45,
```

Use the same parameter block in the `resources()` and `status()` commands.
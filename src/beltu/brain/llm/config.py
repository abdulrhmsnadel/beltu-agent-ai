from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


@dataclass(frozen=True, slots=True)
class LLMConfig:
    """Reasoning configuration.

    BELTU 1.1 defaults to a local FreeToken endpoint. The provider is deliberately
    constrained to loopback so a malformed configuration cannot silently route
    reasoning to a cloud endpoint.
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

    @classmethod
    def from_mapping(cls, mapping: dict[str, Any]) -> "LLMConfig":
        data = mapping if isinstance(mapping, dict) else {}
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
        )

    def api_key(self) -> str | None:
        value = os.getenv(self.api_key_env)
        return value.strip() if value and value.strip() else None

    @property
    def is_loopback(self) -> bool:
        host = (urlparse(self.base_url).hostname or "").lower()
        return host in {"127.0.0.1", "localhost", "::1"}

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

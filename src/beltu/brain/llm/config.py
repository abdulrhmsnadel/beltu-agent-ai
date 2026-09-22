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
    backward compatibility. v1.3 adds a Gemini cloud co-pilot beside the
    standard local operator and optional Altar-1 local deep reviewer.
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

    # v1.3 three-tier router.
    router_enabled: bool = True
    # v1.3 Gemini cloud co-pilot.
    gemini_enabled: bool = True
    gemini_api_key_env: str = "GEMINI_API_KEY"
    gemini_model: str = "gemini-3.8-flash"
    gemini_base_url: str = "https://generativelanguage.googleapis.com/v1beta"
    gemini_timeout_seconds: float = 30.0
    gemini_max_output_tokens: int = 4096
    gemini_max_input_chars: int = 1_500_000
    gemini_max_observation_chars: int = 100_000
    gemini_requests_per_minute: int = 15
    gemini_burst: int = 1
    gemini_retry_after_seconds: float = 5.0
    gemini_fallback_to_standard: bool = True
    gemini_scrub_before_send: bool = True
    gemini_allow_final_reports: bool = False
    gemini_allow_exploit_payloads: bool = False
    gemini_allow_poc_code: bool = False
    gemini_allow_session_data: bool = False
    gemini_allow_credentials: bool = False
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
            gemini_enabled=bool((data.get("gemini", {}) if isinstance(data.get("gemini", {}), dict) else {}).get("enabled", True)),
            gemini_api_key_env=str((data.get("gemini", {}) if isinstance(data.get("gemini", {}), dict) else {}).get("api_key_env", "GEMINI_API_KEY")),
            gemini_model=str((data.get("gemini", {}) if isinstance(data.get("gemini", {}), dict) else {}).get("model", "gemini-3.8-flash")),
            gemini_base_url=str((data.get("gemini", {}) if isinstance(data.get("gemini", {}), dict) else {}).get("base_url", "https://generativelanguage.googleapis.com/v1beta")).rstrip("/"),
            gemini_timeout_seconds=max(1.0, float((data.get("gemini", {}) if isinstance(data.get("gemini", {}), dict) else {}).get("timeout_seconds", 30.0))),
            gemini_max_output_tokens=max(128, int((data.get("gemini", {}) if isinstance(data.get("gemini", {}), dict) else {}).get("max_output_tokens", 4096))),
            gemini_max_input_chars=max(16_384, int((data.get("gemini", {}) if isinstance(data.get("gemini", {}), dict) else {}).get("max_input_chars", 1_500_000))),
            gemini_max_observation_chars=max(256, int((data.get("gemini", {}) if isinstance(data.get("gemini", {}), dict) else {}).get("max_observation_chars", 100_000))),
            gemini_requests_per_minute=max(1, int((data.get("gemini", {}) if isinstance(data.get("gemini", {}), dict) else {}).get("requests_per_minute", 15))),
            gemini_burst=max(1, int((data.get("gemini", {}) if isinstance(data.get("gemini", {}), dict) else {}).get("burst", 1))),
            gemini_retry_after_seconds=max(0.0, float((data.get("gemini", {}) if isinstance(data.get("gemini", {}), dict) else {}).get("retry_after_seconds", 5.0))),
            gemini_fallback_to_standard=bool((data.get("gemini", {}) if isinstance(data.get("gemini", {}), dict) else {}).get("fallback_to_standard", True)),
            gemini_scrub_before_send=bool((data.get("gemini", {}) if isinstance(data.get("gemini", {}), dict) else {}).get("scrub_before_send", True)),
            gemini_allow_final_reports=bool((data.get("gemini", {}) if isinstance(data.get("gemini", {}), dict) else {}).get("allow_final_reports", False)),
            gemini_allow_exploit_payloads=bool((data.get("gemini", {}) if isinstance(data.get("gemini", {}), dict) else {}).get("allow_exploit_payloads", False)),
            gemini_allow_poc_code=bool((data.get("gemini", {}) if isinstance(data.get("gemini", {}), dict) else {}).get("allow_poc_code", False)),
            gemini_allow_session_data=bool((data.get("gemini", {}) if isinstance(data.get("gemini", {}), dict) else {}).get("allow_session_data", False)),
            gemini_allow_credentials=bool((data.get("gemini", {}) if isinstance(data.get("gemini", {}), dict) else {}).get("allow_credentials", False)),
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
            gemini_enabled=self.gemini_enabled,
            gemini_api_key_env=self.gemini_api_key_env,
            gemini_model=self.gemini_model,
            gemini_base_url=self.gemini_base_url,
            gemini_timeout_seconds=self.gemini_timeout_seconds,
            gemini_max_output_tokens=self.gemini_max_output_tokens,
            gemini_max_input_chars=self.gemini_max_input_chars,
            gemini_max_observation_chars=self.gemini_max_observation_chars,
            gemini_requests_per_minute=self.gemini_requests_per_minute,
            gemini_burst=self.gemini_burst,
            gemini_retry_after_seconds=self.gemini_retry_after_seconds,
            gemini_fallback_to_standard=self.gemini_fallback_to_standard,
            gemini_scrub_before_send=self.gemini_scrub_before_send,
            gemini_allow_final_reports=self.gemini_allow_final_reports,
            gemini_allow_exploit_payloads=self.gemini_allow_exploit_payloads,
            gemini_allow_poc_code=self.gemini_allow_poc_code,
            gemini_allow_session_data=self.gemini_allow_session_data,
            gemini_allow_credentials=self.gemini_allow_credentials,
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
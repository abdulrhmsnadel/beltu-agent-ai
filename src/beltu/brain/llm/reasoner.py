from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from beltu.brain.llm.config import LLMConfig
from beltu.brain.llm.prompting import build_user_prompt, load_prompt
from beltu.brain.llm.provider import LLMProvider
from beltu.brain.llm.schemas import LLMRunResult, LLMReasoningResponse
from beltu.brain.llm.validator import extract_json, validate_response
from beltu.brain.schemas import AgentContext


class LLMReasoningEngine:
    """LLM-backed proposal generator. It cannot execute tools or bypass policy."""

    def __init__(self, root: Path, config: LLMConfig, provider: LLMProvider) -> None:
        self.root = root
        self.config = config
        self.provider = provider

    def run(self, context: AgentContext) -> LLMRunResult:
        system_prompt = load_prompt(
            self.root,
            self.config.system_prompt_path,
            "You are BELTU's reasoning module. Return JSON only. Propose hypotheses and declarative action objects. Never emit commands, shell syntax, URLs outside the supplied target, credentials, or execution instructions.",
        )
        user_prompt = build_user_prompt(self.root, self.config.reasoning_prompt_path, context, self.config.max_hypotheses, self.config.max_actions)
        prompt_bytes = (system_prompt + "\n\n" + user_prompt).encode("utf-8")
        prompt_hash = hashlib.sha256(prompt_bytes).hexdigest()
        started = time.perf_counter()
        raw = ""
        try:
            raw, provider_latency = self.provider.complete(system_prompt=system_prompt, user_prompt=user_prompt)
            payload = extract_json(raw)
            response = validate_response(
                payload,
                context,
                provider=self.provider.name,
                model=self.provider.model,
                max_hypotheses=self.config.max_hypotheses,
                max_actions=self.config.max_actions,
            )
            response_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            return LLMRunResult(True, response, raw, None, max(provider_latency, (time.perf_counter() - started) * 1000.0), prompt_hash, response_hash)
        except Exception as exc:
            response_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest() if raw else hashlib.sha256(b"").hexdigest()
            return LLMRunResult(False, None, raw, str(exc), (time.perf_counter() - started) * 1000.0, prompt_hash, response_hash)


class StaticProvider:
    """Offline deterministic provider used by tests and local development."""

    name = "static"
    model = "fixture"

    def __init__(self, response: str, latency_ms: float = 0.0) -> None:
        self.response = response
        self.latency_ms = latency_ms

    def complete(self, *, system_prompt: str, user_prompt: str) -> tuple[str, float]:
        return self.response, self.latency_ms

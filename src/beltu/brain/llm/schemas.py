from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from beltu.brain.schemas import ActionProposal, HypothesisProposal


@dataclass(frozen=True, slots=True)
class LLMReasoningResponse:
    summary: str
    hypotheses: tuple[HypothesisProposal, ...]
    actions: tuple[ActionProposal, ...]
    provider: str
    model: str
    raw_json: dict[str, Any]


@dataclass(frozen=True, slots=True)
class LLMRunResult:
    ok: bool
    response: LLMReasoningResponse | None
    raw_text: str
    error: str | None
    latency_ms: float
    prompt_sha256: str
    response_sha256: str

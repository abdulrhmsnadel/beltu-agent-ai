from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LLMRun:
    id: int
    scan_id: int
    cycle_id: int
    provider: str
    model: str
    status: str
    prompt_sha256: str
    response_sha256: str
    latency_ms: float
    response_text: str | None
    error: str | None
    created_at: str

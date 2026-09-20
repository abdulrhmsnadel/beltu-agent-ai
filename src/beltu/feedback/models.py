from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ReasoningCycle:
    id: int
    scan_id: int
    trigger: str
    trigger_task_id: int
    context_fingerprint: str
    status: str
    summary: dict[str, Any]
    created_at: str
    completed_at: str | None

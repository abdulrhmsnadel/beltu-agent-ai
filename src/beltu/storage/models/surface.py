from __future__ import annotations

from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True, slots=True)
class SurfacePriority:
    id: int
    scan_id: int
    entity_type: str
    entity_id: int
    value: str
    score: float
    priority: str
    exposure: float
    novelty: float
    sensitivity: float
    confidence: float
    rationale: str
    signals: dict[str, Any]
    updated_at: str

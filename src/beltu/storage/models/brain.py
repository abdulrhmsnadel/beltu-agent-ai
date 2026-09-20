from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class Observation:
    id: int
    scan_id: int
    kind: str
    subject: str
    data: dict[str, Any]
    source: str
    confidence: float
    created_at: str


@dataclass(frozen=True, slots=True)
class Hypothesis:
    id: int
    scan_id: int
    statement: str
    basis_observation_ids: list[int]
    confidence: float
    status: str
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class Decision:
    id: int
    scan_id: int
    hypothesis_id: int | None
    action_kind: str
    action_payload: dict[str, Any]
    rationale: str
    confidence: float
    risk_level: str
    requires_approval: bool
    status: str
    created_at: str

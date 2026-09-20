from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True, slots=True)
class FindingCandidate:
    id: int
    scan_id: int
    fingerprint: str
    title: str
    category: str
    severity: str
    confidence: float
    status: str
    subject: str
    entity_type: str | None
    entity_id: int | None
    impact_summary: str
    rationale: str
    source_count: int
    corroboration_score: float
    created_at: str
    updated_at: str

@dataclass(frozen=True, slots=True)
class FindingSource:
    id: int
    scan_id: int
    finding_id: int
    source_type: str
    source_id: int
    relation: str
    confidence: float
    evidence_ids: tuple[int, ...]
    metadata: dict[str, Any]
    created_at: str

@dataclass(frozen=True, slots=True)
class ValidationPlan:
    id: int
    scan_id: int
    finding_id: int
    objective: str
    status: str
    risk_level: str
    requires_approval: bool
    preconditions: tuple[str, ...]
    expected_evidence: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    confidence: float
    rationale: str
    created_at: str
    updated_at: str

@dataclass(frozen=True, slots=True)
class ValidationPlanStep:
    id: int
    plan_id: int
    ordinal: int
    step_kind: str
    title: str
    instruction: str
    expected_observation_kind: str | None
    approval_required: bool
    risk_level: str
    created_at: str

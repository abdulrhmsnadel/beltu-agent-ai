from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class BusinessWorkflow:
    id: int
    scan_id: int
    workflow_key: str
    label: str
    confidence: float
    source: str
    metadata: dict[str, Any]
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class WorkflowState:
    id: int
    workflow_id: int
    state_key: str
    label: str
    initial: bool
    terminal: bool
    confidence: float
    source: str
    metadata: dict[str, Any]
    created_at: str


@dataclass(frozen=True, slots=True)
class WorkflowTransition:
    id: int
    scan_id: int
    workflow_id: int
    from_state: str
    to_state: str
    operation_id: int | None
    relation: str
    action: str | None
    confidence: float
    evidence_ids: tuple[int, ...]
    basis: dict[str, Any]
    created_at: str


@dataclass(frozen=True, slots=True)
class BusinessLogicAnomaly:
    id: int
    scan_id: int
    workflow_id: int
    kind: str
    severity: str
    statement: str
    rationale: str
    confidence: float
    entity_key: str
    basis: dict[str, Any]
    status: str
    created_at: str
    updated_at: str

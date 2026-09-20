from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class AuthorizationMatrixEntry:
    id: int
    scan_id: int
    operation_id: int
    principal_id: int | None
    principal_label: str
    role: str | None
    access_state: str
    auth_required: bool
    confidence: float
    evidence_ids: tuple[int, ...]
    basis: dict[str, Any]
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class AuthorizationAnomaly:
    id: int
    scan_id: int
    kind: str
    severity: str
    entity_type: str
    entity_id: int
    statement: str
    rationale: str
    confidence: float
    basis: dict[str, Any]
    created_at: str
    updated_at: str

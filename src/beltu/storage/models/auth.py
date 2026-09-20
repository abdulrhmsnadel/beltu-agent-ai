
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class AuthPrincipal:
    id: int
    scan_id: int
    label: str
    kind: str
    role: str | None
    confidence: float
    source: str
    metadata: dict[str, Any]
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class AuthSession:
    id: int
    scan_id: int
    label: str
    transport: str
    mechanism: str
    state: str
    secure: bool | None
    http_only: bool | None
    same_site: str | None
    domain: str | None
    path: str | None
    expires_at: str | None
    value_present: bool
    fingerprint_sha256: str
    source: str
    confidence: float
    metadata: dict[str, Any]
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class AuthOperationControl:
    id: int
    scan_id: int
    operation_id: int
    principal_id: int | None
    principal_label: str
    access_state: str
    auth_required: bool
    schemes: tuple[str, ...]
    confidence: float
    basis: dict[str, Any]
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class AuthTransition:
    id: int
    scan_id: int
    from_state: str
    to_state: str
    operation_id: int | None
    relation: str
    confidence: float
    basis: dict[str, Any]
    created_at: str

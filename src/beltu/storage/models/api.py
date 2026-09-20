
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ApiOperation:
    id: int
    scan_id: int
    asset_id: int
    endpoint_id: int | None
    operation_key: str
    method: str
    path: str
    operation_id: str | None
    api_style: str
    tags: tuple[str, ...]
    auth_required: bool
    auth_schemes: tuple[str, ...]
    request_content_types: tuple[str, ...]
    response_content_types: tuple[str, ...]
    summary: str | None
    description: str | None
    source: str
    confidence: float
    metadata: dict[str, Any]
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class ApiParameter:
    id: int
    scan_id: int
    operation_id: int
    name: str
    location: str
    required: bool
    parameter_type: str | None
    schema: dict[str, Any]
    source: str
    confidence: float
    metadata: dict[str, Any]
    created_at: str


@dataclass(frozen=True, slots=True)
class ApiRelation:
    id: int
    scan_id: int
    from_operation_id: int
    to_operation_id: int
    relation: str
    confidence: float
    basis: dict[str, Any]
    created_at: str

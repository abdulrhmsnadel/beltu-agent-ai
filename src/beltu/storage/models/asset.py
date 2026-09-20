from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class Asset:
    id: int
    scan_id: int
    target_id: int
    asset_type: str
    value: str
    normalized_value: str
    status: str
    source: str
    confidence: float
    metadata: dict[str, Any]
    first_seen: str
    last_seen: str


@dataclass(frozen=True, slots=True)
class AssetRelation:
    id: int
    scan_id: int
    parent_asset_id: int
    child_asset_id: int
    relation: str
    confidence: float
    metadata: dict[str, Any]
    created_at: str


@dataclass(frozen=True, slots=True)
class AssetService:
    id: int
    scan_id: int
    asset_id: int
    transport: str
    port: int
    state: str
    service: str | None
    product: str | None
    version: str | None
    source: str
    confidence: float
    metadata: dict[str, Any]
    created_at: str


@dataclass(frozen=True, slots=True)
class AssetEndpoint:
    id: int
    scan_id: int
    asset_id: int
    url: str
    method: str
    path: str
    endpoint_type: str
    auth_hint: str | None
    source: str
    confidence: float
    metadata: dict[str, Any]
    created_at: str


@dataclass(frozen=True, slots=True)
class AssetTechnology:
    id: int
    scan_id: int
    asset_id: int
    name: str
    version: str | None
    category: str | None
    source: str
    confidence: float
    metadata: dict[str, Any]
    created_at: str

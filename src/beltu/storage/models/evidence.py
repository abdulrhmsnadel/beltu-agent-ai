from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class Evidence:
    id: int
    scan_id: int
    observation_id: int | None
    kind: str
    path: str | None
    sha256: str
    size_bytes: int
    mime_type: str
    metadata: dict[str, Any]
    created_at: str


@dataclass(frozen=True, slots=True)
class ObservationLink:
    id: int
    scan_id: int
    observation_id: int
    related_observation_id: int
    relation: str
    score: float
    created_at: str

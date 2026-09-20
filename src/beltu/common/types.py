from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class Target:
    id: int
    value: str
    status: str
    created_at: str


@dataclass(frozen=True, slots=True)
class Scan:
    id: int
    target_id: int
    status: str
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class Task:
    id: int
    scan_id: int
    kind: str
    status: str
    payload: dict[str, Any]
    result: dict[str, Any] | None
    error: str | None
    attempts: int
    priority: int
    max_attempts: int
    next_run_at: str | None
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class Event:
    type: str
    payload: dict[str, Any]
    occurred_at: str

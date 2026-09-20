from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    scan_id: int
    target: str
    capability: str
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    request: ExecutionRequest
    tool: str
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    observations: tuple[dict[str, Any], ...] = ()
    resource_before: Any | None = None
    resource_after: Any | None = None
    evidence_ids: tuple[int, ...] = ()

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0 and not self.timed_out

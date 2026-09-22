from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from beltu.execution.models import ExecutionRequest


class ToolAdapter(ABC):
    name: str
    capability: str
    binary: str
    risk_level: str = "low"
    requires_approval: bool = False
    timeout_seconds: float = 120.0

    @abstractmethod
    def build_argv(self, request: ExecutionRequest) -> list[str]:
        """Build argv for subprocess execution; never return a shell command string."""

    def parse_output(self, request: ExecutionRequest, stdout: str, stderr: str) -> list[dict[str, Any]]:
        return []

    def cleanup_argv(self, argv: tuple[str, ...] | list[str]) -> None:
        """Optional post-execution cleanup for private runtime artifacts."""
        del argv

    @staticmethod
    def runtime_threads(request: ExecutionRequest, default: int = 8) -> int:
        limits = request.options.get("_runtime_limits", {})
        try:
            value = int(limits.get("thread_limit", default))
        except (TypeError, ValueError):
            value = default
        return max(1, min(64, value))

    def validate_request(self, request: ExecutionRequest) -> None:
        if not request.target.strip():
            raise ValueError("Target is required")

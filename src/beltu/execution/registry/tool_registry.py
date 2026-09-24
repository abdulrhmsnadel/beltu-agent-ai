from __future__ import annotations

import shutil

from beltu.execution.adapters.base import ToolAdapter


class ToolRegistry:
    """Allowlisted tool adapters. No arbitrary shell commands are registered."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolAdapter] = {}

    def register(self, adapter: ToolAdapter) -> None:
        if adapter.name in self._tools:
            raise ValueError(f"Tool already registered: {adapter.name}")
        self._tools[adapter.name] = adapter

    def get(self, name: str) -> ToolAdapter:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise KeyError(f"Unknown tool: {name}") from exc

    def list(self) -> list[ToolAdapter]:
        return list(self._tools.values())

    def for_capability(self, capability: str, *, installed_only: bool = False) -> list[ToolAdapter]:
        candidates = [x for x in self._tools.values() if x.capability == capability]
        if installed_only:
            candidates = [x for x in candidates if shutil.which(x.binary) is not None]
        return candidates

    @staticmethod
    def is_available(adapter: ToolAdapter) -> bool:
        """Return whether the adapter's executable is resolvable on PATH."""
        return shutil.which(adapter.binary) is not None

    def unavailable(self) -> list[ToolAdapter]:
        """Return registered adapters whose backing executable is not available."""
        return [adapter for adapter in self._tools.values() if not self.is_available(adapter)]

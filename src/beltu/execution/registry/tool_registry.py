from __future__ import annotations

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

    def for_capability(self, capability: str) -> list[ToolAdapter]:
        return [x for x in self._tools.values() if x.capability == capability]

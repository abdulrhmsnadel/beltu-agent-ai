from __future__ import annotations

from beltu.execution.adapters.base import ToolAdapter
from beltu.execution.registry.tool_registry import ToolRegistry


class CapabilityRegistry:
    """Maps a semantic capability to one or more concrete tool adapters."""

    def __init__(self, tools: ToolRegistry) -> None:
        self.tools = tools

    def resolve(self, capability: str, preferred_tool: str | None = None) -> ToolAdapter:
        if preferred_tool:
            adapter = self.tools.get(preferred_tool)
            if adapter.capability != capability:
                raise ValueError(f"Tool {preferred_tool!r} does not implement {capability!r}")
            return adapter
        candidates = self.tools.for_capability(capability)
        if not candidates:
            raise KeyError(f"No adapter registered for capability: {capability}")
        return candidates[0]

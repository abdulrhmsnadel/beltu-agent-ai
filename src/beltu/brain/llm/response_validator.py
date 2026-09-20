from __future__ import annotations

from typing import Any


class LLMResponseValidator:
    """Minimal structural validation; never treats free-form model text as executable instructions."""

    def require_object(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError("LLM response must be a JSON object")
        return value

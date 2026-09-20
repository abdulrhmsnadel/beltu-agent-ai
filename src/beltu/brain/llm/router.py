from __future__ import annotations

from beltu.brain.llm.provider import DisabledLLMProvider, LLMProvider


class LLMRouter:
    def __init__(self, provider: LLMProvider | None = None) -> None:
        self.provider = provider or DisabledLLMProvider()

    def available(self) -> bool:
        return not isinstance(self.provider, DisabledLLMProvider)

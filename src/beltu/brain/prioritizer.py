from __future__ import annotations

from beltu.brain.schemas import HypothesisProposal


class HypothesisPrioritizer:
    def rank(self, proposals: list[HypothesisProposal]) -> list[HypothesisProposal]:
        return sorted(proposals, key=lambda item: item.confidence, reverse=True)

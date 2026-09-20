from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from beltu.brain.hypothesis_engine import HeuristicHypothesisEngine
from beltu.brain.llm.reasoner import LLMReasoningEngine
from beltu.brain.planner import Planner
from beltu.brain.prioritizer import HypothesisPrioritizer
from beltu.brain.schemas import ActionProposal, AgentContext, HypothesisProposal


@dataclass(frozen=True, slots=True)
class ReasoningProposalSet:
    hypotheses: tuple[HypothesisProposal, ...]
    actions: tuple[ActionProposal, ...] = ()
    source: str = "heuristic"
    summary: str = ""
    llm_error: str | None = None


class ReasoningEngine(Protocol):
    def generate(self, context: AgentContext) -> ReasoningProposalSet:
        ...


class HybridReasoningEngine:
    """Select LLM reasoning when enabled, then fall back to deterministic reasoning if configured."""

    def __init__(
        self,
        *,
        heuristic: HeuristicHypothesisEngine,
        prioritizer: HypothesisPrioritizer,
        planner: Planner,
        llm: LLMReasoningEngine | None = None,
        enabled: bool = False,
        fallback_to_heuristic: bool = True,
    ) -> None:
        self.heuristic = heuristic
        self.prioritizer = prioritizer
        self.planner = planner
        self.llm = llm
        self.enabled = enabled and llm is not None
        self.fallback_to_heuristic = fallback_to_heuristic
        self.last_llm_run = None

    def _heuristic(self, context: AgentContext, *, error: str | None = None) -> ReasoningProposalSet:
        hypotheses = tuple(self.prioritizer.rank(self.heuristic.generate(context)))
        actions = tuple(self.planner.plan(context, list(hypotheses)))
        return ReasoningProposalSet(hypotheses, actions, "heuristic", "Deterministic reasoning baseline", error)

    def generate(self, context: AgentContext) -> ReasoningProposalSet:
        self.last_llm_run = None
        if not self.enabled or self.llm is None:
            return self._heuristic(context)
        result = self.llm.run(context)
        self.last_llm_run = result
        if result.ok and result.response is not None:
            return ReasoningProposalSet(
                result.response.hypotheses,
                result.response.actions,
                "llm",
                result.response.summary,
                None,
            )
        if self.fallback_to_heuristic:
            return self._heuristic(context, error=result.error or "unknown LLM failure")
        raise RuntimeError(result.error or "LLM reasoning failed")

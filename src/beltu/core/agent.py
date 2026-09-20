from __future__ import annotations

from beltu.brain.context_builder import ContextBuilder
from beltu.brain.observer import Observer
from beltu.brain.observation_pipeline import ObservationPipeline
from beltu.brain.decision_engine import DecisionEngine
from beltu.brain.hypothesis_engine import HeuristicHypothesisEngine
from beltu.brain.planner import Planner
from beltu.brain.prioritizer import HypothesisPrioritizer
from beltu.brain.reasoning_engine import HybridReasoningEngine, ReasoningEngine
from beltu.brain.schemas import AgentContext, ObservationInput, ReasoningCycle
from beltu.common.types import Scan, Target, Task
from beltu.core.orchestrator import Orchestrator
from beltu.policy.scope_guard import ScopeGuard
from beltu.storage.repositories.decision_repository import DecisionRepository
from beltu.storage.repositories.hypothesis_repository import HypothesisRepository
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.target_repository import TargetRepository


class Agent:
    """Stateful agent facade; Stage 3 adds a persistent reasoning loop without external execution."""

    def __init__(
        self,
        targets: TargetRepository,
        scope: ScopeGuard,
        orchestrator: Orchestrator | None = None,
        *,
        observations: ObservationRepository | None = None,
        hypotheses: HypothesisRepository | None = None,
        decisions: DecisionRepository | None = None,
        context_builder: ContextBuilder | None = None,
        hypothesis_engine: HeuristicHypothesisEngine | None = None,
        prioritizer: HypothesisPrioritizer | None = None,
        planner: Planner | None = None,
        decision_engine: DecisionEngine | None = None,
        observation_pipeline: ObservationPipeline | None = None,
        reasoning_engine: ReasoningEngine | None = None,
    ) -> None:
        self.targets = targets
        self.scope = scope
        self.orchestrator = orchestrator
        self.observations = observations
        self.hypotheses = hypotheses
        self.decisions = decisions
        self.context_builder = context_builder
        self.hypothesis_engine = hypothesis_engine or HeuristicHypothesisEngine()
        self.prioritizer = prioritizer or HypothesisPrioritizer()
        self.planner = planner or Planner()
        self.decision_engine = decision_engine or DecisionEngine()
        self.observation_pipeline = observation_pipeline
        self.reasoning_engine = reasoning_engine

    def register_target(self, value: str) -> Target:
        normalized = value.strip()
        self.scope.require_allowed(normalized)
        if self.targets.exists(normalized):
            existing = next(x for x in self.targets.list_all() if x.value == normalized)
            return existing
        return self.targets.add(normalized)

    async def start_scan(self, target_id: int) -> tuple[Scan, Task]:
        if self.orchestrator is None:
            raise RuntimeError("Agent orchestrator is not configured")
        return await self.orchestrator.create_scan(target_id)

    def ingest_observation(self, scan_id: int, item: ObservationInput):
        if self.observations is None:
            raise RuntimeError("Observation repository is not configured")
        if self.observation_pipeline is not None:
            return self.observation_pipeline.ingest(scan_id, [item])[0]
        return Observer(self.observations, self.orchestrator.scans, self.targets).ingest(scan_id, item)

    def think(self, scan_id: int) -> ReasoningCycle:
        missing = [
            name for name, value in (
                ("observations", self.observations),
                ("hypotheses", self.hypotheses),
                ("decisions", self.decisions),
                ("context_builder", self.context_builder),
            ) if value is None
        ]
        if missing:
            raise RuntimeError(f"Brain repositories/components are missing: {', '.join(missing)}")
        context: AgentContext = self.context_builder.build(scan_id)
        if self.reasoning_engine is not None:
            reasoning = self.reasoning_engine.generate(context)
            ranked = list(reasoning.hypotheses)
            plans = list(reasoning.actions) if reasoning.actions else self.planner.plan(context, ranked)
        else:
            ranked = self.prioritizer.rank(self.hypothesis_engine.generate(context))
            plans = self.planner.plan(context, ranked)
        persisted_by_statement = {}
        for proposal in ranked:
            persisted_by_statement[proposal.statement] = self.hypotheses.create(
                scan_id,
                proposal.statement,
                proposal.basis_observation_ids,
                proposal.confidence,
            )
        results = []
        for proposal in plans:
            result = self.decision_engine.evaluate(proposal, expected_target=context.target)
            results.append(result)
            if result.accepted:
                hypothesis = persisted_by_statement.get(proposal.action_payload.get("hypothesis"))
                self.decisions.create(
                    scan_id,
                    hypothesis.id if hypothesis else None,
                    proposal.action_kind,
                    proposal.action_payload,
                    proposal.rationale,
                    proposal.confidence,
                    proposal.risk_level,
                    proposal.requires_approval,
                    result.status,
                )
        return ReasoningCycle(context, tuple(ranked), tuple(results))

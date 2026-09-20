from __future__ import annotations

from beltu.storage.models.brain import Decision, Hypothesis, Observation
from beltu.storage.repositories.decision_repository import DecisionRepository
from beltu.storage.repositories.hypothesis_repository import HypothesisRepository
from beltu.storage.repositories.observation_repository import ObservationRepository


class AgentMemory:
    def __init__(
        self,
        observations: ObservationRepository,
        hypotheses: HypothesisRepository,
        decisions: DecisionRepository,
    ) -> None:
        self.observations = observations
        self.hypotheses = hypotheses
        self.decisions = decisions

    def observations_for(self, scan_id: int) -> list[Observation]:
        return self.observations.list_for_scan(scan_id)

    def hypotheses_for(self, scan_id: int) -> list[Hypothesis]:
        return self.hypotheses.list_for_scan(scan_id)

    def decisions_for(self, scan_id: int) -> list[Decision]:
        return self.decisions.list_for_scan(scan_id)

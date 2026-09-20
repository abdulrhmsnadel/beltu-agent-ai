from __future__ import annotations

from typing import Any, Iterable

from beltu.analysis.correlator import ObservationCorrelator
from beltu.brain.observer import Observer
from beltu.brain.schemas import ObservationInput
from beltu.storage.models.brain import Observation


class ObservationPipeline:
    """Ingest normalized observations, attach evidence references, and correlate them."""

    def __init__(self, observer: Observer, correlator: ObservationCorrelator) -> None:
        self.observer = observer
        self.correlator = correlator

    def ingest(
        self,
        scan_id: int,
        items: Iterable[ObservationInput],
        *,
        evidence_ids: tuple[int, ...] = (),
    ) -> list[Observation]:
        existing = list(self.observer.observations.list_for_scan(scan_id))
        stored: list[Observation] = []
        for item in items:
            data: dict[str, Any] = dict(item.data)
            if evidence_ids:
                data.setdefault("evidence_ids", list(evidence_ids))
            observation = self.observer.ingest(
                scan_id,
                ObservationInput(item.kind, item.subject, data, item.source, item.confidence),
            )
            self.correlator.correlate(observation, existing)
            existing.append(observation)
            stored.append(observation)
        return stored

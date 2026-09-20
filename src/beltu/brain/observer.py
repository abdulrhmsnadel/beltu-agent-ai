from __future__ import annotations

from beltu.brain.schemas import ObservationInput
from beltu.common.types import Scan
from beltu.storage.models.brain import Observation
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository


class Observer:
    """Turns external evidence into normalized, persistent observations."""

    def __init__(
        self,
        observations: ObservationRepository,
        scans: ScanRepository,
        targets: TargetRepository,
    ) -> None:
        self.observations = observations
        self.scans = scans
        self.targets = targets

    def ingest(self, scan_id: int, item: ObservationInput) -> Observation:
        if not item.kind.strip() or not item.subject.strip() or not item.source.strip():
            raise ValueError("Observation kind, subject and source are required")
        scan = self.scans.get(scan_id)
        if scan is None:
            raise ValueError(f"Scan #{scan_id} not found")
        target = self.targets.get(scan.target_id)
        if target is None:
            raise ValueError(f"Target #{scan.target_id} not found")
        return self.observations.add(
            scan_id,
            item.kind.strip(),
            item.subject.strip(),
            dict(item.data),
            item.source.strip(),
            item.confidence,
        )

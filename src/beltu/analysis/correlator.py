from __future__ import annotations

from urllib.parse import urlparse

from beltu.brain.schemas import ObservationInput
from beltu.storage.models.brain import Observation
from beltu.storage.repositories.observation_link_repository import ObservationLinkRepository


class ObservationCorrelator:
    """Create deterministic, explainable links between observations; no LLM required."""

    def __init__(self, links: ObservationLinkRepository) -> None:
        self.links = links

    def correlate(self, observation: Observation, existing: list[Observation]) -> list[tuple[int, str, float]]:
        results: list[tuple[int, str, float]] = []
        subject = observation.subject.strip().lower()
        def host_of(value: str) -> str:
            value = value.strip()
            candidate = value if "://" in value else f"//{value}"
            return (urlparse(candidate).hostname or "").lower()

        host = host_of(observation.subject)
        for other in existing:
            if other.id == observation.id or other.scan_id != observation.scan_id:
                continue
            other_subject = other.subject.strip().lower()
            score = 0.0
            relation = "related"
            if subject == other_subject:
                score, relation = 1.0, "same_subject"
            elif host and host == host_of(other.subject):
                score, relation = 0.9, "same_host"
            elif subject and (subject in other_subject or other_subject in subject):
                score, relation = 0.7, "subject_overlap"
            elif observation.kind.startswith("finding.") and other.kind.startswith("web."):
                score, relation = 0.55, "finding_from_web_observation"
            if score:
                self.links.upsert(observation.scan_id, observation.id, other.id, relation, score)
                results.append((other.id, relation, score))
        return results

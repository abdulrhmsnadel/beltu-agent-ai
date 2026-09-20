from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from beltu.storage.models.brain import Observation


@dataclass(frozen=True, slots=True)
class GraphSnapshot:
    nodes: tuple[str, ...]
    edges: tuple[tuple[str, str, str], ...]


class AttackSurfaceGraph:
    """Dependency-free graph for reasoning context; it does not execute actions."""

    def build(self, observations: Iterable[Observation]) -> GraphSnapshot:
        nodes: set[str] = set()
        edges: set[tuple[str, str, str]] = set()
        for obs in observations:
            subject = obs.subject.strip()
            if subject:
                nodes.add(subject)
            related = obs.data.get("related_to")
            if isinstance(related, str) and related.strip() and subject:
                nodes.add(related.strip())
                edges.add((related.strip(), subject, obs.kind))
            for item in obs.data.get("children", []) if isinstance(obs.data.get("children"), list) else []:
                if isinstance(item, str) and item.strip() and subject:
                    nodes.add(item.strip())
                    edges.add((subject, item.strip(), obs.kind))
        return GraphSnapshot(tuple(sorted(nodes)), tuple(sorted(edges)))

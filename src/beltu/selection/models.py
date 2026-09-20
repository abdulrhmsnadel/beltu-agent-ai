from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class CapabilityProfile:
    name: str
    description: str
    base_cost: float
    expected_gain: float
    risk_level: str
    requires_approval: bool
    required_kinds: frozenset[str] = frozenset()
    blocked_by_kinds: frozenset[str] = frozenset()
    produced_kinds: frozenset[str] = frozenset()
    enabled: bool = True
    external: bool = True
    preferred_tools: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CapabilityCandidate:
    profile: CapabilityProfile
    score: float
    expected_information_gain: float
    cost: float
    rationale: str
    tool: str | None = None
    tool_score: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "capability": self.profile.name,
            "tool": self.tool,
            "score": round(self.score, 4),
            "expected_information_gain": round(self.expected_information_gain, 4),
            "cost": round(self.cost, 4),
            "risk_level": self.profile.risk_level,
            "requires_approval": self.profile.requires_approval,
            "rationale": self.rationale,
        }

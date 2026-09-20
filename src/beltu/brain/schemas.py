from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


ALLOWED_ACTIONS = frozenset({
    "surface_inventory",
    "service_enrichment",
    "endpoint_mapping",
    "api_analysis",
    "auth_analysis",
    "access_control_analysis",
    "business_logic_analysis",
    "finding_validation",
})

RISK_LEVELS = frozenset({"low", "medium", "high"})


@dataclass(frozen=True, slots=True)
class ObservationInput:
    kind: str
    subject: str
    data: dict[str, Any]
    source: str
    confidence: float = 1.0


@dataclass(frozen=True, slots=True)
class AgentContext:
    scan_id: int
    target: str
    observations: tuple[dict[str, Any], ...] = ()
    known_hypotheses: tuple[dict[str, Any], ...] = ()
    graph_nodes: tuple[str, ...] = ()
    graph_edges: tuple[tuple[str, str, str], ...] = ()
    assets: tuple[dict[str, Any], ...] = ()
    asset_edges: tuple[tuple[str, str, str], ...] = ()
    asset_summary: dict[str, int] = field(default_factory=dict)
    surface_priorities: tuple[dict[str, Any], ...] = ()
    api_surface: dict[str, Any] = field(default_factory=dict)
    auth_surface: dict[str, Any] = field(default_factory=dict)
    authorization_surface: dict[str, Any] = field(default_factory=dict)
    business_logic_surface: dict[str, Any] = field(default_factory=dict)
    finding_surface: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class HypothesisProposal:
    statement: str
    basis_observation_ids: tuple[int, ...]
    confidence: float


@dataclass(frozen=True, slots=True)
class ActionProposal:
    action_kind: str
    action_payload: dict[str, Any]
    rationale: str
    confidence: float
    risk_level: str = "low"
    requires_approval: bool = False


@dataclass(frozen=True, slots=True)
class DecisionResult:
    accepted: bool
    status: str
    reason: str
    proposal: ActionProposal


@dataclass(frozen=True, slots=True)
class ReasoningCycle:
    context: AgentContext
    hypotheses: tuple[HypothesisProposal, ...]
    decisions: tuple[DecisionResult, ...]

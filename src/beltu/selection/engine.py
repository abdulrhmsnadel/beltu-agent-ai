from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from beltu.brain.schemas import ActionProposal, AgentContext
from beltu.execution.registry.capability_registry import CapabilityRegistry
from beltu.selection.models import CapabilityCandidate, CapabilityProfile


ACTION_TO_CAPABILITY = {
    "surface_inventory": "asset.discovery.subdomains",
    "service_enrichment": "service.discovery",
    "endpoint_mapping": "web.verify",
    "api_analysis": "offline.api.structure_analysis",
    "auth_analysis": "offline.auth.surface_analysis",
    "access_control_analysis": "offline.authorization.matrix_analysis",
    "business_logic_analysis": "offline.business_logic.workflow_analysis",
    "finding_validation": "offline.finding.validation",
}


DEFAULT_PROFILES: tuple[CapabilityProfile, ...] = (
    CapabilityProfile(
        "asset.discovery.subdomains",
        "Discover additional scoped subdomains and asset names.",
        0.18, 0.78, "low", False,
        required_kinds=frozenset(),
        blocked_by_kinds=frozenset({"asset.subdomain"}),
        produced_kinds=frozenset({"asset.subdomain"}),
        external=True,
        preferred_tools=("subfinder", "assetfinder", "amass-passive"),
    ),
    CapabilityProfile(
        "web.verify",
        "Verify web reachability and collect structured HTTP metadata.",
        0.32, 0.72, "medium", True,
        required_kinds=frozenset({"asset.subdomain", "endpoint", "api_endpoint"}),
        produced_kinds=frozenset({"web.http_probe"}),
        external=True,
        preferred_tools=("httpx",),
    ),
    CapabilityProfile(
        "service.discovery",
        "Characterize exposed network services for an already identified host.",
        0.46, 0.66, "medium", True,
        required_kinds=frozenset({"asset.subdomain"}),
        produced_kinds=frozenset({"service.scan_output"}),
        external=True,
        preferred_tools=("nmap",),
    ),
    CapabilityProfile(
        "web.vulnerability_detection",
        "Run a bounded vulnerability-detection pass over already verified web surface.",
        0.78, 0.58, "high", True,
        required_kinds=frozenset({"web.http_probe"}),
        produced_kinds=frozenset({"finding.candidate"}),
        external=True,
        preferred_tools=("nuclei",),
    ),
    CapabilityProfile(
        "offline.endpoint.classification",
        "Classify and prioritize endpoint observations without external traffic.",
        0.08, 0.42, "low", False,
        required_kinds=frozenset({"endpoint", "api_endpoint"}),
        produced_kinds=frozenset({"endpoint.classification"}),
        external=False,
    ),
    CapabilityProfile(
        "offline.api.structure_analysis",
        "Analyze API structure and control boundaries from existing evidence.",
        0.10, 0.64, "low", False,
        required_kinds=frozenset({"api", "api_endpoint", "openapi", "web.http_probe"}),
        produced_kinds=frozenset({"api.analysis"}),
        external=False,
    ),
    CapabilityProfile(
        "offline.auth.surface_analysis",
        "Analyze authentication/session observations without generating new traffic.",
        0.11, 0.61, "low", False,
        required_kinds=frozenset({"login", "auth", "session"}),
        produced_kinds=frozenset({"auth.analysis"}),
        external=False,
    ),
    CapabilityProfile(
        "offline.access_control.surface_analysis",
        "Correlate authorization and role evidence from existing observations.",
        0.11, 0.67, "low", False,
        required_kinds=frozenset({"access_control", "role", "authorization"}),
        produced_kinds=frozenset({"access_control.analysis"}),
        external=False,
    ),
    CapabilityProfile(
        "offline.authorization.matrix_analysis",
        "Build and review the authorization matrix from stored API/auth evidence without generating traffic.",
        0.07, 0.78, "low", False,
        required_kinds=frozenset(),
        produced_kinds=frozenset({"authorization.analysis"}),
        external=False,
    ),
    CapabilityProfile(
        "offline.business_logic.workflow_analysis",
        "Analyze workflow/state evidence already collected by the agent.",
        0.13, 0.69, "low", False,
        required_kinds=frozenset({"workflow", "state_transition", "order", "cart"}),
        produced_kinds=frozenset({"business_logic.analysis"}),
        external=False,
    ),
    CapabilityProfile(
        "offline.finding.correlation",
        "Correlate stored finding signals into candidate findings without target traffic.",
        0.06, 0.81, "low", False,
        required_kinds=frozenset(), produced_kinds=frozenset({"finding.candidate"}), external=False,
    ),
    CapabilityProfile(
        "offline.finding.validation",
        "Cross-check an existing candidate finding against stored evidence.",
        0.09, 0.73, "low", False,
        required_kinds=frozenset({"finding.candidate"}),
        produced_kinds=frozenset({"finding.validation"}),
        external=False,
    ),
)


@dataclass(frozen=True, slots=True)
class SelectionDecision:
    candidates: tuple[CapabilityCandidate, ...]
    selected: CapabilityCandidate | None

    @property
    def selected_capability(self) -> str | None:
        return self.selected.profile.name if self.selected else None


class IntelligentCapabilitySelector:
    """Rank capabilities by evidence fit, expected information gain, cost, and risk.

    Selection is declarative only: no process is launched here.
    """

    def __init__(
        self,
        registry: CapabilityRegistry | None = None,
        profiles: Iterable[CapabilityProfile] = DEFAULT_PROFILES,
    ) -> None:
        self.registry = registry
        self.profiles = tuple(profiles)

    @staticmethod
    def _kind_counts(context: AgentContext) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in context.observations:
            kind = str(item.get("kind", ""))
            counts[kind] = counts.get(kind, 0) + 1
        return counts

    def _tool_fit(self, profile: CapabilityProfile) -> tuple[str | None, float, str]:
        if not profile.external or self.registry is None:
            return None, 0.0, "internal capability"
        candidates = []
        try:
            candidates = self.registry.tools.for_capability(profile.name)
        except Exception:
            candidates = []
        if not candidates:
            return None, -0.25, "no registered adapter"
        preferred = {name: idx for idx, name in enumerate(profile.preferred_tools)}
        best = min(candidates, key=lambda item: (preferred.get(item.name, 999), item.risk_level != profile.risk_level))
        preference_bonus = 0.15 if best.name in preferred else 0.0
        return best.name, 0.35 + preference_bonus, f"adapter={best.name}"

    def score_profile(self, context: AgentContext, profile: CapabilityProfile) -> CapabilityCandidate | None:
        if not profile.enabled:
            return None
        counts = self._kind_counts(context)
        present = set(counts)
        structured_fit = False
        if profile.name == "offline.finding.correlation":
            summary=context.finding_surface.get("summary", {}) if isinstance(context.finding_surface,dict) else {}
            structured_fit=isinstance(summary,dict) and int(summary.get("findings",0) or 0)>0
        if profile.name == "offline.business_logic.workflow_analysis":
            summary = context.business_logic_surface.get("summary", {}) if isinstance(context.business_logic_surface, dict) else {}
            structured_fit = isinstance(summary, dict) and int(summary.get("workflows", 0) or 0) > 0
        if profile.required_kinds and not (profile.required_kinds & present) and not structured_fit:
            return None
        blocked = profile.blocked_by_kinds & present
        if blocked:
            return None
        tool, tool_score, tool_note = self._tool_fit(profile)
        if profile.external and tool is None:
            return None

        novelty = 1.0
        if profile.produced_kinds & present:
            novelty = 0.35
        relevance = min(1.0, 0.25 + 0.15 * sum(counts.get(kind, 0) > 0 for kind in profile.required_kinds))
        info_gain = min(1.0, profile.expected_gain * novelty * (0.65 + 0.35 * relevance))
        cost_penalty = min(1.0, profile.base_cost)
        risk_penalty = {"low": 0.0, "medium": 0.08, "high": 0.18}.get(profile.risk_level, 0.25)
        approval_penalty = 0.05 if profile.requires_approval else 0.0
        surface_bonus = 0.0
        if context.surface_priorities:
            top = context.surface_priorities[0]
            surface_bonus = min(0.06, float(top.get("score", 0.0)) * 0.06)
        authorization_bonus = 0.0
        authz_summary = context.authorization_surface.get("summary", {}) if isinstance(context.authorization_surface, dict) else {}
        authz_anomalies = int(authz_summary.get("anomalies", 0) or 0) if isinstance(authz_summary, dict) else 0
        if profile.name == "offline.authorization.matrix_analysis":
            authorization_bonus = min(0.12, 0.04 + 0.02 * min(authz_anomalies, 4))
        finding_bonus=0.0
        fs=context.finding_surface.get("summary", {}) if isinstance(context.finding_surface,dict) else {}
        fc=int(fs.get("findings",0) or 0) if isinstance(fs,dict) else 0
        if profile.name == "offline.finding.correlation" and fc:
            finding_bonus=min(0.14,0.04+0.02*min(fc,5))
        if profile.name == "offline.finding.validation" and fc:
            finding_bonus=min(0.10,0.03+0.015*min(fc,5))
        business_logic_bonus = 0.0
        business_summary = context.business_logic_surface.get("summary", {}) if isinstance(context.business_logic_surface, dict) else {}
        workflow_count = int(business_summary.get("workflows", 0) or 0) if isinstance(business_summary, dict) else 0
        anomaly_count = int(business_summary.get("anomalies", 0) or 0) if isinstance(business_summary, dict) else 0
        if profile.name == "offline.business_logic.workflow_analysis" and (workflow_count or anomaly_count):
            business_logic_bonus = min(0.12, 0.03 + 0.015 * min(workflow_count + anomaly_count, 6))
        api_bonus = 0.0
        api_summary = context.api_surface.get("summary", {}) if isinstance(context.api_surface, dict) else {}
        api_ops = int(api_summary.get("operations", 0) or 0) if isinstance(api_summary, dict) else 0
        if profile.name == "offline.api.structure_analysis" and api_ops:
            api_bonus = min(0.08, 0.02 + 0.01 * min(api_ops, 6))
        if profile.name == "offline.auth.surface_analysis" and isinstance(api_summary, dict) and int(api_summary.get("protected_operations", 0) or 0):
            api_bonus = min(0.08, 0.03 + 0.01 * min(int(api_summary.get("protected_operations", 0) or 0), 5))
        score = max(0.0, min(1.0, 0.58 * info_gain + 0.22 * tool_score + 0.20 * (1.0 - cost_penalty) - risk_penalty - approval_penalty + surface_bonus + api_bonus + authorization_bonus + business_logic_bonus + finding_bonus))
        rationale = (
            f"required evidence present; expected information gain={info_gain:.2f}; "
            f"estimated cost={profile.base_cost:.2f}; risk={profile.risk_level}; "
            f"surface_bonus={surface_bonus:.2f}; api_bonus={api_bonus:.2f}; authorization_bonus={authorization_bonus:.2f}; business_logic_bonus={business_logic_bonus:.2f}; finding_bonus={finding_bonus:.2f}; {tool_note}"
        )
        return CapabilityCandidate(profile, score, info_gain, profile.base_cost, rationale, tool, tool_score)

    def select(
        self,
        context: AgentContext,
        *,
        preferred_capability: str | None = None,
        executable_only: bool = False,
    ) -> SelectionDecision:
        candidates: list[CapabilityCandidate] = []
        for profile in self.profiles:
            if preferred_capability and profile.name != preferred_capability:
                continue
            if executable_only and not profile.external:
                continue
            candidate = self.score_profile(context, profile)
            if candidate is not None:
                candidates.append(candidate)
        candidates.sort(key=lambda item: (item.score, item.expected_information_gain, -item.cost), reverse=True)
        return SelectionDecision(tuple(candidates), candidates[0] if candidates else None)

    def select_for_action(
        self,
        context: AgentContext,
        action: ActionProposal,
        *,
        executable_only: bool = True,
    ) -> SelectionDecision:
        preferred = ACTION_TO_CAPABILITY.get(action.action_kind)
        decision = self.select(context, preferred_capability=preferred, executable_only=executable_only)
        if decision.selected is not None:
            return decision
        return self.select(context, executable_only=executable_only)

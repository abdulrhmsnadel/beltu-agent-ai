from __future__ import annotations

from beltu.brain.attack_graph import AttackSurfaceGraph
from beltu.brain.context_security import ContextSecurityBoundary
from beltu.brain.schemas import AgentContext
from beltu.storage.repositories.hypothesis_repository import HypothesisRepository
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository
from beltu.intelligence.service import AssetIntelligenceService
from beltu.intelligence.prioritizer import SurfacePrioritizer
from beltu.api_intelligence.service import ApiIntelligenceService
from beltu.auth_intelligence.service import AuthIntelligenceService
from beltu.access_control.service import AccessControlIntelligenceService
from beltu.business_logic.service import BusinessLogicIntelligenceService
from beltu.analysis.finding_intelligence import FindingIntelligenceService


class ContextBuilder:
    def __init__(
        self,
        scans: ScanRepository,
        targets: TargetRepository,
        observations: ObservationRepository,
        hypotheses: HypothesisRepository,
        graph: AttackSurfaceGraph,
        asset_intelligence: AssetIntelligenceService | None = None,
        surface_intelligence: SurfacePrioritizer | None = None,
        api_intelligence: ApiIntelligenceService | None = None,
        auth_intelligence: AuthIntelligenceService | None = None,
        authorization_intelligence: AccessControlIntelligenceService | None = None,
        business_logic_intelligence: BusinessLogicIntelligenceService | None = None,
        finding_intelligence: FindingIntelligenceService | None = None,
        context_security: ContextSecurityBoundary | None = None,
    ) -> None:
        self.scans = scans
        self.targets = targets
        self.observations = observations
        self.hypotheses = hypotheses
        self.graph = graph
        self.asset_intelligence = asset_intelligence
        self.surface_intelligence = surface_intelligence
        self.api_intelligence = api_intelligence
        self.auth_intelligence = auth_intelligence
        self.authorization_intelligence = authorization_intelligence
        self.business_logic_intelligence = business_logic_intelligence
        self.finding_intelligence = finding_intelligence
        self.context_security = context_security or ContextSecurityBoundary()

    def build(self, scan_id: int) -> AgentContext:
        scan = self.scans.get(scan_id)
        if scan is None:
            raise ValueError(f"Scan #{scan_id} not found")
        target = self.targets.get(scan.target_id)
        if target is None:
            raise ValueError(f"Target #{scan.target_id} not found")
        observations = self.observations.list_for_scan(scan_id)
        hypotheses = self.hypotheses.list_for_scan(scan_id)
        graph = self.graph.build(observations)
        obs_payload = tuple(
            {
                "id": obs.id,
                "kind": obs.kind,
                "subject": obs.subject,
                "data": obs.data,
                "source": obs.source,
                "confidence": obs.confidence,
            }
            for obs in observations
        )
        hyp_payload = tuple(
            {
                "id": hyp.id,
                "statement": hyp.statement,
                "basis_observation_ids": hyp.basis_observation_ids,
                "confidence": hyp.confidence,
                "status": hyp.status,
            }
            for hyp in hypotheses
        )
        asset_payload = {}
        if self.asset_intelligence is not None:
            asset_payload = self.asset_intelligence.context_payload(scan_id)
        surface_payload = {}
        if self.surface_intelligence is not None:
            surface_payload = self.surface_intelligence.context_payload(scan_id, limit=20)
        api_payload = {}
        if self.api_intelligence is not None:
            api_payload = self.api_intelligence.context_payload(scan_id, limit=200)
        auth_payload = {}
        if self.auth_intelligence is not None:
            auth_payload = self.auth_intelligence.context_payload(scan_id, limit=100)
        authorization_payload = {}
        if self.authorization_intelligence is not None:
            authorization_payload = self.authorization_intelligence.context_payload(scan_id, limit=200)
        business_logic_payload = {}
        if self.business_logic_intelligence is not None:
            business_logic_payload = self.business_logic_intelligence.context_payload(scan_id, limit=100)
        finding_payload = {}
        if self.finding_intelligence is not None:
            finding_payload = self.finding_intelligence.context_payload(scan_id, limit=100)
        raw_context = AgentContext(
            scan_id=scan_id,
            target=target.value,
            observations=obs_payload,
            known_hypotheses=hyp_payload,
            graph_nodes=graph.nodes,
            graph_edges=graph.edges,
            assets=tuple(asset_payload.get("assets", [])),
            asset_edges=tuple(tuple(x) for x in asset_payload.get("relations", [])),
            asset_summary=dict(asset_payload.get("summary", {})),
            surface_priorities=tuple(surface_payload.get("priorities", [])),
            api_surface=dict(api_payload),
            auth_surface=dict(auth_payload),
            authorization_surface=dict(authorization_payload),
            business_logic_surface=dict(business_logic_payload),
            finding_surface=dict(finding_payload),
        )
        # Mandatory trust boundary: no raw observation/intelligence text leaves
        # ContextBuilder for the reasoning layer.
        return self.context_security.sanitize(raw_context)

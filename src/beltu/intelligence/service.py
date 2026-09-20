from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from beltu.brain.schemas import ObservationInput
from beltu.intelligence.graph import AssetGraphBuilder, AssetGraphSnapshot
from beltu.intelligence.normalizer import extract_observation, host_from_url, normalize_host
from beltu.storage.database import Database
from beltu.storage.models.asset import Asset
from beltu.storage.repositories.asset_repository import AssetRepository
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository

@dataclass(frozen=True, slots=True)
class InventoryResult:
    assets: tuple[Asset, ...]
    summary: dict[str, int]
    graph: AssetGraphSnapshot

class AssetIntelligenceService:
    """Build a persistent, observation-derived attack-surface inventory.

    This stage is read/normalize/store only. It does not initiate network activity.
    """

    def __init__(self, db: Database) -> None:
        self.db = db
        self.assets = AssetRepository(db)
        self.observations = ObservationRepository(db)
        self.scans = ScanRepository(db)
        self.targets = TargetRepository(db)
        self.graph_builder = AssetGraphBuilder()

    def rebuild(self, scan_id: int) -> InventoryResult:
        scan = self.scans.get(scan_id)
        if scan is None:
            raise ValueError(f"Scan #{scan_id} not found")
        target_obj = self.targets.get(scan.target_id)
        if target_obj is None:
            raise ValueError(f"Target #{scan.target_id} not found")
        target_host = normalize_host(target_obj.value) or target_obj.value.strip().lower()

        for observation in self.observations.list_for_scan(scan_id):
            asset_candidates, service_candidates, endpoint_candidates, tech_candidates = extract_observation(observation, target_host)
            asset_by_host: dict[str, Asset] = {}
            for candidate in asset_candidates:
                asset = self.assets.upsert_asset(
                    scan_id, scan.target_id, candidate.asset_type, candidate.value, candidate.normalized_value,
                    candidate.source, candidate.confidence, candidate.metadata,
                )
                asset_by_host[candidate.normalized_value] = asset
            for service in service_candidates:
                asset = self.assets.find(scan_id, service.host)
                if asset:
                    self.assets.upsert_service(scan_id, asset.id, service.transport, service.port, service.state, service.service, service.product, service.version, service.source, service.confidence, service.metadata)
            for endpoint in endpoint_candidates:
                asset = self.assets.find(scan_id, endpoint.host)
                if asset:
                    self.assets.upsert_endpoint(scan_id, asset.id, endpoint.url, endpoint.method, endpoint.path, endpoint.endpoint_type, endpoint.auth_hint, endpoint.source, endpoint.confidence, endpoint.metadata)
            for technology in tech_candidates:
                if not technology.host:
                    continue
                asset = self.assets.find(scan_id, technology.host)
                if asset:
                    self.assets.upsert_technology(scan_id, asset.id, technology.name, technology.version, technology.category, technology.source, technology.confidence, technology.metadata)

        self._build_parent_relations(scan_id, target_host)
        assets = self.assets.list_for_scan(scan_id)
        relations = self.assets.relations_for_scan(scan_id)
        graph = self.graph_builder.build(assets, relations)
        return InventoryResult(tuple(assets), self.assets.summary(scan_id), graph)

    def _build_parent_relations(self, scan_id: int, target_host: str) -> None:
        assets = self.assets.list_for_scan(scan_id)
        by_value = {a.normalized_value: a for a in assets}
        root = by_value.get(target_host)
        if root is None:
            # Root is useful even before subdomains are seen, so materialize the registered target.
            scan = self.scans.get(scan_id)
            if scan is None:
                return
            target = self.targets.get(scan.target_id)
            if target is None:
                return
            root = self.assets.upsert_asset(scan_id, scan.target_id, 'domain', target.value.strip().lower().rstrip('.'), target.value.strip().lower().rstrip('.'), 'registered_target', 1.0, {'registered': True})
            by_value[root.normalized_value] = root

        for asset in list(by_value.values()):
            if asset.id == root.id or asset.asset_type == 'ip':
                continue
            host = asset.normalized_value
            if host.endswith('.' + root.normalized_value):
                parent_label = host[len(host) - len(root.normalized_value) - 1 : -len(root.normalized_value) - 1]
                parent_host = parent_label.rsplit('.', 1)[-1] + '.' + root.normalized_value if '.' in parent_label else root.normalized_value
                parent = by_value.get(parent_host, root)
                self.assets.add_relation(scan_id, parent.id, asset.id, 'subdomain_of', min(parent.confidence, asset.confidence))
            elif host == root.normalized_value:
                continue

    def context_payload(self, scan_id: int) -> dict[str, Any]:
        result = self.rebuild(scan_id)
        services = self.assets.list_services(scan_id)
        endpoints = self.assets.list_endpoints(scan_id)
        technologies = self.assets.list_technologies(scan_id)
        return {
            'summary': result.summary,
            'assets': [self._asset_payload(a) for a in result.assets],
            'relations': [list(edge) for edge in result.graph.edges],
            'services': [
                {'asset_id': s.asset_id, 'transport': s.transport, 'port': s.port, 'state': s.state, 'service': s.service, 'product': s.product, 'version': s.version, 'source': s.source, 'confidence': s.confidence}
                for s in services
            ],
            'endpoints': [
                {'asset_id': e.asset_id, 'url': e.url, 'method': e.method, 'path': e.path, 'endpoint_type': e.endpoint_type, 'auth_hint': e.auth_hint, 'source': e.source, 'confidence': e.confidence}
                for e in endpoints
            ],
            'technologies': [
                {'asset_id': t.asset_id, 'name': t.name, 'version': t.version, 'category': t.category, 'source': t.source, 'confidence': t.confidence}
                for t in technologies
            ],
        }

    @staticmethod
    def _asset_payload(asset: Asset) -> dict[str, Any]:
        return {'id': asset.id, 'type': asset.asset_type, 'value': asset.value, 'normalized_value': asset.normalized_value, 'status': asset.status, 'source': asset.source, 'confidence': asset.confidence, 'metadata': asset.metadata}

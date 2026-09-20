from __future__ import annotations

from pathlib import Path

from beltu.brain.schemas import ObservationInput
from beltu.intelligence.normalizer import extract_observation, normalize_host
from beltu.intelligence.service import AssetIntelligenceService
from beltu.storage.database import Database
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository
from beltu.common.enums import ScanStatus

def make_db(tmp_path: Path):
    db = Database(tmp_path / 'beltu.db')
    db.initialize()
    return db

def test_normalize_host_and_parse_subdomain():
    assert normalize_host('API.Example.COM.') == 'api.example.com'
    assets, _, _, _ = extract_observation(
        ObservationInput('asset.subdomain', 'api.example.com', {}, 'subfinder', 0.9),
        'example.com',
    )
    assert assets[0].asset_type == 'subdomain'
    assert assets[0].normalized_value == 'api.example.com'

def test_http_observation_extracts_endpoint_and_tech():
    obs = ObservationInput(
        'web.http_probe', 'https://api.example.com/login',
        {'structured': {'url': 'https://api.example.com/login', 'status_code': 200, 'technologies': ['nginx', 'FastAPI'], 'server': 'nginx/1.25.2'}},
        'httpx', 0.85,
    )
    assets, services, endpoints, techs = extract_observation(obs, 'example.com')
    assert assets[0].normalized_value == 'api.example.com'
    assert endpoints[0].path == '/login'
    assert {t.name for t in techs} >= {'nginx', 'FastAPI'}
    assert services == []

def test_nmap_like_service_is_normalized():
    obs = ObservationInput(
        'service.scan_output', '443/tcp open https nginx 1.25.2',
        {'raw': '443/tcp open https nginx 1.25.2', 'host': 'api.example.com'},
        'nmap', 0.8,
    )
    assets, services, _, _ = extract_observation(obs, 'example.com')
    assert assets[0].normalized_value == 'api.example.com'
    assert services[0].port == 443
    assert services[0].service == 'https'
    assert services[0].version == '1.25.2'

def test_inventory_is_idempotent_and_builds_parent_relation(tmp_path: Path):
    db = make_db(tmp_path)
    targets = TargetRepository(db)
    scans = ScanRepository(db)
    target = targets.add('example.com')
    scan = scans.create(target.id, ScanStatus.PENDING)
    observations = ObservationRepository(db)
    observations.add(scan.id, 'asset.subdomain', 'api.example.com', {}, 'subfinder', 0.9)
    observations.add(scan.id, 'web.http_probe', 'https://api.example.com/login', {'structured': {'url': 'https://api.example.com/login', 'technologies': ['FastAPI']}}, 'httpx', 0.85)

    service = AssetIntelligenceService(db)
    first = service.rebuild(scan.id)
    second = service.rebuild(scan.id)

    assert first.summary == second.summary
    assert any(a.normalized_value == 'example.com' for a in second.assets)
    assert any(a.normalized_value == 'api.example.com' for a in second.assets)
    assert any(edge[2] == 'subdomain_of' for edge in second.graph.edges)
    assert second.summary['endpoints'] == 1
    assert second.summary['technologies'] >= 1

def test_context_includes_asset_inventory(tmp_path: Path):
    db = make_db(tmp_path)
    targets = TargetRepository(db)
    scans = ScanRepository(db)
    target = targets.add('example.com')
    scan = scans.create(target.id, ScanStatus.PENDING)
    ObservationRepository(db).add(scan.id, 'asset.subdomain', 'shop.example.com', {}, 'manual', 1.0)
    service = AssetIntelligenceService(db)
    payload = service.context_payload(scan.id)
    assert payload['summary']['assets'] >= 2
    assert any(a['normalized_value'] == 'shop.example.com' for a in payload['assets'])

from pathlib import Path
from beltu.brain.schemas import ObservationInput
from beltu.intelligence.service import AssetIntelligenceService
from beltu.intelligence.prioritizer import SurfacePrioritizer
from beltu.selection.engine import IntelligentCapabilitySelector
from beltu.storage.database import Database
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository
from beltu.common.enums import ScanStatus

def make_db(tmp_path: Path):
    db=Database(tmp_path/'beltu.db'); db.initialize(); return db

def seed(tmp_path: Path):
    db=make_db(tmp_path); t=TargetRepository(db).add('example.com'); scan=ScanRepository(db).create(t.id, ScanStatus.PENDING); obs=ObservationRepository(db)
    obs.add(scan.id,'asset.subdomain','api.example.com',{},'subfinder',.9)
    obs.add(scan.id,'web.http_probe','https://api.example.com/login',{'structured':{'url':'https://api.example.com/login','technologies':['FastAPI']}},'httpx',.9)
    obs.add(scan.id,'endpoint','https://api.example.com/admin','{"structured": {}}','manual',.95) if False else None
    obs.add(scan.id,'endpoint','https://api.example.com/admin',{'structured':{'url':'https://api.example.com/admin','method':'POST'}},'crawler',.95)
    obs.add(scan.id,'service.scan_output','443/tcp open https nginx 1.25.2',{'raw':'443/tcp open https nginx 1.25.2','host':'api.example.com'},'nmap',.9)
    return db,scan

def test_surface_priorities_are_persistent_and_explainable(tmp_path: Path):
    db,scan=seed(tmp_path); svc=SurfacePrioritizer(db)
    first=svc.rebuild(scan.id); second=svc.rebuild(scan.id)
    assert first.summary['total'] >= 4
    assert first.summary == second.summary
    assert any(r.entity_type=='endpoint' and r.priority in {'P1','P2'} for r in first.priorities)
    assert any('path' in r.rationale or 'Endpoint' in r.rationale for r in first.priorities)
    rows=svc.repo.list_for_scan(scan.id)
    assert len(rows)==len(first.priorities)

def test_context_carries_surface_priorities(tmp_path: Path):
    db,scan=seed(tmp_path); from beltu.brain.context_builder import ContextBuilder
    from beltu.brain.attack_graph import AttackSurfaceGraph
    from beltu.storage.repositories.hypothesis_repository import HypothesisRepository
    ctx=ContextBuilder(ScanRepository(db),TargetRepository(db),ObservationRepository(db),HypothesisRepository(db),AttackSurfaceGraph(),AssetIntelligenceService(db),SurfacePrioritizer(db)).build(scan.id)
    assert ctx.surface_priorities
    assert 'priority' in ctx.surface_priorities[0]

def test_selector_uses_surface_signal(tmp_path: Path):
    db,scan=seed(tmp_path); from beltu.brain.context_builder import ContextBuilder
    from beltu.brain.attack_graph import AttackSurfaceGraph
    from beltu.storage.repositories.hypothesis_repository import HypothesisRepository
    ctx=ContextBuilder(ScanRepository(db),TargetRepository(db),ObservationRepository(db),HypothesisRepository(db),AttackSurfaceGraph(),AssetIntelligenceService(db),SurfacePrioritizer(db)).build(scan.id)
    sel=IntelligentCapabilitySelector().select(ctx)
    assert sel.candidates
    assert 'surface_bonus=' in sel.candidates[0].rationale

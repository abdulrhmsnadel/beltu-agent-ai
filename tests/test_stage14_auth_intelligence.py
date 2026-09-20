
from pathlib import Path

from beltu.auth_intelligence.service import AuthIntelligenceService
from beltu.brain.context_builder import ContextBuilder
from beltu.brain.attack_graph import AttackSurfaceGraph
from beltu.brain.schemas import ObservationInput
from beltu.brain.observation_pipeline import ObservationPipeline
from beltu.brain.observer import Observer
from beltu.analysis.correlator import ObservationCorrelator
from beltu.storage.database import Database
from beltu.storage.repositories.auth_repository import AuthRepository
from beltu.storage.repositories.api_repository import ApiRepository
from beltu.storage.repositories.observation_link_repository import ObservationLinkRepository
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.hypothesis_repository import HypothesisRepository
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository
from beltu.storage.repositories.asset_repository import AssetRepository
from beltu.intelligence.service import AssetIntelligenceService
from beltu.intelligence.prioritizer import SurfacePrioritizer
from beltu.api_intelligence.service import ApiIntelligenceService


def setup(tmp_path: Path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    targets = TargetRepository(db)
    target = targets.add("authorized.test")
    scans = ScanRepository(db)
    scan = scans.create(target.id)
    return db, target, scan


def seed_api(db: Database, scan_id: int, target_id: int):
    assets = AssetRepository(db)
    asset = assets.upsert_asset(scan_id, target_id, "domain", "api.authorized.test", "api.authorized.test", "manual", 1.0, {})
    api = ApiRepository(db)
    op = api.upsert_operation(scan_id, asset.id, None, "api.authorized.test|POST|/login", "POST", "/login", "login", "rest", (), False, (), ("application/json",), ("application/json",), "Login", None, "test", 0.95, {})
    op2 = api.upsert_operation(scan_id, asset.id, None, "api.authorized.test|GET|/admin", "GET", "/admin", "admin", "rest", (), True, ("bearerAuth",), (), ("application/json",), "Admin", None, "test", 0.95, {})
    return asset, op, op2


def test_auth_principal_session_and_control_are_persisted(tmp_path: Path):
    db, target, scan = setup(tmp_path)
    seed_api(db, scan.id, target.id)
    obs = ObservationRepository(db)
    obs.add(scan.id, "authentication", "/login", {
        "principal": "analyst",
        "role": "member",
        "state": "authenticated",
        "transition_from": "anonymous",
        "transition_to": "authenticated",
        "schemes": ["password"],
        "session": {"cookie_name": "SESSIONID", "secure": True, "http_only": True, "same_site": "lax"},
        "token": "SECRET-MUST-NOT-BE-STORED",
    }, "fixture", 0.91)
    result = AuthIntelligenceService(db).rebuild(scan.id)
    assert len(result.principals) == 1
    assert result.principals[0].label == "analyst"
    assert result.principals[0].role == "member"
    assert len(result.sessions) == 1
    assert result.sessions[0].label == "SESSIONID"
    assert result.sessions[0].value_present is True
    assert len(result.controls) >= 2
    assert any(c.auth_required for c in result.controls)
    assert any(t.from_state == "anonymous" and t.to_state == "authenticated" for t in result.transitions)


def test_sensitive_session_values_do_not_reach_context(tmp_path: Path):
    db, target, scan = setup(tmp_path)
    seed_api(db, scan.id, target.id)
    obs = ObservationRepository(db)
    obs.add(scan.id, "session", "/session", {
        "session": {"cookie_name": "SID", "value": "VERY-SECRET", "token": "VERY-SECRET-2", "secure": True}
    }, "fixture", 0.9)
    payload = AuthIntelligenceService(db).context_payload(scan.id)
    rendered = str(payload)
    assert "VERY-SECRET" not in rendered
    assert "VERY-SECRET-2" not in rendered
    assert payload["sessions"][0]["value_present"] is True


def test_rebuild_is_idempotent(tmp_path: Path):
    db, target, scan = setup(tmp_path)
    seed_api(db, scan.id, target.id)
    obs = ObservationRepository(db)
    obs.add(scan.id, "authentication", "/admin", {"principal": "admin", "role": "admin", "access_state": "protected"}, "fixture", 0.8)
    service = AuthIntelligenceService(db)
    first = service.rebuild(scan.id)
    second = service.rebuild(scan.id)
    assert first.summary == second.summary


def test_auth_surface_is_included_in_agent_context(tmp_path: Path):
    db, target, scan = setup(tmp_path)
    seed_api(db, scan.id, target.id)
    obs = ObservationRepository(db)
    obs.add(scan.id, "authentication", "/admin", {"principal": "admin", "role": "admin", "access_state": "protected"}, "fixture", 0.8)
    builder = ContextBuilder(
        ScanRepository(db), TargetRepository(db), obs, HypothesisRepository(db), AttackSurfaceGraph(),
        AssetIntelligenceService(db), SurfacePrioritizer(db, AssetIntelligenceService(db)), ApiIntelligenceService(db), AuthIntelligenceService(db)
    )
    context = builder.build(scan.id)
    assert "operation_controls" in context.auth_surface
    assert context.auth_surface["summary"]["controls"] >= 1


def test_repository_never_persists_raw_token_in_session_columns(tmp_path: Path):
    db, _, scan = setup(tmp_path)
    repo = AuthRepository(db)
    session = repo.upsert_session(scan.id, label="SID", transport="cookie", mechanism="session_token", state="observed",
                                   secure=True, http_only=True, same_site="lax", domain="authorized.test", path="/",
                                   expires_at=None, value_present=True, source="fixture", confidence=0.9,
                                   metadata={"token": "DO-NOT-PERSIST"})
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM auth_sessions WHERE id=?", (session.id,)).fetchone()
    assert "DO-NOT-PERSIST" not in str(row["metadata_json"])
    assert row["value_present"] == 1
    assert "DO-NOT-PERSIST" not in str(row)

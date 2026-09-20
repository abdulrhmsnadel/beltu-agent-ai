from pathlib import Path

from beltu.access_control.service import AccessControlIntelligenceService
from beltu.api_intelligence.service import ApiIntelligenceService
from beltu.auth_intelligence.service import AuthIntelligenceService
from beltu.brain.attack_graph import AttackSurfaceGraph
from beltu.brain.context_builder import ContextBuilder
from beltu.brain.schemas import AgentContext
from beltu.brain.llm.prompting import build_user_prompt
from beltu.intelligence.prioritizer import SurfacePrioritizer
from beltu.intelligence.service import AssetIntelligenceService
from beltu.selection.engine import IntelligentCapabilitySelector
from beltu.storage.database import Database
from beltu.storage.repositories.api_repository import ApiRepository
from beltu.storage.repositories.asset_repository import AssetRepository
from beltu.storage.repositories.auth_repository import AuthRepository
from beltu.storage.repositories.hypothesis_repository import HypothesisRepository
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository


def setup(tmp_path: Path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    targets = TargetRepository(db)
    target = targets.add("authorized.test")
    scan = ScanRepository(db).create(target.id)
    assets = AssetRepository(db)
    asset = assets.upsert_asset(scan.id, target.id, "domain", "api.authorized.test", "api.authorized.test", "fixture", 1.0, {})
    api = ApiRepository(db)
    login = api.upsert_operation(scan.id, asset.id, None, "api.authorized.test|POST|/login", "POST", "/login", "login", "rest", (), False, (), ("application/json",), ("application/json",), "Login", None, "fixture", 0.95, {})
    admin = api.upsert_operation(scan.id, asset.id, None, "api.authorized.test|GET|/admin", "GET", "/admin", "admin", "rest", (), True, ("bearerAuth",), (), ("application/json",), "Admin", None, "fixture", 0.95, {})
    return db, target, scan, login, admin


def test_authorization_matrix_is_built_from_auth_controls(tmp_path: Path):
    db, _, scan, _, admin = setup(tmp_path)
    obs = ObservationRepository(db)
    obs.add(scan.id, "authentication", "/admin", {"principal": "alice", "role": "member", "access_state": "allowed"}, "fixture", 0.9)
    result = AccessControlIntelligenceService(db).rebuild(scan.id)
    rows = [r for r in result.matrix if r.operation_id == admin.id and r.principal_label == "alice"]
    assert rows
    assert rows[0].role == "member"
    assert rows[0].access_state == "allowed"


def test_protected_operation_with_anonymous_positive_access_is_candidate(tmp_path: Path):
    db, _, scan, _, admin = setup(tmp_path)
    obs = ObservationRepository(db)
    obs.add(scan.id, "authentication", "/admin", {"principal": "anonymous", "role": "guest", "access_state": "public"}, "fixture", 0.92)
    result = AccessControlIntelligenceService(db).rebuild(scan.id)
    candidate = [a for a in result.anomalies if a.kind == "anonymous_access_to_protected" and a.entity_id == admin.id]
    assert candidate
    assert candidate[0].severity == "high"
    assert "candidate" in candidate[0].rationale.lower()


def test_conflicting_same_principal_states_are_recorded(tmp_path: Path):
    db, _, scan, _, admin = setup(tmp_path)
    obs = ObservationRepository(db)
    obs.add(scan.id, "authentication", "/admin", {"principal": "bob", "role": "member", "access_state": "allowed"}, "fixture", 0.8)
    obs.add(scan.id, "authentication", "/admin", {"principal": "bob", "role": "member", "access_state": "denied"}, "fixture", 0.95)
    result = AccessControlIntelligenceService(db).rebuild(scan.id)
    assert any(a.kind == "principal_state_conflict" and a.entity_id == admin.id for a in result.anomalies)


def test_rebuild_is_idempotent(tmp_path: Path):
    db, _, scan, _, _ = setup(tmp_path)
    service = AccessControlIntelligenceService(db)
    first = service.rebuild(scan.id)
    second = service.rebuild(scan.id)
    assert first.summary == second.summary
    assert [(a.kind, a.entity_id) for a in first.anomalies] == [(a.kind, a.entity_id) for a in second.anomalies]


def test_authorization_context_reaches_llm_prompt(tmp_path: Path):
    db, _, scan, _, admin = setup(tmp_path)
    obs = ObservationRepository(db)
    obs.add(scan.id, "authentication", "/admin", {"principal": "anonymous", "role": "guest", "access_state": "public"}, "fixture", 0.9)
    service = AccessControlIntelligenceService(db)
    payload = service.context_payload(scan.id)
    assert payload["summary"]["matrix_entries"] >= 2
    assert any(x["kind"] == "anonymous_access_to_protected" for x in payload["anomalies"])

    context = AgentContext(scan_id=scan.id, target="authorized.test", authorization_surface=payload)
    prompt = build_user_prompt(tmp_path, "missing.md", context, 3, 3)
    assert "authorization_surface" in prompt
    assert "anonymous_access_to_protected" in prompt


def test_access_control_capability_gets_signal_from_authorization_context():
    context = AgentContext(
        scan_id=1, target="authorized.test",
        authorization_surface={"summary": {"anomalies": 2}, "matrix": [], "anomalies": []},
    )
    decision = IntelligentCapabilitySelector().select(context)
    names = [c.profile.name for c in decision.candidates]
    assert "offline.authorization.matrix_analysis" in names


def test_stage15_schema_is_additive_and_existing_tables_survive(tmp_path: Path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    with db.connect() as conn:
        tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert "targets" in tables
    assert "auth_operation_controls" in tables
    assert "authorization_matrix" in tables
    assert "authorization_anomalies" in tables

from pathlib import Path

from beltu.api_intelligence.service import ApiIntelligenceService
from beltu.business_logic.service import BusinessLogicIntelligenceService
from beltu.brain.context_builder import ContextBuilder
from beltu.brain.schemas import AgentContext
from beltu.brain.llm.prompting import build_user_prompt
from beltu.selection.engine import IntelligentCapabilitySelector
from beltu.storage.database import Database
from beltu.storage.repositories.api_repository import ApiRepository
from beltu.storage.repositories.asset_repository import AssetRepository
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository
from beltu.storage.repositories.hypothesis_repository import HypothesisRepository
from beltu.brain.attack_graph import AttackSurfaceGraph


def setup(tmp_path: Path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    target = TargetRepository(db).add("workflow.test")
    scan = ScanRepository(db).create(target.id)
    asset = AssetRepository(db).upsert_asset(scan.id, target.id, "domain", "workflow.test", "workflow.test", "fixture", 1.0, {})
    api = ApiRepository(db)
    create = api.upsert_operation(scan.id, asset.id, None, "workflow.test|POST|/orders", "POST", "/orders", "createOrder", "rest", ("orders",), True, ("bearerAuth",), ("application/json",), ("application/json",), "Create order", None, "fixture", 0.95, {})
    approve = api.upsert_operation(scan.id, asset.id, None, "workflow.test|POST|/orders/{id}/approve", "POST", "/orders/{id}/approve", "approveOrder", "rest", ("orders",), True, ("bearerAuth",), ("application/json",), ("application/json",), "Approve order", None, "fixture", 0.92, {})
    complete = api.upsert_operation(scan.id, asset.id, None, "workflow.test|POST|/orders/{id}/complete", "POST", "/orders/{id}/complete", "completeOrder", "rest", ("orders",), True, ("bearerAuth",), ("application/json",), ("application/json",), "Complete order", None, "fixture", 0.9, {})
    return db, target, scan, create, approve, complete


def test_workflow_model_is_persistent_and_idempotent(tmp_path: Path):
    db, _, scan, _, _, _ = setup(tmp_path)
    service = BusinessLogicIntelligenceService(db)
    first = service.rebuild(scan.id)
    second = service.rebuild(scan.id)
    assert first.summary == second.summary
    assert first.summary["workflows"] >= 1
    assert first.summary["transitions"] >= 1
    assert [(t.from_state, t.to_state, t.action) for t in first.transitions] == [(t.from_state, t.to_state, t.action) for t in second.transitions]


def test_explicit_state_transition_is_reconciled(tmp_path: Path):
    db, _, scan, _, approve, _ = setup(tmp_path)
    obs = ObservationRepository(db)
    obs.add(scan.id, "workflow.transition", "/orders/{id}/approve", {
        "workflow": "orders", "from_state": "pending", "to_state": "approved", "operation_id": approve.id, "action": "approve",
    }, "fixture", 0.96)
    result = BusinessLogicIntelligenceService(db).rebuild(scan.id)
    assert any(t.from_state == "pending" and t.to_state == "approved" and t.operation_id == approve.id for t in result.transitions)


def test_terminal_state_outgoing_is_candidate(tmp_path: Path):
    db, _, scan, _, _, _ = setup(tmp_path)
    obs = ObservationRepository(db)
    obs.add(scan.id, "workflow.state", "orders", {
        "workflow": "orders", "state": "closed", "terminal": True,
    }, "fixture", 0.9)
    obs.add(scan.id, "workflow.transition", "/orders/{id}/reopen", {
        "workflow": "orders", "from_state": "closed", "to_state": "open", "action": "open",
    }, "fixture", 0.88)
    result = BusinessLogicIntelligenceService(db).rebuild(scan.id)
    assert any(a.kind == "terminal_state_has_outgoing" and a.entity_key == "closed" for a in result.anomalies)


def test_business_logic_context_reaches_llm_and_selector(tmp_path: Path):
    db, target, scan, _, _, _ = setup(tmp_path)
    service = BusinessLogicIntelligenceService(db)
    payload = service.context_payload(scan.id)
    assert payload["summary"]["workflows"] >= 1
    context = AgentContext(scan_id=scan.id, target=target.value, business_logic_surface=payload)
    prompt = build_user_prompt(tmp_path, "missing.md", context, 3, 3)
    assert "business_logic_surface" in prompt
    selection = IntelligentCapabilitySelector().select(context, preferred_capability="offline.business_logic.workflow_analysis")
    assert selection.selected is not None
    assert selection.selected.profile.name == "offline.business_logic.workflow_analysis"


def test_sensitive_transition_candidate_requires_stored_authz(tmp_path: Path):
    db, _, scan, _, approve, _ = setup(tmp_path)
    # Seed authorization candidate directly through observation + Stage 15 rebuild.
    obs = ObservationRepository(db)
    obs.add(scan.id, "authentication", "/orders/{id}/approve", {"principal": "anonymous", "role": "guest", "access_state": "public"}, "fixture", 0.93)
    result = BusinessLogicIntelligenceService(db).rebuild(scan.id)
    # Without Stage 15 matrix data, the workflow model alone must not assert a weak boundary.
    assert not any(a.kind == "sensitive_transition_weak_boundary" and a.entity_key == str(approve.id) for a in result.anomalies)


def test_stage15_tables_survive_and_stage16_tables_exist(tmp_path: Path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    with db.connect() as conn:
        tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert "authorization_matrix" in tables
    assert "business_workflows" in tables
    assert "workflow_states" in tables
    assert "workflow_transitions" in tables
    assert "business_logic_anomalies" in tables

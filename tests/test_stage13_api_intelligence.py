from pathlib import Path
from beltu.api_intelligence.service import ApiIntelligenceService
from beltu.brain.context_builder import ContextBuilder
from beltu.brain.attack_graph import AttackSurfaceGraph
from beltu.brain.schemas import ObservationInput
from beltu.intelligence.service import AssetIntelligenceService
from beltu.intelligence.prioritizer import SurfacePrioritizer
from beltu.selection.engine import IntelligentCapabilitySelector
from beltu.storage.database import Database
from beltu.storage.repositories.api_repository import ApiRepository
from beltu.storage.repositories.hypothesis_repository import HypothesisRepository
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository
from beltu.common.enums import ScanStatus


def seed(tmp_path: Path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    target = TargetRepository(db).add("example.com")
    scan = ScanRepository(db).create(target.id, ScanStatus.PENDING)
    obs = ObservationRepository(db)
    return db, scan, obs


def test_openapi_operations_auth_and_parameters_are_persisted(tmp_path: Path):
    db, scan, obs = seed(tmp_path)
    obs.add(scan.id, "openapi", "https://api.example.com/openapi.json", {
        "structured": {
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.example.com"}],
            "security": [{"bearerAuth": []}],
            "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
            "paths": {
                "/users/{id}": {
                    "get": {
                        "operationId": "getUser",
                        "tags": ["users"],
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
                            {"name": "expand", "in": "query", "required": False, "schema": {"type": "string"}},
                        ],
                        "responses": {"200": {"content": {"application/json": {}}}},
                    }
                }
            }
        }
    }, "openapi-fixture", .95)
    # Create asset through the same stored-observation path used by Stage 11.
    obs.add(scan.id, "asset.subdomain", "api.example.com", {}, "subfinder", .9)
    result = ApiIntelligenceService(db).rebuild(scan.id)
    assert result.summary["operations"] == 1
    assert result.summary["parameters"] == 2
    op = result.operations[0]
    assert op.method == "GET"
    assert op.path == "/users/{id}"
    assert op.auth_required is True
    assert op.auth_schemes == ("bearerAuth",)
    assert op.response_content_types == ("application/json",)

    params = ApiRepository(db).list_parameters(scan.id)
    assert {p.name for p in params} == {"id", "expand"}
    assert {p.location for p in params} == {"path", "query"}


def test_api_rebuild_is_idempotent(tmp_path: Path):
    db, scan, obs = seed(tmp_path)
    obs.add(scan.id, "asset.subdomain", "api.example.com", {}, "subfinder", .9)
    obs.add(scan.id, "api_endpoint", "https://api.example.com/orders", {
        "structured": {"url": "https://api.example.com/orders", "method": "POST", "auth_required": True, "auth_schemes": ["session"]}
    }, "crawler", .9)
    svc = ApiIntelligenceService(db)
    first = svc.rebuild(scan.id)
    second = svc.rebuild(scan.id)
    assert first.summary == second.summary
    assert len(ApiRepository(db).list_operations(scan.id)) == 1


def test_graphql_operation_is_classified(tmp_path: Path):
    db, scan, obs = seed(tmp_path)
    obs.add(scan.id, "asset.subdomain", "api.example.com", {}, "manual", 1.0)
    obs.add(scan.id, "api_endpoint", "https://api.example.com/graphql", {
        "structured": {"url": "https://api.example.com/graphql", "method": "POST", "endpoint_type": "graphql"}
    }, "crawler", .9)
    op = ApiIntelligenceService(db).rebuild(scan.id).operations[0]
    assert op.api_style == "graphql"


def test_workflow_relation_uses_explicit_transition_only(tmp_path: Path):
    db, scan, obs = seed(tmp_path)
    obs.add(scan.id, "asset.subdomain", "api.example.com", {}, "manual", 1.0)
    obs.add(scan.id, "api_endpoint", "https://api.example.com/cart", {
        "structured": {"url": "https://api.example.com/cart", "method": "POST", "next_path": "/checkout"}
    }, "crawler", .9)
    obs.add(scan.id, "api_endpoint", "https://api.example.com/checkout", {
        "structured": {"url": "https://api.example.com/checkout", "method": "POST"}
    }, "crawler", .9)
    result = ApiIntelligenceService(db).rebuild(scan.id)
    assert any(r["relation"] == "workflow_next" for r in result.relations)


def test_sensitive_metadata_is_redacted_and_query_values_are_not_persisted(tmp_path: Path):
    db, scan, obs = seed(tmp_path)
    obs.add(scan.id, "asset.subdomain", "api.example.com", {}, "manual", 1.0)
    obs.add(scan.id, "crawler.request", "https://api.example.com/search?q=secretvalue", {
        "structured": {
            "url": "https://api.example.com/search?q=secretvalue",
            "method": "GET",
            "headers": {"Authorization": "Bearer REALSECRET", "X-Test": "ok"},
        }
    }, "crawler", .9)
    result = ApiIntelligenceService(db).rebuild(scan.id)
    op = result.operations[0]
    assert "secretvalue" not in op.metadata.__repr__()
    assert "REALSECRET" not in repr(op.metadata)
    params = ApiRepository(db).list_parameters(scan.id)
    assert any(p.name == "q" and p.location == "query" for p in params)
    assert all("secretvalue" not in repr(p.schema) for p in params)


def test_api_surface_enters_context_and_capability_selection(tmp_path: Path):
    db, scan, obs = seed(tmp_path)
    obs.add(scan.id, "asset.subdomain", "api.example.com", {}, "manual", 1.0)
    obs.add(scan.id, "api_endpoint", "https://api.example.com/users", {
        "structured": {"url": "https://api.example.com/users", "method": "GET", "auth_required": True}
    }, "crawler", .9)
    ctx = ContextBuilder(
        ScanRepository(db), TargetRepository(db), obs, HypothesisRepository(db), AttackSurfaceGraph(),
        AssetIntelligenceService(db), SurfacePrioritizer(db), ApiIntelligenceService(db)
    ).build(scan.id)
    assert ctx.api_surface["summary"]["operations"] == 1
    assert ctx.api_surface["summary"]["protected_operations"] == 1
    selected = IntelligentCapabilitySelector().select(ctx)
    assert selected.candidates
    assert any("api_bonus=" in c.rationale for c in selected.candidates)

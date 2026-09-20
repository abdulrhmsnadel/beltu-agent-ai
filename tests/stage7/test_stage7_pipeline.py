from pathlib import Path

from beltu.analysis.correlator import ObservationCorrelator
from beltu.brain.observation_pipeline import ObservationPipeline
from beltu.brain.observer import Observer
from beltu.brain.schemas import ObservationInput
from beltu.common.enums import ScanStatus
from beltu.evidence.collector import EvidenceCollector
from beltu.execution.normalizers import normalize_jsonl_or_lines
from beltu.storage.database import Database
from beltu.storage.repositories.evidence_repository import EvidenceRepository
from beltu.storage.repositories.observation_link_repository import ObservationLinkRepository
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository


def make_env(tmp_path: Path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    targets = TargetRepository(db)
    scans = ScanRepository(db)
    observations = ObservationRepository(db)
    evidence = EvidenceRepository(db)
    links = ObservationLinkRepository(db)
    target = targets.add("example.com")
    scan = scans.create(target.id, ScanStatus.RUNNING)
    pipeline = ObservationPipeline(Observer(observations, scans, targets), ObservationCorrelator(links))
    return db, scan, observations, evidence, links, pipeline


def test_database_migration_creates_stage7_tables(tmp_path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    with db.connect() as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"evidence", "observation_links"} <= tables


def test_evidence_is_content_addressed_and_bounded(tmp_path):
    db, scan, _, evidence, _, _ = make_env(tmp_path)
    collector = EvidenceCollector(evidence, tmp_path / "evidence", max_bytes=1024)
    item = collector.collect_text(scan.id, None, "tool.stdout", "abcdefghijklmnop")
    assert item.size_bytes == 16
    assert len(item.sha256) == 64
    assert Path(item.path).read_bytes() == b"abcdefghijklmnop"


def test_jsonl_normalizer_prefers_structured_fields():
    rows = normalize_jsonl_or_lines("finding.candidate", "nuclei", '{"host":"api.example.com","template-id":"x"}\nplain')
    assert rows[0]["subject"] == "api.example.com"
    assert rows[0]["data"]["structured"]["template-id"] == "x"
    assert rows[1]["data"]["raw"] == "plain"


def test_pipeline_attaches_evidence_and_correlates_same_host(tmp_path):
    _, scan, observations, evidence, links, pipeline = make_env(tmp_path)
    ev = EvidenceCollector(evidence, tmp_path / "evidence").collect_text(scan.id, None, "tool.stdout", "api.example.com")
    first = pipeline.ingest(scan.id, [ObservationInput("asset.subdomain", "api.example.com", {}, "test", 0.9)], evidence_ids=(ev.id,))
    second = pipeline.ingest(scan.id, [ObservationInput("web.http_probe", "https://api.example.com/login", {}, "test", 0.8)], evidence_ids=(ev.id,))
    assert first[0].data["evidence_ids"] == [ev.id]
    assert second[0].data["evidence_ids"] == [ev.id]
    assert links.list_for_observation(second[0].id)[0].relation == "same_host"
    assert len(observations.list_for_scan(scan.id)) == 2


def test_dispatcher_persists_execution_artifact_and_returns_evidence_ids(tmp_path):
    import asyncio
    from beltu.common.enums import ScanStatus
    from beltu.execution.adapters.base import ToolAdapter
    from beltu.execution.capability_dispatcher import CapabilityDispatcher
    from beltu.execution.models import ExecutionRequest
    from beltu.execution.process_manager import ProcessManager
    from beltu.execution.registry import CapabilityRegistry, ToolRegistry
    from beltu.execution.resource_governor import ResourceGovernor
    from beltu.policy.scope_guard import ScopeGuard

    class FixtureAdapter(ToolAdapter):
        name = "fixture-echo"
        capability = "fixture.evidence"
        binary = "printf"

        def build_argv(self, request):
            return [self.binary, "fixture-output"]

        def parse_output(self, request, stdout, stderr):
            return [{"kind": "fixture.result", "subject": "example.com", "data": {}, "source": self.name, "confidence": 1.0}]

    db, scan, observations, evidence, links, _ = make_env(tmp_path)
    scope = tmp_path / "scope.yaml"
    scope.write_text("targets:\n  - example.com\n", encoding="utf-8")
    tools = ToolRegistry(); tools.register(FixtureAdapter())
    dispatcher = CapabilityDispatcher(
        ScopeGuard(scope), CapabilityRegistry(tools), ProcessManager(), ResourceGovernor(1),
        observations, ScanRepository(db), TargetRepository(db), evidence=evidence, links=links,
        evidence_root=str(tmp_path / "artifacts"),
    )

    result = asyncio.run(dispatcher.execute(ExecutionRequest(scan.id, "example.com", "fixture.evidence")))
    assert result.succeeded
    assert result.evidence_ids
    assert evidence.list_for_scan(scan.id)[0].sha256
    stored = observations.list_for_scan(scan.id)[0]
    assert stored.data["evidence_ids"] == list(result.evidence_ids)

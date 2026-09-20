from __future__ import annotations

import asyncio
from pathlib import Path

from beltu.analysis.correlator import ObservationCorrelator
from beltu.brain.attack_graph import AttackSurfaceGraph
from beltu.brain.context_builder import ContextBuilder
from beltu.brain.observation_pipeline import ObservationPipeline
from beltu.brain.observer import Observer
from beltu.brain.llm.config import LLMConfig
from beltu.brain.llm.reasoner import LLMReasoningEngine, StaticProvider
from beltu.brain.reasoning_engine import HybridReasoningEngine
from beltu.brain.schemas import ObservationInput
from beltu.common.enums import ScanStatus
from beltu.core.event_bus import EventBus
from beltu.core.orchestrator import Orchestrator
from beltu.execution.scheduler import Scheduler
from beltu.feedback.replanner import AutonomousReplanner
from beltu.feedback.repository import ReasoningCycleRepository
from beltu.storage.database import Database
from beltu.storage.repositories.decision_repository import DecisionRepository
from beltu.storage.repositories.hypothesis_repository import HypothesisRepository
from beltu.storage.repositories.llm_run_repository import LLMRunRepository
from beltu.storage.repositories.observation_link_repository import ObservationLinkRepository
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository
from beltu.storage.repositories.task_repository import TaskRepository


def make_context(tmp_path: Path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    targets = TargetRepository(db)
    scans = ScanRepository(db)
    tasks = TaskRepository(db)
    observations = ObservationRepository(db)
    hypotheses = HypothesisRepository(db)
    target = targets.add("example.com")
    scan = scans.create(target.id, ScanStatus.RUNNING)
    events = EventBus()
    scheduler = Scheduler(tasks, scans, targets, events, workers=1)
    scheduler.register("agent.evaluate", lambda task: asyncio.sleep(0, result={"ok": True}))
    orchestrator = Orchestrator(targets, scans, tasks, scheduler, events)
    context = ContextBuilder(scans, targets, observations, hypotheses, AttackSurfaceGraph())
    pipeline = ObservationPipeline(Observer(observations, scans, targets), ObservationCorrelator(ObservationLinkRepository(db)))
    return db, target, scan, observations, hypotheses, context, orchestrator, pipeline


def valid_response(scan_id: int, target: str) -> str:
    return '{"summary":"Evidence indicates a mapped API surface.","hypotheses":[{"statement":"A web API endpoint surface exists.","basis_observation_ids":[1],"confidence":0.91}],"actions":[{"action_kind":"api_analysis","action_payload":{"target":"example.com","hypothesis":"A web API endpoint surface exists.","observation_ids":[1]},"rationale":"API analysis reduces uncertainty about control boundaries.","confidence":0.88,"risk_level":"medium","requires_approval":true}]}'


def test_llm_reasoner_accepts_valid_structured_output(tmp_path: Path):
    db, _, scan, observations, _, context_builder, _, pipeline = make_context(tmp_path)
    stored = pipeline.ingest(scan.id, [ObservationInput("api_endpoint", "/v1/users", {}, "fixture", 0.95)])[0]
    context = context_builder.build(scan.id)
    config = LLMConfig(enabled=True, api_key_required=False, use_json_mode=False)
    response = valid_response(scan.id, "example.com")
    reasoner = LLMReasoningEngine(tmp_path, config, StaticProvider(response))
    result = reasoner.run(context)
    assert result.ok
    assert result.response is not None
    assert result.response.actions[0].requires_approval is True
    assert result.response.hypotheses[0].basis_observation_ids == (stored.id,)


def test_llm_validator_rejects_unknown_observation_and_wrong_target(tmp_path: Path):
    _, _, scan, observations, _, context_builder, _, pipeline = make_context(tmp_path)
    pipeline.ingest(scan.id, [ObservationInput("api_endpoint", "/v1/users", {}, "fixture", 0.95)])
    context = context_builder.build(scan.id)
    bad_obs = '{"summary":"x","hypotheses":[{"statement":"x","basis_observation_ids":[999],"confidence":0.9}],"actions":[]}'
    result = LLMReasoningEngine(tmp_path, LLMConfig(enabled=True, api_key_required=False), StaticProvider(bad_obs)).run(context)
    assert result.ok is False
    bad_target = '{"summary":"x","hypotheses":[{"statement":"x","basis_observation_ids":[1],"confidence":0.9}],"actions":[{"action_kind":"surface_inventory","action_payload":{"target":"evil.example"},"rationale":"x","confidence":0.9,"risk_level":"low","requires_approval":false}]}'
    result2 = LLMReasoningEngine(tmp_path, LLMConfig(enabled=True, api_key_required=False), StaticProvider(bad_target)).run(context)
    assert result2.ok is False


def test_hybrid_falls_back_without_key(tmp_path: Path):
    _, _, scan, observations, _, context_builder, _, pipeline = make_context(tmp_path)
    pipeline.ingest(scan.id, [ObservationInput("technology", "example.com", {"name": "fixture"}, "fixture", 0.8)])
    config = LLMConfig(enabled=True, api_key_required=True)
    class MissingKeyProvider:
        name = "openai_compatible"
        model = "fixture"
        def complete(self, *, system_prompt: str, user_prompt: str):
            raise RuntimeError("LLM API key is missing; set BELTU_LLM_API_KEY")
    reasoner = LLMReasoningEngine(tmp_path, config, MissingKeyProvider())
    hybrid = HybridReasoningEngine(
        heuristic=__import__("beltu.brain.hypothesis_engine", fromlist=["HeuristicHypothesisEngine"]).HeuristicHypothesisEngine(),
        prioritizer=__import__("beltu.brain.prioritizer", fromlist=["HypothesisPrioritizer"]).HypothesisPrioritizer(),
        planner=__import__("beltu.brain.planner", fromlist=["Planner"]).Planner(),
        llm=reasoner,
        enabled=True,
        fallback_to_heuristic=True,
    )
    out = hybrid.generate(context_builder.build(scan.id))
    assert out.source == "heuristic"
    assert out.llm_error
    assert hybrid.last_llm_run is not None and hybrid.last_llm_run.ok is False


def test_replanner_persists_llm_run_and_uses_llm_actions(tmp_path: Path):
    db, _, scan, observations, hypotheses, context_builder, _, pipeline = make_context(tmp_path)
    pipeline.ingest(scan.id, [ObservationInput("api_endpoint", "/v1/users", {}, "fixture", 0.95)])
    config = LLMConfig(enabled=True, api_key_required=False, use_json_mode=False)
    llm = LLMReasoningEngine(tmp_path, config, StaticProvider(valid_response(scan.id, "example.com")))
    from beltu.brain.hypothesis_engine import HeuristicHypothesisEngine
    from beltu.brain.planner import Planner
    from beltu.brain.prioritizer import HypothesisPrioritizer
    hybrid = HybridReasoningEngine(
        heuristic=HeuristicHypothesisEngine(),
        prioritizer=HypothesisPrioritizer(),
        planner=Planner(),
        llm=llm,
        enabled=True,
    )
    decisions = DecisionRepository(db)
    tasks = TaskRepository(db)
    cycles = ReasoningCycleRepository(db)
    llm_runs = LLMRunRepository(db)
    replanner = AutonomousReplanner(
        context_builder=context_builder,
        observations=observations,
        hypotheses=hypotheses,
        decisions=decisions,
        tasks=tasks,
        cycles=cycles,
        llm_runs=llm_runs,
        reasoning_engine=hybrid,
        auto_execute_low_risk=False,
    )
    result = asyncio.run(replanner.replan(scan.id, trigger="manual", trigger_task_id=0))
    assert result.cycle.summary["reasoning_source"] == "llm"
    assert result.cycle.summary["llm_run_id"] is not None
    stored_runs = llm_runs.list_for_scan(scan.id)
    assert len(stored_runs) == 1
    decision = decisions.get(result.decision_ids[0])
    assert decision is not None
    assert decision.action_kind == "api_analysis"
    assert decision.requires_approval is True


def test_openai_compatible_provider_uses_json_chat_contract(tmp_path: Path, monkeypatch):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import json
    import threading

    class Handler(BaseHTTPRequestHandler):
        received = {}
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            Handler.received = {"headers": dict(self.headers), "body": json.loads(body)}
            payload = {"choices": [{"message": {"content": '{"summary":"ok","hypotheses":[],"actions":[]}'}}]}
            raw = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        config = LLMConfig(
            enabled=True,
            base_url=f"http://127.0.0.1:{server.server_port}/v1",
            model="fixture-model",
            api_key_env="BELTU_TEST_KEY",
            api_key_required=True,
            use_json_mode=True,
        )
        monkeypatch.setenv("BELTU_TEST_KEY", "test-secret")
        from beltu.brain.llm.provider import OpenAICompatibleProvider
        text, latency = OpenAICompatibleProvider(config).complete(system_prompt="system", user_prompt="user")
        assert "hypotheses" in text
        assert latency >= 0
        assert Handler.received["headers"]["Authorization"] == "Bearer test-secret"
        assert Handler.received["body"]["model"] == "fixture-model"
        assert Handler.received["body"]["response_format"] == {"type": "json_object"}
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_decision_engine_binds_proposal_to_expected_target():
    from beltu.brain.decision_engine import DecisionEngine
    from beltu.brain.schemas import ActionProposal
    proposal = ActionProposal(
        "surface_inventory", {"target": "evil.example"}, "inventory", 0.9, "low", False
    )
    result = DecisionEngine().evaluate(proposal, expected_target="example.com")
    assert result.accepted is False
    assert "current scan target" in result.reason

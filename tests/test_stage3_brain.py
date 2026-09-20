from pathlib import Path

from beltu.brain.attack_graph import AttackSurfaceGraph
from beltu.brain.context_builder import ContextBuilder
from beltu.brain.decision_engine import DecisionEngine
from beltu.brain.hypothesis_engine import HeuristicHypothesisEngine
from beltu.brain.planner import Planner
from beltu.brain.prioritizer import HypothesisPrioritizer
from beltu.brain.schemas import ActionProposal, ObservationInput
from beltu.common.enums import ScanStatus
from beltu.core.agent import Agent
from beltu.core.event_bus import EventBus
from beltu.core.orchestrator import Orchestrator
from beltu.execution.scheduler import Scheduler
from beltu.policy.scope_guard import ScopeGuard
from beltu.storage.database import Database
from beltu.storage.repositories.decision_repository import DecisionRepository
from beltu.storage.repositories.hypothesis_repository import HypothesisRepository
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository
from beltu.storage.repositories.task_repository import TaskRepository


def build(tmp_path: Path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    targets = TargetRepository(db)
    scans = ScanRepository(db)
    tasks = TaskRepository(db)
    observations = ObservationRepository(db)
    hypotheses = HypothesisRepository(db)
    decisions = DecisionRepository(db)
    events = EventBus()
    scheduler = Scheduler(tasks, scans, targets, events, workers=1)
    scheduler.register("agent.evaluate", lambda task: __import__('asyncio').sleep(0, result={"ok": True}))
    orchestrator = Orchestrator(targets, scans, tasks, scheduler, events)
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text("targets:\n  - example.com\n", encoding="utf-8")
    context_builder = ContextBuilder(scans, targets, observations, hypotheses, AttackSurfaceGraph())
    agent = Agent(
        targets,
        ScopeGuard(scope_file),
        orchestrator,
        observations=observations,
        hypotheses=hypotheses,
        decisions=decisions,
        context_builder=context_builder,
    )
    return agent, targets, scans, observations, hypotheses, decisions, orchestrator


def test_brain_generates_and_persists_reasoning_cycle(tmp_path: Path):
    import asyncio

    async def run():
        agent, _, scans, observations, hypotheses, decisions, orchestrator = build(tmp_path)
        target = agent.register_target("example.com")
        await orchestrator.start()
        scan, _ = await agent.start_scan(target.id)
        await orchestrator.scheduler.queue.join()
        return agent, scan, observations, hypotheses, decisions, orchestrator

    agent, scan, observations, hypotheses, decisions, orchestrator = asyncio.run(run())
    agent.ingest_observation(scan.id, ObservationInput("api_endpoint", "/v1/users", {"children": ["/v1/orders"]}, "fixture", 0.9))
    cycle = agent.think(scan.id)
    assert cycle.hypotheses
    assert cycle.decisions
    assert hypotheses.list_for_scan(scan.id)
    assert decisions.list_for_scan(scan.id)
    assert observations.list_for_scan(scan.id)
    assert cycle.decisions[0].accepted is True
    asyncio.run(orchestrator.stop())


def test_decision_engine_rejects_unknown_action():
    result = DecisionEngine().evaluate(ActionProposal("execute_shell", {"target": "example.com"}, "x", 0.5))
    assert result.accepted is False
    assert result.status == "rejected"


def test_decision_engine_requires_approval_for_high_risk():
    result = DecisionEngine().evaluate(ActionProposal("finding_validation", {"target": "example.com"}, "x", 0.9, "high", False))
    assert result.accepted is False


def test_context_graph_links_related_observations(tmp_path: Path):
    import asyncio

    async def run():
        agent, _, _, observations, _, _, orchestrator = build(tmp_path)
        target = agent.register_target("example.com")
        await orchestrator.start()
        scan, _ = await agent.start_scan(target.id)
        await orchestrator.scheduler.queue.join()
        agent.ingest_observation(scan.id, ObservationInput("service", "443", {"related_to": "example.com"}, "fixture"))
        ctx = agent.context_builder.build(scan.id)
        await orchestrator.stop()
        return ctx

    ctx = asyncio.run(run())
    assert "443" in ctx.graph_nodes
    assert ("example.com", "443", "service") in ctx.graph_edges

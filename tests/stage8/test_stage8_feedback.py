from __future__ import annotations

import asyncio
from pathlib import Path

from beltu.analysis.correlator import ObservationCorrelator
from beltu.brain.attack_graph import AttackSurfaceGraph
from beltu.brain.context_builder import ContextBuilder
from beltu.brain.observation_pipeline import ObservationPipeline
from beltu.brain.observer import Observer
from beltu.brain.schemas import ObservationInput
from beltu.common.enums import ScanStatus, TaskStatus
from beltu.control.approval_service import ApprovalService
from beltu.core.event_bus import EventBus
from beltu.feedback.replanner import AutonomousReplanner, action_fingerprint, context_fingerprint
from beltu.feedback.repository import ReasoningCycleRepository
from beltu.storage.database import Database
from beltu.storage.repositories.approval_repository import ApprovalRepository
from beltu.storage.repositories.decision_repository import DecisionRepository
from beltu.storage.repositories.hypothesis_repository import HypothesisRepository
from beltu.storage.repositories.observation_link_repository import ObservationLinkRepository
from beltu.storage.repositories.observation_repository import ObservationRepository
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository
from beltu.storage.repositories.task_repository import TaskRepository


def make_env(tmp_path: Path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    targets = TargetRepository(db)
    scans = ScanRepository(db)
    tasks = TaskRepository(db)
    observations = ObservationRepository(db)
    hypotheses = HypothesisRepository(db)
    decisions = DecisionRepository(db)
    links = ObservationLinkRepository(db)
    cycles = ReasoningCycleRepository(db)
    target = targets.add("example.com")
    scan = scans.create(target.id, ScanStatus.RUNNING)
    context = ContextBuilder(scans, targets, observations, hypotheses, AttackSurfaceGraph())
    pipeline = ObservationPipeline(Observer(observations, scans, targets), ObservationCorrelator(links))
    return db, target, scan, tasks, observations, hypotheses, decisions, cycles, context, pipeline


def make_replanner(env, **kwargs):
    db, _, scan, tasks, observations, hypotheses, decisions, cycles, context, _ = env
    del db
    return AutonomousReplanner(
        context_builder=context,
        observations=observations,
        hypotheses=hypotheses,
        decisions=decisions,
        tasks=tasks,
        cycles=cycles,
        events=kwargs.pop("events", None),
        max_cycles_per_scan=kwargs.pop("max_cycles_per_scan", 20),
        max_auto_tasks_per_cycle=kwargs.pop("max_auto_tasks_per_cycle", 2),
        auto_execute_low_risk=kwargs.pop("auto_execute_low_risk", True),
        enqueue_task=kwargs.pop("enqueue_task", None),
        **kwargs,
    )


def test_stage8_database_migration_is_additive(tmp_path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    with db.connect() as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(decisions)").fetchall()}
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"cycle_id", "action_fingerprint", "superseded_at", "superseded_reason"} <= columns
    assert "reasoning_cycles" in tables


def test_fingerprints_are_deterministic(tmp_path):
    env = make_env(tmp_path)
    context = env[8].build(env[2].id)
    assert context_fingerprint(context) == context_fingerprint(context)
    assert action_fingerprint("surface_inventory", {"target": "example.com"}) == action_fingerprint("surface_inventory", {"target": "example.com"})
    assert action_fingerprint("surface_inventory", {"target": "example.com"}) != action_fingerprint("surface_inventory", {"target": "other.example"})


def test_initial_cycle_creates_decision_and_can_auto_queue_low_risk(tmp_path):
    env = make_env(tmp_path)
    queued = []
    async def enqueue(task):
        queued.append(task.id)
    replanner = make_replanner(env, enqueue_task=enqueue)
    result = asyncio.run(replanner.replan(env[2].id, trigger="initial_scan", trigger_task_id=1))
    assert result.cycle.status == "succeeded"
    assert len(result.hypothesis_ids) == 1
    assert len(result.decision_ids) == 1
    assert len(result.queued_task_ids) == 1
    assert queued == list(result.queued_task_ids)
    decision = env[6].get(result.decision_ids[0])
    assert decision.status == "queued"


def test_identical_feedback_event_is_idempotent(tmp_path):
    env = make_env(tmp_path)
    replanner = make_replanner(env, enqueue_task=lambda task: asyncio.sleep(0))
    first = asyncio.run(replanner.replan(env[2].id, trigger="initial_scan", trigger_task_id=7))
    second = asyncio.run(replanner.replan(env[2].id, trigger="initial_scan", trigger_task_id=7))
    assert second.cycle.id == first.cycle.id
    assert env[7].count_for_scan(env[2].id) == 1
    assert len(env[6].list_for_scan(env[2].id)) == 1


def test_new_evidence_supersedes_stale_hypothesis_and_decision(tmp_path):
    env = make_env(tmp_path)
    queued = []
    async def enqueue(task):
        queued.append(task.id)
    replanner = make_replanner(env, enqueue_task=enqueue)
    first = asyncio.run(replanner.replan(env[2].id, trigger="initial_scan", trigger_task_id=1))
    old_decision = env[6].get(first.decision_ids[0])
    assert old_decision.status == "queued"

    env[9].ingest(env[2].id, [ObservationInput("endpoint", "https://api.example.com/login", {}, "fixture", 0.9)])
    second = asyncio.run(replanner.replan(env[2].id, trigger="task_succeeded", trigger_task_id=2))
    assert first.cycle.id != second.cycle.id
    assert first.hypothesis_ids[0] in second.superseded_hypothesis_ids
    assert old_decision.id in second.superseded_decision_ids
    assert env[6].get(old_decision.id).status == "superseded"
    assert env[3].list_for_decision(env[2].id, old_decision.id)[0].status == TaskStatus.CANCELLED.value


def test_failed_task_with_same_context_does_not_duplicate_action(tmp_path):
    env = make_env(tmp_path)
    replanner = make_replanner(env, enqueue_task=lambda task: asyncio.sleep(0))
    first = asyncio.run(replanner.replan(env[2].id, trigger="initial_scan", trigger_task_id=1))
    # A distinct failure event may create a cycle, but the same action fingerprint is still suppressed.
    second = asyncio.run(replanner.replan(env[2].id, trigger="task_failed", trigger_task_id=first.queued_task_ids[0]))
    assert second.cycle.id != first.cycle.id
    assert len(second.decision_ids) == 0
    assert len(env[6].list_for_scan(env[2].id)) == 1


def test_medium_risk_decisions_remain_outside_auto_execution(tmp_path):
    env = make_env(tmp_path)
    env[9].ingest(env[2].id, [ObservationInput("endpoint", "https://api.example.com/login", {}, "fixture", 0.9)])
    queued = []
    async def enqueue(task):
        queued.append(task.id)
    replanner = make_replanner(env, enqueue_task=enqueue)
    result = asyncio.run(replanner.replan(env[2].id, trigger="initial_scan", trigger_task_id=1))
    assert result.decision_ids
    assert not result.queued_task_ids
    assert not queued
    decisions = env[6].list_for_scan(env[2].id)
    assert any(item.status == "approval_required" for item in decisions)


def test_superseded_approved_decision_cannot_be_executed(tmp_path):
    env = make_env(tmp_path)
    replanner = make_replanner(env, auto_execute_low_risk=False)
    env[9].ingest(env[2].id, [ObservationInput("endpoint", "https://api.example.com/login", {}, "fixture", 0.9)])
    result = asyncio.run(replanner.replan(env[2].id, trigger="initial_scan", trigger_task_id=1))
    decision = env[6].get(result.decision_ids[0])
    env[6].set_status(decision.id, "approved")
    # Same evidence plus a new materially different endpoint observation causes a new context.
    env[9].ingest(env[2].id, [ObservationInput("technology", "api.example.com", {"name": "fixture"}, "fixture", 0.9)])
    replanned = asyncio.run(replanner.replan(env[2].id, trigger="task_succeeded", trigger_task_id=2))
    # The original endpoint hypothesis remains active because technology evidence adds information;
    # to exercise the execution guard directly, supersede the approved decision explicitly.
    env[6].supersede(decision.id, "test invalidation")
    from beltu.execution.service import ExecutionService
    del replanned
    # A real dispatcher is not needed: request_from_decision performs the authoritative gate first.
    approvals = ApprovalService(env[6], ApprovalRepository(env[0]))
    class StubDispatcher:
        async def execute(self, request):
            raise AssertionError("must not execute")
    service = ExecutionService(env[6], StubDispatcher(), approvals)
    try:
        service.request_from_decision(decision.id)
    except (ValueError, PermissionError) as exc:
        assert "not executable" in str(exc) or "requires explicit approval" in str(exc)
    else:
        raise AssertionError("superseded decision was considered executable")


def test_cycle_budget_is_persistent_and_bounded(tmp_path):
    env = make_env(tmp_path)
    replanner = make_replanner(env, max_cycles_per_scan=1, auto_execute_low_risk=False)
    first = asyncio.run(replanner.replan(env[2].id, trigger="initial_scan", trigger_task_id=1))
    second = asyncio.run(replanner.replan(env[2].id, trigger="task_failed", trigger_task_id=2))
    assert first.cycle.status == "succeeded"
    assert second.cycle.status == "skipped"
    assert env[7].count_for_scan(env[2].id) == 2


def test_event_bus_feedback_handler_replans_only_capability_tasks(tmp_path):
    env = make_env(tmp_path)
    events = EventBus()
    seen = []
    replanner = make_replanner(env, events=events, enqueue_task=lambda task: asyncio.sleep(0))
    replanner.install()
    events.subscribe_sync("replan.completed", lambda event: _record(seen, event))
    # Publish unrelated agent task — must be ignored.
    asyncio.run(events.publish("task.succeeded", {"task_id": 999999}))
    assert seen == []
    # Create a capability task so the handler can process it.
    task = env[3].create(env[2].id, "capability.execute", {"decision_id": 0})
    env[3].mark_running(task.id)
    env[3].mark_succeeded(task.id, {"ok": True})
    asyncio.run(events.publish("task.succeeded", {"task_id": task.id}))
    assert len(seen) == 1


def _record(bucket, event):
    bucket.append(event.payload)

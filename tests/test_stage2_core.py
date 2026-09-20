from pathlib import Path

from beltu.common.enums import ScanStatus, TaskStatus
from beltu.core.event_bus import EventBus
from beltu.core.orchestrator import Orchestrator
from beltu.execution.scheduler import Scheduler
from beltu.policy.scope_guard import ScopeGuard
from beltu.storage.database import Database
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository
from beltu.storage.repositories.task_repository import TaskRepository
from beltu.core.agent import Agent
import asyncio


def build(tmp_path: Path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    targets = TargetRepository(db)
    scans = ScanRepository(db)
    tasks = TaskRepository(db)
    events = EventBus()
    scheduler = Scheduler(tasks, scans, targets, events, workers=2)
    scheduler.register("agent.evaluate", lambda task: asyncio.sleep(0, result={"ok": True}))
    orchestrator = Orchestrator(targets, scans, tasks, scheduler, events)
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text("targets:\n  - example.com\n", encoding="utf-8")
    agent = Agent(targets, ScopeGuard(scope_file), orchestrator)
    return agent, scans, tasks, orchestrator


def test_scan_task_lifecycle_persists(tmp_path: Path):
    async def run():
        agent, scans, tasks, orchestrator = build(tmp_path)
        target = agent.register_target("example.com")
        await orchestrator.start()
        scan, task = await agent.start_scan(target.id)
        await orchestrator.scheduler.queue.join()
        await orchestrator.stop()
        return scans.get(scan.id), tasks.get(task.id)

    scan, task = asyncio.run(run())
    assert scan is not None
    assert scan.status == ScanStatus.SUCCEEDED.value
    assert task is not None
    assert task.status == TaskStatus.SUCCEEDED.value
    assert task.result == {"ok": True}


def test_event_bus_delivers_events():
    events = []

    async def run():
        bus = EventBus()

        async def handler(event):
            events.append((event.type, event.payload))

        await bus.subscribe("task.succeeded", handler)
        await bus.publish("task.succeeded", {"task_id": 7})

    asyncio.run(run())
    assert events == [("task.succeeded", {"task_id": 7})]

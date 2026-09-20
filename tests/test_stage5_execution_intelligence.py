from __future__ import annotations

import asyncio
from pathlib import Path

from beltu.common.enums import ScanStatus
from beltu.execution.adapters.base import ToolAdapter
from beltu.execution.models import ExecutionRequest
from beltu.execution.process_manager import ProcessManager
from beltu.execution.resource_governor import LinuxResourceMonitor, ResourceGovernor, ResourceSnapshot
from beltu.execution.retry_manager import RetryManager
from beltu.execution.scheduler import Scheduler
from beltu.execution.registry.capability_registry import CapabilityRegistry
from beltu.execution.registry.tool_registry import ToolRegistry
from beltu.storage.database import Database
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository
from beltu.storage.repositories.task_repository import TaskRepository
from beltu.core.event_bus import EventBus


class TrueAdapter(ToolAdapter):
    name = "fixture-true-stage5"
    capability = "fixture.stage5"
    binary = "true"

    def build_argv(self, request: ExecutionRequest) -> list[str]:
        return [self.binary, request.target]


def test_resource_snapshot_has_linux_or_fallback_fields():
    snap = LinuxResourceMonitor().snapshot()
    assert snap.cpu_count >= 1
    assert 0 <= snap.beltu_cpu_percent <= 100
    assert 0 <= snap.host_cpu_percent <= 100
    assert snap.memory_total_bytes >= 0


def test_effective_capacity_adapts_to_pressure():
    governor = ResourceGovernor(max_concurrent_processes=4, cpu_budget_percent=30, memory_budget_percent=30)
    quiet = ResourceSnapshot(0, 5, 1, 20, 30, 1, 1, 0, 1, 0, 0)
    busy = ResourceSnapshot(0, 50, 1, 70, 30, 1, 1, 0, 1, 0, 0)
    assert governor.effective_capacity(quiet) == 4
    assert governor.effective_capacity(busy) == 1


def test_retry_manager_backoff_and_limit():
    manager = RetryManager(base_delay=0.5, max_delay=5, jitter=0)
    first = manager.decide(1, 3)
    final = manager.decide(3, 3)
    assert first.retry and first.delay_seconds == 0.5
    assert not final.retry


def build(tmp_path: Path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    targets = TargetRepository(db)
    scans = ScanRepository(db)
    tasks = TaskRepository(db)
    target = targets.add("example.com")
    scan = scans.create(target.id, ScanStatus.RUNNING)
    events = EventBus()
    scheduler = Scheduler(tasks, scans, targets, events, workers=1, retry_manager=RetryManager(jitter=0))
    return tasks, scans, scheduler, scan


def test_task_priority_is_persisted_and_queue_orders_high_first(tmp_path: Path):
    tasks, _, scheduler, scan = build(tmp_path)
    low = tasks.create(scan.id, "low", priority=10)
    high = tasks.create(scan.id, "high", priority=90)

    async def run():
        await scheduler.enqueue(low)
        await scheduler.enqueue(high)
        first = await scheduler.queue.get()
        scheduler.queue.task_done()
        second = await scheduler.queue.get()
        scheduler.queue.task_done()
        return first, second

    first, second = asyncio.run(run())
    assert first.id == high.id
    assert second.id == low.id


def test_scheduler_retries_transient_errors(tmp_path: Path):
    tasks, scans, scheduler, scan = build(tmp_path)
    task = tasks.create(scan.id, "fixture.retry", max_attempts=2, priority=100)
    scheduler.retry_manager = RetryManager(base_delay=0.01, max_delay=0.02, jitter=0)
    calls = {"count": 0}

    async def handler(current):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("transient")
        return {"ok": True}

    scheduler.register("fixture.retry", handler)

    async def run():
        await scheduler.start()
        await asyncio.sleep(0.05)
        current = tasks.get(task.id)
        assert current is not None
        await scheduler.queue.join()
        await scheduler.queue.join()
        await scheduler.stop()

    asyncio.run(run())
    final = tasks.get(task.id)
    assert final is not None and final.status == "succeeded"
    assert final.attempts == 2
    assert calls["count"] == 2


def test_database_migrates_new_task_columns(tmp_path: Path):
    db = Database(tmp_path / "beltu.db")
    db.initialize()
    columns = {row[1] for row in db.connect().execute("PRAGMA table_info(tasks)")}
    assert {"priority", "max_attempts", "next_run_at"}.issubset(columns)


def test_scheduler_restores_delayed_pending_task_after_restart(tmp_path: Path):
    tasks, _, scheduler, scan = build(tmp_path)
    task = tasks.create(scan.id, "fixture.future", priority=90)
    from datetime import datetime, timedelta, timezone
    future = (datetime.now(timezone.utc) + timedelta(seconds=0.05)).isoformat()
    scheduled = tasks.schedule_retry(task.id, future, "deferred")

    calls = {"count": 0}
    async def handler(current):
        calls["count"] += 1
        return {"restored": True}

    scheduler.register("fixture.future", handler)

    async def run():
        await scheduler.start()
        await asyncio.sleep(0.10)
        await scheduler.queue.join()
        await scheduler.stop()

    asyncio.run(run())
    final = tasks.get(scheduled.id)
    assert final is not None and final.status == "succeeded"
    assert calls["count"] == 1

from __future__ import annotations

from typing import Any

from beltu.common.enums import ScanStatus, TargetStatus, TaskStatus
from beltu.common.types import Scan, Task
from beltu.core.event_bus import EventBus
from beltu.execution.scheduler import Scheduler
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.target_repository import TargetRepository
from beltu.storage.repositories.task_repository import TaskRepository


class Orchestrator:
    """Owns scan/task lifecycle and connects persistence to the async scheduler."""

    def __init__(
        self,
        targets: TargetRepository,
        scans: ScanRepository,
        tasks: TaskRepository,
        scheduler: Scheduler,
        events: EventBus,
    ) -> None:
        self.targets = targets
        self.scans = scans
        self.tasks = tasks
        self.scheduler = scheduler
        self.events = events

    async def start(self) -> None:
        self.scans.recover_interrupted()
        self.tasks.recover_interrupted()
        await self.scheduler.start()

    async def stop(self) -> None:
        await self.scheduler.stop()

    async def create_scan(self, target_id: int, kind: str = "agent.evaluate", payload: dict[str, Any] | None = None) -> tuple[Scan, Task]:
        target = self.targets.get(target_id)
        if target is None:
            raise ValueError(f"Target #{target_id} not found")
        if target.status == TargetStatus.BLOCKED.value:
            raise ValueError(f"Target #{target_id} is blocked")
        if target.status == TargetStatus.NEW.value:
            self.targets.set_status(target_id, TargetStatus.ACTIVE)
        scan = self.scans.create(target_id, ScanStatus.RUNNING)
        task = self.tasks.create(scan.id, kind, payload)
        await self.scheduler.enqueue(task)
        await self.events.publish("scan.created", {"scan_id": scan.id, "target_id": target_id})
        return scan, task

    async def pause_scan(self, scan_id: int) -> bool:
        changed = self.scans.set_status(scan_id, ScanStatus.PAUSED)
        if changed:
            for task in self.tasks.list_for_scan(scan_id):
                if task.status in {"pending", "running"}:
                    self.tasks.set_status(task.id, TaskStatus.CANCELLED)
            await self.events.publish("scan.paused", {"scan_id": scan_id})
        return changed

    async def resume_scan(self, scan_id: int) -> bool:
        scan = self.scans.get(scan_id)
        if scan is None or scan.status not in {ScanStatus.PAUSED.value, ScanStatus.FAILED.value, ScanStatus.PENDING.value}:
            return False
        self.scans.set_status(scan_id, ScanStatus.RUNNING)
        runnable = self.tasks.list_for_scan(scan_id)
        for task in runnable:
            if task.status in {"cancelled", "failed"}:
                task = self.tasks.set_status(task.id, TaskStatus.PENDING)
            if task.status == "pending":
                await self.scheduler.enqueue(task)
        await self.events.publish("scan.resumed", {"scan_id": scan_id})
        return True

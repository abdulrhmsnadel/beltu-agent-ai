from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from beltu.common.enums import ScanStatus, TaskStatus
from beltu.common.types import Task
from beltu.core.event_bus import EventBus
from beltu.execution.retry_manager import RetryManager
from beltu.execution.task_queue import TaskQueue
from beltu.storage.repositories.scan_repository import ScanRepository
from beltu.storage.repositories.task_repository import TaskRepository
from beltu.storage.repositories.target_repository import TargetRepository

TaskHandler = Callable[[Task], Awaitable[dict[str, Any] | None]]


class Scheduler:
    """Persistent priority scheduler with retry/backoff and async workers."""

    def __init__(
        self,
        tasks: TaskRepository,
        scans: ScanRepository,
        targets: TargetRepository,
        events: EventBus,
        workers: int = 2,
        retry_manager: RetryManager | None = None,
    ) -> None:
        self.tasks = tasks
        self.scans = scans
        self.targets = targets
        self.events = events
        self.workers = max(1, int(workers))
        self.queue = TaskQueue()
        self.handlers: dict[str, TaskHandler] = {}
        self.retry_manager = retry_manager or RetryManager()
        self._stop = asyncio.Event()
        self._worker_tasks: list[asyncio.Task[None]] = []
        self._delayed_tasks: list[asyncio.Task[None]] = []

    def register(self, kind: str, handler: TaskHandler) -> None:
        self.handlers[kind] = handler

    async def start(self) -> None:
        self._stop.clear()
        now = datetime.now(timezone.utc)
        for task in self.tasks.list_pending():
            if task.next_run_at:
                try:
                    run_at = datetime.fromisoformat(task.next_run_at)
                    delay = max(0.0, (run_at - now).total_seconds())
                except ValueError:
                    delay = 0.0
                if delay > 0:
                    self._delayed_tasks.append(asyncio.create_task(self._requeue_after(task, delay)))
                    continue
            await self.queue.put(task)
        if not self._worker_tasks:
            self._worker_tasks = [asyncio.create_task(self._worker(i)) for i in range(self.workers)]

    async def stop(self) -> None:
        self._stop.set()
        for worker in self._worker_tasks:
            worker.cancel()
        if self._worker_tasks:
            await asyncio.gather(*self._worker_tasks, return_exceptions=True)
        self._worker_tasks.clear()
        for delayed in self._delayed_tasks:
            delayed.cancel()
        if self._delayed_tasks:
            await asyncio.gather(*self._delayed_tasks, return_exceptions=True)
        self._delayed_tasks.clear()

    async def enqueue(self, task: Task) -> None:
        await self.queue.put(task)

    async def _worker(self, worker_id: int) -> None:
        while not self._stop.is_set():
            try:
                task = await asyncio.wait_for(self.queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            try:
                await self._execute(task, worker_id)
            finally:
                self.queue.task_done()

    async def _execute(self, task: Task, worker_id: int) -> None:
        handler = self.handlers.get(task.kind)
        if handler is None:
            failed = self.tasks.mark_failed(task.id, f"No handler registered for task kind: {task.kind}")
            await self.events.publish("task.failed", {"task_id": failed.id, "reason": "missing_handler"})
            return

        current = self.tasks.get(task.id)
        if current is None or current.status != TaskStatus.PENDING.value:
            return

        running = self.tasks.mark_running(task.id)
        await self.events.publish("task.running", {"task_id": running.id, "worker_id": worker_id, "attempt": running.attempts})
        try:
            result = await handler(running)
        except asyncio.CancelledError:
            raise
        except (PermissionError, ValueError) as exc:
            await self._final_failure(running, str(exc), retryable=False)
            return
        except Exception as exc:
            await self._handle_failure(running, str(exc), retryable=True)
            return

        succeeded = self.tasks.mark_succeeded(task.id, result)
        await self.events.publish("task.succeeded", {"task_id": succeeded.id, "result": succeeded.result or {}})

        siblings = self.tasks.list_for_scan(succeeded.scan_id)
        if siblings and all(item.status == TaskStatus.SUCCEEDED.value for item in siblings):
            self.scans.set_status(succeeded.scan_id, ScanStatus.SUCCEEDED)
            await self.events.publish("scan.succeeded", {"scan_id": succeeded.scan_id})

    async def _handle_failure(self, task: Task, error: str, *, retryable: bool) -> None:
        decision = self.retry_manager.decide(task.attempts, task.max_attempts, retryable=retryable)
        if decision.retry:
            next_run = datetime.now(timezone.utc) + timedelta(seconds=decision.delay_seconds)
            scheduled = self.tasks.schedule_retry(task.id, next_run.isoformat(), error)
            await self.events.publish(
                "task.retry_scheduled",
                {"task_id": scheduled.id, "attempt": scheduled.attempts, "delay_seconds": decision.delay_seconds, "error": error},
            )
            delayed = asyncio.create_task(self._requeue_after(scheduled, decision.delay_seconds))
            self._delayed_tasks.append(delayed)
            return
        await self._final_failure(task, error, retryable=retryable)

    async def _final_failure(self, task: Task, error: str, *, retryable: bool) -> None:
        failed = self.tasks.mark_failed(task.id, error)
        self.scans.set_status(failed.scan_id, ScanStatus.FAILED)
        await self.events.publish("task.failed", {"task_id": failed.id, "error": error, "retryable": retryable})

    async def _requeue_after(self, task: Task, delay: float) -> None:
        await asyncio.sleep(delay)
        if self._stop.is_set():
            return
        current = self.tasks.get(task.id)
        if current and current.status == TaskStatus.PENDING.value:
            await self.queue.put(current)

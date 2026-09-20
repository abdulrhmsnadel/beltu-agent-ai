from __future__ import annotations

import asyncio
from dataclasses import dataclass

from beltu.common.types import Task


@dataclass(frozen=True, slots=True)
class _QueuedTask:
    priority_key: int
    sequence: int
    task: Task

    def __lt__(self, other: '_QueuedTask') -> bool:
        if self.priority_key != other.priority_key:
            return self.priority_key < other.priority_key
        return self.sequence < other.sequence


class TaskQueue:
    """Priority queue: higher Task.priority values execute first."""

    def __init__(self) -> None:
        self._queue: asyncio.PriorityQueue[_QueuedTask] = asyncio.PriorityQueue()
        self._sequence = 0

    async def put(self, task: Task) -> None:
        self._sequence += 1
        await self._queue.put(_QueuedTask(-int(task.priority), self._sequence, task))

    async def get(self) -> Task:
        return (await self._queue.get()).task

    def task_done(self) -> None:
        self._queue.task_done()

    async def join(self) -> None:
        await self._queue.join()

    def qsize(self) -> int:
        return self._queue.qsize()

from __future__ import annotations

import asyncio
from typing import Any

from beltu.common.types import Event
from beltu.core.event_bus import EventBus


class EventHub:
    def __init__(self, event_bus: EventBus | None = None) -> None:
        self.event_bus = event_bus
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        if self.event_bus is not None:
            await self.event_bus.subscribe("*", self._on_event)

    async def _on_event(self, event: Event) -> None:
        message = {"type": event.type, "payload": event.payload, "created_at": event.occurred_at}
        async with self._lock:
            queues = list(self._subscribers)
        for queue in queues:
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                pass

    async def subscribe(self, maxsize: int = 200) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=maxsize)
        async with self._lock:
            self._subscribers.add(queue)
        return queue

    async def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        async with self._lock:
            self._subscribers.discard(queue)

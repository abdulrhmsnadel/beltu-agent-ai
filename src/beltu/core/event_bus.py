from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any

from beltu.common.types import Event

Handler = Callable[[Event], Awaitable[None]]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EventBus:
    def __init__(self) -> None:
        self._handlers: dict[str, list[Handler]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def subscribe(self, event_type: str, handler: Handler) -> None:
        async with self._lock:
            self._handlers[event_type].append(handler)

    def subscribe_sync(self, event_type: str, handler: Handler) -> None:
        """Register a handler before the runtime loop starts. Safe for composition-time wiring."""
        self._handlers[event_type].append(handler)

    async def publish(self, event_type: str, payload: dict[str, Any] | None = None) -> None:
        event = Event(event_type, payload or {}, utc_now())
        async with self._lock:
            handlers = [*self._handlers.get(event_type, ()), *self._handlers.get("*", ())]
        if handlers:
            await asyncio.gather(*(handler(event) for handler in handlers))

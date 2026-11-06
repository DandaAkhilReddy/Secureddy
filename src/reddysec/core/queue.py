"""Job queue abstraction.

Development and tests use the in-memory queue. Production uses Azure Service
Bus (see infra) through the same interface; the worker never knows which.
"""

from __future__ import annotations

import asyncio
from collections import deque
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from .ids import new_id


class Job(BaseModel):
    id: str = Field(default_factory=lambda: new_id("job"))
    kind: str
    payload: dict[str, Any] = Field(default_factory=dict)
    attempts: int = 0
    max_attempts: int = 3
    enqueued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_error: str | None = None


@runtime_checkable
class JobQueue(Protocol):
    async def enqueue(self, job: Job) -> None: ...
    async def dequeue(self, kinds: set[str] | None = None, timeout: float | None = None) -> Job | None: ...
    async def ack(self, job: Job) -> None: ...
    async def fail(self, job: Job, error: str) -> None: ...
    async def size(self) -> int: ...


class InMemoryJobQueue:
    def __init__(self) -> None:
        self._items: deque[Job] = deque()
        self._dead: list[Job] = []
        self._cond = asyncio.Condition()

    async def enqueue(self, job: Job) -> None:
        async with self._cond:
            self._items.append(job)
            self._cond.notify()

    async def dequeue(self, kinds: set[str] | None = None, timeout: float | None = None) -> Job | None:
        async def _take() -> Job | None:
            async with self._cond:
                while True:
                    for i, j in enumerate(self._items):
                        if kinds is None or j.kind in kinds:
                            del self._items[i]
                            j.attempts += 1
                            return j
                    await self._cond.wait()

        if timeout is None:
            return await _take()
        try:
            return await asyncio.wait_for(_take(), timeout)
        except TimeoutError:
            return None

    async def ack(self, job: Job) -> None:  # nothing to do for in-memory
        return None

    async def fail(self, job: Job, error: str) -> None:
        job.last_error = error
        if job.attempts >= job.max_attempts:
            self._dead.append(job)
            return
        await self.enqueue(job)

    async def size(self) -> int:
        return len(self._items)

    @property
    def dead_letters(self) -> list[Job]:
        return list(self._dead)

"""Importable fakes for the chamber unit tests.

A uniquely named module (not ``conftest``) so test files in different
directories can ``from chamber_helpers import ...`` without the two-conftests
``sys.modules`` collision.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path
from typing import Any

from reddysec.chamber.readingroom import ReadingRoomSession, RoomSender
from reddysec.models import DetonationJob, DetonationKind, DetonationResult, DetonationStatus, PageFeatures


def url_job(url: str = "https://example.com", **kw: Any) -> DetonationJob:
    return DetonationJob(job_id=kw.pop("job_id", "det_test"), kind=DetonationKind.URL, url=url, **kw)


def ok_result(job: DetonationJob, **kw: Any) -> DetonationResult:
    return DetonationResult(
        job_id=job.job_id,
        status=kw.pop("status", DetonationStatus.OK),
        features=kw.pop("features", PageFeatures(title="ok", final_url=job.url, status_code=200)),
        **kw,
    )


class RecordingBackend:
    """A SandboxBackend that returns a scripted result and records calls.

    ``delay`` makes the backend outlast the chamber's deadline; the in-flight
    counters let a test assert the semaphore is doing its job.
    """

    def __init__(self, name: str = "fake", result: DetonationResult | Callable[[DetonationJob], DetonationResult] | None = None) -> None:
        self.name = name
        self.result = result
        self.calls: list[DetonationJob] = []
        self.delay = 0.0
        self.raise_exc: Exception | None = None
        self.in_flight = 0
        self.max_in_flight = 0

    async def run(self, job: DetonationJob) -> DetonationResult:
        self.calls.append(job)
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            if self.raise_exc is not None:
                raise self.raise_exc
            if callable(self.result):
                return self.result(job)
            if self.result is not None:
                return self.result.model_copy(update={"job_id": job.job_id})
            return ok_result(job)
        finally:
            self.in_flight -= 1


class FakeRoomEngine:
    """A RoomEngine that never touches a browser. Records inputs, lets tests
    push outbound messages through the attached sender, and can be told to
    fail ``start`` or ``handle_input``."""

    def __init__(self, session: ReadingRoomSession, *, workdir: Path, on_download: Any) -> None:
        self.session = session
        self.workdir = workdir
        self.on_download = on_download
        self.started_url: str | None = None
        self.inputs: list[dict[str, Any]] = []
        self.closed = False
        self.start_error: Exception | None = None
        self.input_error: Exception | None = None
        self._senders: list[RoomSender] = []

    def attach(self, send: RoomSender) -> Callable[[], None]:
        self._senders.append(send)

        def detach() -> None:
            if send in self._senders:
                self._senders.remove(send)

        return detach

    async def start(self, session: ReadingRoomSession, url: str) -> None:
        if self.start_error is not None:
            raise self.start_error
        self.started_url = url

    async def handle_input(self, event: dict[str, Any]) -> None:
        if self.input_error is not None:
            raise self.input_error
        self.inputs.append(event)

    async def close(self) -> None:
        self.closed = True

    async def emit(self, message: dict[str, Any] | bytes) -> None:
        for send in list(self._senders):
            await send(message)

    async def trigger_download(self, path_name: str, data: bytes, suggested: str) -> None:
        target = self.workdir / path_name
        target.write_bytes(data)
        await self.on_download(target, suggested)

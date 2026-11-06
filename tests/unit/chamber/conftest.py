"""Fixtures for the chamber unit tests. No browser, no network.

Shared fakes live in ``chamber_helpers`` (a uniquely named module) so test
files can import them directly; this conftest only supplies fixtures.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from reddysec.chamber.readingroom import ReadingRoomSession

from .chamber_helpers import (
    FakeRoomEngine,  # noqa: E402  (test-tree module, resolved via prepend import mode)
)


@pytest.fixture(autouse=True)
def offline_dns(request, monkeypatch):
    """Unit tests never touch the real resolver. Hostnames resolve to a fixed
    public address; tests that want a different answer re-patch ``resolve_host``
    themselves (the later patch wins). IP literals and internal names
    short-circuit before resolution and are unaffected.

    ``test_targets`` exercises the real resolver, so it opts out."""
    if request.module.__name__ == "test_targets":
        return
    import ipaddress

    from reddysec.chamber import targets

    async def fake_resolve(host, timeout_s=5.0):
        literal = targets.parse_ip_literal(host)
        if literal is not None:  # keep the real literal short-circuit (loopback, metadata, ...)
            return [literal]
        return [ipaddress.ip_address("93.184.216.34")]

    monkeypatch.setattr(targets, "resolve_host", fake_resolve)


@pytest.fixture
def store(tmp_path):
    from reddysec.core.artifacts import LocalArtifactStore

    return LocalArtifactStore(tmp_path / "artifacts")


@pytest.fixture
def fake_engine_factory():
    """Returns (factory, created) where ``created`` collects the engines made."""
    created: list[FakeRoomEngine] = []

    def factory(session: ReadingRoomSession, *, workdir: Path, on_download: Any) -> FakeRoomEngine:
        engine = FakeRoomEngine(session, workdir=workdir, on_download=on_download)
        created.append(engine)
        return engine

    return factory, created


@pytest.fixture
def frozen_clock():
    """A controllable clock for the idle reaper."""

    class Clock:
        def __init__(self) -> None:
            self.now = datetime(2026, 1, 1, tzinfo=UTC)

        def __call__(self) -> datetime:
            return self.now

        def advance(self, seconds: float) -> None:
            self.now += timedelta(seconds=seconds)

    return Clock()

"""Unit tests for the Reading Room engine's non-browser helpers: the client
fan-out, the known-login-host check and ``_quiet``."""

from __future__ import annotations

from datetime import UTC, datetime

from reddysec.chamber.readingroom import (
    DEFAULT_KNOWN_LOGIN_DOMAINS,
    PlaywrightRoomEngine,
    ReadingRoomSession,
    _Fanout,
    _quiet,
)


class TestFanout:
    async def test_emit_to_all(self):
        fan = _Fanout()
        got_a, got_b = [], []
        fan.attach(lambda m: _collect(got_a, m))
        fan.attach(lambda m: _collect(got_b, m))
        await fan.emit({"t": "frame"})
        assert got_a and got_b and fan.count == 2

    async def test_failing_sender_is_dropped(self):
        fan = _Fanout()
        good = []

        async def bad(_m):
            raise RuntimeError("socket closed")

        fan.attach(bad)
        fan.attach(lambda m: _collect(good, m))
        await fan.emit({"t": "frame"})
        assert good  # the good sender still got it
        assert fan.count == 1  # the bad one was removed

    async def test_detach(self):
        fan = _Fanout()
        got = []
        detach = fan.attach(lambda m: _collect(got, m))
        detach()
        await fan.emit({"t": "x"})
        assert not got and fan.count == 0


async def _collect(bucket, message):
    bucket.append(message)


class TestKnownLoginHost:
    def _engine(self):
        session = ReadingRoomSession(session_id="room_1", principal_id="p", url="https://x.com", created_at=datetime.now(UTC), last_activity_at=datetime.now(UTC))

        async def provider():
            raise AssertionError("browser should not be launched in this test")

        async def on_download(path, name):
            return None

        return PlaywrightRoomEngine(session, browser_provider=provider, workdir=__import__("pathlib").Path("/tmp"), on_download=on_download)

    def test_known_hosts(self):
        engine = self._engine()
        assert engine.is_known_login_host("chase.com")
        assert engine.is_known_login_host("login.chase.com")  # subdomain -> registrable domain
        assert engine.is_known_login_host("accounts.google.com")

    def test_unknown_host(self):
        engine = self._engine()
        assert not engine.is_known_login_host("127.0.0.1")
        assert not engine.is_known_login_host("chase.com.evil.example")

    def test_default_list_is_frozen(self):
        assert isinstance(DEFAULT_KNOWN_LOGIN_DOMAINS, frozenset)
        assert len(DEFAULT_KNOWN_LOGIN_DOMAINS) > 20


class TestQuiet:
    async def test_swallows_exceptions(self):
        async def boom():
            raise RuntimeError("x")

        assert await _quiet(boom()) is None

    async def test_returns_value(self):
        async def ok():
            return 42

        assert await _quiet(ok()) == 42

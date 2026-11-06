"""Unit tests for ReadingRoomManager with a fake engine (no browser).

Input validation, client fan-out, download + CDR handling, idle reaping, the
session cap, the password-warning path and failure handling are all here.
"""

from __future__ import annotations

import asyncio

import pytest

from reddysec.chamber.readingroom import (
    DEFAULT_KNOWN_LOGIN_DOMAINS,
    ReadingRoomManager,
    RoomClosed,
    RoomFull,
    RoomInputError,
    RoomNotFound,
    RoomUrlError,
    validate_input,
    validate_room_url,
)
from reddysec.models import RoomState


@pytest.fixture
def manager(store, fake_engine_factory, frozen_clock):
    factory, created = fake_engine_factory
    mgr = ReadingRoomManager(store, max_sessions=3, idle_timeout_s=300, engine_factory=factory, clock=frozen_clock)
    mgr._created = created  # type: ignore[attr-defined]
    mgr._clock_obj = frozen_clock  # type: ignore[attr-defined]
    return mgr


class Collector:
    def __init__(self):
        self.messages = []

    async def __call__(self, message):
        self.messages.append(message)

    def of_type(self, t):
        return [m for m in self.messages if isinstance(m, dict) and m.get("t") == t]


# --- URL validation ------------------------------------------------------------------


class TestValidateUrl:
    @pytest.mark.parametrize("url", ["https://example.com", "http://example.com/x?y=1"])
    def test_valid(self, url):
        assert validate_room_url(url) == url

    def test_adds_https_scheme(self):
        assert validate_room_url("example.com/path") == "https://example.com/path"

    @pytest.mark.parametrize(
        "url",
        ["ftp://x.com", "file:///etc/passwd", "javascript:alert(1)", "https://", "", 123, "x" * 5000, "https://host:999999999/"],
    )
    def test_invalid(self, url):
        with pytest.raises(RoomUrlError):
            validate_room_url(url)


# --- input validation ----------------------------------------------------------------


class TestValidateInput:
    def test_mouse_click(self):
        out = validate_input({"t": "mouse", "action": "click", "x": 10, "y": 20})
        assert out == {"t": "mouse", "action": "click", "button": "left", "x": 10.0, "y": 20.0}

    def test_mouse_wheel(self):
        out = validate_input({"t": "mouse", "action": "wheel", "x": 1, "y": 2, "deltaY": 100})
        assert out["deltaY"] == 100.0 and out["deltaX"] == 0.0

    def test_mouse_coords_clamped(self):
        out = validate_input({"t": "mouse", "action": "move", "x": 99999, "y": -50})
        assert out["x"] <= 3840 and out["y"] == 0.0

    def test_key_press(self):
        assert validate_input({"t": "key", "action": "press", "key": "a", "text": "a"})["key"] == "a"

    def test_nav_validates_url(self):
        assert validate_input({"t": "nav", "url": "example.com"})["url"] == "https://example.com"

    @pytest.mark.parametrize("event", [{"t": "back"}, {"t": "forward"}, {"t": "reload"}, {"t": "ping"}])
    def test_simple_events(self, event):
        assert validate_input(event) == event

    def test_resize_clamped(self):
        assert validate_input({"t": "resize", "w": 99999, "h": 10}) == {"t": "resize", "w": 1920, "h": 320}

    @pytest.mark.parametrize(
        "event",
        [
            "not a dict",
            {"t": "mouse", "action": "teleport"},
            {"t": "mouse", "action": "click", "button": "scroll"},
            {"t": "key", "action": "smash", "key": "a"},
            {"t": "key", "action": "press", "key": ""},
            {"t": "key", "action": "press", "key": "x" * 50},
            {"t": "nav", "url": "ftp://x"},
            {"t": "unknown"},
            {"t": "mouse", "action": "move", "x": float("nan"), "y": 1},
            {"t": "mouse", "action": "move", "x": float("inf"), "y": 1},
        ],
    )
    def test_rejected(self, event):
        with pytest.raises(RoomInputError):
            validate_input(event)


# --- lifecycle -----------------------------------------------------------------------


class TestLifecycle:
    async def test_start_sets_ready_and_passes_url(self, manager):
        session = await manager.start("example.com/doc", "prin_1")
        assert session.state is RoomState.READY
        assert manager._created[0].started_url == "https://example.com/doc"
        assert manager.active_count == 1

    async def test_bad_url_raises_before_engine(self, manager):
        with pytest.raises(RoomUrlError):
            await manager.start("ftp://x", "prin_1")
        assert manager.active_count == 0

    async def test_session_cap(self, manager):
        for i in range(3):
            await manager.start("example.com", f"prin_{i}")
        with pytest.raises(RoomFull):
            await manager.start("example.com", "prin_x")

    async def test_cap_frees_after_close(self, manager):
        sessions = [await manager.start("example.com", "p") for _ in range(3)]
        await manager.close(sessions[0].session_id)
        assert manager.active_count == 2
        await manager.start("example.com", "p")  # no longer full

    async def test_start_failure_marks_error(self, manager, fake_engine_factory):
        # Make the next engine fail to start.
        orig = manager._engine_factory

        def failing(session, *, workdir, on_download):
            engine = orig(session, workdir=workdir, on_download=on_download)
            engine.start_error = RuntimeError("chromium missing")
            return engine

        manager._engine_factory = failing
        session = await manager.start("example.com", "prin_1")
        assert session.state is RoomState.ERROR and "chromium missing" in session.error
        assert manager.active_count == 0

    async def test_get_returns_active_then_recent(self, manager):
        session = await manager.start("example.com", "prin_1")
        sid = session.session_id
        assert manager.get(sid) is session
        await manager.close(sid)
        assert manager.get(sid).state is RoomState.CLOSED  # still findable in recent
        assert manager.get("room_missing") is None

    async def test_list_for_principal(self, manager):
        await manager.start("example.com", "prin_a")
        await manager.start("example.com", "prin_a")
        await manager.start("example.com", "prin_b")
        assert len(manager.list_for("prin_a")) == 2
        assert len(manager.list_for("prin_b")) == 1


# --- clients + fan-out ---------------------------------------------------------------


class TestClients:
    async def test_attach_gets_snapshot(self, manager):
        session = await manager.start("example.com", "prin_1")
        client = Collector()
        manager.attach_client(session.session_id, client)
        await asyncio.sleep(0)  # let the snapshot task run
        assert client.of_type("state")

    async def test_engine_messages_reach_clients(self, manager):
        session = await manager.start("example.com", "prin_1")
        client = Collector()
        manager.attach_client(session.session_id, client)
        await manager._created[0].emit({"t": "frame", "b64": "xxx", "w": 100, "h": 80})
        assert client.of_type("frame")

    async def test_url_message_updates_session(self, manager):
        session = await manager.start("example.com", "prin_1")
        await manager._created[0].emit({"t": "url", "url": "https://example.com/next"})
        assert session.current_url == "https://example.com/next"

    async def test_detach_stops_delivery(self, manager):
        session = await manager.start("example.com", "prin_1")
        client = Collector()
        detach = manager.attach_client(session.session_id, client)
        detach()
        await manager._created[0].emit({"t": "frame", "b64": "y", "w": 1, "h": 1})
        assert not client.of_type("frame")

    async def test_attach_to_missing_raises(self, manager):
        with pytest.raises(RoomNotFound):
            manager.attach_client("room_missing", Collector())


# --- input dispatch ------------------------------------------------------------------


class TestInputDispatch:
    async def test_input_forwarded_and_updates_activity(self, manager):
        session = await manager.start("example.com", "prin_1")
        before = session.last_activity_at
        manager._clock_obj.advance(10)
        await manager.handle_input(session.session_id, {"t": "mouse", "action": "click", "x": 5, "y": 5})
        assert manager._created[0].inputs[-1]["action"] == "click"
        assert session.last_activity_at > before

    async def test_resize_updates_session(self, manager):
        session = await manager.start("example.com", "prin_1")
        await manager.handle_input(session.session_id, {"t": "resize", "w": 800, "h": 600})
        assert session.viewport_width == 800 and session.viewport_height == 600

    async def test_bad_input_raises(self, manager):
        session = await manager.start("example.com", "prin_1")
        with pytest.raises(RoomInputError):
            await manager.handle_input(session.session_id, {"t": "nope"})

    async def test_input_to_missing_raises(self, manager):
        with pytest.raises(RoomNotFound):
            await manager.handle_input("room_missing", {"t": "ping"})


# --- downloads + CDR -----------------------------------------------------------------


class TestDownloads:
    async def test_pdf_download_gets_safe_copy(self, manager):
        from .test_cdr import pdf_with_js

        session = await manager.start("example.com", "prin_1")
        client = Collector()
        manager.attach_client(session.session_id, client)
        await manager._created[0].trigger_download("dl_0", pdf_with_js(), "statement.pdf")
        assert len(session.downloads) == 1
        record = session.downloads[0]
        assert record.stored_ref is not None  # original kept
        assert record.safe_copy_ref is not None  # safe copy made
        msg = client.of_type("download")[-1]
        assert msg["safe_ready"] is True and msg["sniffed_type"] == "pdf"

    async def test_exe_download_has_no_safe_copy(self, manager):
        session = await manager.start("example.com", "prin_1")
        client = Collector()
        manager.attach_client(session.session_id, client)
        await manager._created[0].trigger_download("dl_0", b"MZ\x90\x00" + b"\x00" * 60, "invoice.exe")
        record = session.downloads[0]
        assert record.stored_ref is not None  # original still kept for the concierge
        assert record.safe_copy_ref is None
        msg = client.of_type("download")[-1]
        assert msg["safe_ready"] is False and msg["reason"]

    async def test_oversized_download_dropped(self, manager, monkeypatch):
        import reddysec.chamber.readingroom as rr

        monkeypatch.setattr(rr, "MAX_DOWNLOAD_BYTES", 100)
        session = await manager.start("example.com", "prin_1")
        await manager._created[0].trigger_download("dl_0", b"A" * 500, "big.bin")
        record = session.downloads[0]
        assert record.stored_ref is None and record.size == 500
        assert record.sha256  # hash still computed


# --- idle reaping --------------------------------------------------------------------


class TestIdleReaping:
    async def test_reaps_idle_sessions(self, manager):
        session = await manager.start("example.com", "prin_1")
        manager._clock_obj.advance(301)
        reaped = await manager.reap_idle()
        assert session.session_id in reaped
        assert manager.active_count == 0
        assert manager._created[0].closed

    async def test_keeps_active_sessions(self, manager):
        await manager.start("example.com", "prin_1")
        manager._clock_obj.advance(100)
        assert await manager.reap_idle() == []
        assert manager.active_count == 1

    async def test_activity_resets_idle(self, manager):
        session = await manager.start("example.com", "prin_1")
        manager._clock_obj.advance(200)
        await manager.handle_input(session.session_id, {"t": "ping"})
        manager._clock_obj.advance(200)  # 200 since last activity, < 300
        assert await manager.reap_idle() == []


# --- known-login-host warning path ---------------------------------------------------


class TestKnownLoginHosts:
    def test_default_list_has_major_brands(self):
        assert "chase.com" in DEFAULT_KNOWN_LOGIN_DOMAINS
        assert "google.com" in DEFAULT_KNOWN_LOGIN_DOMAINS

    async def test_close_emits_closed(self, manager):
        session = await manager.start("example.com", "prin_1")
        client = Collector()
        manager.attach_client(session.session_id, client)
        await manager.close(session.session_id)
        assert client.of_type("closed")

    async def test_engine_closed_event_tears_down(self, manager):
        session = await manager.start("example.com", "prin_1")
        client = Collector()
        manager.attach_client(session.session_id, client)
        await manager._created[0].emit({"t": "closed", "reason": "page crashed", "error": True})
        assert session.state is RoomState.ERROR
        assert manager.active_count == 0
        assert client.of_type("closed")

    async def test_closed_session_rejects_input(self, manager):
        session = await manager.start("example.com", "prin_1")
        await manager.close(session.session_id)
        with pytest.raises((RoomNotFound, RoomClosed)):
            await manager.handle_input(session.session_id, {"t": "ping"})


class TestManagerInternals:
    async def test_close_unknown_returns_false(self, manager):
        assert await manager.close("room_nope") is False

    async def test_shutdown_closes_browser_and_sessions(self, manager):
        await manager.start("example.com", "prin_1")

        class FakeBrowser:
            def __init__(self):
                self.closed = False

            async def close(self):
                self.closed = True

        class FakePlaywright:
            def __init__(self):
                self.stopped = False

            async def stop(self):
                self.stopped = True

        browser, pw = FakeBrowser(), FakePlaywright()
        manager._browser = browser
        manager._playwright = pw
        await manager.shutdown()
        assert manager.active_count == 0
        assert browser.closed and pw.stopped
        assert manager._browser is None and manager._playwright is None

    async def test_browser_lost_tears_down_all(self, manager):
        s1 = await manager.start("example.com", "prin_1")
        s2 = await manager.start("example.com", "prin_2")

        class FakeBrowser:
            pass

        browser = FakeBrowser()
        manager._browser = browser
        await manager._on_browser_lost(browser)
        assert manager.active_count == 0
        assert s1.state is RoomState.ERROR and s2.state is RoomState.ERROR
        assert "disconnected" in (s1.error or "")

    async def test_double_teardown_is_safe(self, manager):
        session = await manager.start("example.com", "prin_1")
        room = manager._rooms[session.session_id]
        await manager._teardown(room, reason="first")
        await manager._teardown(room, reason="second")  # already closing -> no-op
        assert manager.active_count == 0

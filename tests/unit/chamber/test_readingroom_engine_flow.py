"""Unit tests for PlaywrightRoomEngine's input/navigation/download handling,
driven with fake Playwright objects (page, mouse, keyboard, download, cdp) so
the branches are covered without a real browser."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import pytest

from reddysec.chamber import readingroom
from reddysec.chamber.readingroom import PlaywrightRoomEngine, ReadingRoomSession, RoomClosed


def make_session():
    now = datetime.now(UTC)
    return ReadingRoomSession(session_id="room_1", principal_id="p", url="https://x.com", created_at=now, last_activity_at=now, viewport_width=1280, viewport_height=800)


class FakeMouse:
    def __init__(self):
        self.events = []

    async def move(self, x, y, steps=1):
        self.events.append(("move", x, y))

    async def down(self, button="left"):
        self.events.append(("down", button))

    async def up(self, button="left"):
        self.events.append(("up", button))

    async def click(self, x, y, button="left"):
        self.events.append(("click", x, y, button))

    async def dblclick(self, x, y, button="left"):
        self.events.append(("dblclick", x, y, button))

    async def wheel(self, dx, dy):
        self.events.append(("wheel", dx, dy))


class FakeKeyboard:
    def __init__(self):
        self.events = []

    async def down(self, key):
        self.events.append(("down", key))

    async def up(self, key):
        self.events.append(("up", key))

    async def press(self, key):
        self.events.append(("press", key))

    async def insert_text(self, text):
        self.events.append(("insert", text))


class FakeFrame:
    def __init__(self, url, password_focused=False):
        self.url = url
        self._pw = password_focused

    async def evaluate(self, script):
        return self._pw


class FakePage:
    def __init__(self, url="https://x.com/"):
        self.mouse = FakeMouse()
        self.keyboard = FakeKeyboard()
        self._url = url
        self.main_frame = FakeFrame(url)
        self.frames = [self.main_frame]
        self.closed = False
        self.goto_calls = []
        self.viewport = None
        self.raise_on_goto = None

    def is_closed(self):
        return self.closed

    @property
    def url(self):
        return self._url

    async def goto(self, url, **kw):
        self.goto_calls.append(url)
        if self.raise_on_goto:
            raise self.raise_on_goto

    async def set_viewport_size(self, size):
        self.viewport = size


class FakeCdp:
    def __init__(self):
        self.sent = []

    async def send(self, method, params=None):
        self.sent.append((method, params))


class FakeBrowser:
    def __init__(self, connected=True):
        self._connected = connected

    def is_connected(self):
        return self._connected


class FakeContext:
    def __init__(self, connected=True):
        self.browser = FakeBrowser(connected)
        self.closed = False

    async def close(self):
        self.closed = True


async def _bare_engine(tmp_path, page=None):
    """An engine with its internals wired to fakes, no browser launched."""
    engine = PlaywrightRoomEngine(
        make_session(),
        browser_provider=_no_browser,
        workdir=tmp_path,
        on_download=_noop_download,
    )
    engine._page = page or FakePage()
    engine._context = FakeContext(connected=True)
    engine._cdp = FakeCdp()
    engine._streaming = True
    return engine


async def _no_browser():
    raise AssertionError("no browser in these tests")


async def _noop_download(path, name):
    return None


class TestInputDispatch:
    async def test_mouse_actions(self, tmp_path):
        engine = await _bare_engine(tmp_path)
        for action in ("move", "down", "up", "click", "dblclick"):
            await engine.handle_input({"t": "mouse", "action": action, "x": 5, "y": 6, "button": "left"})
        await engine.handle_input({"t": "mouse", "action": "wheel", "x": 5, "y": 6, "deltaX": 0, "deltaY": 100})
        kinds = [e[0] for e in engine._page.mouse.events]
        assert "click" in kinds and "wheel" in kinds and "dblclick" in kinds

    async def test_key_actions(self, tmp_path):
        engine = await _bare_engine(tmp_path)
        await engine.handle_input({"t": "key", "action": "down", "key": "Shift", "text": None})
        await engine.handle_input({"t": "key", "action": "up", "key": "Shift", "text": None})
        await engine.handle_input({"t": "key", "action": "press", "key": "Enter", "text": None})
        await engine.handle_input({"t": "key", "action": "press", "key": "KeyA", "text": "A"})  # composed -> insert_text
        kinds = [e[0] for e in engine._page.keyboard.events]
        assert "down" in kinds and "up" in kinds and "press" in kinds and "insert" in kinds

    async def test_nav_back_forward_reload(self, tmp_path):
        engine = await _bare_engine(tmp_path)
        engine._page.go_back = engine._page.goto  # reuse recorder
        engine._page.go_forward = engine._page.goto
        engine._page.reload = engine._page.goto
        await engine.handle_input({"t": "nav", "url": "https://example.com/"})
        await engine.handle_input({"t": "back"})
        await engine.handle_input({"t": "forward"})
        await engine.handle_input({"t": "reload"})
        await _drain(engine)
        assert "https://example.com/" in engine._page.goto_calls

    async def test_resize_restarts_screencast(self, tmp_path):
        engine = await _bare_engine(tmp_path)
        await engine.handle_input({"t": "resize", "w": 1024, "h": 640})
        assert engine._page.viewport == {"width": 1024, "height": 640}
        methods = [m for m, _ in engine._cdp.sent]
        assert "Page.stopScreencast" in methods and "Page.startScreencast" in methods

    async def test_ping_emits_pong(self, tmp_path):
        engine = await _bare_engine(tmp_path)
        got = []
        engine.attach(lambda m: _collect(got, m))
        await engine.handle_input({"t": "ping"})
        assert {"t": "pong"} in got

    async def test_input_on_closed_raises(self, tmp_path):
        engine = await _bare_engine(tmp_path)
        engine._closed = True
        with pytest.raises(RoomClosed):
            await engine.handle_input({"t": "ping"})

    async def test_input_failure_warns_when_page_alive(self, tmp_path):
        engine = await _bare_engine(tmp_path)
        got = []
        engine.attach(lambda m: _collect(got, m))

        async def boom(*a, **k):
            raise RuntimeError("transient")

        engine._page.mouse.click = boom
        await engine.handle_input({"t": "mouse", "action": "click", "x": 1, "y": 1, "button": "left"})
        await _drain(engine)
        assert any(m.get("code") == "input_failed" for m in got)


class TestNavigateAndScreencast:
    async def test_navigate_download_is_silent(self, tmp_path):
        engine = await _bare_engine(tmp_path)
        engine._page.raise_on_goto = RuntimeError("Page.goto: Download is starting")
        got = []
        engine.attach(lambda m: _collect(got, m))
        await engine._navigate("https://example.com/file")
        assert not any(m.get("t") == "warning" for m in got)

    async def test_navigate_failure_warns(self, tmp_path):
        engine = await _bare_engine(tmp_path)
        engine._page.raise_on_goto = RuntimeError("net::ERR_NAME_NOT_RESOLVED")
        got = []
        engine.attach(lambda m: _collect(got, m))
        await engine._navigate("https://nope.invalid/")
        assert any(m.get("code") == "navigation_failed" for m in got)

    async def test_screencast_frame_acks_and_pushes(self, tmp_path):
        engine = await _bare_engine(tmp_path)
        got = []
        engine.attach(lambda m: _collect(got, m))
        await engine._on_screencast_frame({"data": "b64data", "sessionId": "s1", "metadata": {"deviceWidth": 640, "deviceHeight": 480}})
        assert any(m.get("t") == "frame" and m["b64"] == "b64data" for m in got)
        assert ("Page.screencastFrameAck", {"sessionId": "s1"}) in engine._cdp.sent

    async def test_emit_title(self, tmp_path):
        page = FakePage()

        async def title():
            return "Hello"

        page.title = title
        engine = await _bare_engine(tmp_path, page=page)
        got = []
        engine.attach(lambda m: _collect(got, m))
        await engine._emit_title()
        assert any(m.get("t") == "title" and m["title"] == "Hello" for m in got)


class TestPasswordFocus:
    async def test_warns_on_unknown_host(self, tmp_path):
        page = FakePage(url="https://127.0.0.1/login")
        page.main_frame = FakeFrame("http://127.0.0.1/login", password_focused=True)
        page.frames = [page.main_frame]
        engine = await _bare_engine(tmp_path, page=page)
        got = []
        engine.attach(lambda m: _collect(got, m))
        await engine._check_password_focus()
        warnings = [m for m in got if m.get("code") == "password_on_unknown_host"]
        assert warnings and warnings[0]["host"] == "127.0.0.1"
        # second call for the same host does not warn again
        engine._last_focus_check = 0.0
        got.clear()
        await engine._check_password_focus()
        assert not got

    async def test_no_warning_on_known_host(self, tmp_path):
        page = FakePage()
        page.main_frame = FakeFrame("https://login.chase.com/", password_focused=True)
        page.frames = [page.main_frame]
        engine = await _bare_engine(tmp_path, page=page)
        got = []
        engine.attach(lambda m: _collect(got, m))
        await engine._check_password_focus()
        assert not any(m.get("code") == "password_on_unknown_host" for m in got)


class TestDownloadAndPopup:
    async def test_save_download_calls_handler(self, tmp_path):
        handled = []

        async def handler(path, name):
            handled.append((Path(path).read_bytes(), name))

        engine = PlaywrightRoomEngine(make_session(), browser_provider=_no_browser, workdir=tmp_path, on_download=handler)
        engine._page = FakePage()

        class Dl:
            suggested_filename = "report.pdf"

            async def save_as(self, path):
                Path(path).write_bytes(b"%PDF-1.4")

        await engine._save_download(Dl())
        assert handled and handled[0][1] == "report.pdf"

    async def test_download_cap(self, tmp_path):
        engine = await _bare_engine(tmp_path)
        engine._download_count = readingroom.MAX_DOWNLOADS_PER_SESSION
        got = []
        engine.attach(lambda m: _collect(got, m))

        class Dl:
            suggested_filename = "x"
            cancelled = False

            async def cancel(self):
                self.cancelled = True

        await engine._save_download(Dl())
        assert any(m.get("code") == "download_limit" for m in got)

    async def test_save_failure_warns(self, tmp_path):
        engine = await _bare_engine(tmp_path)
        got = []
        engine.attach(lambda m: _collect(got, m))

        class Dl:
            suggested_filename = "x"

            async def save_as(self, path):
                raise RuntimeError("io error")

            async def failure(self):
                return "disk gone"

        await engine._save_download(Dl())
        assert any(m.get("code") == "download_failed" for m in got)

    async def test_absorb_popup_navigates(self, tmp_path):
        engine = await _bare_engine(tmp_path)

        class Popup:
            url = "https://example.com/opened"

            async def wait_for_load_state(self, state, timeout):
                return None

            async def close(self):
                return None

        await engine._absorb_popup(Popup())
        await _drain(engine)
        assert "https://example.com/opened" in engine._page.goto_calls


class TestCloseAndFail:
    async def test_close_is_idempotent(self, tmp_path):
        closed = []

        class Ctx:
            async def close(self):
                closed.append(True)

        engine = await _bare_engine(tmp_path)
        engine._context = Ctx()
        await engine.close()
        await engine.close()  # second close is a no-op
        assert len(closed) == 1 and engine._closed

    async def test_fail_emits_closed_and_closes(self, tmp_path):
        engine = await _bare_engine(tmp_path)
        got = []
        engine.attach(lambda m: _collect(got, m))
        await engine._fail("page crashed")
        assert any(m.get("t") == "closed" and m.get("error") for m in got)
        assert engine._closed


async def _collect(bucket, message):
    bucket.append(message)


async def _drain(engine):
    """Let the engine's fire-and-forget tasks finish."""
    for _ in range(5):
        pending = [t for t in engine._tasks if not t.done()]
        if not pending:
            break
        await asyncio.gather(*pending, return_exceptions=True)

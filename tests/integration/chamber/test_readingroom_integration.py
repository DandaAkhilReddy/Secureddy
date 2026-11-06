"""Integration test for the Reading Room: a real FastAPI app with a real
Playwright engine, driven over a real websocket.

The app runs in uvicorn on a background thread so the manager (and therefore
Playwright) is created inside uvicorn's own event loop - the one that will
drive the browser. The test thread connects with the synchronous
``websockets`` client. Marked ``integration``.
"""

from __future__ import annotations

import json
import socket
import threading
import time

import pytest
import uvicorn
from fastapi import FastAPI
from websockets.sync.client import connect

from reddysec.chamber.readingroom import ReadingRoomManager
from reddysec.chamber.readingroom_web import make_room_router

pytestmark = pytest.mark.integration


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class RunningApp:
    """A uvicorn server on a thread, with the manager created in its loop."""

    def __init__(self, store, evil_site):
        self.store = store
        self.evil_site = evil_site
        self.port = _free_port()
        self.manager: ReadingRoomManager | None = None
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None

    def _build_app(self) -> FastAPI:
        app = FastAPI()
        # The manager does no async work until a session starts; its Playwright
        # browser is launched lazily on first use, which happens inside a
        # request handler - i.e. in uvicorn's loop, the one that drives the
        # browser. So constructing it here (main thread) is safe.
        self.manager = ReadingRoomManager(self.store, max_sessions=4, idle_timeout_s=300)
        app.state.manager = self.manager

        @app.on_event("shutdown")
        async def _shutdown() -> None:
            await self.manager.shutdown()

        app.include_router(make_room_router(self.manager))
        return app

    def start(self) -> None:
        config = uvicorn.Config(self._build_app(), host="127.0.0.1", port=self.port, log_level="warning", loop="asyncio")
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self._server.started:
                return
            time.sleep(0.05)
        raise RuntimeError("uvicorn did not start")

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=15)

    def http(self, method: str, path: str, **kw):
        import httpx

        return httpx.request(method, f"http://127.0.0.1:{self.port}{path}", **kw)

    def ws_url(self, session_id: str) -> str:
        return f"ws://127.0.0.1:{self.port}/room/{session_id}/ws"


@pytest.fixture
def running_app(store, evil_site):
    app = RunningApp(store, evil_site)
    app.start()
    try:
        yield app
    finally:
        app.stop()


def _recv_until(ws, predicate, timeout=12.0):
    """Collect messages until ``predicate(msg)`` is true; return (match, all)."""
    deadline = time.monotonic() + timeout
    seen = []
    while time.monotonic() < deadline:
        remaining = max(0.1, deadline - time.monotonic())
        try:
            raw = ws.recv(timeout=remaining)
        except TimeoutError:
            break
        msg = json.loads(raw)
        seen.append(msg)
        if predicate(msg):
            return msg, seen
    return None, seen


class TestReadingRoomOverWebsocket:
    def test_start_stream_input_download_close(self, running_app, evil_site):
        # 1) start a session to /benign
        resp = running_app.http("POST", "/room/start", json={"url": evil_site.url("/benign")})
        assert resp.status_code == 201
        session_id = resp.json()["session_id"]

        with connect(running_app.ws_url(session_id), open_timeout=12) as ws:
            # 2) receive at least one frame within 10 s
            frame, _ = _recv_until(ws, lambda m: m.get("t") == "frame", timeout=12)
            assert frame is not None, "no frame received"
            assert frame["b64"] and frame["w"] > 0 and frame["h"] > 0

            # 3) send a click and a key (just must not break the stream)
            ws.send(json.dumps({"t": "mouse", "action": "click", "x": 20, "y": 20}))
            ws.send(json.dumps({"t": "key", "action": "press", "key": "a", "text": "a"}))
            ws.send(json.dumps({"t": "ping"}))
            pong, _ = _recv_until(ws, lambda m: m.get("t") == "pong", timeout=6)
            assert pong is not None

            # 4) navigate to a download; expect a download event (exe -> no safe copy)
            ws.send(json.dumps({"t": "nav", "url": evil_site.url("/download")}))
            dl, _ = _recv_until(ws, lambda m: m.get("t") == "download", timeout=12)
            assert dl is not None
            assert dl["filename"] == "invoice.exe"
            assert dl["safe_ready"] is False
            assert dl["reason"]  # explains why no safe copy (PE is unsupported)

        # 5) close via the HTTP route
        close = running_app.http("POST", f"/room/{session_id}/close")
        assert close.status_code == 200 and close.json()["closed"] is True

    def test_pdf_download_offers_safe_copy(self, running_app, evil_site):
        resp = running_app.http("POST", "/room/start", json={"url": evil_site.url("/benign")})
        session_id = resp.json()["session_id"]
        with connect(running_app.ws_url(session_id), open_timeout=12) as ws:
            _recv_until(ws, lambda m: m.get("t") == "frame", timeout=12)
            ws.send(json.dumps({"t": "nav", "url": evil_site.url("/pdf-download")}))
            dl, _ = _recv_until(ws, lambda m: m.get("t") == "download" and m.get("safe_ready"), timeout=15)
            assert dl is not None, "no safe-ready download event"
            index = dl["index"]
        # 6) GET the safe copy; it is a real PDF
        safe = running_app.http("GET", f"/room/{session_id}/download/{index}/safe")
        assert safe.status_code == 200
        assert safe.headers["content-type"] == "application/pdf"
        assert safe.content[:5] == b"%PDF-"
        running_app.http("POST", f"/room/{session_id}/close")

    def test_password_warning_on_unknown_host(self, running_app, evil_site):
        # Open the fake Chase login and type into the password field, which sits
        # on 127.0.0.1 - not a known login host - so a warning must fire.
        resp = running_app.http("POST", "/room/start", json={"url": evil_site.url("/phish-login")})
        session_id = resp.json()["session_id"]
        warning = None
        seen_types: list[str] = []
        with connect(running_app.ws_url(session_id), open_timeout=12) as ws:
            _recv_until(ws, lambda m: m.get("t") == "frame", timeout=12)
            # Tab from the top of the form (username, then password). Tab one
            # field at a time with a gap longer than the focus-check throttle,
            # and stop the moment the warning arrives so we never overshoot past
            # the password field to the submit button.
            for _ in range(5):
                ws.send(json.dumps({"t": "key", "action": "press", "key": "Tab"}))
                match, seen = _recv_until(
                    ws, lambda m: m.get("t") == "warning" and m.get("code") == "password_on_unknown_host", timeout=0.6
                )
                seen_types.extend(m.get("t") for m in seen)
                if match is not None:
                    warning = match
                    break
        running_app.http("POST", f"/room/{session_id}/close")
        assert warning is not None, f"no password warning; saw {seen_types}"
        assert warning["host"] == "127.0.0.1"

    def test_closed_event_on_close(self, running_app, evil_site):
        resp = running_app.http("POST", "/room/start", json={"url": evil_site.url("/benign")})
        session_id = resp.json()["session_id"]
        with connect(running_app.ws_url(session_id), open_timeout=12) as ws:
            _recv_until(ws, lambda m: m.get("t") == "frame", timeout=12)
            running_app.http("POST", f"/room/{session_id}/close")
            closed, _ = _recv_until(ws, lambda m: m.get("t") == "closed", timeout=8)
            assert closed is not None

    def test_navigation_history_and_resize(self, running_app, evil_site):
        # Exercise the full input surface: title, nav, back/forward/reload,
        # resize, mouse wheel/move - the stream must survive all of it.
        resp = running_app.http("POST", "/room/start", json={"url": evil_site.url("/benign")})
        session_id = resp.json()["session_id"]
        with connect(running_app.ws_url(session_id), open_timeout=12) as ws:
            title, _ = _recv_until(ws, lambda m: m.get("t") == "title", timeout=12)
            assert title is not None and title["title"]
            # navigate to a second page, building history
            ws.send(json.dumps({"t": "nav", "url": evil_site.url("/final")}))
            url_msg, _ = _recv_until(ws, lambda m: m.get("t") == "url" and m["url"].endswith("/final"), timeout=10)
            assert url_msg is not None
            # back, forward, reload
            for action in ("back", "forward", "reload"):
                ws.send(json.dumps({"t": action}))
                time.sleep(0.4)
            # resize restarts the screencast; a frame must still arrive after it
            ws.send(json.dumps({"t": "resize", "w": 1024, "h": 640}))
            ws.send(json.dumps({"t": "mouse", "action": "wheel", "x": 10, "y": 10, "deltaY": 120}))
            ws.send(json.dumps({"t": "mouse", "action": "move", "x": 30, "y": 40}))
            frame, _ = _recv_until(ws, lambda m: m.get("t") == "frame", timeout=10)
            assert frame is not None
        running_app.http("POST", f"/room/{session_id}/close")

    def test_navigation_failure_warns(self, running_app, evil_site):
        resp = running_app.http("POST", "/room/start", json={"url": evil_site.url("/benign")})
        session_id = resp.json()["session_id"]
        with connect(running_app.ws_url(session_id), open_timeout=12) as ws:
            _recv_until(ws, lambda m: m.get("t") == "frame", timeout=12)
            # An unreachable port fails to load -> navigation_failed warning.
            ws.send(json.dumps({"t": "nav", "url": "http://127.0.0.1:1/nowhere"}))
            warn, _ = _recv_until(ws, lambda m: m.get("t") == "warning" and m.get("code") == "navigation_failed", timeout=10)
            assert warn is not None
        running_app.http("POST", f"/room/{session_id}/close")

    def test_popup_is_absorbed(self, running_app, evil_site):
        # /popup calls window.open('/benign'); the single-tab engine should
        # follow the popup's destination rather than open a second page.
        resp = running_app.http("POST", "/room/start", json={"url": evil_site.url("/popup")})
        session_id = resp.json()["session_id"]
        with connect(running_app.ws_url(session_id), open_timeout=12) as ws:
            # a url event for /benign (the popup target) should arrive
            url_msg, _ = _recv_until(ws, lambda m: m.get("t") == "url" and m["url"].endswith("/benign"), timeout=12)
            assert url_msg is not None
        running_app.http("POST", f"/room/{session_id}/close")

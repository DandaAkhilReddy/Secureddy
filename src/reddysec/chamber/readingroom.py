"""The Reading Room: remote browser isolation for the moments when the client
insists on opening a link themselves.

A Reading Room *session* is a Chromium page that lives on our side. The
client's device receives JPEG frames and sends back mouse, keyboard and
navigation events; no page content, script or cookie ever reaches them.
Downloads land on our side, are sanitized by ``cdr`` and offered as a safe
PDF. The original bytes are kept in the artifact store too, but only for
concierge roles (the web layer enforces that).

Two layers, so the engine can move out of process later:

``RoomEngine`` (protocol)   one isolated browser page: ``start``, ``attach`` a
                           sender for outbound events, ``handle_input``, ``close``.
                           ``PlaywrightRoomEngine`` is the in-process
                           implementation (development grade: every session
                           shares this worker's Chromium, so it offers crash
                           isolation between sessions but not kernel-level
                           isolation from the host). A production engine runs
                           the same contract inside a per-session sandbox and
                           relays the same JSON messages.
``ReadingRoomManager``     sessions, authorization data (``principal_id``),
                           client fan-out, input validation, download
                           handling + CDR, the idle reaper, the session cap.

Outbound messages (engine -> clients), all JSON objects with a ``t`` field::

    {"t":"frame","b64":<jpeg>,"w":..,"h":..}
    {"t":"url","url":..}                      main frame navigated
    {"t":"title","title":..}
    {"t":"download","index":i,"filename":..,"size":..,"sniffed_type":..,"safe_ready":bool,"reason":..}
    {"t":"warning","code":"password_on_unknown_host","host":..}   (also: navigation_failed, download_failed, ...)
    {"t":"state", ...}                        snapshot sent to a client on attach
    {"t":"pong"}
    {"t":"closed","reason":..}

Inbound events (clients -> engine), validated by ``validate_input``::

    {"t":"mouse","action":"move|down|up|click|dblclick|wheel","x":..,"y":..,"button":"left|right|middle","deltaX":..,"deltaY":..}
    {"t":"key","action":"down|up|press","key":..,"text":..}
    {"t":"nav","url":..}   {"t":"back"}   {"t":"forward"}   {"t":"reload"}
    {"t":"resize","w":..,"h":..}   {"t":"ping"}
"""

from __future__ import annotations

import asyncio
import hashlib
import shutil
import tempfile
import time
from collections import deque
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlsplit

from reddysec.core.artifacts import ArtifactStore
from reddysec.core.ids import new_id
from reddysec.core.logging import get_logger
from reddysec.models import DownloadRecord, ReadingRoomSession, RoomState

from . import cdr
from .common import host_of, registrable_domain, sniff_type, user_agent_for

log = get_logger(__name__)

RoomSender = Callable[[dict[str, Any] | bytes], Awaitable[None]]
DownloadHandler = Callable[[Path, str], Awaitable[None]]

MIN_VIEWPORT, MAX_VIEWPORT = 320, 1920
MAX_DOWNLOADS_PER_SESSION = 10
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024
MAX_KEY_LEN = 32
MAX_TEXT_LEN = 256
MOUSE_ACTIONS = frozenset({"move", "down", "up", "click", "dblclick", "wheel"})
KEY_ACTIONS = frozenset({"down", "up", "press"})
MOUSE_BUTTONS = frozenset({"left", "right", "middle"})
FRAME_QUALITY = 60
NAV_TIMEOUT_MS = 30_000
RECENT_SESSIONS_KEPT = 50

LAUNCH_ARGS: tuple[str, ...] = (
    "--disable-blink-features=AutomationControlled",
    "--no-first-run",
    "--disable-dev-shm-usage",
)

# Registrable domains where a password prompt is expected. Anything else
# gets the "are you sure?" banner. Injected into the engine so the web app can
# extend it with the client's own banks and services.
DEFAULT_KNOWN_LOGIN_DOMAINS: frozenset[str] = frozenset(
    {
        "google.com",
        "microsoft.com",
        "microsoftonline.com",
        "live.com",
        "office.com",
        "apple.com",
        "icloud.com",
        "amazon.com",
        "paypal.com",
        "facebook.com",
        "instagram.com",
        "linkedin.com",
        "github.com",
        "dropbox.com",
        "docusign.com",
        "chase.com",
        "bankofamerica.com",
        "wellsfargo.com",
        "citi.com",
        "capitalone.com",
        "americanexpress.com",
        "schwab.com",
        "fidelity.com",
        "vanguard.com",
        "yahoo.com",
        "netflix.com",
        "zoom.us",
        "slack.com",
        "adobe.com",
        "salesforce.com",
        "okta.com",
    }
)


class RoomError(Exception):
    """Base class; the web layer maps subclasses to status codes."""


class RoomNotFound(RoomError):
    pass


class RoomFull(RoomError):
    pass


class RoomClosed(RoomError):
    pass


class RoomInputError(RoomError, ValueError):
    pass


class RoomUrlError(RoomError, ValueError):
    pass


# --- validation -------------------------------------------------------------------


def validate_room_url(url: Any) -> str:
    """Only http/https, with a host. The Reading Room is a browser, not a
    file viewer or a way to poke at ``chrome://`` pages."""
    if not isinstance(url, str) or len(url) > 4096:
        raise RoomUrlError("url must be a string of at most 4096 characters")
    candidate = url.strip()
    try:
        parts = urlsplit(candidate)
    except ValueError as exc:
        raise RoomUrlError(f"unparsable url: {exc}") from exc
    # Bare "example.com/path" has no scheme -> assume https. A real scheme
    # (including "javascript:" or "data:") is kept so it can be rejected below.
    if not parts.scheme and not candidate.startswith("//"):
        candidate = "https://" + candidate
        try:
            parts = urlsplit(candidate)
        except ValueError as exc:
            raise RoomUrlError(f"unparsable url: {exc}") from exc
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise RoomUrlError("only http and https links can be opened")
    try:
        if not parts.hostname:
            raise RoomUrlError("url has no host")
        _ = parts.port  # raises ValueError for a malformed port
    except ValueError as exc:
        raise RoomUrlError(f"invalid host: {exc}") from exc
    return candidate


def _number(event: dict[str, Any], key: str, default: float | None = None) -> float:
    value = event.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int | float) or value != value or value in (float("inf"), float("-inf")):
        raise RoomInputError(f"{key} must be a finite number")
    return float(value)


def validate_input(event: Any) -> dict[str, Any]:
    """Normalize one client event or raise ``RoomInputError``. Everything the
    browser side of the websocket sends is untrusted, including its shape."""
    if not isinstance(event, dict):
        raise RoomInputError("event must be an object")
    kind = event.get("t")
    if kind == "mouse":
        action = event.get("action")
        if action not in MOUSE_ACTIONS:
            raise RoomInputError("unknown mouse action")
        button = event.get("button", "left")
        if button not in MOUSE_BUTTONS:
            raise RoomInputError("unknown mouse button")
        out: dict[str, Any] = {"t": "mouse", "action": action, "button": button}
        if action != "wheel" or "x" in event:
            out["x"] = max(0.0, min(MAX_VIEWPORT * 2.0, _number(event, "x", 0.0)))
            out["y"] = max(0.0, min(MAX_VIEWPORT * 2.0, _number(event, "y", 0.0)))
        if action == "wheel":
            out["deltaX"] = max(-2000.0, min(2000.0, _number(event, "deltaX", 0.0)))
            out["deltaY"] = max(-2000.0, min(2000.0, _number(event, "deltaY", 0.0)))
        return out
    if kind == "key":
        action = event.get("action")
        if action not in KEY_ACTIONS:
            raise RoomInputError("unknown key action")
        key = event.get("key")
        if not isinstance(key, str) or not key or len(key) > MAX_KEY_LEN:
            raise RoomInputError("key must be a short string")
        text = event.get("text")
        if text is not None and (not isinstance(text, str) or len(text) > MAX_TEXT_LEN):
            raise RoomInputError("text too long")
        return {"t": "key", "action": action, "key": key, "text": text}
    if kind == "nav":
        try:
            return {"t": "nav", "url": validate_room_url(event.get("url"))}
        except RoomUrlError as exc:
            raise RoomInputError(str(exc)) from exc
    if kind in ("back", "forward", "reload", "ping"):
        return {"t": kind}
    if kind == "resize":
        w = int(max(MIN_VIEWPORT, min(MAX_VIEWPORT, _number(event, "w"))))
        h = int(max(MIN_VIEWPORT, min(MAX_VIEWPORT, _number(event, "h"))))
        return {"t": "resize", "w": w, "h": h}
    raise RoomInputError(f"unknown event type {kind!r}")


# --- engine protocol --------------------------------------------------------------


@runtime_checkable
class RoomEngine(Protocol):
    async def start(self, session: ReadingRoomSession, url: str) -> None: ...

    def attach(self, send: RoomSender) -> Callable[[], None]: ...

    async def handle_input(self, event: dict[str, Any]) -> None: ...

    async def close(self) -> None: ...


class RoomEngineFactory(Protocol):
    def __call__(self, session: ReadingRoomSession, *, workdir: Path, on_download: DownloadHandler) -> RoomEngine: ...


class _Fanout:
    """Shared sender bookkeeping for engines."""

    def __init__(self) -> None:
        self._senders: list[RoomSender] = []

    def attach(self, send: RoomSender) -> Callable[[], None]:
        self._senders.append(send)

        def detach() -> None:
            try:
                self._senders.remove(send)
            except ValueError:
                pass

        return detach

    @property
    def count(self) -> int:
        return len(self._senders)

    async def emit(self, message: dict[str, Any] | bytes) -> None:
        for send in list(self._senders):
            try:
                await send(message)
            except Exception as exc:
                log.debug("room.sender_failed", error=str(exc))
                try:
                    self._senders.remove(send)
                except ValueError:
                    pass


# --- Playwright engine --------------------------------------------------------------


class PlaywrightRoomEngine:
    """One Chromium context + page, streamed with CDP ``Page.startScreencast``."""

    def __init__(
        self,
        session: ReadingRoomSession,
        *,
        browser_provider: Callable[[], Awaitable[Any]],
        workdir: Path,
        on_download: DownloadHandler,
        known_login_domains: frozenset[str] = DEFAULT_KNOWN_LOGIN_DOMAINS,
        nav_timeout_ms: int = NAV_TIMEOUT_MS,
    ) -> None:
        self.session = session
        self._browser_provider = browser_provider
        self.workdir = workdir
        self._on_download = on_download
        self.known_login_domains = known_login_domains
        self.nav_timeout_ms = nav_timeout_ms
        self._fanout = _Fanout()
        self._context: Any = None
        self._page: Any = None
        self._cdp: Any = None
        self._tasks: set[asyncio.Task[Any]] = set()
        self._closed = False
        self._download_count = 0
        self._warned_hosts: set[str] = set()
        self._last_focus_check = 0.0
        self._streaming = False

    # -- protocol ---------------------------------------------------------------------

    def attach(self, send: RoomSender) -> Callable[[], None]:
        return self._fanout.attach(send)

    async def start(self, session: ReadingRoomSession, url: str) -> None:
        browser = await self._browser_provider()
        self._context = await browser.new_context(
            user_agent=user_agent_for(browser.version),
            viewport={"width": session.viewport_width, "height": session.viewport_height},
            accept_downloads=True,
            locale="en-US",
            permissions=[],  # clipboard, camera, notifications: all denied
            java_script_enabled=True,
        )
        await self._context.clear_permissions()
        self._page = await self._context.new_page()
        page = self._page
        page.on("framenavigated", self._on_frame_navigated)
        page.on("load", lambda _page: self._spawn(self._emit_title()))
        page.on("download", lambda download: self._spawn(self._save_download(download)))
        page.on("dialog", lambda dialog: self._spawn(_quiet(dialog.dismiss())))
        page.on("close", lambda _page: self._spawn(self._fail("page closed")))
        page.on("crash", lambda _page: self._spawn(self._fail("page crashed")))
        self._context.on("page", lambda popup: self._spawn(self._absorb_popup(popup)))
        self._cdp = await self._context.new_cdp_session(page)
        self._cdp.on("Page.screencastFrame", lambda params: self._spawn(self._on_screencast_frame(params)))
        await self._start_screencast()
        self._spawn(self._navigate(url))

    async def handle_input(self, event: dict[str, Any]) -> None:
        if self._closed or self._page is None:
            raise RoomClosed("session is closed")
        kind = event["t"]
        try:
            if kind == "mouse":
                await self._mouse(event)
            elif kind == "key":
                await self._key(event)
            elif kind == "nav":
                self._spawn(self._navigate(event["url"]))
            elif kind == "back":
                self._spawn(self._history(self._page.go_back))
            elif kind == "forward":
                self._spawn(self._history(self._page.go_forward))
            elif kind == "reload":
                self._spawn(self._history(self._page.reload))
            elif kind == "resize":
                await self._resize(event["w"], event["h"])
            elif kind == "ping":
                await self._fanout.emit({"t": "pong"})
        except RoomError:
            raise
        except Exception as exc:
            if self._page_gone():
                await self._fail(f"browser gone: {str(exc).splitlines()[0][:120]}")
                raise RoomClosed("session is closed") from exc
            await self._fanout.emit({"t": "warning", "code": "input_failed", "detail": str(exc).splitlines()[0][:200]})

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for task in list(self._tasks):
            task.cancel()
        await _quiet(self._stop_screencast())
        if self._context is not None:
            await _quiet(asyncio.wait_for(self._context.close(), timeout=10))
        self._context = None
        self._page = None

    # -- streaming -----------------------------------------------------------------------

    async def _start_screencast(self) -> None:
        if self._cdp is None or self._streaming:
            return
        await self._cdp.send(
            "Page.startScreencast",
            {
                "format": "jpeg",
                "quality": FRAME_QUALITY,
                "maxWidth": self.session.viewport_width,
                "maxHeight": self.session.viewport_height,
                "everyNthFrame": 1,
            },
        )
        self._streaming = True

    async def _stop_screencast(self) -> None:
        if self._cdp is None or not self._streaming:
            return
        self._streaming = False
        await self._cdp.send("Page.stopScreencast")

    async def _on_screencast_frame(self, params: dict[str, Any]) -> None:
        if self._closed:
            return
        metadata = params.get("metadata") or {}
        await self._fanout.emit(
            {
                "t": "frame",
                "b64": params.get("data", ""),
                "w": int(metadata.get("deviceWidth") or self.session.viewport_width),
                "h": int(metadata.get("deviceHeight") or self.session.viewport_height),
            }
        )
        if self._cdp is not None and "sessionId" in params:
            await _quiet(self._cdp.send("Page.screencastFrameAck", {"sessionId": params["sessionId"]}))

    # -- page events ----------------------------------------------------------------------

    def _on_frame_navigated(self, frame: Any) -> None:
        if self._page is None or frame != self._page.main_frame or self._closed:
            return
        self._spawn(self._fanout.emit({"t": "url", "url": frame.url[:4096]}))

    async def _emit_title(self) -> None:
        if self._page is None or self._closed:
            return
        try:
            title = await self._page.title()
        except Exception:
            return
        await self._fanout.emit({"t": "title", "title": (title or "")[:300]})

    async def _navigate(self, url: str) -> None:
        if self._page is None or self._closed:
            return
        try:
            await self._page.goto(url, wait_until="domcontentloaded", timeout=self.nav_timeout_ms)
        except Exception as exc:
            message = str(exc).splitlines()[0]
            if "Download is starting" in message:
                return  # the download handler takes it from here
            if self._page_gone():
                await self._fail("browser gone during navigation")
                return
            await self._fanout.emit({"t": "warning", "code": "navigation_failed", "detail": message[:300], "url": url[:2000]})

    async def _history(self, action: Callable[..., Awaitable[Any]]) -> None:
        try:
            await action(wait_until="domcontentloaded", timeout=self.nav_timeout_ms)
        except Exception as exc:
            if self._page_gone():
                await self._fail("browser gone")
                return
            await self._fanout.emit({"t": "warning", "code": "navigation_failed", "detail": str(exc).splitlines()[0][:300]})

    async def _absorb_popup(self, popup: Any) -> None:
        """Single-tab model: a popup's destination replaces the current page.
        Pop-unders and tab sprawl are a phishing staple; the client never
        sees more than one page."""
        try:
            await popup.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
        url = popup.url
        await _quiet(popup.close())
        if url and url != "about:blank" and self._page is not None and not self._closed:
            await self._navigate(url)

    async def _save_download(self, download: Any) -> None:
        index = self._download_count
        self._download_count += 1
        suggested = (download.suggested_filename or "download")[:200]
        if index >= MAX_DOWNLOADS_PER_SESSION:
            await _quiet(download.cancel())
            await self._fanout.emit({"t": "warning", "code": "download_limit", "filename": suggested})
            return
        path = self.workdir / f"dl_{index}"
        try:
            await download.save_as(path)
        except Exception as exc:
            failure = await _quiet(download.failure())
            await self._fanout.emit({"t": "warning", "code": "download_failed", "filename": suggested, "detail": str(failure or exc)[:200]})
            return
        try:
            await self._on_download(path, suggested)
        except Exception as exc:
            log.error("room.download_handler_failed", error=str(exc))
            await self._fanout.emit({"t": "warning", "code": "download_failed", "filename": suggested, "detail": str(exc)[:200]})

    # -- input --------------------------------------------------------------------------------

    async def _mouse(self, event: dict[str, Any]) -> None:
        mouse = self._page.mouse
        action = event["action"]
        x, y = event.get("x"), event.get("y")
        if action == "move":
            await mouse.move(x, y)
        elif action == "down":
            await mouse.move(x, y)
            await mouse.down(button=event["button"])
        elif action == "up":
            await mouse.move(x, y)
            await mouse.up(button=event["button"])
        elif action == "click":
            await mouse.click(x, y, button=event["button"])
        elif action == "dblclick":
            await mouse.dblclick(x, y, button=event["button"])
        elif action == "wheel":
            if x is not None and y is not None:
                await mouse.move(x, y)
            await mouse.wheel(event["deltaX"], event["deltaY"])
        if action in ("down", "up", "click", "dblclick"):
            self._spawn(self._check_password_focus())

    async def _key(self, event: dict[str, Any]) -> None:
        keyboard = self._page.keyboard
        action, key, text = event["action"], event["key"], event.get("text")
        if action == "down":
            await keyboard.down(key)
        elif action == "up":
            await keyboard.up(key)
        elif text and len(key) > 1 and key not in ("Enter", "Tab", "Backspace", "Delete", "Escape"):
            await keyboard.insert_text(text)  # IME / composed input arrives as text
        else:
            await keyboard.press(key)
        self._spawn(self._check_password_focus())

    async def _resize(self, width: int, height: int) -> None:
        self.session.viewport_width = width
        self.session.viewport_height = height
        await self._page.set_viewport_size({"width": width, "height": height})
        await self._stop_screencast()
        await self._start_screencast()

    async def _check_password_focus(self) -> None:
        """After a click or key, see whether the focus landed in a password
        field on a host we do not recognise and warn once per host."""
        now = time.monotonic()
        if self._closed or self._page is None or now - self._last_focus_check < 0.25:
            return
        self._last_focus_check = now
        for frame in list(self._page.frames)[:20]:
            try:
                focused = await asyncio.wait_for(
                    frame.evaluate(
                        "(() => { const a = document.activeElement; "
                        "return !!(a && a.tagName === 'INPUT' && (a.getAttribute('type') || '').toLowerCase() === 'password'); })()"
                    ),
                    timeout=2.0,
                )
            except Exception:
                continue
            if not focused:
                continue
            host = host_of(frame.url)
            if host and not self.is_known_login_host(host) and host not in self._warned_hosts:
                self._warned_hosts.add(host)
                await self._fanout.emit({"t": "warning", "code": "password_on_unknown_host", "host": host})
            return

    def is_known_login_host(self, host: str) -> bool:
        host = host.lower()
        return host in self.known_login_domains or registrable_domain(host) in self.known_login_domains

    # -- failure / housekeeping ----------------------------------------------------------------

    def _page_gone(self) -> bool:
        try:
            return self._page is None or self._page.is_closed() or not self._context.browser.is_connected()
        except Exception:
            return True

    async def _fail(self, reason: str) -> None:
        if self._closed:
            return
        log.warning("room.engine_failed", session_id=self.session.session_id, reason=reason)
        await self._fanout.emit({"t": "closed", "reason": reason, "error": True})
        await self.close()

    def _spawn(self, coro: Awaitable[Any]) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)


async def _quiet(awaitable: Awaitable[Any]) -> Any:
    try:
        return await awaitable
    except (Exception, asyncio.CancelledError):
        return None


# --- manager ---------------------------------------------------------------------------------


class _Room:
    def __init__(self, session: ReadingRoomSession, engine: RoomEngine, workdir: Path) -> None:
        self.session = session
        self.engine = engine
        self.workdir = workdir
        self.clients = _Fanout()
        self.detach_engine: Callable[[], None] = lambda: None
        self.closing = False
        self.lock = asyncio.Lock()


class ReadingRoomManager:
    """Owns every open Reading Room on this worker. Create it inside the
    event loop that will drive Playwright (an app ``lifespan`` is the usual
    place) and call ``shutdown()`` when that loop ends."""

    def __init__(
        self,
        artifact_store: ArtifactStore,
        *,
        max_sessions: int = 10,
        idle_timeout_s: int = 300,
        engine_factory: RoomEngineFactory | None = None,
        workdir_root: str | Path | None = None,
        known_login_domains: frozenset[str] = DEFAULT_KNOWN_LOGIN_DOMAINS,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.artifact_store = artifact_store
        self.max_sessions = max_sessions
        self.idle_timeout_s = idle_timeout_s
        self.known_login_domains = known_login_domains
        self._clock = clock
        self._engine_factory: RoomEngineFactory = engine_factory or self._playwright_engine
        self._workdir_root = Path(workdir_root) if workdir_root else Path(tempfile.mkdtemp(prefix="rs-room-"))
        self._rooms: dict[str, _Room] = {}
        self._recent: deque[ReadingRoomSession] = deque(maxlen=RECENT_SESSIONS_KEPT)
        self._playwright: Any = None
        self._browser: Any = None
        self._browser_lock = asyncio.Lock()

    # -- sessions ---------------------------------------------------------------------------

    @property
    def active_count(self) -> int:
        return len(self._rooms)

    def get(self, session_id: str) -> ReadingRoomSession | None:
        room = self._rooms.get(session_id)
        if room is not None:
            return room.session
        for session in self._recent:
            if session.session_id == session_id:
                return session
        return None

    def list_for(self, principal_id: str) -> list[ReadingRoomSession]:
        return [room.session for room in self._rooms.values() if room.session.principal_id == principal_id]

    async def start(self, url: str, principal_id: str, viewport: tuple[int, int] = (1280, 800)) -> ReadingRoomSession:
        clean_url = validate_room_url(url)
        if len(self._rooms) >= self.max_sessions:
            raise RoomFull(f"all {self.max_sessions} reading rooms are in use")
        width = int(max(MIN_VIEWPORT, min(MAX_VIEWPORT, viewport[0])))
        height = int(max(MIN_VIEWPORT, min(MAX_VIEWPORT, viewport[1])))
        now = self._clock()
        session = ReadingRoomSession(
            session_id=new_id("room"),
            principal_id=principal_id,
            url=clean_url,
            current_url=clean_url,
            viewport_width=width,
            viewport_height=height,
            created_at=now,
            last_activity_at=now,
        )
        workdir = self._workdir_root / session.session_id
        workdir.mkdir(parents=True, exist_ok=True)
        engine = self._engine_factory(session, workdir=workdir, on_download=self._download_handler(session.session_id))
        room = _Room(session, engine, workdir)
        self._rooms[session.session_id] = room
        room.detach_engine = engine.attach(self._engine_sink(session.session_id))
        try:
            await engine.start(session, clean_url)
        except Exception as exc:
            log.error("room.start_failed", session_id=session.session_id, error=str(exc))
            session.state = RoomState.ERROR
            session.error = f"{type(exc).__name__}: {exc}"[:300]
            await self._teardown(room, reason="failed to start")
            return session
        session.state = RoomState.READY
        log.info("room.started", session_id=session.session_id, principal_id=principal_id)
        return session

    async def close(self, session_id: str, reason: str = "closed by user") -> bool:
        room = self._rooms.get(session_id)
        if room is None:
            return False
        await self._teardown(room, reason=reason)
        return True

    async def reap_idle(self, now: datetime | None = None) -> list[str]:
        """Close sessions nobody has touched for ``idle_timeout_s``."""
        now = now or self._clock()
        reaped: list[str] = []
        for room in list(self._rooms.values()):
            idle = (now - room.session.last_activity_at).total_seconds()
            if idle > self.idle_timeout_s:
                await self._teardown(room, reason="idle timeout")
                reaped.append(room.session.session_id)
        return reaped

    async def shutdown(self) -> None:
        for room in list(self._rooms.values()):
            await self._teardown(room, reason="server shutting down")
        if self._browser is not None:
            await _quiet(asyncio.wait_for(self._browser.close(), timeout=10))
            self._browser = None
        if self._playwright is not None:
            await _quiet(asyncio.wait_for(self._playwright.stop(), timeout=10))
            self._playwright = None
        shutil.rmtree(self._workdir_root, ignore_errors=True)

    # -- clients -----------------------------------------------------------------------------

    def attach_client(self, session_id: str, send: RoomSender) -> Callable[[], None]:
        """Register a websocket (or any sender). Returns the detach callable.
        The new client first receives a ``state`` snapshot so it can draw the
        download list and current URL before the first frame arrives."""
        room = self._room(session_id)
        detach = room.clients.attach(send)
        asyncio.ensure_future(_quiet(send(self._snapshot(room.session))))
        return detach

    async def handle_input(self, session_id: str, event: Any) -> None:
        room = self._room(session_id)
        clean = validate_input(event)
        room.session.last_activity_at = self._clock()
        if clean["t"] == "resize":
            room.session.viewport_width, room.session.viewport_height = clean["w"], clean["h"]
        await room.engine.handle_input(clean)

    # -- internals ------------------------------------------------------------------------------

    def _room(self, session_id: str) -> _Room:
        room = self._rooms.get(session_id)
        if room is None:
            raise RoomNotFound(session_id)
        if room.closing:
            raise RoomClosed(session_id)
        return room

    def _snapshot(self, session: ReadingRoomSession) -> dict[str, Any]:
        return {
            "t": "state",
            "state": session.state.value,
            "url": session.current_url,
            "w": session.viewport_width,
            "h": session.viewport_height,
            "downloads": [self._download_message(i, d) for i, d in enumerate(session.downloads)],
        }

    @staticmethod
    def _download_message(index: int, record: DownloadRecord, reason: str | None = None) -> dict[str, Any]:
        return {
            "t": "download",
            "index": index,
            "filename": record.suggested_filename,
            "size": record.size,
            "sniffed_type": record.sniffed_type,
            "safe_ready": record.safe_copy_ref is not None,
            "reason": reason,
        }

    def _engine_sink(self, session_id: str) -> RoomSender:
        async def sink(message: dict[str, Any] | bytes) -> None:
            room = self._rooms.get(session_id)
            if room is None or room.closing:
                return
            if isinstance(message, dict):
                kind = message.get("t")
                if kind == "url" and isinstance(message.get("url"), str):
                    room.session.current_url = message["url"]
                elif kind == "closed":
                    room.session.state = RoomState.ERROR if message.get("error") else RoomState.CLOSED
                    room.session.error = str(message.get("reason") or "")[:300] if message.get("error") else None
                    await room.clients.emit({"t": "closed", "reason": message.get("reason")})
                    await self._teardown(room, reason=str(message.get("reason") or "engine closed"), announce=False)
                    return
            await room.clients.emit(message)

        return sink

    def _download_handler(self, session_id: str) -> DownloadHandler:
        async def handle(path: Path, suggested_filename: str) -> None:
            room = self._rooms.get(session_id)
            if room is None:
                return
            record, reason = await self._ingest_download(path, suggested_filename)
            room.session.downloads.append(record)
            room.session.last_activity_at = self._clock()
            index = len(room.session.downloads) - 1
            await room.clients.emit(self._download_message(index, record, reason))

        return handle

    async def _ingest_download(self, path: Path, suggested_filename: str) -> tuple[DownloadRecord, str | None]:
        """Hash, store the original, build the safe copy. Runs CDR in a thread
        because LibreOffice and page rasterization are slow and blocking."""
        size = path.stat().st_size
        if size > MAX_DOWNLOAD_BYTES:
            digest = hashlib.sha256()
            with path.open("rb") as fh:
                head = fh.read(4096)
                digest.update(head)
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    digest.update(chunk)
            path.unlink(missing_ok=True)
            record = DownloadRecord(suggested_filename=suggested_filename, sha256=digest.hexdigest(), size=size, sniffed_type=sniff_type(head))
            return record, f"file larger than {MAX_DOWNLOAD_BYTES // (1024 * 1024)} MB; not kept"
        data = path.read_bytes()
        path.unlink(missing_ok=True)
        record = DownloadRecord(
            suggested_filename=suggested_filename,
            sha256=hashlib.sha256(data).hexdigest(),
            size=size,
            sniffed_type=sniff_type(data),
            stored_ref=self.artifact_store.put(data, ".bin"),
        )
        try:
            result = await asyncio.to_thread(cdr.sanitize, data, suggested_filename)
        except Exception as exc:  # CDR must never take the session down
            log.error("room.cdr_failed", error=str(exc))
            return record, f"sanitizer failed: {type(exc).__name__}"
        if result.ok and result.pdf_bytes:
            record.safe_copy_ref = self.artifact_store.put(result.pdf_bytes, ".pdf")
            return record, result.reason
        return record, result.reason or "no safe copy available"

    async def _teardown(self, room: _Room, *, reason: str, announce: bool = True) -> None:
        async with room.lock:
            if room.closing:
                return
            room.closing = True
        self._rooms.pop(room.session.session_id, None)
        if room.session.state not in (RoomState.ERROR,):
            room.session.state = RoomState.CLOSED
        room.detach_engine()
        await _quiet(room.engine.close())
        if announce:
            await room.clients.emit({"t": "closed", "reason": reason})
        self._recent.append(room.session)
        shutil.rmtree(room.workdir, ignore_errors=True)
        log.info("room.closed", session_id=room.session.session_id, reason=reason)

    # -- browser provisioning (Playwright engine) ----------------------------------------------------

    def _playwright_engine(self, session: ReadingRoomSession, *, workdir: Path, on_download: DownloadHandler) -> RoomEngine:
        return PlaywrightRoomEngine(
            session,
            browser_provider=self._browser_provider,
            workdir=workdir,
            on_download=on_download,
            known_login_domains=self.known_login_domains,
        )

    async def _browser_provider(self) -> Any:
        """One Chromium per manager, launched on first use and relaunched if
        it dies. Sessions are separate contexts inside it."""
        async with self._browser_lock:
            if self._browser is not None and self._browser.is_connected():
                return self._browser
            from playwright.async_api import async_playwright

            if self._playwright is None:
                self._playwright = await async_playwright().start()
            browser = await self._playwright.chromium.launch(args=list(LAUNCH_ARGS))
            browser.on("disconnected", lambda _b: asyncio.ensure_future(self._on_browser_lost(browser)))
            self._browser = browser
            return browser

    async def _on_browser_lost(self, browser: Any) -> None:
        """Chromium died under us: every session that lived in it is over.
        The next ``start`` relaunches a fresh browser."""
        if self._browser is browser:
            self._browser = None
        for room in list(self._rooms.values()):
            room.session.state = RoomState.ERROR
            room.session.error = "browser disconnected"
            await self._teardown(room, reason="browser disconnected")

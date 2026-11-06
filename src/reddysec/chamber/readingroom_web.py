"""FastAPI router for the Reading Room.

Mount it on the main app and give it a way to identify the caller::

    from reddysec.chamber.readingroom import ReadingRoomManager
    from reddysec.chamber.readingroom_web import make_room_router

    manager = ReadingRoomManager(artifact_store, max_sessions=settings.reading_room_max_sessions,
                                 idle_timeout_s=settings.reading_room_idle_timeout_s)

    @asynccontextmanager
    async def lifespan(app):
        # Create the manager inside the running loop so Playwright shares it.
        app.state.room_manager = manager
        reaper = asyncio.create_task(_reap_loop(manager))
        try:
            yield
        finally:
            reaper.cancel()
            await manager.shutdown()

    app = FastAPI(lifespan=lifespan)
    app.include_router(make_room_router(manager, get_principal_id=principal_from_session))

``get_principal_id(request) -> str`` returns the caller's principal id from
your auth (the signed session cookie, a bearer token, ...). Every route then
checks it against the session's ``principal_id`` and returns 403 on a
mismatch; the websocket closes with policy code 1008. When omitted, a
development dependency returns ``"dev"`` so the router runs standalone - never
rely on that in production. ``on_session_event(principal_id, session_id,
event)`` is an optional audit hook, awaited on start/close.

``POST /room/start`` serves both API and browser callers:

* ``Content-Type: application/json`` ``{"url": ...}`` -> ``{"session_id","room_url"}``
  (201), or ``{"error"}`` with 4xx;
* an HTML form (``url``, optional ``message_id``) -> 303 redirect to the room
  page, or the start page re-rendered with an error.

Routes: ``GET /room/{id}`` (the UI), ``WS /room/{id}/ws`` (frames + events),
``GET /room/{id}/download/{index}/safe`` (the CDR PDF), ``POST /room/{id}/close``.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from importlib import resources
from typing import Any

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from reddysec.core.logging import get_logger

from .readingroom import (
    ReadingRoomManager,
    RoomClosed,
    RoomFull,
    RoomInputError,
    RoomNotFound,
    RoomUrlError,
    validate_room_url,
)

log = get_logger(__name__)

PrincipalResolver = Callable[[Request], Awaitable[str]]
MutationGuard = Callable[[Request], Awaitable[None]]
SessionEventHook = Callable[[str, str, dict[str, Any]], Awaitable[None]]

WS_POLICY_VIOLATION = 1008
WS_INTERNAL_ERROR = 1011


async def _dev_principal(_request: Request) -> str:
    return "dev"


def make_room_router(
    manager: ReadingRoomManager,
    get_principal_id: PrincipalResolver | None = None,
    on_session_event: SessionEventHook | None = None,
    mutation_guard: MutationGuard | None = None,
) -> APIRouter:
    """Build the Reading Room router.

    ``mutation_guard`` is awaited before every state-changing HTTP route
    (start, close). The web application passes its CSRF check here so a page
    on another origin cannot open or close rooms on a signed-in client's
    behalf; standalone use (tests, the dev server) leaves it ``None``.
    """
    router = APIRouter()
    resolve = get_principal_id or _dev_principal

    async def _guard(request: Request) -> None:
        if mutation_guard is not None:
            await mutation_guard(request)

    async def _principal_for_ws(websocket: WebSocket) -> str:
        if get_principal_id is None:
            return "dev"
        # The resolver expects a Request-like object; a Starlette WebSocket
        # exposes the same scope attributes (headers, cookies, query_params).
        return await get_principal_id(websocket)  # type: ignore[arg-type]

    async def _audit(principal_id: str, session_id: str, event: dict[str, Any]) -> None:
        if on_session_event is not None:
            try:
                await on_session_event(principal_id, session_id, event)
            except Exception as exc:  # auditing must not break the request
                log.error("room.audit_hook_failed", error=str(exc))

    # -- start --------------------------------------------------------------------------

    @router.post("/room/start")
    async def start_room(request: Request) -> Response:
        await _guard(request)
        principal_id = await resolve(request)
        content_type = request.headers.get("content-type", "")
        is_form = content_type.startswith("application/x-www-form-urlencoded") or content_type.startswith("multipart/form-data")

        url = ""
        message_id = None
        if is_form:
            form = await request.form()
            url = str(form.get("url") or "").strip()
            message_id = str(form.get("message_id") or "") or None
        else:
            try:
                body = await request.json()
            except (json.JSONDecodeError, ValueError):
                return JSONResponse({"error": "body must be JSON with a 'url' field"}, status_code=400)
            if not isinstance(body, dict):
                return JSONResponse({"error": "body must be a JSON object"}, status_code=400)
            url = str(body.get("url") or "").strip()

        try:
            validate_room_url(url)
        except RoomUrlError as exc:
            if is_form:
                return _render_start_page(error=str(exc), url=url)
            return JSONResponse({"error": str(exc)}, status_code=400)

        try:
            session = await manager.start(url, principal_id)
        except RoomFull as exc:
            if is_form:
                return _render_start_page(error=str(exc), url=url, status_code=503)
            return JSONResponse({"error": str(exc)}, status_code=503)
        except RoomUrlError as exc:
            if is_form:
                return _render_start_page(error=str(exc), url=url)
            return JSONResponse({"error": str(exc)}, status_code=400)

        await _audit(principal_id, session.session_id, {"event": "start", "url": url, "message_id": message_id})
        room_url = f"/room/{session.session_id}"
        if is_form:
            return RedirectResponse(room_url, status_code=303)
        return JSONResponse({"session_id": session.session_id, "room_url": room_url}, status_code=201)

    # -- the UI -------------------------------------------------------------------------

    @router.get("/room/{session_id}", response_class=HTMLResponse)
    async def room_page(session_id: str, request: Request) -> Response:
        principal_id = await resolve(request)
        session = manager.get(session_id)
        if session is None:
            return HTMLResponse(_not_found_page(), status_code=404)
        if session.principal_id != principal_id:
            raise HTTPException(status_code=403, detail="not your reading room")
        return HTMLResponse(_room_page(session_id))

    # -- websocket ----------------------------------------------------------------------

    @router.websocket("/room/{session_id}/ws")
    async def room_ws(websocket: WebSocket, session_id: str) -> None:
        principal_id = await _principal_for_ws(websocket)
        session = manager.get(session_id)
        if session is None or session.principal_id != principal_id:
            await websocket.close(code=WS_POLICY_VIOLATION)
            return
        await websocket.accept()

        async def send(message: dict[str, Any] | bytes) -> None:
            if isinstance(message, bytes):
                await websocket.send_bytes(message)
            else:
                await websocket.send_text(json.dumps(message))

        try:
            detach = manager.attach_client(session_id, send)
        except (RoomNotFound, RoomClosed):
            await websocket.close(code=WS_POLICY_VIOLATION)
            return

        try:
            while True:
                raw = await websocket.receive_text()
                try:
                    event = json.loads(raw)
                except json.JSONDecodeError:
                    await send({"t": "warning", "code": "bad_event", "detail": "not valid JSON"})
                    continue
                try:
                    await manager.handle_input(session_id, event)
                except RoomInputError as exc:
                    await send({"t": "warning", "code": "bad_event", "detail": str(exc)})
                except (RoomNotFound, RoomClosed):
                    break
        except WebSocketDisconnect:
            pass
        except Exception as exc:  # pragma: no cover - defensive
            log.error("room.ws_error", session_id=session_id, error=str(exc))
        finally:
            detach()

    # -- safe download ------------------------------------------------------------------

    @router.get("/room/{session_id}/download/{index}/safe")
    async def safe_download(session_id: str, index: int, request: Request) -> Response:
        principal_id = await resolve(request)
        session = manager.get(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        if session.principal_id != principal_id:
            raise HTTPException(status_code=403, detail="not your reading room")
        if index < 0 or index >= len(session.downloads):
            raise HTTPException(status_code=404, detail="no such download")
        record = session.downloads[index]
        if record.safe_copy_ref is None:
            raise HTTPException(status_code=409, detail="no safe copy is available for this file")
        try:
            data = manager.artifact_store.get(record.safe_copy_ref)
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(status_code=410, detail="safe copy is no longer available") from exc
        await _audit(principal_id, session_id, {"event": "safe_download", "index": index, "sha256": record.sha256})
        filename = _safe_pdf_name(record.suggested_filename)
        return Response(
            content=data,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"},
        )

    # -- close --------------------------------------------------------------------------

    @router.post("/room/{session_id}/close")
    async def close_room(session_id: str, request: Request) -> Response:
        await _guard(request)
        principal_id = await resolve(request)
        session = manager.get(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        if session.principal_id != principal_id:
            raise HTTPException(status_code=403, detail="not your reading room")
        closed = await manager.close(session_id, reason="closed by user")
        await _audit(principal_id, session_id, {"event": "close"})
        return JSONResponse({"closed": closed})

    return router


# --- page rendering ----------------------------------------------------------------------


def _safe_pdf_name(name: str) -> str:
    cleaned = "".join(c for c in name if c.isalnum() or c in " ._-").strip().lstrip(".") or "download"
    if cleaned.lower().endswith(".pdf"):
        cleaned = cleaned[:-4].rstrip(". ") or "download"
    return cleaned[:100] + ".safe.pdf"


def _load_static(name: str) -> str:
    return resources.files("reddysec.chamber.static").joinpath(name).read_text(encoding="utf-8")


def _room_page(session_id: str) -> str:
    return _load_static("room.html").replace("__SESSION_ID__", json.dumps(session_id))


def _render_start_page(error: str, url: str = "", status_code: int = 400) -> HTMLResponse:
    html = (
        _load_static("start.html")
        .replace("__ERROR__", _escape(error))
        .replace("__URL__", _escape(url))
    )
    return HTMLResponse(html, status_code=status_code)


def _not_found_page() -> str:
    return _load_static("start.html").replace("__ERROR__", "That reading room is not open. Start a new one below.").replace("__URL__", "")


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )

"""Glue between the web application and the chamber's Reading Room.

The Reading Room (``reddysec.chamber.readingroom``) knows nothing about users,
sessions or CSRF; this module gives it the three things it needs from the web
tier: the signed-in principal, a CSRF check for its state-changing routes, and
an audit sink so every room a client opens shows up in their glass-box log.

The manager is created when the app is built but launches Chromium lazily, so
construction is cheap and the browser always lives in the server's event loop.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status

from reddysec.config import Settings
from reddysec.core.artifacts import ArtifactStore
from reddysec.core.logging import get_logger
from reddysec.store.db import Database

from . import auth, queries
from .security import CSRF_FORM_FIELD, CSRF_HEADER, tokens_match

log = get_logger(__name__)

REAP_INTERVAL_S = 30.0


async def csrf_guard(request: Request) -> None:
    """CSRF check for the room's mutating routes. HTML forms carry the session
    token in the body; JSON callers (a future mobile app) send it as a header."""
    expected = request.session.get("csrf") if "session" in request.scope else None
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("application/json"):
        presented: str | None = request.headers.get(CSRF_HEADER)
    else:
        form = await request.form()
        value = form.get(CSRF_FORM_FIELD)
        presented = value if isinstance(value, str) else None
    if not tokens_match(expected, presented):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="This form has expired. Please go back, refresh the page and try again.",
        )


def make_audit_hook(database: Database):
    """Record room events (start, close, downloads) in the client's audit log."""

    async def on_session_event(principal_id: str, session_id: str, event: dict[str, Any]) -> None:
        kind = str(event.get("event") or "event")
        async with database.session() as session:
            actor = await queries.get_user(session, principal_id)
            queries.audit(
                session,
                actor=actor,
                action=f"reading_room_{kind}",
                target=session_id,
                details={k: v for k, v in event.items() if k != "event"},
            )

    return on_session_event


class ReadingRoomBundle:
    """What ``create_app`` needs: the router to mount and a lifespan hook."""

    def __init__(self, manager: Any, router: APIRouter):
        self.manager = manager
        self.router = router

    @asynccontextmanager
    async def lifespan(self) -> AsyncIterator[None]:
        stop = asyncio.Event()

        async def reaper() -> None:
            while not stop.is_set():
                try:
                    await asyncio.wait_for(stop.wait(), REAP_INTERVAL_S)
                except TimeoutError:
                    try:
                        closed = await self.manager.reap_idle()
                        if closed:
                            log.info("reading_room.reaped_idle", count=len(closed))
                    except Exception:  # the reaper must never die
                        log.exception("reading_room.reap_failed")

        task = asyncio.create_task(reaper())
        try:
            yield
        finally:
            stop.set()
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
            try:
                await self.manager.shutdown()
            except Exception:
                log.exception("reading_room.shutdown_failed")


def build_reading_room(settings: Settings, artifact_store: ArtifactStore, database: Database) -> ReadingRoomBundle:
    """Create the manager and its router wired to the web tier's auth, CSRF and audit."""
    from reddysec.chamber.readingroom import ReadingRoomManager  # lazy: pulls in Playwright
    from reddysec.chamber.readingroom_web import make_room_router

    manager = ReadingRoomManager(
        artifact_store,
        max_sessions=settings.reading_room_max_sessions,
        idle_timeout_s=settings.reading_room_idle_timeout_s,
    )
    router = make_room_router(
        manager,
        get_principal_id=auth.get_principal_id,
        on_session_event=make_audit_hook(database),
        mutation_guard=csrf_guard,
    )
    return ReadingRoomBundle(manager, router)

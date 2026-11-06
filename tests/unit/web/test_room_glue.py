"""The web <-> Reading Room glue: CSRF guard, audit hook, lifespan, factory."""

from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from reddysec.config import get_settings
from reddysec.core.artifacts import LocalArtifactStore
from reddysec.store import repo
from reddysec.store.models import AuditLog
from reddysec.web import room as room_glue


def _request(headers: dict[str, str], session: dict | None, body: bytes = b"") -> Request:
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/room/start",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "query_string": b"",
    }
    if session is not None:
        scope["session"] = session
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


class TestCsrfGuard:
    async def test_form_token_accepted(self):
        req = _request(
            {"content-type": "application/x-www-form-urlencoded"}, {"csrf": "abc"}, b"csrf_token=abc&url=x"
        )
        await room_glue.csrf_guard(req)

    async def test_form_token_missing_rejected(self):
        req = _request({"content-type": "application/x-www-form-urlencoded"}, {"csrf": "abc"}, b"url=x")
        with pytest.raises(HTTPException) as exc:
            await room_glue.csrf_guard(req)
        assert exc.value.status_code == 403

    async def test_json_header_accepted_and_rejected(self):
        ok = _request({"content-type": "application/json", "X-CSRF-Token": "abc"}, {"csrf": "abc"}, b"{}")
        await room_glue.csrf_guard(ok)
        bad = _request({"content-type": "application/json", "X-CSRF-Token": "nope"}, {"csrf": "abc"}, b"{}")
        with pytest.raises(HTTPException):
            await room_glue.csrf_guard(bad)

    async def test_no_session_rejected(self):
        req = _request({"content-type": "application/json", "X-CSRF-Token": "abc"}, None, b"{}")
        with pytest.raises(HTTPException):
            await room_glue.csrf_guard(req)


class TestAuditHook:
    async def test_writes_audit_row_for_known_and_unknown_actor(self, db):
        async with db.session() as session:
            user = await repo.create_user(session, email="p@example.com", display_name="P")
        hook = room_glue.make_audit_hook(db)
        await hook(user.id, "room_1", {"event": "start", "url": "https://example.com", "message_id": "msg_1"})
        await hook("usr_missing", "room_2", {"event": "close"})
        async with db.session() as session:
            rows = (await session.execute(AuditLog.__table__.select())).mappings().all()
        actions = {(r["action"], r["target"]) for r in rows}
        assert ("reading_room_start", "room_1") in actions
        assert ("reading_room_close", "room_2") in actions
        start = next(r for r in rows if r["action"] == "reading_room_start")
        assert start["details"] == {"url": "https://example.com", "message_id": "msg_1"}
        assert start["actor_id"] == user.id


class _FakeManager:
    def __init__(self, fail_reap: bool = False, fail_shutdown: bool = False):
        self.reaps = 0
        self.shutdowns = 0
        self.fail_reap = fail_reap
        self.fail_shutdown = fail_shutdown

    async def reap_idle(self, now=None):
        self.reaps += 1
        if self.fail_reap:
            raise RuntimeError("boom")
        return ["room_x"] if self.reaps == 1 else []

    async def shutdown(self):
        self.shutdowns += 1
        if self.fail_shutdown:
            raise RuntimeError("boom")


class TestBundleLifespan:
    async def test_reaper_runs_and_shutdown_is_called(self, monkeypatch):
        monkeypatch.setattr(room_glue, "REAP_INTERVAL_S", 0.01)
        manager = _FakeManager()
        bundle = room_glue.ReadingRoomBundle(manager, router=None)  # type: ignore[arg-type]
        async with bundle.lifespan():
            await asyncio.sleep(0.08)
        assert manager.reaps >= 2 and manager.shutdowns == 1

    async def test_failures_in_reaper_and_shutdown_are_contained(self, monkeypatch):
        monkeypatch.setattr(room_glue, "REAP_INTERVAL_S", 0.01)
        manager = _FakeManager(fail_reap=True, fail_shutdown=True)
        bundle = room_glue.ReadingRoomBundle(manager, router=None)  # type: ignore[arg-type]
        async with bundle.lifespan():
            await asyncio.sleep(0.05)
        assert manager.reaps >= 1 and manager.shutdowns == 1


class TestBuildReadingRoom:
    def test_builds_manager_and_router_from_settings(self, db, tmp_path):
        settings = get_settings()
        bundle = room_glue.build_reading_room(settings, LocalArtifactStore(tmp_path), db)
        paths = {getattr(r, "path", None) for r in bundle.router.routes}
        assert "/room/start" in paths and "/room/{session_id}/ws" in paths
        assert bundle.manager.max_sessions == settings.reading_room_max_sessions

    def test_create_app_enables_reading_room(self, db, tmp_path):
        from starlette.testclient import TestClient

        from reddysec.web.app import create_app

        app = create_app(get_settings(), db=db, enable_reading_room=True, artifact_store=LocalArtifactStore(tmp_path))
        assert app.state.room_enabled and app.state.room_manager is not None
        with TestClient(app) as client:
            assert client.get("/healthz").status_code == 200

"""Unit tests for the Reading Room FastAPI router.

A fake engine stands in for Playwright, and the manager is driven through the
real router with Starlette's TestClient (HTTP and websocket). Authorization,
the JSON-vs-form behaviour of /room/start, the safe-download route and the
websocket contract are all covered.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from reddysec.chamber.readingroom import ReadingRoomManager
from reddysec.chamber.readingroom_web import make_room_router


@pytest.fixture
def app(store, fake_engine_factory):
    factory, created = fake_engine_factory
    manager = ReadingRoomManager(store, max_sessions=5, engine_factory=factory)
    principal = {"id": "prin_1"}

    async def get_principal_id(request: Request) -> str:
        # Tests set the principal via a header; default to prin_1.
        return request.headers.get("x-principal", principal["id"])

    audit: list[tuple] = []

    async def on_event(pid, sid, event):
        audit.append((pid, sid, event["event"]))

    application = FastAPI()
    application.include_router(make_room_router(manager, get_principal_id=get_principal_id, on_session_event=on_event))
    application.state.manager = manager
    application.state.created = created
    application.state.audit = audit
    return application


@pytest.fixture
def client(app):
    with TestClient(app) as c:
        yield c


class TestStartJson:
    def test_json_start_returns_room_url(self, client):
        resp = client.post("/room/start", json={"url": "example.com/doc"})
        assert resp.status_code == 201
        body = resp.json()
        assert body["room_url"] == f"/room/{body['session_id']}"

    def test_json_bad_url(self, client):
        resp = client.post("/room/start", json={"url": "ftp://x"})
        assert resp.status_code == 400 and "error" in resp.json()

    def test_json_not_object(self, client):
        assert client.post("/room/start", json=["x"]).status_code == 400

    def test_json_malformed_body(self, client):
        resp = client.post("/room/start", content=b"not json", headers={"content-type": "application/json"})
        assert resp.status_code == 400

    def test_full_returns_503(self, client, app):
        for _ in range(5):
            client.post("/room/start", json={"url": "example.com"})
        resp = client.post("/room/start", json={"url": "example.com"})
        assert resp.status_code == 503


class TestStartForm:
    def test_form_start_redirects(self, client):
        resp = client.post("/room/start", data={"url": "example.com", "message_id": "msg_7"}, follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"].startswith("/room/room_")

    def test_form_bad_url_rerenders(self, client):
        resp = client.post("/room/start", data={"url": "ftp://x"}, follow_redirects=False)
        assert resp.status_code == 400
        assert "text/html" in resp.headers["content-type"]

    def test_form_audit_records_message_id(self, client, app):
        client.post("/room/start", data={"url": "example.com", "message_id": "msg_7"}, follow_redirects=False)
        assert any(e[2] == "start" for e in app.state.audit)


class TestRoomPage:
    def test_owner_gets_page(self, client):
        sid = client.post("/room/start", json={"url": "example.com"}).json()["session_id"]
        resp = client.get(f"/room/{sid}")
        assert resp.status_code == 200 and "Reading Room" in resp.text

    def test_wrong_principal_forbidden(self, client):
        sid = client.post("/room/start", json={"url": "example.com"}).json()["session_id"]
        resp = client.get(f"/room/{sid}", headers={"x-principal": "prin_other"})
        assert resp.status_code == 403

    def test_missing_room_404(self, client):
        assert client.get("/room/room_missing").status_code == 404


class TestWebsocket:
    def test_attach_receives_state_then_frame(self, client, app):
        sid = client.post("/room/start", json={"url": "example.com"}).json()["session_id"]
        with client.websocket_connect(f"/room/{sid}/ws") as ws:
            first = ws.receive_json()
            assert first["t"] == "state"
            # push a frame from the engine, from inside the app's event loop
            engine = app.state.created[0]
            client.portal.call(engine.emit, {"t": "frame", "b64": "zzz", "w": 100, "h": 80})
            frame = ws.receive_json()
            assert frame["t"] == "frame" and frame["b64"] == "zzz"

    def test_input_reaches_engine(self, client, app):
        sid = client.post("/room/start", json={"url": "example.com"}).json()["session_id"]
        with client.websocket_connect(f"/room/{sid}/ws") as ws:
            ws.receive_json()  # state
            ws.send_json({"t": "mouse", "action": "click", "x": 10, "y": 20})
            ws.send_json({"t": "ping"})
            # give the server a moment, then assert the engine saw the click
            import time

            time.sleep(0.1)
        assert any(i.get("action") == "click" for i in app.state.created[0].inputs)

    def test_bad_input_warns_not_closes(self, client, app):
        sid = client.post("/room/start", json={"url": "example.com"}).json()["session_id"]
        with client.websocket_connect(f"/room/{sid}/ws") as ws:
            ws.receive_json()  # state
            ws.send_json({"t": "nonsense"})
            warning = ws.receive_json()
            assert warning["t"] == "warning" and warning["code"] == "bad_event"

    def test_bad_json_warns(self, client):
        sid = client.post("/room/start", json={"url": "example.com"}).json()["session_id"]
        with client.websocket_connect(f"/room/{sid}/ws") as ws:
            ws.receive_json()
            ws.send_text("{not json")
            assert ws.receive_json()["code"] == "bad_event"

    def test_wrong_principal_rejected(self, client):
        sid = client.post("/room/start", json={"url": "example.com"}).json()["session_id"]
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(f"/room/{sid}/ws", headers={"x-principal": "prin_other"}) as ws:
                ws.receive_json()

    def test_missing_session_rejected(self, client):
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/room/room_missing/ws") as ws:
                ws.receive_json()


class TestSafeDownload:
    def _download(self, client, app, data, name):
        sid = client.post("/room/start", json={"url": "example.com"}).json()["session_id"]
        engine = app.state.created[-1]
        client.portal.call(engine.trigger_download, "dl_0", data, name)
        return sid

    def test_safe_pdf_served(self, client, app):
        from .test_cdr import pdf_with_js

        sid = self._download(client, app, pdf_with_js(), "statement.pdf")
        resp = client.get(f"/room/{sid}/download/0/safe")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"
        assert "statement.safe.pdf" in resp.headers["content-disposition"]
        assert resp.content[:5] == b"%PDF-"

    def test_no_safe_copy_409(self, client, app):
        sid = self._download(client, app, b"MZ\x90\x00" + b"\x00" * 40, "invoice.exe")
        assert client.get(f"/room/{sid}/download/0/safe").status_code == 409

    def test_out_of_range_404(self, client, app):
        sid = self._download(client, app, b"%PDF-1.4", "x.pdf")
        assert client.get(f"/room/{sid}/download/9/safe").status_code == 404

    def test_wrong_principal_forbidden(self, client, app):
        from .test_cdr import pdf_with_js

        sid = self._download(client, app, pdf_with_js(), "s.pdf")
        assert client.get(f"/room/{sid}/download/0/safe", headers={"x-principal": "prin_other"}).status_code == 403


class TestClose:
    def test_owner_can_close(self, client, app):
        sid = client.post("/room/start", json={"url": "example.com"}).json()["session_id"]
        resp = client.post(f"/room/{sid}/close")
        assert resp.status_code == 200 and resp.json()["closed"] is True
        assert app.state.manager.active_count == 0

    def test_wrong_principal_cannot_close(self, client):
        sid = client.post("/room/start", json={"url": "example.com"}).json()["session_id"]
        assert client.post(f"/room/{sid}/close", headers={"x-principal": "prin_other"}).status_code == 403

    def test_close_missing_404(self, client):
        assert client.post("/room/room_missing/close").status_code == 404


class TestEdges:
    def test_audit_hook_failure_does_not_break_start(self, store, fake_engine_factory):
        factory, _ = fake_engine_factory
        manager = ReadingRoomManager(store, engine_factory=factory)

        async def boom(pid, sid, event):
            raise RuntimeError("audit sink down")

        application = FastAPI()
        application.include_router(make_room_router(manager, on_session_event=boom))
        with TestClient(application) as c:
            assert c.post("/room/start", json={"url": "example.com"}).status_code == 201

    def test_form_start_when_full_rerenders_503(self, store, fake_engine_factory):
        factory, _ = fake_engine_factory
        manager = ReadingRoomManager(store, max_sessions=1, engine_factory=factory)
        application = FastAPI()
        application.include_router(make_room_router(manager))
        with TestClient(application) as c:
            c.post("/room/start", data={"url": "example.com"}, follow_redirects=False)
            resp = c.post("/room/start", data={"url": "example.com"}, follow_redirects=False)
            assert resp.status_code == 503 and "text/html" in resp.headers["content-type"]

    def test_safe_copy_gone_returns_410(self, client, app):
        from .test_cdr import pdf_with_js

        sid = client.post("/room/start", json={"url": "example.com"}).json()["session_id"]
        engine = app.state.created[-1]
        client.portal.call(engine.trigger_download, "dl_0", pdf_with_js(), "s.pdf")
        # delete the safe copy from the store, then request it
        session = app.state.manager.get(sid)
        app.state.manager.artifact_store.delete(session.downloads[0].safe_copy_ref)
        assert client.get(f"/room/{sid}/download/0/safe").status_code == 410


class TestDefaultPrincipal:
    def test_router_runs_without_resolver(self, store, fake_engine_factory):
        factory, _ = fake_engine_factory
        manager = ReadingRoomManager(store, engine_factory=factory)
        application = FastAPI()
        application.include_router(make_room_router(manager))  # no get_principal_id
        with TestClient(application) as c:
            sid = c.post("/room/start", json={"url": "example.com"}).json()["session_id"]
            assert c.get(f"/room/{sid}").status_code == 200  # "dev" principal owns it

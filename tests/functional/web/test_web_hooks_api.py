"""Pub/Sub webhook and the JSON API."""

from __future__ import annotations

import base64
import json

from starlette.testclient import TestClient

from reddysec.web.app import create_app

HOOK = "/hooks/gmail/pubsub"


def envelope(email: str = "client@gmail.com", history_id: int | str = 4242) -> dict:
    data = base64.b64encode(json.dumps({"emailAddress": email, "historyId": history_id}).encode()).decode()
    return {
        "message": {"data": data, "messageId": "1", "publishTime": "2026-11-05T12:00:00Z"},
        "subscription": "s",
    }


async def test_pubsub_rejects_wrong_or_missing_token(client, push):
    assert client.post(HOOK, json=envelope()).status_code == 403
    assert client.post(f"{HOOK}?token=wrong", json=envelope()).status_code == 403
    assert push.calls == []


async def test_pubsub_calls_handler_and_acknowledges(client, push):
    response = client.post(f"{HOOK}?token=pubsub-shared-token", json=envelope(history_id=99))
    assert response.status_code == 204 and response.content == b""
    assert push.calls == [("client@gmail.com", "99")]


async def test_pubsub_acknowledges_bad_payloads_without_calling_handler(client, push):
    good = f"{HOOK}?token=pubsub-shared-token"
    assert (
        client.post(good, content=b"not json", headers={"content-type": "application/json"}).status_code
        == 204
    )
    assert client.post(good, json={"message": {"data": "!!!not-base64!!!"}}).status_code == 204
    assert (
        client.post(good, json={"message": {"data": base64.b64encode(b"[1,2]").decode()}}).status_code == 204
    )
    assert client.post(good, json={"nope": 1}).status_code == 204
    missing_fields = base64.b64encode(json.dumps({"emailAddress": "x@y"}).encode()).decode()
    assert client.post(good, json={"message": {"data": missing_fields}}).status_code == 204
    assert push.calls == []


async def test_pubsub_swallows_handler_errors(client, push):
    push.fail_with = RuntimeError("worker queue down")
    assert client.post(f"{HOOK}?token=pubsub-shared-token", json=envelope()).status_code == 204
    assert push.calls == [("client@gmail.com", "4242")]


async def test_pubsub_without_configured_token_rejects_everything(settings, db):
    app = create_app(settings, db=db, pubsub_token=None)
    with TestClient(app) as c:
        assert c.post(f"{HOOK}?token=anything", json=envelope()).status_code == 403


async def test_pubsub_without_handler_still_acknowledges(settings, db):
    app = create_app(settings, db=db, pubsub_token="t", on_gmail_push=None)
    with TestClient(app) as c:
        assert c.post(f"{HOOK}?token=t", json=envelope()).status_code == 204


async def test_api_me_and_messages(client, seed, login):
    user = await seed.user("api@example.com", name="Api Person")
    gmail = await seed.mailbox(user)
    yahoo = await seed.mailbox(user, provider="yahoo", address="api@yahoo.com", mode="hold")
    newest = await seed.message(gmail, level="malicious", subject="Newest", hours_ago=0.5)
    await seed.message(gmail, level="safe", subject="Older", hours_ago=5)
    await seed.message(yahoo, level="suspicious", subject="Yahoo one", quarantined=False, hours_ago=2)
    login(client, "api@example.com")

    me = client.get("/api/me")
    assert me.status_code == 200
    body = me.json()
    assert body["login_email"] == "api@example.com" and body["role"] == "principal"
    assert [m["address"] for m in body["mailboxes"]] == ["api@example.com", "api@yahoo.com"]
    assert body["mailboxes"][1]["mode"] == "hold"

    listing = client.get("/api/messages?limit=2")
    assert listing.status_code == 200
    items = listing.json()["items"]
    assert [i["subject"] for i in items] == ["Newest", "Yahoo one"]
    assert (
        items[0]["id"] == newest.id
        and items[0]["verdict_label"] == "Suspicious"
        and items[0]["quarantined"] is True
    )
    assert items[0]["received_at"].endswith("+00:00")
    assert items[0]["summary"].startswith("Test summary")

    filtered = client.get(f"/api/messages?mailbox_id={yahoo.id}&level=suspicious")
    assert [i["subject"] for i in filtered.json()["items"]] == ["Yahoo one"]
    assert client.get("/api/messages?limit=0").status_code == 422

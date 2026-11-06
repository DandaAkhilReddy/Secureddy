""""Ask Secureddy" pages: CSRF, authz, disabled state, sending, proposal cards."""

from __future__ import annotations

import re

import pytest
from sqlalchemy import select
from starlette.testclient import TestClient

from reddysec.assistant.llm import ChatError, ChatReply, ToolCall
from reddysec.store.models import AssistantMessageRow, AuditLog, FeedbackReasonRow, MessageRow
from reddysec.web.app import create_app

JSON = {"Accept": "application/json"}


class FakeChat:
    def __init__(self, *replies):
        self.replies = list(replies)
        self.seen = []

    async def complete(self, system, messages, tools):
        self.seen.append(messages)
        reply = self.replies.pop(0) if self.replies else ChatReply("Okay.")
        if isinstance(reply, Exception):
            raise reply
        return reply


@pytest.fixture
def chat():
    return FakeChat()


@pytest.fixture
def app(settings, db, artifact_store, chat):
    return create_app(settings, db=db, artifact_store=artifact_store, chat_model=chat)


async def _world(seed, login, client, email="owner@example.com"):
    user = await seed.user(email)
    mailbox = await seed.mailbox(user)
    message = await seed.message(mailbox, level="suspicious", quarantined=False, subject="Your order has shipped",
                                 from_address="orders@walmart-deliveries.net", from_name="Walmart.com")
    login(client, email)
    return user, mailbox, message


def _conv_id(location: str) -> str:
    return re.search(r"/assistant/(cnv_[A-Za-z0-9]+)", location).group(1)


async def test_page_renders_with_suggestions_and_nav(client, seed, login):
    await _world(seed, login, client)
    page = client.get("/assistant")
    assert page.status_code == 200
    assert "What&#39;s suspicious this week?" in page.text and 'id="composer"' in page.text
    assert 'href="/assistant" aria-current="page"' in page.text
    assert re.search(r'<script src="/static/assistant.js\?v=[0-9a-f]{10}" defer></script>', page.text)
    assert "innerHTML" not in client.get("/static/assistant.js").text


async def test_disabled_state_is_calm(settings, db, artifact_store, seed, login):
    app = create_app(settings, db=db, artifact_store=artifact_store)  # no provider configured
    with TestClient(app, follow_redirects=False) as c:
        await _world(seed, login, c)
        page = c.get("/assistant")
        assert page.status_code == 200 and "The assistant isn't switched on yet" in page.text
        assert 'id="composer"' not in page.text and "assistant.js" not in page.text
        token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        reply = c.post("/assistant/send", data={"message": "hi", "csrf_token": token}, headers=JSON)
        assert reply.status_code == 200 and "switched on" in reply.json()["reply"]["text"]
        assert "isn't switched on yet" in c.get("/").text


async def test_send_requires_csrf(client, seed, login):
    await _world(seed, login, client)
    for path in ("/assistant/send", "/assistant/new"):
        assert client.post(path, data={"message": "hi"}).status_code == 403


async def test_send_json_with_tool_and_proposal(client, seed, login, csrf_of, db, chat):
    _u, _mb, message = await _world(seed, login, client)
    chat.replies = [
        ChatReply("", (ToolCall("t1", "propose_mark_fake", {"message_id": message.id, "reason": "<b>Fake</b> shop"}),)),
        ChatReply("**Careful.** It is not from Walmart.\n- short link\n- new sender"),
    ]
    token = csrf_of(client, "/assistant")
    reply = client.post("/assistant/send", data={"message": "Is the Walmart one real?", "csrf_token": token}, headers=JSON)
    assert reply.status_code == 200
    body = reply.json()
    assert body["reply"]["text"].startswith("**Careful.**") and body["conversation_url"].startswith("/assistant/cnv_")
    (card,) = body["reply"]["proposals"]
    assert card["action"] == f"/messages/{message.id}/fake" and card["yes"] == "Yes, mark as fake"
    assert card["status"] == "open" and card["next"].startswith(body["conversation_url"])
    async with db.session() as s:
        row = await s.get(MessageRow, message.id)
        assert row.state == "done" and row.level == "suspicious"  # nothing changed

    page = client.get(body["conversation_url"]).text
    assert "<strong>Careful.</strong>" in page and "<li>short link</li>" in page
    assert "&lt;b&gt;Fake&lt;/b&gt; shop" in page and "<b>Fake</b>" not in page
    assert f'action="/messages/{message.id}/fake"' in page and 'name="reason_code" value="assistant"' in page
    assert "Is the Walmart one real?" in client.get("/assistant").text  # listed on the left

    # The person clicks "Yes": the ordinary route acts, and the page reflects it.
    token = csrf_of(client, body["conversation_url"])
    done = client.post(f"/messages/{message.id}/fake",
                       data={"csrf_token": token, "reason_code": "assistant", "next": card["next"]})
    assert done.status_code == 303 and done.headers["location"] == card["next"]
    page = client.get(body["conversation_url"]).text
    assert "Marked as fake." in page and "Yes, mark as fake" not in page
    async with db.session() as s:
        (reason,) = (await s.execute(select(FeedbackReasonRow))).scalars()
        assert reason.reason_code == "assistant"
        actions = [a.action for a in (await s.execute(select(AuditLog))).scalars()]
    assert "assistant_question" in actions and "sender_blocked" in actions


async def test_send_without_js_redirects_and_decline(client, seed, login, csrf_of, db, chat):
    _u, _mb, message = await _world(seed, login, client)
    chat.replies = [ChatReply("", (ToolCall("t", "propose_recheck", {"message_id": message.id}),)), ChatReply("Try again?")]
    token = csrf_of(client, "/")
    sent = client.post("/assistant/send", data={"message": "What's suspicious this week?", "csrf_token": token})
    assert sent.status_code == 303
    conv = _conv_id(sent.headers["location"])
    page = client.get(f"/assistant/{conv}").text
    assert "Check this email again?" in page and "Try again?" in page
    reply_id = re.search(r'name="reply_id" value="([^"]+)"', page).group(1)
    token = csrf_of(client, f"/assistant/{conv}")
    declined = client.post(f"/assistant/{conv}/proposals/decline", data={"csrf_token": token, "reply_id": reply_id, "index": 0})
    assert declined.status_code == 303
    page = client.get(f"/assistant/{conv}").text
    assert "You said no. Nothing changed." in page and "Yes, check again" not in page
    json_decline = client.post(f"/assistant/{conv}/proposals/decline",
                               data={"csrf_token": token, "reply_id": reply_id, "index": 7}, headers=JSON)
    assert json_decline.json() == {"ok": False}
    assert client.post(f"/assistant/{conv}/proposals/decline",
                       data={"csrf_token": token, "reply_id": "amsg_nope", "index": 0}).status_code == 404


async def test_conversations_are_private(client, seed, login, csrf_of, chat):
    await _world(seed, login, client, "a@example.com")
    token = csrf_of(client, "/assistant")
    conv = _conv_id(client.post("/assistant/new", data={"csrf_token": token}).headers["location"])
    assert client.get(f"/assistant/{conv}").status_code == 200
    client.post("/auth/logout", data={"csrf_token": token})
    login(client, "b@example.com")
    token = csrf_of(client, "/assistant")
    assert client.get(f"/assistant/{conv}").status_code == 404
    assert client.post("/assistant/send", data={"message": "hi", "conversation_id": conv, "csrf_token": token}).status_code == 404
    assert client.post(f"/assistant/{conv}/proposals/decline",
                       data={"csrf_token": token, "reply_id": "x", "index": 0}).status_code == 404


async def test_about_is_validated(client, seed, login, csrf_of, chat):
    _u, _mb, message = await _world(seed, login, client)
    other = await seed.user("other@example.com")
    foreign = await seed.message(await seed.mailbox(other), subject="Not yours")
    page = client.get(f"/assistant?about={message.id}").text
    assert "About: Your order has shipped" in page and "Why was this email flagged?" in page
    assert client.get(f"/assistant?about={foreign.id}").status_code == 404
    report = client.get(f"/messages/{message.id}").text
    assert f'href="/assistant?about={message.id}"' in report and "Ask about this email" in report
    token = csrf_of(client, "/assistant")
    client.post("/assistant/send", data={"message": "Why?", "about": message.id, "csrf_token": token}, headers=JSON)
    assert message.id in chat.seen[-1][-1]["text"]


async def test_bad_input_limits_and_errors(client, seed, login, csrf_of, app, chat):
    await _world(seed, login, client)
    token = csrf_of(client, "/assistant")
    assert client.post("/assistant/send", data={"message": "  ", "csrf_token": token}, headers=JSON).status_code == 400
    too_long = client.post("/assistant/send", data={"message": "x" * 2001, "csrf_token": token})
    assert too_long.status_code == 303
    chat.replies = [ChatError("status 500")]
    failed = client.post("/assistant/send", data={"message": "hi", "csrf_token": token}, headers=JSON)
    assert failed.status_code == 200 and failed.json()["reply"]["failed"] is True
    app.state.assistant.daily_limit = 1
    limited = client.post("/assistant/send", data={"message": "again", "csrf_token": token}, headers=JSON)
    assert limited.status_code == 429 and "tomorrow" in limited.json()["error"]
    no_js = client.post("/assistant/send", data={"message": "again", "csrf_token": token})
    assert no_js.status_code == 303
    assert "The assistant will be back tomorrow" in client.get("/assistant").text


async def test_tool_rows_are_not_shown(client, seed, login, csrf_of, db, chat):
    await _world(seed, login, client)
    chat.replies = [ChatReply("", (ToolCall("t", "get_stats", {}),)), ChatReply("Quiet week.")]
    token = csrf_of(client, "/assistant")
    url = client.post("/assistant/send", data={"message": "stats", "csrf_token": token}, headers=JSON).json()["conversation_url"]
    page = client.get(url).text
    assert "Quiet week." in page and "checked_and_fine" not in page
    async with db.session() as s:
        roles = [r.role for r in (await s.execute(select(AssistantMessageRow))).scalars()]
    assert "tool" in roles


async def test_app_builds_model_from_settings(settings, db, artifact_store):
    from pydantic import SecretStr

    from reddysec.assistant.llm import AnthropicChat

    configured = settings.model_copy(update={"assistant_provider": "anthropic", "anthropic_api_key": SecretStr("sk")})
    app = create_app(configured, db=db, artifact_store=artifact_store)
    assert isinstance(app.state.assistant.model, AnthropicChat) and app.state.assistant.enabled
    with TestClient(app):
        pass  # lifespan opens and closes the owned HTTP client

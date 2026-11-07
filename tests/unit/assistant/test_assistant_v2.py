"""New assistant behaviour: streaming, result cards, the search / top / accounts /
link / preferences tools and their scoping, and "Let the assistant read this email"."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select

from reddysec.assistant.agent import FRIENDLY_ERROR, SYSTEM_PROMPT, Assistant
from reddysec.assistant.llm import AnthropicChat, ChatError, ChatReply, ToolCall, _anthropic_events
from reddysec.assistant.tools import ToolBox
from reddysec.core.anthropic_auth import AnthropicCredentials
from reddysec.core.ids import new_id
from reddysec.store.models import AppLockRow, AssistantMessageRow, AuditLog, MailboxRow, MessageRow
from reddysec.web import preferences

from .test_assistant_agent import INJECTION, ScriptedChat, call, new_conv, rows, verdict

# --------------------------------------------------------------------------- streaming parser


def sse(*events: dict, tail: bool = True) -> bytes:
    out = "".join(f"event: {e.get('type')}\ndata: {json.dumps(e)}\n\n" for e in events)
    return out.encode() if tail else out.rstrip("\n").encode()


STREAM = [
    {"type": "message_start"},
    {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Let me "}},
    {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "look."}},
    {"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": "tu1", "name": "top_suspicious"}},
    {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": '{"n": '}},
    {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "3}"}},
    {"type": "ping"},
    {"type": "message_stop"},
]


class TestAnthropicStream:
    async def test_text_and_tool_calls(self):
        seen: list[httpx.Request] = []

        def handler(request):
            seen.append(request)
            return httpx.Response(200, content=sse(*STREAM) + b"data: not json\n\n", headers={"content-type": "text/event-stream"})

        chat = AnthropicChat(httpx.AsyncClient(transport=httpx.MockTransport(handler)), "sk-key", "claude-sonnet-5-5")
        items = [i async for i in chat.stream("S", [{"role": "user", "text": "q"}], [])]
        assert items[:2] == ["Let me ", "look."]
        reply = items[-1]
        assert reply.text == "Let me look." and reply.tool_calls == (ToolCall("tu1", "top_suspicious", {"n": 3}),)
        assert json.loads(seen[0].content)["stream"] is True and seen[0].headers["x-api-key"] == "sk-key"
        assert chat.auth_mode == "api_key"

    async def test_stream_without_trailing_blank_line_and_errors(self):
        resp = httpx.Response(200, content=sse(STREAM[2], tail=False))
        items = [i async for i in _anthropic_events(resp)]
        assert items[0] == "Let me " and items[-1].text == "Let me"
        bad = httpx.Response(200, content=sse({"type": "error", "error": {"type": "overloaded_error"}}))
        with pytest.raises(ChatError):
            [i async for i in _anthropic_events(bad)]

    async def test_status_timeout_network(self):
        for handler, message in (
            (lambda r: httpx.Response(529), "status 529"),
            (lambda r: (_ for _ in ()).throw(httpx.ReadTimeout("slow")), "timeout"),
            (lambda r: (_ for _ in ()).throw(httpx.ConnectError("down")), "network"),
        ):
            chat = AnthropicChat(httpx.AsyncClient(transport=httpx.MockTransport(handler)), "k", "m")
            with pytest.raises(ChatError, match=message):
                [i async for i in chat.stream("S", [{"role": "user", "text": "q"}], [])]

    async def test_keyless_credentials_retry_once_after_401(self):
        exchanges = {"n": 0}
        api_calls: list[httpx.Request] = []

        def handler(request):
            if request.url.path == "/v1/oauth/token":
                exchanges["n"] += 1
                return httpx.Response(200, json={"access_token": f"oat-{exchanges['n']}", "expires_in": 600,
                                                 "token_type": "Bearer"})
            api_calls.append(request)
            if request.headers["authorization"] == "Bearer oat-1":
                return httpx.Response(401, json={"error": {"type": "authentication_error"}})
            if json.loads(request.content).get("stream"):
                return httpx.Response(200, content=sse(STREAM[1], STREAM[2]))
            return httpx.Response(200, json={"content": [{"type": "text", "text": "ok"}]})

        async def identity():
            return "jwt"

        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        creds = AnthropicCredentials(federation_rule_id="f", organization_id="o", service_account_id="s",
                                     identity_token=identity, http=http)
        chat = AnthropicChat(http, creds, "m")
        assert (await chat.complete("S", [{"role": "user", "text": "q"}], [])).text == "ok"
        assert exchanges["n"] == 2 and api_calls[-1].headers["anthropic-beta"] == "oauth-2025-04-20"
        assert "x-api-key" not in api_calls[-1].headers
        creds.invalidate()
        exchanges["n"] = 0  # next token is oat-1 again: 401, then oat-2
        items = [i async for i in chat.stream("S", [{"role": "user", "text": "q"}], [])]
        assert items[-1].text == "Let me"

    async def test_auth_failure_is_a_chat_error(self):
        async def identity():
            return "jwt"

        http = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(401, json={"error": "invalid_grant"})))
        creds = AnthropicCredentials(federation_rule_id="f", organization_id="o", service_account_id="s",
                                     identity_token=identity, http=http)
        with pytest.raises(ChatError, match="auth"):
            await AnthropicChat(http, creds, "m").complete("S", [{"role": "user", "text": "q"}], [])
        with pytest.raises(ChatError, match="status 401"):
            await AnthropicChat(http, "k", "m").complete("S", [{"role": "user", "text": "q"}], [])


# --------------------------------------------------------------------------- tools


class TestNewTools:
    async def test_top_suspicious_ranks_and_cards(self, db, world):
        async with db.session() as s:
            box = ToolBox(s, world["me"])
            out = await box.run("top_suspicious", {"n": 5, "days": 7})
        data = json.loads(out.content)
        ids = [m["message_id"] for m in data["messages"]]
        assert ids == [world["phish"].id, world["walmart"].id]  # quarantined first; the old one is outside 7 days
        assert world["secret"].id not in out.content
        (card,) = out.cards
        assert card["kind"] == "ranked" and [r["rank"] for r in card["rows"]] == [1, 2]
        assert card["rows"][0]["href"] == f"/messages/{world['phish'].id}" and card["rows"][0]["chip"]["tone"] == "bad"

    async def test_top_suspicious_other_user_and_nothing(self, db, world):
        from reddysec.store.models import UserRow

        async with db.session() as s:
            data = json.loads((await ToolBox(s, world["other"]).run("top_suspicious", {"days": 1, "mailbox": "all"})).content)
            assert [m["message_id"] for m in data["messages"]] == [world["secret"].id]
            lonely = UserRow(id=new_id("usr"), display_name="L", login_email="l@example.com")
            s.add(lonely)
            await s.flush()
            empty = json.loads((await ToolBox(s, lonely).run("top_suspicious", {})).content)
        assert empty["count"] == 0 and empty["note"]

    async def test_search_messages_words_level_sort_and_scope(self, db, world):
        async with db.session() as s:
            box = ToolBox(s, world["me"])
            words = json.loads((await box.run("search_messages", {"query": "walmart", "days": 90})).content)
            assert [m["message_id"] for m in words["messages"]] == [world["walmart"].id]
            out = await box.run("search_messages", {"query": "", "sort": "risk", "days": 90})
            risk = json.loads(out.content)
            assert risk["messages"][0]["message_id"] == world["phish"].id and out.cards[0]["kind"] == "ranked"
            q = json.loads((await box.run("search_messages", {"level": "quarantine", "sort": "risk"})).content)
            assert q["filter"]["level"] == "suspicious" and q["messages"][0]["message_id"] == world["phish"].id
            c = json.loads((await box.run("search_messages", {"level": "checked", "query": "dinner"})).content)
            assert c["count"] == 1
            sus = json.loads((await box.run("search_messages", {"level": "suspicious", "days": 90})).content)
            assert {m["message_id"] for m in sus["messages"]} == {world["walmart"].id, world["old"].id, world["phish"].id}
            nobody = json.loads((await box.run("search_messages", {"query": "Other person's secret", "days": 90})).content)
            assert nobody["count"] == 0
            bad = json.loads((await box.run("search_messages", {"mailbox": "other@example.com"})).content)
            assert bad["error"] == "unknown_mailbox"
            more = (await box.run("search_messages", {"query": "walmart"})).cards[0]["more_href"]
            assert more.startswith("/messages?q=walmart")

    async def test_selected_inbox_scopes_answers(self, db, world):
        async with db.session() as s:
            second = MailboxRow(id=new_id("mbx"), user_id=world["me"].id, provider="yahoo", address="me@yahoo.com",
                                labels={"x": "y"}, status="error")
            s.add(second)
            await s.flush()
            s.add(MessageRow(id=new_id("msg"), mailbox_id=second.id, provider_message_id="y1", from_address="z@z.com",
                             subject="Yahoo only", received_at=datetime.now(UTC) - timedelta(hours=1), state="done",
                             level="suspicious", score=50, verdict=verdict(), quarantined=False))
        async with db.session() as s:
            scoped = ToolBox(s, world["me"], mailbox_id=second.id)
            data = json.loads((await scoped.run("list_messages", {"level": "all"})).content)
            assert [m["email"]["untrusted"]["subject"] for m in data["messages"]] == ["Yahoo only"]
            everywhere = json.loads((await scoped.run("list_messages", {"mailbox": "all"})).content)
            assert everywhere["count"] == 4
            named = json.loads((await scoped.run("get_stats", {"mailbox": "me@example.com"})).content)
            assert named["inbox"] == "me@example.com" and named["suspicious"] == 2 and named["moved_out_of_inbox"] == 1
            bad = json.loads((await scoped.run("get_stats", {"mailbox": "nobody@x.com"})).content)
            assert bad["error"] == "unknown_mailbox"
            bad2 = json.loads((await scoped.run("list_messages", {"mailbox": "nobody@x.com"})).content)
            assert bad2["error"] == "unknown_mailbox"
            bad3 = json.loads((await scoped.run("top_suspicious", {"mailbox": "nobody@x.com"})).content)
            assert bad3["error"] == "unknown_mailbox"
            accounts = await scoped.run("list_accounts", {})
            data = json.loads(accounts.content)
            assert [a["address"] for a in data["accounts"]] == ["me@example.com", "me@yahoo.com"]
            assert data["accounts"][1]["status"] == "Needs reconnect" and data["accounts"][1]["selected"]
            assert accounts.cards[0]["kind"] == "accounts" and len(accounts.cards[0]["rows"]) == 2

    async def test_helper_sees_principal_only(self, db, world):
        async with db.session() as s:
            data = json.loads((await ToolBox(s, world["helper"]).run("list_accounts", {})).content)
            other = json.loads((await ToolBox(s, world["other"]).run("list_accounts", {})).content)
        assert [a["address"] for a in data["accounts"]] == ["me@example.com"]
        assert [a["address"] for a in other["accounts"]] == ["other@example.com"]

    async def test_preferences(self, db, world):
        async with db.session() as s:
            await preferences.set_preference(s, world["me"].id, preferences.INBOX_VIEW, "separate")
            s.add(AppLockRow(user_id=world["me"].id, kind="pin", secret_hash="x", timeout_s=60))
        async with db.session() as s:
            data = json.loads((await ToolBox(s, world["me"], mailbox_id=world["mailbox"].id).run("get_preferences", {})).content)
        assert data == {"accounts_shown": "separately", "looking_at": "me@example.com", "app_lock": "on",
                        "where_to_change": "Settings"}

    async def test_explain_link(self, db, world):
        async with db.session() as s:
            box = ToolBox(s, world["me"])
            out = await box.run("explain_link", {"message_id": world["walmart"].id, "url_index": 9})
            none = json.loads((await box.run("explain_link", {"message_id": world["safe"].id})).content)
            hidden = json.loads((await box.run("explain_link", {"message_id": world["secret"].id})).content)
        data = json.loads(out.content)
        assert data["advice"] == "open_in_reading_room" and data["link"]["untrusted"]["final_host"] == "track.evil.example"
        assert out.cards[0]["kind"] == "link" and out.cards[0]["href"].endswith("#links")
        assert none["error"] == "no_links" and hidden["error"] == "not_found"


# --------------------------------------------------------------------------- agent events


class StreamingChat(ScriptedChat):
    async def stream(self, system, messages, tools):
        reply = await self.complete(system, messages, tools)
        for word in reply.text.split(" "):
            if word:
                yield word + " "
        yield reply


class BrokenStream(ScriptedChat):
    async def stream(self, system, messages, tools):
        yield "partial "
        if False:  # pragma: no cover
            yield None


class TestEvents:
    async def test_stream_emits_status_deltas_cards_and_done(self, db, world):
        chat = StreamingChat(ChatReply("Let me look.", (ToolCall("t", "top_suspicious", {}),)),
                             ChatReply("Two need a look."))
        conv = await new_conv(db, world["me"])
        events = [e async for e in Assistant(chat).events(db, world["me"], conv, "most suspicious?")]
        kinds = [e["type"] for e in events]
        assert kinds[:3] == ["delta", "delta", "delta"] and "draft_done" in kinds and "status" in kinds
        assert kinds[-1] == "done" and "cards" in kinds
        result = events[-1]["result"]
        assert result.text == "Two need a look." and result.cards[0]["kind"] == "ranked"
        async with db.session() as s:
            stored = [r for r in (await s.execute(select(AssistantMessageRow))).scalars() if r.id == result.reply_id]
        assert stored[0].content["cards"] == result.cards
        assert chat.calls[0][0] == SYSTEM_PROMPT

    async def test_complete_only_model_still_streams_text(self, db, world):
        conv = await new_conv(db, world["me"])
        events = [e async for e in Assistant(ScriptedChat(ChatReply("Hi."))).events(db, world["me"], conv, "hi")]
        assert [e["type"] for e in events] == ["delta", "done"] and events[0]["text"] == "Hi."

    async def test_stream_ending_without_reply_is_friendly(self, db, world):
        conv = await new_conv(db, world["me"])
        events = [e async for e in Assistant(BrokenStream()).events(db, world["me"], conv, "hi")]
        assert events[-1]["result"].text == FRIENDLY_ERROR and events[-1]["result"].failed

    async def test_read_email_once_audited_and_not_stored(self, db, world):
        reads: list[str] = []

        async def reader(message, mailbox):
            reads.append(message.id)
            return "Please wire $5,000 today. " + INJECTION

        chat = ScriptedChat(ChatReply("It asks for a wire transfer."))
        conv = await new_conv(db, world["me"])
        result = await Assistant(chat).ask(db, world["me"], conv, "What does it want?", about=world["walmart"].id,
                                           read_email=reader)
        assert reads == [world["walmart"].id] and "wire transfer" in result.text
        sent = chat.calls[0][1][-1]["text"]
        assert '"untrusted"' in sent and "email_text" in sent and "Please wire" in sent
        async with db.session() as s:
            stored = list((await s.execute(select(AssistantMessageRow))).scalars())
            audits = [a for a in (await s.execute(select(AuditLog))).scalars() if a.action == "assistant_read_email"]
        assert all("Please wire" not in json.dumps(r.content) for r in stored)
        user_row = next(r for r in stored if r.role == "user")
        assert user_row.content["read_email"] is True
        assert len(audits) == 1 and audits[0].target == world["walmart"].id

    async def test_read_email_failures(self, db, world):
        async def broken(message, mailbox):
            raise RuntimeError("provider down")

        chat = ScriptedChat(ChatReply("I could not read it."))
        conv = await new_conv(db, world["me"])
        await Assistant(chat).ask(db, world["me"], conv, "q", about=world["walmart"].id, read_email=broken)
        assert "could not fetch the email" in chat.calls[0][1][-1]["text"]
        # Someone else's email: no read, no audit.
        chat2 = ScriptedChat(ChatReply("ok"))
        await Assistant(chat2).ask(db, world["me"], conv, "q", about=world["secret"].id, read_email=broken)
        assert "email_text" not in chat2.calls[0][1][-1]["text"]
        assert len([a for a in await rows(db, AuditLog) if a.action == "assistant_read_email"]) == 1

    async def test_cards_capped_and_deduplicated(self, db, world):
        calls = [ChatReply("", tuple(ToolCall(f"t{i}", "list_accounts", {}) for i in range(3)))] * 3
        chat = ScriptedChat(*calls, ChatReply("done"))
        conv = await new_conv(db, world["me"])
        result = await Assistant(chat).ask(db, world["me"], conv, "accounts?")
        assert len(result.cards) == 1

    def test_prompt_has_scope_guard(self):
        assert "Scope: only this person's own email" in SYSTEM_PROMPT and "top_suspicious" in SYSTEM_PROMPT
        assert call("x")  # helper import used

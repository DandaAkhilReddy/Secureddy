"""Notifier: dashboard rows, SMTP (real local server), webhook (MockTransport)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from reddysec.models import ParsedMessage, RawMessage, TriageLane, Verdict, VerdictLevel
from reddysec.store import repo
from reddysec.worker.notify import CHANNEL_DASHBOARD, CHANNEL_EMAIL, CHANNEL_WEBHOOK, Notifier

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)


def verdict(level: VerdictLevel, summary: str = "Nothing bad found.") -> Verdict:
    return Verdict(level=level, score=5, summary=summary, lane=TriageLane.RELEASE_FAST)


async def message_row(
    db, mailbox_id: str, *, quarantined: bool = False, level: VerdictLevel = VerdictLevel.SAFE
):
    parsed = ParsedMessage(
        provider_message_id="p1",
        mailbox_id=mailbox_id,
        received_at=NOW,
        from_address="alice@example.com",
        from_name="Alice",
        subject="Lunch?",
    )
    raw = RawMessage(provider_message_id="p1", mailbox_id=mailbox_id, received_at=NOW, raw=b"x")
    async with db.session() as s:
        row = await repo.upsert_message(s, parsed, raw)
        await repo.record_verdict(s, row, verdict(level), quarantined=quarantined)
    return row


class TestDashboard:
    async def test_verdict_notification_dashboard_only(self, db, client_rows, make_settings):
        notifier = Notifier(db, make_settings(), clock=lambda: NOW)
        row = await message_row(db, client_rows.mailbox.id, quarantined=True, level=VerdictLevel.MALICIOUS)
        rows = await notifier.notify_verdict(
            client_rows.user, row, verdict(VerdictLevel.MALICIOUS, "This is a fake invoice.")
        )
        assert [r.channel for r in rows] == [CHANNEL_DASHBOARD]
        assert rows[0].level == "malicious" and rows[0].sent_at == NOW and rows[0].error is None
        assert rows[0].title == "Quarantined: Lunch?"
        assert "This is a fake invoice." in rows[0].body
        assert "From: Alice <alice@example.com>" in rows[0].body
        assert "kept this message out of your inbox" in rows[0].body
        assert f"https://rs.example/messages/{row.id}" in rows[0].body
        async with db.session() as s:
            stored = await repo.list_notifications(s, client_rows.user.id)
        assert len(stored) == 1 and stored[0].message_id == row.id and stored[0].sent_at is not None

    @pytest.mark.parametrize(
        ("level", "title_prefix", "needle"),
        [
            (VerdictLevel.SAFE, "Checked", "Details:"),
            (VerdictLevel.SUSPICIOUS, "Suspicious message", "Reading Room"),
            (VerdictLevel.UNKNOWN, "Needs a look", "could not finish"),
        ],
    )
    async def test_texts_per_level(self, db, client_rows, make_settings, level, title_prefix, needle):
        notifier = Notifier(db, make_settings())
        row = await message_row(db, client_rows.mailbox.id, level=level)
        title, body = notifier.verdict_text(row, verdict(level))
        assert title.startswith(title_prefix) and needle in body

    async def test_text_without_sender_name_or_subject(self, db, client_rows, make_settings):
        notifier = Notifier(db, make_settings())
        row = await message_row(db, client_rows.mailbox.id)
        row.from_name = None
        row.subject = ""
        title, body = notifier.verdict_text(row, verdict(VerdictLevel.SAFE))
        assert title == "Checked: (no subject)" and "From: alice@example.com" in body


class TestEmail:
    async def test_email_delivered_to_local_smtp_server(self, db, client_rows, make_settings, smtp_sink):
        settings = make_settings(
            smtp_host=smtp_sink.host, smtp_port=smtp_sink.port, notification_from="alerts@rs.example"
        )
        notifier = Notifier(db, settings)
        row = await message_row(db, client_rows.mailbox.id, level=VerdictLevel.SUSPICIOUS)
        rows = await notifier.notify_verdict(
            client_rows.user, row, verdict(VerdictLevel.SUSPICIOUS, "Lookalike domain.")
        )
        assert [r.channel for r in rows] == [CHANNEL_DASHBOARD, CHANNEL_EMAIL]
        assert all(r.sent_at is not None and r.error is None for r in rows)
        (envelope,) = smtp_sink.handler.envelopes
        assert envelope.mail_from == "alerts@rs.example" and envelope.rcpt_tos == ["client@example.com"]
        (msg,) = smtp_sink.handler.messages
        assert msg["Subject"] == "Suspicious message: Lunch?"
        assert "Lookalike domain." in msg.get_payload()
        assert f"/messages/{row.id}" in msg.get_payload()

    async def test_smtp_failure_is_recorded_not_raised(self, db, client_rows, make_settings):
        from .conftest import free_port

        settings = make_settings(smtp_host="127.0.0.1", smtp_port=free_port())  # nothing listens here
        notifier = Notifier(db, settings)
        rows = await notifier.notify_user(client_rows.user, level="alert", title="t", body="b")
        email_row = next(r for r in rows if r.channel == CHANNEL_EMAIL)
        assert email_row.sent_at is None and email_row.error
        async with db.session() as s:
            stored = {n.channel: n for n in await repo.list_notifications(s, client_rows.user.id)}
            assert await repo.list_unsent(s) == []  # errored rows are not retried blindly
        assert stored[CHANNEL_EMAIL].error and stored[CHANNEL_DASHBOARD].sent_at is not None

    async def test_starttls_and_login_on_587(self, db, client_rows, make_settings):
        calls: list[tuple[str, Any]] = []

        class FakeSmtp:
            def __init__(self, host: str, port: int) -> None:
                calls.append(("connect", (host, port)))

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                calls.append(("quit", None))

            def starttls(self):
                calls.append(("starttls", None))

            def login(self, user, password):
                calls.append(("login", (user, password)))

            def send_message(self, msg):
                calls.append(("send", msg["To"]))

        settings = make_settings(
            smtp_host="smtp.example", smtp_port=587, smtp_username="u", smtp_password="p"
        )
        notifier = Notifier(db, settings, smtp_factory=FakeSmtp)
        await notifier.send_email("to@example.com", "s", "b")
        assert [c[0] for c in calls] == ["connect", "starttls", "login", "send", "quit"]
        assert calls[2][1] == ("u", "p") and calls[3][1] == "to@example.com"
        # port 25 with credentials: login without STARTTLS (e.g. an internal relay)
        calls.clear()
        notifier = Notifier(
            db,
            make_settings(smtp_host="relay", smtp_port=25, smtp_username="u", smtp_password="p"),
            smtp_factory=FakeSmtp,
        )
        await notifier.send_email("to@example.com", "s", "b")
        assert [c[0] for c in calls] == ["connect", "login", "send", "quit"]

    async def test_send_email_requires_configuration(self, db, make_settings):
        with pytest.raises(RuntimeError, match="not configured"):
            await Notifier(db, make_settings()).send_email("a@b", "s", "b")


class TestWebhook:
    async def test_webhook_payload_and_failure(self, db, client_rows, make_settings):
        received: list[dict[str, Any]] = []
        status = {"code": 200}

        def handler(request: httpx.Request) -> httpx.Response:
            received.append(httpx.Response(200, content=request.content).json())
            return httpx.Response(status["code"])

        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        notifier = Notifier(db, make_settings(notify_webhook_url="https://hooks.example/rs"), http=http)
        row = await message_row(db, client_rows.mailbox.id)
        rows = await notifier.notify_verdict(client_rows.user, row, verdict(VerdictLevel.SAFE))
        assert [r.channel for r in rows] == [CHANNEL_DASHBOARD, CHANNEL_WEBHOOK]
        assert received == [
            {
                "level": "safe",
                "title": "Checked: Lunch?",
                "body": rows[0].body,
                "user_id": client_rows.user.id,
                "message_id": row.id,
            }
        ]
        status["code"] = 500
        rows = await notifier.notify_user(client_rows.user, level="alert", title="t", body="b")
        hook = next(r for r in rows if r.channel == CHANNEL_WEBHOOK)
        assert hook.error and "500" in hook.error and hook.sent_at is None
        await http.aclose()

    async def test_webhook_with_own_client(self, db, make_settings, monkeypatch):
        received: list[str] = []

        class MockClient(httpx.AsyncClient):
            def __init__(self, *a: Any, **kw: Any) -> None:
                kw["transport"] = httpx.MockTransport(
                    lambda req: (received.append(req.url.host), httpx.Response(204))[1]
                )
                super().__init__(*a, **kw)

        monkeypatch.setattr(httpx, "AsyncClient", MockClient)
        notifier = Notifier(db, make_settings(notify_webhook_url="https://hooks.example/rs"))
        await notifier._send_webhook({"x": 1})
        assert received == ["hooks.example"]
        await Notifier(db, make_settings())._send_webhook({"x": 1})  # no url: nothing happens
        assert received == ["hooks.example"]


class TestConcierge:
    async def test_notifies_every_concierge_and_admin_once(self, db, client_rows, make_settings, smtp_sink):
        hooks: list[dict[str, Any]] = []
        http = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda r: (hooks.append(httpx.Response(200, content=r.content).json()), httpx.Response(200))[
                    1
                ]
            )
        )
        async with db.session() as s:
            await repo.create_user(s, email="ana@rs.example", display_name="Ana", role="concierge")
            await repo.create_user(s, email="boss@rs.example", display_name="Boss", role="admin")
            await repo.create_user(s, email="fam@example.com", display_name="Fam", role="family")
        settings = make_settings(
            smtp_host=smtp_sink.host, smtp_port=smtp_sink.port, notify_webhook_url="https://hooks.example/rs"
        )
        rows = await Notifier(db, settings, http=http).notify_concierge("Needs review", "Details here")
        channels = sorted(r.channel for r in rows)
        assert channels == [
            CHANNEL_DASHBOARD,
            CHANNEL_DASHBOARD,
            CHANNEL_EMAIL,
            CHANNEL_EMAIL,
            CHANNEL_WEBHOOK,
        ]
        assert sorted(e.rcpt_tos[0] for e in smtp_sink.handler.envelopes) == [
            "ana@rs.example",
            "boss@rs.example",
        ]
        assert len(hooks) == 1 and hooks[0]["title"] == "Needs review"
        assert all(r.level == "alert" for r in rows)
        await http.aclose()

    async def test_without_staff_falls_back_to_webhook(self, db, make_settings):
        hooks: list[dict[str, Any]] = []
        http = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda r: (hooks.append(httpx.Response(200, content=r.content).json()), httpx.Response(200))[
                    1
                ]
            )
        )
        rows = await Notifier(
            db, make_settings(notify_webhook_url="https://hooks.example/rs"), http=http
        ).notify_concierge("s", "b")
        assert rows == [] and hooks == [
            {"level": "alert", "title": "s", "body": "b", "audience": "concierge"}
        ]
        assert await Notifier(db, make_settings()).notify_concierge("s", "b") == []
        await http.aclose()

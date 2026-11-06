"""End-to-end worker flows: FakeMailbox + fake parser + scripted analyzer + SQLite.

The analysis and chamber packages are replaced by fakes injected through the
Worker constructor, so these tests exercise the real engine, repository,
notifier and dead man's switch without any network or browser.
"""

from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime, timedelta
from email import message_from_bytes
from email.message import EmailMessage
from email.utils import parseaddr
from types import SimpleNamespace
from typing import Any

import pytest

from reddysec.config import Settings
from reddysec.mail.base import AuthExpired, ConnectorError
from reddysec.models import (
    AttachmentVerdict,
    ExtractedUrl,
    ParsedMessage,
    ProtectionMode,
    TriageLane,
    UrlSource,
    UrlVerdict,
    Verdict,
    VerdictLevel,
)
from reddysec.store import repo
from reddysec.testing.fakes import FakeMailbox
from reddysec.worker.deadman import DeadManSwitch
from reddysec.worker.engine import MODE_KEY, CycleStats, Worker, fallback_verdict, policy_for
from reddysec.worker.notify import Notifier

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
URL_RE = re.compile(r"https?://\S+")


# ---------------------------------------------------------------- test doubles
def email_bytes(
    subject: str,
    *,
    sender: str = "Alice <alice@example.com>",
    body: str = "hello",
    message_id: str | None = None,
) -> bytes:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = "client@gmail.com"
    msg["Subject"] = subject
    msg["Message-ID"] = message_id or f"<{re.sub(r'[^a-z0-9]', '-', subject.lower())}@example.com>"
    msg.set_content(body)
    return bytes(msg)


def fake_parse_raw(
    raw: bytes,
    *,
    provider_message_id: str,
    mailbox_id: str,
    received_at: datetime,
    thread_id: str | None = None,
) -> ParsedMessage:
    """A deliberately small parser: headers plus bare URLs in the text body."""
    msg = message_from_bytes(raw)
    name, address = parseaddr(msg.get("From", ""))
    body = msg.get_payload(decode=True) or b""
    urls = [
        ExtractedUrl(raw=u, normalized=u, source=UrlSource.TEXT, host=u.split("/")[2])
        for u in URL_RE.findall(body.decode(errors="replace"))
    ]
    return ParsedMessage(
        provider_message_id=provider_message_id,
        mailbox_id=mailbox_id,
        rfc_message_id=msg.get("Message-ID"),
        from_address=address.lower(),
        from_name=name or None,
        subject=msg.get("Subject", ""),
        received_at=received_at,
        text_body=body.decode(errors="replace"),
        urls=urls,
        raw_size=len(raw),
    )


class ExplodingParser:
    def __call__(self, raw: bytes, **kw: Any) -> ParsedMessage:
        raise ValueError("cannot parse")


def verdict(level: VerdictLevel, **kw: Any) -> Verdict:
    defaults = dict(
        score={"safe": 5, "suspicious": 50, "malicious": 90, "unknown": 0}[level.value],
        summary=f"{level.value} summary",
        lane=TriageLane.DETONATE,
    )
    defaults.update(kw)
    return Verdict(level=level, **defaults)


class ScriptedAnalyzer:
    """Returns a verdict keyed by subject: a Verdict, an Exception to raise, or
    the string "hang" to never return."""

    def __init__(self, scripts: dict[str, Any] | None = None) -> None:
        self.scripts = dict(scripts or {})
        self.calls: list[tuple[ParsedMessage, Any]] = []

    async def __call__(self, parsed: ParsedMessage, ctx: Any) -> Verdict:
        self.calls.append((parsed, ctx))
        scripted = self.scripts.get(parsed.subject, verdict(VerdictLevel.SAFE))
        if scripted == "hang":
            await asyncio.sleep(3600)
        if isinstance(scripted, Exception):
            raise scripted
        return scripted


class CountingMailbox(FakeMailbox):
    def __init__(self, mailbox_id: str = "mbx_test") -> None:
        super().__init__(mailbox_id)
        self.setup_calls: list[ProtectionMode] = []
        self.poll_error: Exception | None = None

    async def setup(self, mode: ProtectionMode) -> dict[str, str]:
        self.setup_calls.append(mode)
        return await super().setup(mode)

    async def poll(self, cursor: str | None):
        if self.poll_error is not None:
            raise self.poll_error
        return await super().poll(cursor)


# ------------------------------------------------------------------- fixtures
@pytest.fixture
def settings() -> Settings:
    return Settings(
        env="test",
        base_url="https://rs.example",
        secret_key="functional",
        gmail_poll_seconds=1,
        imap_poll_seconds=1,
        detonation_timeout_s=2,
        hold_dead_man_minutes=10,
    )


class Harness:
    def __init__(self, db, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self.analyzer = ScriptedAnalyzer()
        self.contexts: list[dict[str, Any]] = []
        self.connectors: dict[str, FakeMailbox] = {}
        self.factory_errors: dict[str, Exception] = {}
        self.detonator = object()
        self.intel = object()
        self.notifier = Notifier(db, settings, clock=lambda: NOW)
        self.sleeps: list[float] = []

    async def add_client(
        self,
        *,
        mode: str = "scan",
        policy: dict[str, Any] | None = None,
        email: str = "client@example.com",
        address: str = "client@gmail.com",
        provider: str = "gmail",
    ):
        async with self.db.session() as s:
            user = await repo.get_user_by_email(s, email) or await repo.create_user(
                s, email=email, display_name="The Client"
            )
            mailbox = await repo.create_mailbox(
                s, user_id=user.id, provider=provider, address=address, mode=mode, policy=policy
            )
        fake = CountingMailbox(mailbox.id)
        self.connectors[mailbox.id] = fake
        return user, mailbox, fake

    def context_factory(self, **kwargs: Any) -> Any:
        self.contexts.append(kwargs)
        return SimpleNamespace(**kwargs)

    async def connector_factory(self, mailbox):
        if mailbox.id in self.factory_errors:
            raise self.factory_errors[mailbox.id]
        return self.connectors[mailbox.id]

    async def fake_sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)

    def worker(self, **overrides: Any) -> Worker:
        kwargs: dict[str, Any] = dict(
            connector_factory=self.connector_factory,
            parser=fake_parse_raw,
            analyzer=self.analyzer,
            context_factory=self.context_factory,
            detonator=self.detonator,
            intel=self.intel,
            notifier=self.notifier,
            clock=lambda: NOW,
            sleep=self.fake_sleep,
        )
        kwargs.update(overrides)
        return Worker(self.db, self.settings, **kwargs)

    async def mailbox_row(self, mailbox_id: str):
        async with self.db.session() as s:
            return await repo.get_mailbox(s, mailbox_id)

    async def messages(self, mailbox_id: str) -> dict[str, Any]:
        async with self.db.session() as s:
            rows = await repo.list_recent_messages(s, [mailbox_id], limit=100)
        return {r.provider_message_id: r for r in rows}

    async def notifications(self, user_id: str) -> list[Any]:
        async with self.db.session() as s:
            return await repo.list_notifications(s, user_id, limit=100)

    async def audit_actions(self, mailbox_id: str) -> list[str]:
        async with self.db.session() as s:
            return [a.action for a in reversed(await repo.list_audit(s, mailbox_id))]


@pytest.fixture
def harness(db, settings) -> Harness:
    return Harness(db, settings)


# ----------------------------------------------------------------------- tests
class TestScanMode:
    async def test_labels_quarantine_records_and_notifications(self, harness: Harness):
        user, mailbox, fake = await harness.add_client(mode="scan")
        harness.analyzer.scripts = {
            "Lunch": verdict(VerdictLevel.SAFE),
            "Invoice": verdict(
                VerdictLevel.SUSPICIOUS,
                urls=[
                    UrlVerdict(
                        url="https://pay.example/x",
                        level=VerdictLevel.SUSPICIOUS,
                        score=50,
                        detonation_job_id="det_1",
                        detonated=True,
                    )
                ],
            ),
            "Urgent wire": verdict(
                VerdictLevel.MALICIOUS,
                attachments=[
                    AttachmentVerdict(
                        filename="wire.pdf",
                        sha256="0" * 64,
                        level=VerdictLevel.MALICIOUS,
                        score=95,
                        detonation_job_id="det_2",
                    )
                ],
            ),
        }
        fake.deliver(email_bytes("Lunch"), "m1")
        fake.deliver(email_bytes("Invoice", body="pay at https://pay.example/x now"), "m2")
        fake.deliver(email_bytes("Urgent wire", sender="CFO <cfo@evil.example>"), "m3")

        worker = harness.worker()
        stats = await worker.run_cycle()

        assert isinstance(stats, CycleStats) and (stats.mailboxes, stats.messages, stats.failed) == (1, 3, 0)
        assert fake.labels["m1"] == {"Secureddy/Checked"} and fake.in_inbox["m1"]
        assert fake.labels["m2"] == {"Secureddy/Suspicious"} and fake.in_inbox["m2"]
        assert fake.labels["m3"] == {"Secureddy/Quarantine"} and not fake.in_inbox["m3"]

        rows = await harness.messages(mailbox.id)
        assert {pid: (r.level, r.quarantined, r.state) for pid, r in rows.items()} == {
            "m1": ("safe", False, "done"),
            "m2": ("suspicious", False, "done"),
            "m3": ("malicious", True, "done"),
        }
        assert rows["m2"].url_count == 1 and rows["m2"].verdict["urls"][0]["detonation_job_id"] == "det_1"
        assert rows["m3"].from_address == "cfo@evil.example" and rows["m3"].from_name == "CFO"

        row = await harness.mailbox_row(mailbox.id)
        assert row.cursor == "3" and row.last_sync_at is not None and row.status == "active"
        assert row.labels[MODE_KEY] == "scan"

        async with harness.db.session() as s:
            alice = await repo.sender_history(s, mailbox.id, "alice@example.com")
            dets = {d.job_id: d for d in await repo.list_detonations(s, rows["m2"].id)} | {
                d.job_id: d for d in await repo.list_detonations(s, rows["m3"].id)
            }
            heartbeat = await repo.get_heartbeat(s, mailbox.id)
        assert alice.message_count == 2 and alice.display_names == ["Alice"]
        assert (
            dets["det_1"].kind == "url"
            and dets["det_1"].target == "https://pay.example/x"
            and dets["det_1"].status == "unknown"
        )
        assert dets["det_2"].kind == "file" and dets["det_2"].target == "wire.pdf"
        assert heartbeat is None  # SCAN mode never arms the dead man's switch

        notes = await harness.notifications(user.id)
        assert sorted(n.level for n in notes) == [
            "malicious",
            "suspicious",
        ]  # notify_at defaults to SUSPICIOUS
        assert all(n.channel == "dashboard" and n.sent_at is not None for n in notes)
        assert await harness.audit_actions(mailbox.id) == ["mailbox_setup", "verdict", "verdict", "verdict"]

        # The first analysis saw no sender history; the second from Alice did.
        first_ctx, _, third_ctx = [ctx for _, ctx in harness.analyzer.calls]
        assert first_ctx.history is None and first_ctx.policy.mode is ProtectionMode.SCAN
        assert first_ctx.detonator is harness.detonator and first_ctx.intel is harness.intel
        assert first_ctx.detonation_timeout_s == 2
        assert third_ctx.history is None  # cfo@evil.example is new

    async def test_notify_at_safe_notifies_everything(self, harness: Harness):
        user, mailbox, fake = await harness.add_client(mode="scan", policy={"notify_at": "safe"})
        fake.deliver(email_bytes("Lunch"), "m1")
        await harness.worker().run_cycle()
        notes = await harness.notifications(user.id)
        assert [n.level for n in notes] == ["safe"] and notes[0].title.startswith("Checked: Lunch")
        assert f"https://rs.example/messages/{(await harness.messages(mailbox.id))['m1'].id}" in notes[0].body

    async def test_strict_policy_quarantines_suspicious(self, harness: Harness):
        _user, _mailbox, fake = await harness.add_client(mode="scan", policy={"quarantine_at": "suspicious"})
        harness.analyzer.scripts = {"Invoice": verdict(VerdictLevel.SUSPICIOUS)}
        fake.deliver(email_bytes("Invoice"), "m1")
        await harness.worker().run_cycle()
        assert not fake.in_inbox["m1"] and (await harness.messages(fake.mailbox_id))["m1"].quarantined


class TestHoldMode:
    async def test_setup_on_first_cycle_persists_labels_and_installs_rule(self, harness: Harness):
        _user, mailbox, fake = await harness.add_client(mode="hold")
        assert mailbox.labels == {}
        worker = harness.worker()
        await worker.run_cycle()
        row = await harness.mailbox_row(mailbox.id)
        assert row.labels == {"Secureddy": "L1", "Secureddy/Checking": "L2", MODE_KEY: "hold"}
        assert fake.setup_calls == [ProtectionMode.HOLD] and fake.hold_rule_installed
        await worker.run_cycle()
        assert fake.setup_calls == [ProtectionMode.HOLD]  # not repeated
        # The web app flips the mode: the next cycle reconciles the provider side.
        async with harness.db.session() as s:
            await repo.set_mode(s, mailbox.id, "scan")
        await worker.run_cycle()
        assert fake.setup_calls == [ProtectionMode.HOLD, ProtectionMode.SCAN] and not fake.hold_rule_installed
        assert (await harness.mailbox_row(mailbox.id)).labels[MODE_KEY] == "scan"
        assert await harness.audit_actions(mailbox.id) == ["mailbox_setup", "mailbox_setup"]

    async def test_held_mail_is_released_after_verdict_and_heartbeat_recorded(self, harness: Harness):
        _user, mailbox, fake = await harness.add_client(mode="hold")
        worker = harness.worker()
        await worker.run_cycle()  # installs the rule
        held = fake.deliver(email_bytes("Lunch"), "h1")
        assert fake.labels["h1"] == {"Secureddy/Checking"} and not fake.in_inbox["h1"]
        await worker.run_cycle()
        assert fake.in_inbox["h1"] and fake.labels["h1"] == {"Secureddy/Checked"}
        assert ("release", "h1") in fake.actions
        async with harness.db.session() as s:
            heartbeat = await repo.get_heartbeat(s, mailbox.id)
        assert repo.aware(heartbeat.beat_at) >= NOW - timedelta(minutes=1)
        assert (await harness.messages(mailbox.id))["h1"].state == "done"
        del held

    async def test_hold_timeout_releases_with_unknown_verdict(self, harness: Harness):
        user, mailbox, fake = await harness.add_client(mode="hold", policy={"hold_timeout_s": 1})
        harness.analyzer.scripts = {"Slow": "hang"}
        worker = harness.worker()
        await worker.run_cycle()
        fake.deliver(email_bytes("Slow"), "h1")
        await worker.run_cycle()
        assert fake.in_inbox["h1"]
        row = (await harness.messages(mailbox.id))["h1"]
        assert row.level == "unknown" and row.state == "done" and not row.quarantined
        assert row.verdict["needs_human_review"] is True
        assert row.verdict["signals"][0]["code"] == "engine.timeout"
        notes = await harness.notifications(user.id)
        assert (
            len(notes) == 1
            and notes[0].title.startswith("Needs a look")
            and "could not finish" in notes[0].body
        )
        async with harness.db.session() as s:
            (entry,) = [a for a in await repo.list_audit(s, mailbox.id) if a.action == "verdict"]
        assert entry.details["outcome"] == "timeout"

    async def test_hold_timeout_without_release_keeps_message_and_pages_concierge(self, harness: Harness):
        user, mailbox, fake = await harness.add_client(
            mode="hold", policy={"hold_timeout_s": 1, "release_on_timeout": False}
        )
        async with harness.db.session() as s:
            ana = await repo.create_user(s, email="ana@rs.example", display_name="Ana", role="concierge")
        harness.analyzer.scripts = {"Slow": "hang"}
        worker = harness.worker()
        await worker.run_cycle()
        fake.deliver(email_bytes("Slow"), "h1")
        await worker.run_cycle()
        assert not fake.in_inbox["h1"] and fake.labels["h1"] == {"Secureddy/Checking"}
        assert not [a for a in fake.actions if a[1] == "h1"]
        row = (await harness.messages(mailbox.id))["h1"]
        assert row.state == "held_for_review" and row.level == "unknown"
        staff = await harness.notifications(ana.id)
        assert len(staff) == 1 and "needs review" in staff[0].title
        assert len(await harness.notifications(user.id)) == 1  # the client is told too (needs_human_review)

    async def test_analyzer_crash_fails_open(self, harness: Harness):
        _user, mailbox, fake = await harness.add_client(mode="hold")
        harness.analyzer.scripts = {"Boom": RuntimeError("pipeline bug")}
        worker = harness.worker()
        await worker.run_cycle()
        fake.deliver(email_bytes("Boom"), "h1")
        stats = await worker.run_cycle()
        assert stats.messages == 1 and stats.failed == 0
        assert fake.in_inbox["h1"]  # released despite the crash
        row = (await harness.messages(mailbox.id))["h1"]
        assert (
            row.state == "failed"
            and row.level == "unknown"
            and row.verdict["signals"][0]["code"] == "engine.error"
        )

    async def test_parser_crash_marks_failure_and_releases_held_mail(self, harness: Harness):
        _user, mailbox, fake = await harness.add_client(mode="hold")
        worker = harness.worker(parser=ExplodingParser())
        await worker.run_cycle()
        fake.deliver(email_bytes("Any"), "h1")
        stats = await worker.run_cycle()
        assert stats.failed == 1 and stats.messages == 0
        assert ("release", "h1") in fake.actions and fake.in_inbox["h1"]
        assert "message_failed" in await harness.audit_actions(mailbox.id)
        assert await harness.messages(mailbox.id) == {}  # nothing parsed, nothing stored
        assert (await harness.mailbox_row(mailbox.id)).cursor == "1"  # the cycle still completed


class TestRestoreAndIdempotency:
    async def test_restore_request_flow(self, harness: Harness):
        _user, mailbox, fake = await harness.add_client(mode="scan")
        harness.analyzer.scripts = {"Bad": verdict(VerdictLevel.MALICIOUS)}
        fake.deliver(email_bytes("Bad"), "m1")
        worker = harness.worker()
        await worker.run_cycle()
        row = (await harness.messages(mailbox.id))["m1"]
        assert row.quarantined and not fake.in_inbox["m1"]
        async with harness.db.session() as s:
            await repo.request_restore(s, row.id)
            await repo.audit(s, "usr_client", "principal", "restore_requested", mailbox.id, row.id)
        stats = await worker.run_cycle()
        assert stats.restored == 1
        assert ("restore", "m1") in fake.actions and fake.in_inbox["m1"]
        assert fake.labels["m1"] == {"Secureddy/Released by you"}
        row = (await harness.messages(mailbox.id))["m1"]
        assert row.state == "done" and not row.quarantined and row.restored_by_client
        assert (await harness.audit_actions(mailbox.id))[-2:] == ["restore_requested", "restore"]

    async def test_restore_failure_is_recorded(self, harness: Harness):
        _user, mailbox, fake = await harness.add_client(mode="scan")

        async def failing_restore(pid: str) -> None:
            raise ConnectorError("message vanished", retryable=False)

        fake.restore = failing_restore  # type: ignore[method-assign]
        fake.deliver(email_bytes("Bad"), "m1")
        worker = harness.worker()
        await worker.run_cycle()
        row = (await harness.messages(mailbox.id))["m1"]
        async with harness.db.session() as s:
            await repo.request_restore(s, row.id)
        stats = await worker.run_cycle()
        assert stats.restored == 0
        assert (await harness.messages(mailbox.id))["m1"].state == "restore_failed"
        assert "restore_failed" in await harness.audit_actions(mailbox.id)

    async def test_repoll_creates_no_duplicate_rows(self, harness: Harness):
        _user, mailbox, fake = await harness.add_client(mode="scan")
        fake.deliver(email_bytes("Lunch"), "m1")
        fake.deliver(email_bytes("Dinner"), "m2")
        worker = harness.worker()
        await worker.run_cycle()
        # Simulate a lost cursor: the connector returns everything again.
        async with harness.db.session() as s:
            await repo.update_cursor(s, mailbox.id, None)
        stats = await worker.run_cycle()
        assert stats.skipped == 2 and stats.messages == 0
        async with harness.db.session() as s:
            assert await repo.count_messages(s, mailbox.id) == 2
        assert len(harness.analyzer.calls) == 2
        assert len([a for a in fake.actions if a[0] == "release"]) == 2

    async def test_rows_stuck_in_analyzing_are_reprocessed(self, harness: Harness):
        _user, mailbox, fake = await harness.add_client(mode="scan")
        fake.deliver(email_bytes("Lunch"), "m1")
        parsed = fake_parse_raw(
            fake.messages["m1"].raw, provider_message_id="m1", mailbox_id=mailbox.id, received_at=NOW
        )
        async with harness.db.session() as s:
            await repo.upsert_message(
                s, parsed, fake.messages["m1"], state="analyzing"
            )  # a crashed worker left this
        stats = await harness.worker().run_cycle()
        assert stats.messages == 1 and stats.skipped == 0
        assert (await harness.messages(mailbox.id))["m1"].state == "done"


class TestMailboxErrors:
    async def test_auth_expired_marks_error_and_notifies(self, harness: Harness):
        user, broken, _fake = await harness.add_client(mode="scan", address="broken@gmail.com")
        _user2, healthy, fake2 = await harness.add_client(
            mode="scan", email="two@example.com", address="two@gmail.com"
        )
        async with harness.db.session() as s:
            ana = await repo.create_user(s, email="ana@rs.example", display_name="Ana", role="concierge")
        harness.factory_errors[broken.id] = AuthExpired("refresh token revoked")
        fake2.deliver(email_bytes("Lunch"), "m1")
        stats = await harness.worker().run_cycle()
        assert stats.mailbox_errors == [broken.id] and stats.messages == 1  # the other mailbox still ran
        row = await harness.mailbox_row(broken.id)
        assert row.status == "error" and "revoked" in row.last_error
        notes = await harness.notifications(user.id)
        assert (
            len(notes) == 1 and notes[0].title == "Reconnect your Gmail mailbox" and notes[0].level == "alert"
        )
        assert f"/mailboxes/{broken.id}" in notes[0].body
        assert "mailbox_auth_expired" in await harness.audit_actions(broken.id)
        assert any("access lost" in n.title for n in await harness.notifications(ana.id))
        # Error mailboxes are skipped from then on.
        stats = await harness.worker().run_cycle()
        assert stats.mailboxes == 1
        del healthy

    async def test_retryable_connector_error_skips_cycle(self, harness: Harness):
        _user, mailbox, fake = await harness.add_client(mode="scan")
        fake.deliver(email_bytes("Lunch"), "m1")
        fake.poll_error = ConnectorError("gmail 503", retryable=True)
        stats = await harness.worker().run_cycle()
        assert stats.mailbox_errors == [mailbox.id] and stats.messages == 0
        row = await harness.mailbox_row(mailbox.id)
        assert row.status == "active" and row.cursor is None  # nothing advanced; try again next cycle
        fake.poll_error = None
        stats = await harness.worker().run_cycle()
        assert stats.messages == 1 and (await harness.mailbox_row(mailbox.id)).cursor == "1"

    async def test_permanent_connector_error_marks_mailbox(self, harness: Harness):
        _user, mailbox, fake = await harness.add_client(mode="scan")
        fake.poll_error = ConnectorError("scope missing", retryable=False)
        await harness.worker().run_cycle()
        row = await harness.mailbox_row(mailbox.id)
        assert row.status == "error" and row.last_error == "scope missing"
        assert "mailbox_error" in await harness.audit_actions(mailbox.id)

    async def test_unexpected_crash_is_recorded_and_isolated(self, harness: Harness):
        _user, mailbox, fake = await harness.add_client(mode="scan")
        fake.poll_error = RuntimeError("bug")
        stats = await harness.worker().run_cycle()
        assert stats.mailbox_errors == [mailbox.id]
        row = await harness.mailbox_row(mailbox.id)
        assert row.status == "active" and "worker error: bug" in row.last_error
        fake.poll_error = None
        stats = await harness.worker().run_cycle()
        assert stats.mailbox_errors == [] and (await harness.mailbox_row(mailbox.id)).last_error is None


class TestDeadMan:
    async def test_stale_hold_mailbox_is_released_and_audited(self, harness: Harness):
        user, mailbox, fake = await harness.add_client(mode="hold")
        async with harness.db.session() as s:
            ana = await repo.create_user(s, email="ana@rs.example", display_name="Ana", role="concierge")
        worker = harness.worker()
        await worker.run_cycle()  # setup + first heartbeat at NOW
        fake.deliver(email_bytes("Waiting"), "h1")
        fake.deliver(email_bytes("Also waiting"), "h2")
        assert not fake.in_inbox["h1"] and not fake.in_inbox["h2"]

        # The worker is now "dead"; the watchdog wakes up 20 minutes later.
        clock = {"now": NOW + timedelta(minutes=20)}
        switch = DeadManSwitch(
            harness.db,
            harness.settings,
            connector_factory=harness.connector_factory,
            notifier=harness.notifier,
            clock=lambda: clock["now"],
        )
        assert await switch.check_once() == [mailbox.id]
        assert fake.in_inbox["h1"] and fake.in_inbox["h2"] and not fake.hold_rule_installed
        row = await harness.mailbox_row(mailbox.id)
        assert row.status == "error" and "released 2 held message(s)" in row.last_error
        assert MODE_KEY not in row.labels
        assert await harness.audit_actions(mailbox.id) == ["mailbox_setup", "deadman_release"]
        assert any("released your held mail" in n.title for n in await harness.notifications(user.id))
        assert any("Dead man's switch fired" in n.title for n in await harness.notifications(ana.id))

        # Once the concierge re-activates the mailbox, the worker re-runs setup
        # (labels lost their _mode marker) and heart-beats again.
        async with harness.db.session() as s:
            await repo.set_mailbox_status(s, mailbox.id, "active")
        await worker.run_cycle()
        assert fake.setup_calls == [ProtectionMode.HOLD, ProtectionMode.HOLD] and fake.hold_rule_installed
        clock["now"] = NOW + timedelta(minutes=1)  # the worker just beat at NOW
        assert await switch.check_once() == []

    async def test_live_worker_is_never_tripped(self, harness: Harness):
        _user, mailbox, _fake = await harness.add_client(mode="hold")
        await harness.worker().run_cycle()
        switch = DeadManSwitch(
            harness.db,
            harness.settings,
            connector_factory=harness.connector_factory,
            notifier=harness.notifier,
            clock=lambda: NOW + timedelta(minutes=9),
        )
        assert await switch.check_once() == []
        assert (await harness.mailbox_row(mailbox.id)).status == "active"


class TestRunLoop:
    async def test_run_forever_cycles_until_stopped(self, harness: Harness):
        _user, _mailbox, fake = await harness.add_client(mode="scan")
        fake.deliver(email_bytes("Lunch"), "m1")
        worker = harness.worker()
        stop = asyncio.Event()
        original_sleep = harness.fake_sleep

        async def stopping_sleep(seconds: float) -> None:
            await original_sleep(seconds)
            if len(harness.sleeps) == 2:
                stop.set()

        worker._sleep = stopping_sleep  # type: ignore[attr-defined]
        await asyncio.wait_for(worker.run_forever(stop), timeout=10)
        assert worker.cycles == 2 and harness.sleeps == [1.0, 1.0]
        assert worker.poll_interval_s == 1.0
        assert len(harness.analyzer.calls) == 1  # the message was processed exactly once

    async def test_default_sleep_wakes_early(self, harness: Harness):
        worker = Worker(
            harness.db,
            harness.settings,
            connector_factory=harness.connector_factory,
            notifier=harness.notifier,
        )
        started = asyncio.get_running_loop().time()
        task = asyncio.create_task(worker._sleep(30))
        await asyncio.sleep(0.01)
        worker.wake()  # e.g. a Gmail Pub/Sub push just arrived
        await asyncio.wait_for(task, timeout=5)
        assert asyncio.get_running_loop().time() - started < 5

    async def test_run_forever_survives_cycle_crash(self, harness: Harness):
        worker = harness.worker()
        stop = asyncio.Event()
        calls = {"n": 0}

        async def exploding_cycle() -> CycleStats:
            calls["n"] += 1
            if calls["n"] == 2:
                stop.set()
            raise RuntimeError("cycle bug")

        worker.run_cycle = exploding_cycle  # type: ignore[method-assign]
        await asyncio.wait_for(worker.run_forever(stop), timeout=5)
        assert calls["n"] == 2 and harness.sleeps == [1.0]


class TestHelpers:
    def test_policy_for_uses_mailbox_mode_and_survives_garbage(self):
        mailbox = SimpleNamespace(
            id="mbx", mode="hold", policy={"quarantine_at": "suspicious", "mode": "scan"}
        )
        policy = policy_for(mailbox)  # type: ignore[arg-type]
        assert policy.mode is ProtectionMode.HOLD and policy.quarantine_at is VerdictLevel.SUSPICIOUS
        garbage = SimpleNamespace(id="mbx", mode="scan", policy={"quarantine_at": "nonsense"})
        assert policy_for(garbage).quarantine_at is VerdictLevel.MALICIOUS  # type: ignore[arg-type]

    def test_fallback_verdict_texts(self):
        released = fallback_verdict("timeout", released=True)
        held = fallback_verdict("error: ValueError", released=False)
        assert released.level is VerdictLevel.UNKNOWN and "delivered" in released.summary
        assert held.needs_human_review and "held" in held.summary
        assert released.signals[0].code == "engine.timeout" and held.signals[0].code == "engine.error"

    def test_default_wiring_is_lazy(self, db, settings):
        """Importing the worker must not import analysis/chamber; resolving the
        defaults happens on first use (and fails clearly while they are absent)."""
        worker = Worker(db, settings, connector_factory=lambda m: None)  # type: ignore[arg-type]
        assert worker.notifier is not None
        for attr in ("parser", "analyzer", "context_factory", "intel", "detonator"):
            try:
                getattr(worker, attr)
            except ImportError:
                continue  # the other team's package is not installed in this checkout yet


class CrashingApply(CountingMailbox):
    """apply_verdict blows up with a non-connector error; release is broken too."""

    async def apply_verdict(self, msg, verdict, policy) -> None:
        raise RuntimeError("label api returned garbage")

    async def release(self, provider_message_id: str) -> None:
        raise ConnectorError("cannot release", retryable=True)


class RetryableRestore(CountingMailbox):
    async def restore(self, provider_message_id: str) -> None:
        raise ConnectorError("gmail 503", retryable=True)


class TestMoreEngineEdges:
    async def test_crash_after_row_exists_marks_row_failed_even_if_release_fails(self, harness: Harness):
        _user, mailbox, fake = await harness.add_client(mode="hold")
        crashing = CrashingApply(mailbox.id)
        harness.connectors[mailbox.id] = crashing
        worker = harness.worker()
        await worker.run_cycle()
        crashing.deliver(email_bytes("Any"), "h1")
        stats = await worker.run_cycle()
        assert stats.failed == 1
        row = (await harness.messages(mailbox.id))["h1"]
        assert row.state == "failed" and row.verdict == {"error": "RuntimeError: label api returned garbage"}
        assert "message_failed" in await harness.audit_actions(mailbox.id)
        del fake

    async def test_retryable_restore_error_aborts_the_mailbox_cycle(self, harness: Harness):
        _user, mailbox, _fake = await harness.add_client(mode="scan")
        flaky = RetryableRestore(mailbox.id)
        harness.connectors[mailbox.id] = flaky
        harness.analyzer.scripts = {"Bad": verdict(VerdictLevel.MALICIOUS)}
        flaky.deliver(email_bytes("Bad"), "m1")
        worker = harness.worker()
        await worker.run_cycle()
        row = (await harness.messages(mailbox.id))["m1"]
        async with harness.db.session() as s:
            await repo.request_restore(s, row.id)
        stats = await worker.run_cycle()
        assert stats.mailbox_errors == [mailbox.id]
        assert (await harness.messages(mailbox.id))["m1"].state == "restore_requested"  # retried next cycle
        assert (await harness.mailbox_row(mailbox.id)).status == "active"

    async def test_default_sleep_times_out_quietly(self, harness: Harness):
        worker = Worker(
            harness.db,
            harness.settings,
            connector_factory=harness.connector_factory,
            notifier=harness.notifier,
        )
        await asyncio.wait_for(worker._sleep(0.01), timeout=5)


class TestProcessEntryPoint:
    async def test_run_starts_and_stops_both_services(self, db, settings, monkeypatch):
        from reddysec.worker import __main__ as entry

        stop = asyncio.Event()
        stop.set()  # both loops observe the flag before their first cycle
        await asyncio.wait_for(entry.run(settings, stop_event=stop, db=db), timeout=10)
        await asyncio.wait_for(
            entry.run(settings, with_worker=False, with_deadman=False, stop_event=stop, db=db), timeout=10
        )

    def test_main_uses_asyncio_run(self, monkeypatch, settings):
        from reddysec.worker import __main__ as entry

        ran: list[Any] = []

        def fake_run(coro):
            ran.append(coro)
            coro.close()

        monkeypatch.setattr(entry.asyncio, "run", fake_run)
        entry.main()
        assert len(ran) == 1

    def test_signal_handlers_outside_a_loop_are_ignored(self):
        from reddysec.worker import __main__ as entry

        async def go() -> None:
            stop = asyncio.Event()
            entry.install_stop_signals(stop)
            assert not stop.is_set()

        asyncio.run(go())


class TestRealWiring:
    """Smoke tests against the real analysis/chamber packages when present.
    They are skipped in a checkout where those packages do not exist yet."""

    def test_default_wiring_resolves(self, db, settings, fake_detonator):
        pytest.importorskip("reddysec.analysis.pipeline")
        pytest.importorskip("reddysec.chamber.backends")
        from reddysec.analysis.intel import CompositeIntel
        from reddysec.analysis.parser import parse_raw
        from reddysec.analysis.pipeline import AnalysisContext, analyze

        worker = Worker(db, settings, connector_factory=lambda m: None)  # type: ignore[arg-type]
        assert (
            worker.parser is parse_raw
            and worker.analyzer is analyze
            and worker.context_factory is AnalysisContext
        )
        assert isinstance(worker.intel, CompositeIntel)
        assert worker.detonator is not None  # make_chamber(settings, artifact_store) for the "local" backend

    async def test_real_parser_and_analyzer_with_fake_detonator(self, harness: Harness, fake_detonator):
        pytest.importorskip("reddysec.analysis.pipeline")
        from reddysec.analysis.intel import OfflineIntel
        from reddysec.analysis.parser import parse_raw
        from reddysec.analysis.pipeline import AnalysisContext, analyze

        user, mailbox, fake = await harness.add_client(mode="hold")
        fake.deliver(email_bytes("Plain note", body="See you at noon."), "m1")
        fake.deliver(email_bytes("Link inside", body="Agenda: https://example.com/agenda"), "m2")
        worker = harness.worker(
            parser=parse_raw,
            analyzer=analyze,
            context_factory=AnalysisContext,
            intel=OfflineIntel(),
            detonator=fake_detonator,
        )
        stats = await worker.run_cycle()  # setup + the two messages already waiting
        assert stats.messages == 2 and stats.failed == 0
        rows = await harness.messages(mailbox.id)
        assert rows["m1"].state == "done" and rows["m1"].level in {
            "safe",
            "suspicious",
            "malicious",
            "unknown",
        }
        assert rows["m2"].url_count == 1 and rows["m2"].state == "done"
        assert all(fake.in_inbox[pid] for pid in ("m1", "m2") if not rows[pid].quarantined)
        del user

    def test_online_intel_wiring_uses_shared_http_client(self, db):
        pytest.importorskip("reddysec.analysis.intel")
        import httpx

        from reddysec.analysis.intel import CompositeIntel
        from reddysec.worker.engine import _default_intel

        http = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
        online = Settings(env="test", intel_online=True, safe_browsing_api_key="key")
        intel = _default_intel(online, http)
        assert isinstance(intel, CompositeIntel) and intel._online is not None
        assert _default_intel(Settings(env="test", intel_online=False), http)._online is None

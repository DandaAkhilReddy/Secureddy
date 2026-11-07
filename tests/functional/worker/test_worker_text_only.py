"""The worker ignores email with nothing to click or open.

Owner's rule: "This application should only take emails that have buttons or
links or downloads; pure-text emails: don't even count them." These tests
drive the real engine, repository and notifier against a fake mailbox:

* SCAN: a text-only email gets no row, no label, no notification, no audit
  entry; only the operations counter moves.
* HOLD: it is released at once, the Checking label removed; never trapped.
* The opt-in "Also watch text-only emails for money scams" checks text-only
  email that trips the BEC heuristics, and still ignores clean ones.
* Backfill and re-check follow the same rule; a backfill never loops on
  text-only mail it already skipped.
* A paused HOLD mailbox has its hold rule lifted and held mail released.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import func, select

from reddysec.core.ids import new_id
from reddysec.mail.base import ConnectorError
from reddysec.models import VerdictLevel
from reddysec.store import repo
from reddysec.store.models import (
    AuditLog,
    MailboxDailyCounterRow,
    MessageRow,
    NotificationRow,
    UserPreferenceRow,
)
from reddysec.testing.fakes import FakeMailbox

from .test_worker_flows import NOW, Harness, email_bytes, verdict
from .test_worker_flows import settings as settings  # noqa: F401 - the shared fixture

PLAIN = "Are we still on for Saturday at 7? No rush."
WIRE = ("Please wire the closing funds today. Our bank account details have changed: new routing number "
        "021000021, account 12345678. Keep this confidential and do it before the bank closes.")
GIFT = ("Are you at your desk? I need you to buy 5 Apple gift cards for a client and send me photos of the "
        "codes. Keep this between us.")


async def counter(harness: Harness, mailbox_id: str) -> int:
    async with harness.db.session() as s:
        return await repo.skipped_text_only(s, mailbox_id)


async def audit_rows(harness: Harness, mailbox_id: str) -> list[str]:
    return await harness.audit_actions(mailbox_id)


async def watch_scams(harness: Harness, user_id: str, value: str = "on") -> None:
    async with harness.db.session() as s:
        s.add(UserPreferenceRow(id=new_id("prf"), user_id=user_id, key=repo.PREF_WATCH_TEXT_SCAMS, value=value))


@pytest.fixture
def harness(db, settings) -> Harness:
    return Harness(db, settings)


class TestScan:
    async def test_text_only_email_is_ignored_completely(self, harness: Harness):
        user, mailbox, fake = await harness.add_client(mode="scan")
        fake.deliver(email_bytes("Saturday", body=PLAIN), "t1")
        fake.deliver(email_bytes("Agenda", body="Agenda: https://docs.example/agenda"), "l1")
        harness.analyzer.scripts = {"Saturday": verdict(VerdictLevel.MALICIOUS)}  # never consulted
        worker = harness.worker()

        stats = await worker.run_cycle()

        assert stats.messages == 1 and stats.text_only == 1 and stats.failed == 0
        rows = await harness.messages(mailbox.id)
        assert set(rows) == {"l1"}
        assert fake.labels["t1"] == set() and fake.in_inbox["t1"]  # no "Checked" label
        assert "Secureddy/Checked" in fake.labels["l1"]
        assert [p.subject for p, _ in harness.analyzer.calls] == ["Agenda"]
        assert await harness.notifications(user.id) == []
        actions = await audit_rows(harness, mailbox.id)
        assert actions.count("verdict") == 1
        async with harness.db.session() as s:
            audits = (await s.execute(select(AuditLog).where(AuditLog.target == "t1"))).scalars().all()
        assert audits == []
        assert await counter(harness, mailbox.id) == 1

    async def test_counter_is_per_day_and_never_notifies(self, harness: Harness):
        user, mailbox, fake = await harness.add_client(mode="scan")
        for i in range(3):
            fake.deliver(email_bytes(f"note {i}", body=PLAIN), f"t{i}")
        await harness.worker().run_cycle()
        async with harness.db.session() as s:
            rows = (await s.execute(select(MailboxDailyCounterRow))).scalars().all()
        assert [(r.mailbox_id, r.day, r.skipped_text_only) for r in rows] == [
            (mailbox.id, repo.utc_day(NOW), 3)
        ]
        async with harness.db.session() as s:
            assert (await s.execute(select(func.count()).select_from(NotificationRow))).scalar_one() == 0
            assert (await s.execute(select(func.count()).select_from(MessageRow))).scalar_one() == 0

    async def test_counter_failure_does_not_cost_the_cycle(self, harness: Harness, monkeypatch):
        from sqlalchemy.exc import OperationalError

        _user, mailbox, fake = await harness.add_client(mode="scan")
        fake.deliver(email_bytes("note", body=PLAIN), "t1")

        async def broken(*a, **k):
            raise OperationalError("UPDATE", {}, Exception("db hiccup"))

        monkeypatch.setattr(repo, "bump_skipped_text_only", broken)
        stats = await harness.worker().run_cycle()
        assert stats.text_only == 1 and stats.mailbox_errors == []

    async def test_left_over_pending_row_is_forgotten(self, harness: Harness):
        """A worker that died mid-flight left a 'pending' row; on retry the
        email turns out to be text-only, so the row goes."""
        _user, mailbox, fake = await harness.add_client(mode="scan")
        raw = fake.deliver(email_bytes("note", body=PLAIN), "t1")
        async with harness.db.session() as s:
            s.add(MessageRow(id=new_id("msg"), mailbox_id=mailbox.id, provider_message_id="t1",
                             received_at=raw.received_at, state="pending"))
        await harness.worker().run_cycle()
        assert await harness.messages(mailbox.id) == {}


class TestHold:
    async def test_text_only_is_released_at_once_and_never_trapped(self, harness: Harness):
        _user, mailbox, fake = await harness.add_client(mode="hold")
        worker = harness.worker()
        await worker.run_cycle()  # installs the hold rule
        fake.deliver(email_bytes("note", body=PLAIN), "t1")
        fake.deliver(email_bytes("Agenda", body="see https://docs.example/a"), "l1")
        assert fake.labels["t1"] == {"Secureddy/Checking"} and not fake.in_inbox["t1"]

        stats = await worker.run_cycle()

        assert stats.text_only == 1
        assert fake.in_inbox["t1"] and "Secureddy/Checking" not in fake.labels["t1"]
        assert ("release", "t1") in fake.actions
        assert "t1" not in await harness.messages(mailbox.id)
        # The analysed one goes through the normal path.
        assert "Secureddy/Checked" in fake.labels["l1"] and fake.in_inbox["l1"]

    async def test_release_not_found_is_tolerated(self, harness: Harness):
        _user, mailbox, fake = await harness.add_client(mode="hold")
        worker = harness.worker()
        await worker.run_cycle()
        fake.deliver(email_bytes("note", body=PLAIN), "t1")

        async def gone(pid: str) -> None:
            raise ConnectorError("message t1 not found", retryable=False)

        fake.release = gone  # type: ignore[method-assign]
        stats = await worker.run_cycle()
        assert stats.text_only == 1 and stats.mailbox_errors == []
        assert (await harness.mailbox_row(mailbox.id)).status == "active"

    async def test_release_outage_retries_the_cycle(self, harness: Harness):
        _user, mailbox, fake = await harness.add_client(mode="hold")
        worker = harness.worker()
        await worker.run_cycle()
        cursor = (await harness.mailbox_row(mailbox.id)).cursor
        fake.deliver(email_bytes("note", body=PLAIN), "t1")

        async def outage(pid: str) -> None:
            raise ConnectorError("503", retryable=True)

        original = fake.release
        fake.release = outage  # type: ignore[method-assign]
        stats = await worker.run_cycle()
        assert stats.mailbox_errors == [mailbox.id]
        assert (await harness.mailbox_row(mailbox.id)).cursor == cursor  # read again next time
        fake.release = original  # type: ignore[method-assign]
        stats = await worker.run_cycle()
        assert stats.text_only == 1 and fake.in_inbox["t1"]


class TestWatchTextScams:
    async def test_off_by_default_even_for_scams(self, harness: Harness):
        user, mailbox, fake = await harness.add_client()
        fake.deliver(email_bytes("Wire today", body=WIRE, sender="Title <closing@title-co.example>"), "w1")
        stats = await harness.worker().run_cycle()
        assert stats.text_only == 1 and await harness.messages(mailbox.id) == {}
        del user

    async def test_on_checks_scams_and_still_ignores_clean_text(self, harness: Harness):
        user, mailbox, fake = await harness.add_client()
        await watch_scams(harness, user.id)
        fake.deliver(email_bytes("Wire today", body=WIRE, sender="Title <closing@title-co.example>"), "w1")
        fake.deliver(email_bytes("Gift", body=GIFT, sender="CEO <ceo.office@gmail.com>"), "g1")
        fake.deliver(email_bytes("Saturday", body=PLAIN), "t1")
        harness.analyzer.scripts = {
            "Wire today": verdict(VerdictLevel.SUSPICIOUS),
            "Gift": verdict(VerdictLevel.MALICIOUS),
        }
        stats = await harness.worker().run_cycle()

        assert stats.messages == 2 and stats.text_only == 1
        rows = await harness.messages(mailbox.id)
        assert set(rows) == {"w1", "g1"}
        assert rows["g1"].quarantined and not fake.in_inbox["g1"]
        assert "Secureddy/Suspicious" in fake.labels["w1"]
        assert fake.labels["t1"] == set()
        assert len(await harness.notifications(user.id)) >= 1  # the dangerous ones notify as usual

    async def test_trusted_sender_text_is_ignored(self, harness: Harness):
        from reddysec.store.models import SenderFeedbackRow

        user, mailbox, fake = await harness.add_client()
        await watch_scams(harness, user.id)
        async with harness.db.session() as s:
            s.add(SenderFeedbackRow(id=new_id("sfb"), mailbox_id=mailbox.id, scope="address",
                                    value="closing@title-co.example", decision="trusted", authenticated=False))
        fake.deliver(email_bytes("Wire today", body=WIRE, sender="Title <closing@title-co.example>"), "w1")
        stats = await harness.worker().run_cycle()
        assert stats.text_only == 1 and await harness.messages(mailbox.id) == {}

    async def test_explicit_off_and_broken_check(self, harness: Harness):
        user, mailbox, fake = await harness.add_client()
        await watch_scams(harness, user.id, "off")
        fake.deliver(email_bytes("Gift", body=GIFT), "g1")
        assert (await harness.worker().run_cycle()).text_only == 1

        async with harness.db.session() as s:
            row = (await s.execute(select(UserPreferenceRow))).scalar_one()
            row.value = "on"

        def boom(*a, **k):
            raise RuntimeError("heuristic bug")

        fake.deliver(email_bytes("Gift 2", body=GIFT), "g2")
        stats = await harness.worker(text_scam_check=boom).run_cycle()
        assert stats.text_only == 1 and stats.failed == 0


class TestBackfillAndRescore:
    async def test_backfill_skips_text_only_without_looping(self, harness: Harness):
        from .test_worker_backfill_and_retry import NewMailOnly

        harness.settings.backfill_batch_size = 5
        _user, mailbox, _ = await harness.add_client()

        class Recording(NewMailOnly):
            returned: list[str] = []

            async def backfill(self, since, limit, *, skip=()):
                found = await super().backfill(since, limit, skip=skip)
                self.returned.extend(m.provider_message_id for m in found)
                return found

        fake = harness.connectors[mailbox.id] = Recording(mailbox.id)
        for i in range(12):  # already in the mailbox: 8 text-only, 4 with a link
            body = f"see https://docs.example/{i}" if i % 3 == 0 else PLAIN
            fake.deliver(email_bytes(f"Old {i:02d}", body=body), f"o{i:02d}", received_at=NOW - timedelta(hours=30 - i))
        worker = harness.worker()
        total_text = 0
        for _ in range(6):
            stats = await worker.run_cycle()
            total_text += stats.text_only
        async with harness.db.session() as s:
            task = await repo.open_backfill(s, mailbox.id)
            finished = (await s.execute(select(func.count()).select_from(MessageRow))).scalar_one()
        assert task is None  # finished
        assert finished == 4 and total_text == 8
        # Each email was fetched once: the skip list carries the text-only ones.
        assert sorted(fake.returned) == sorted(f"o{i:02d}" for i in range(12))
        assert {"o11", "o10"} <= set(fake.backfill_calls[-1][2])
        async with harness.db.session() as s:
            done = (await s.execute(select(AuditLog).where(AuditLog.action == "backfill_done"))).scalar_one()
        assert done.details["checked"] == 4  # text-only is not counted, even in the audit log

    async def test_rescore_of_stored_text_only_row_forgets_it(self, harness: Harness):
        user, mailbox, fake = await harness.add_client()
        raw = fake.deliver(email_bytes("Old note", body=PLAIN), "t1")
        async with harness.db.session() as s:
            await repo.update_cursor(s, mailbox.id, str(len(fake.messages)))
            await repo.set_mailbox_labels(s, mailbox.id, {"Secureddy": "L1", "_mode": "scan"})
            row = MessageRow(id=new_id("msg"), mailbox_id=mailbox.id, provider_message_id="t1",
                             received_at=raw.received_at, state=repo.STATE_RESCORE_REQUESTED, level="safe",
                             verdict={"level": "safe", "signals": []})
            s.add(row)
            await repo.create_notification(s, user_id=user.id, channel="dashboard", level="safe", title="t",
                                           body="b", message_id=row.id)
        stats = await harness.worker().run_cycle()
        assert stats.client_requests == 1
        assert await harness.messages(mailbox.id) == {}
        assert await harness.notifications(user.id) == []
        assert await counter(harness, mailbox.id) == 1

    async def test_rescore_keeps_a_quarantined_text_only_row(self, harness: Harness):
        _user, mailbox, fake = await harness.add_client()
        raw = fake.deliver(email_bytes("Blocked note", body=PLAIN), "q1")
        await fake.quarantine("q1")
        harness.analyzer.scripts = {"Blocked note": verdict(VerdictLevel.SAFE)}
        async with harness.db.session() as s:
            await repo.update_cursor(s, mailbox.id, str(len(fake.messages)))
            await repo.set_mailbox_labels(s, mailbox.id, {"Secureddy": "L1", "_mode": "scan"})
            s.add(MessageRow(id=new_id("msg"), mailbox_id=mailbox.id, provider_message_id="q1",
                             received_at=raw.received_at, state=repo.STATE_RESCORE_REQUESTED, level="malicious",
                             quarantined=True, verdict={"level": "malicious", "signals": []}))
        await harness.worker().run_cycle()
        rows = await harness.messages(mailbox.id)
        assert rows["q1"].level == "safe" and not rows["q1"].quarantined and fake.in_inbox["q1"]


class TestPausedHold:
    async def test_pausing_a_hold_mailbox_releases_and_lifts_the_rule(self, harness: Harness):
        _user, mailbox, fake = await harness.add_client(mode="hold")
        worker = harness.worker()
        await worker.run_cycle()
        assert fake.hold_rule_installed
        fake.deliver(email_bytes("Agenda", body="see https://docs.example/a"), "h1")
        async with harness.db.session() as s:
            await repo.set_mailbox_status(s, mailbox.id, "paused")
        assert not fake.in_inbox["h1"]

        stats = await worker.run_cycle()

        assert fake.in_inbox["h1"] and not fake.hold_rule_installed
        assert stats.restored == 1
        row = await harness.mailbox_row(mailbox.id)
        assert row.labels == {} and row.status == "paused"
        assert "hold_released_on_pause" in await harness.audit_actions(mailbox.id)
        # Nothing left to do on the next cycle.
        assert (await worker.run_cycle()).restored == 0

        async with harness.db.session() as s:
            await repo.set_mailbox_status(s, mailbox.id, "active")
        await worker.run_cycle()
        assert fake.hold_rule_installed  # resuming installs the rule again

    async def test_release_failure_is_retried(self, harness: Harness):
        _user, mailbox, fake = await harness.add_client(mode="hold")
        worker = harness.worker()
        await worker.run_cycle()

        class Broken(FakeMailbox):
            async def teardown(self) -> None:
                raise ConnectorError("down")

        harness.connectors[mailbox.id] = Broken(mailbox.id)
        async with harness.db.session() as s:
            await repo.set_mailbox_status(s, mailbox.id, "paused")
        await worker.run_cycle()
        assert (await harness.mailbox_row(mailbox.id)).labels  # still set up: tried again next cycle

"""Worker: "check my recent mail" (backfill) and never failing silently."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError, OperationalError

from reddysec.config import Settings
from reddysec.mail.base import AuthExpired, ConnectorError
from reddysec.store import repo
from reddysec.store.models import MailboxTaskRow
from reddysec.worker import engine as engine_mod
from reddysec.worker.engine import (
    ERROR_CHECK_FAILED,
    ERROR_SAVE_PLACE,
    ERROR_UNREACHABLE,
    Worker,
)

from .test_worker_flows import NOW, CountingMailbox, Harness, email_bytes


class NewMailOnly(CountingMailbox):
    """Like Gmail/IMAP/Graph after the first poll: ``poll`` reports only mail
    that arrives after it started watching; what was already in the mailbox
    is reachable through ``backfill`` alone."""

    def __init__(self, mailbox_id: str = "mbx_test") -> None:
        super().__init__(mailbox_id)
        self.backfill_error: Exception | None = None

    async def poll(self, cursor):
        if self.poll_error is not None:
            raise self.poll_error
        if cursor is None:
            return [], str(len(self.messages))
        return await super().poll(cursor)

    async def backfill(self, since, limit, *, skip=()):
        if self.backfill_error is not None:
            raise self.backfill_error
        return await super().backfill(since, limit, skip=skip)


@pytest.fixture
def settings() -> Settings:
    return Settings(
        env="test",
        base_url="https://rs.example",
        secret_key="functional",
        gmail_poll_seconds=10,
        imap_poll_seconds=10,
        graph_poll_seconds=10,
        detonation_timeout_s=2,
        initial_backfill_days=2,
        initial_backfill_limit=50,
        backfill_batch_size=20,
        mailbox_failures_before_error=3,
        mailbox_retry_max_seconds=600,
    )


@pytest.fixture
def harness(db, settings) -> Harness:
    return Harness(db, settings)


async def client_with(harness: Harness, fake_cls=NewMailOnly, **kw):
    user, mailbox, _ = await harness.add_client(**kw)
    fake = fake_cls(mailbox.id)
    harness.connectors[mailbox.id] = fake
    return user, mailbox, fake


async def tasks(harness: Harness) -> list[MailboxTaskRow]:
    async with harness.db.session() as s:
        return list((await s.execute(select(MailboxTaskRow).order_by(MailboxTaskRow.created_at))).scalars())


class TestInitialBackfill:
    async def test_new_mailbox_checks_last_two_days_in_batches_newest_first(self, harness: Harness):
        _user, mailbox, fake = await client_with(harness)
        for i in range(45):  # already in the mailbox before we were connected
            fake.deliver(email_bytes(f"Recent {i:02d}"), f"r{i:02d}", received_at=NOW - timedelta(hours=40 - i))
        fake.deliver(email_bytes("Too old"), "old", received_at=NOW - timedelta(days=3))
        worker = harness.worker()

        stats = await worker.run_cycle()  # setup, empty first poll, first batch of 20
        assert stats.backfilled == 20 and stats.messages == 20
        (task,) = await tasks(harness)
        assert (task.reason, task.state, task.processed, task.max_messages) == (
            "first_setup", "backfill_running", 20, 50,
        )
        assert sorted(await harness.messages(mailbox.id)) == [f"r{i:02d}" for i in range(25, 45)]  # newest first

        fake.deliver(email_bytes("Brand new"), "new1")  # arrives meanwhile
        stats = await worker.run_cycle()
        assert stats.messages == 21 and stats.backfilled == 20  # new mail first, then a batch
        stats = await worker.run_cycle()
        assert stats.backfilled == 5
        (task,) = await tasks(harness)
        assert task.state == "done" and task.processed == 45 and task.finished_at is not None
        seen = await harness.messages(mailbox.id)
        assert "old" not in seen and len(seen) == 46
        assert "backfill_done" in await harness.audit_actions(mailbox.id)
        assert (await worker.run_cycle()).backfilled == 0
        assert len(fake.backfill_calls) == 3  # nothing left to ask for

    async def test_only_once_per_mailbox_and_can_be_turned_off(self, harness: Harness, settings: Settings):
        _user, mailbox, fake = await client_with(harness)
        worker = harness.worker()
        await worker.run_cycle()
        async with harness.db.session() as s:
            await repo.set_mailbox_labels(s, mailbox.id, {})  # e.g. a mode change: set up again
        mailbox_row = await harness.mailbox_row(mailbox.id)
        assert mailbox_row.cursor is not None
        await worker.run_cycle()
        assert len(await tasks(harness)) == 1

        settings.initial_backfill_days = 0
        _u2, other, _f2 = await client_with(harness, address="second@gmail.com")
        await harness.worker().run_cycle()
        assert [t.mailbox_id for t in await tasks(harness)] == [mailbox.id]
        del other


class TestRecheckBackfill:
    async def test_request_is_idempotent_and_capped(self, harness: Harness):
        _user, mailbox, fake = await client_with(harness)
        harness.settings.initial_backfill_days = 0
        worker = harness.worker()
        await worker.run_cycle()
        for i in range(5):
            fake.deliver(email_bytes(f"Week {i}"), f"w{i}", received_at=NOW - timedelta(days=i + 1))
        async with harness.db.session() as s:
            await repo.update_cursor(s, mailbox.id, str(len(fake.messages)))  # poll will not report them
            first, created = await repo.request_backfill(s, mailbox.id, since=NOW - timedelta(days=3), limit=2)
            again, created_again = await repo.request_backfill(s, mailbox.id, since=NOW - timedelta(days=7), limit=3)
        assert created and not created_again and again.id == first.id
        assert repo.aware(again.since) == NOW - timedelta(days=7) and again.max_messages == 3

        assert (await worker.run_cycle()).backfilled == 3
        (task,) = await tasks(harness)
        assert task.state == "done" and task.processed == 3
        assert sorted(await harness.messages(mailbox.id)) == ["w0", "w1", "w2"]  # newest three
        # Already-known mail is never fetched again.
        async with harness.db.session() as s:
            await repo.request_backfill(s, mailbox.id, since=NOW - timedelta(days=7), limit=200)
        assert (await worker.run_cycle()).backfilled == 2
        assert fake.backfill_calls[-1][2] >= {"w0", "w1", "w2"}

    async def test_connector_without_backfill_or_permanent_error_closes_the_request(self, harness: Harness):
        _user, mailbox, fake = await client_with(harness)
        harness.settings.initial_backfill_days = 0
        worker = harness.worker()
        await worker.run_cycle()
        async with harness.db.session() as s:
            await repo.request_backfill(s, mailbox.id, since=NOW - timedelta(days=7), limit=10)
        fake.backfill_error = ConnectorError("folder gone", retryable=False)
        await worker.run_cycle()
        (task,) = await tasks(harness)
        assert task.state == "failed" and task.error == "folder gone"

        _u2, other, _plain = await client_with(harness, fake_cls=_NoBackfill, address="old@gmail.com")
        await worker.run_cycle()
        async with harness.db.session() as s:
            await repo.request_backfill(s, other.id, since=NOW - timedelta(days=7), limit=10)
        await worker.run_cycle()
        last = (await tasks(harness))[-1]
        assert last.state == "failed" and "cannot fetch older mail" in last.error

    async def test_retryable_backfill_error_retries_the_mailbox(self, harness: Harness):
        _user, mailbox, fake = await client_with(harness)
        worker = harness.worker()
        fake.deliver(email_bytes("Earlier"), "e1", received_at=NOW - timedelta(hours=3))
        fake.backfill_error = ConnectorError("503", retryable=True)
        stats = await worker.run_cycle()
        assert stats.mailbox_errors == [mailbox.id]
        (task,) = await tasks(harness)
        assert task.state == "backfill_requested"  # still open, tried again later
        fake.backfill_error = None
        assert (await worker.run_cycle()).backfilled == 1

    async def test_auth_expired_during_backfill_marks_the_mailbox(self, harness: Harness):
        _user, mailbox, fake = await client_with(harness)
        fake.deliver(email_bytes("Earlier"), "e1", received_at=NOW - timedelta(hours=3))
        fake.backfill_error = AuthExpired("revoked")
        await harness.worker().run_cycle()
        assert (await harness.mailbox_row(mailbox.id)).status == "error"


class _NoBackfill(CountingMailbox):
    def __getattribute__(self, name):
        if name == "backfill":
            raise AttributeError(name)
        return super().__getattribute__(name)


class TestNeverFailSilently:
    async def test_repeated_crash_shows_plain_error_backs_off_and_recovers(self, harness: Harness):
        _user, mailbox, fake = await client_with(harness, fake_cls=CountingMailbox)
        async with harness.db.session() as s:
            ana = await repo.create_user(s, email="ana@rs.example", display_name="Ana", role="concierge")
        clock = {"now": NOW}
        worker = harness.worker(clock=lambda: clock["now"])
        fake.poll_error = RuntimeError("value too long for type character varying(100)")

        await worker.run_cycle()  # 1st failure: retried on the next cycle
        assert (await harness.mailbox_row(mailbox.id)).last_error is None
        await worker.run_cycle()  # 2nd: now a pause of 2 x poll interval
        assert worker.retry_delay_s(2) == 20
        assert (await worker.run_cycle()).deferred == 1  # still pausing
        clock["now"] += timedelta(seconds=21)
        await worker.run_cycle()  # 3rd: shown to the client
        row = await harness.mailbox_row(mailbox.id)
        assert row.status == "error" and row.last_error == ERROR_CHECK_FAILED
        assert "character varying" not in row.last_error
        notes = await harness.notifications(ana.id)
        assert len(notes) == 1 and "keeps failing" in notes[0].title

        clock["now"] += timedelta(seconds=41)
        await worker.run_cycle()  # 4th: still error, no second page to the concierge
        assert len(await harness.notifications(ana.id)) == 1
        assert worker.retry_delay_s(10) == 600  # capped

        fake.poll_error = None
        clock["now"] += timedelta(seconds=601)
        stats = await worker.run_cycle()  # error mailboxes the worker parked are still retried
        assert stats.mailbox_errors == [] and stats.mailboxes == 1
        row = await harness.mailbox_row(mailbox.id)
        assert row.status == "active" and row.last_error is None
        assert "mailbox_retrying" in await harness.audit_actions(mailbox.id)

    async def test_cursor_save_failure_is_named_for_the_client(self, harness: Harness, monkeypatch):
        _user, mailbox, fake = await client_with(harness, fake_cls=CountingMailbox)
        clock = {"now": NOW}
        worker = harness.worker(clock=lambda: clock["now"])

        async def broken_update_cursor(session, mailbox_id, cursor):
            raise DBAPIError("UPDATE mailboxes", {}, Exception("value too long for type character varying(100)"))

        monkeypatch.setattr(engine_mod.repo, "update_cursor", broken_update_cursor)
        for _ in range(3):
            await worker.run_cycle()
            clock["now"] += timedelta(hours=1)
        row = await harness.mailbox_row(mailbox.id)
        assert row.status == "error" and row.last_error == ERROR_SAVE_PLACE

    async def test_provider_unreachable_for_a_while(self, harness: Harness):
        _user, mailbox, fake = await client_with(harness, fake_cls=CountingMailbox)
        clock = {"now": NOW}
        worker = harness.worker(clock=lambda: clock["now"])
        fake.poll_error = ConnectorError("imap down", retryable=True)
        for _ in range(3):
            await worker.run_cycle()
            clock["now"] += timedelta(hours=1)
        row = await harness.mailbox_row(mailbox.id)
        assert row.status == "error" and row.last_error == ERROR_UNREACHABLE

    async def test_auth_errors_are_not_retried_by_the_worker(self, harness: Harness):
        _user, mailbox, _fake = await client_with(harness, fake_cls=CountingMailbox)
        harness.factory_errors[mailbox.id] = AuthExpired("revoked")
        worker = harness.worker()
        await worker.run_cycle()
        assert (await worker.run_cycle()).mailboxes == 0  # waits for the client to reconnect

    async def test_status_write_failure_is_survived(self, harness: Harness, monkeypatch):
        _user, mailbox, fake = await client_with(harness, fake_cls=CountingMailbox)
        clock = {"now": NOW}
        worker: Worker = harness.worker(clock=lambda: clock["now"])
        fake.poll_error = RuntimeError("db down")

        async def broken_status(*a, **kw):
            raise OperationalError("UPDATE", {}, Exception("down"))

        monkeypatch.setattr(engine_mod.repo, "set_mailbox_status", broken_status)
        for _ in range(3):
            await worker.run_cycle()
            clock["now"] += timedelta(hours=1)
        assert (await harness.mailbox_row(mailbox.id)).status == "active"

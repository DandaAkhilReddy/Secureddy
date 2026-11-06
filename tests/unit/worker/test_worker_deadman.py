"""DeadManSwitch with FakeMailbox connectors and the real repository."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from reddysec.mail.base import ConnectorError
from reddysec.models import ParsedMessage, ProtectionMode, RawMessage
from reddysec.store import repo
from reddysec.testing.fakes import FakeMailbox
from reddysec.worker.deadman import DeadManSwitch
from reddysec.worker.engine import MODE_KEY
from reddysec.worker.notify import Notifier

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)


class FailingRelease(FakeMailbox):
    async def release_all_pending(self) -> int:
        raise ConnectorError("gmail down", retryable=True)


class FailingTeardown(FakeMailbox):
    async def teardown(self) -> None:
        raise ConnectorError("filters api 403", retryable=False)


def make_switch(db, settings, connectors: dict[str, FakeMailbox], **kw) -> DeadManSwitch:
    async def factory(mailbox):
        return connectors[mailbox.id]

    return DeadManSwitch(
        db,
        settings,
        connector_factory=factory,
        notifier=Notifier(db, settings, clock=lambda: NOW),
        clock=lambda: NOW,
        **kw,
    )


async def held_mailbox(db, client_rows, fake: FakeMailbox, *, beat_minutes_ago: int) -> None:
    """A HOLD mailbox that was set up, has two held messages, and a stale heartbeat."""
    fake.mailbox_id = client_rows.mailbox.id
    await fake.setup(ProtectionMode.HOLD)
    fake.deliver(b"raw-1", "p1")
    fake.deliver(b"raw-2", "p2")
    async with db.session() as s:
        await repo.set_mailbox_labels(s, client_rows.mailbox.id, {"Secureddy": "L1", MODE_KEY: "hold"})
        await repo.beat(s, client_rows.mailbox.id, at=NOW - timedelta(minutes=beat_minutes_ago))
        for pid in ("p1", "p2"):
            parsed = ParsedMessage(
                provider_message_id=pid, mailbox_id=client_rows.mailbox.id, received_at=NOW
            )
            raw = RawMessage(
                provider_message_id=pid, mailbox_id=client_rows.mailbox.id, received_at=NOW, raw=b"x"
            )
            await repo.upsert_message(s, parsed, raw, state="analyzing")
        await repo.create_user(s, email="ana@rs.example", display_name="Ana", role="concierge")


class TestCheckOnce:
    async def test_fresh_heartbeat_is_left_alone(self, db, client_rows, make_settings):
        fake = FakeMailbox()
        await held_mailbox(db, client_rows, fake, beat_minutes_ago=2)
        switch = make_switch(db, make_settings(), {client_rows.mailbox.id: fake})
        assert await switch.check_once() == []
        assert fake.actions == [] and all(not v for v in fake.in_inbox.values())

    async def test_stale_mailbox_is_released_disarmed_and_reported(self, db, client_rows, make_settings):
        fake = FakeMailbox()
        await held_mailbox(db, client_rows, fake, beat_minutes_ago=11)
        switch = make_switch(db, make_settings(), {client_rows.mailbox.id: fake})
        assert switch.threshold == timedelta(minutes=10)

        released = await switch.check_once()

        assert released == [client_rows.mailbox.id]
        assert fake.actions == [("release_all_pending", "2"), ("teardown", "")]
        assert all(fake.in_inbox.values()) and not fake.hold_rule_installed
        async with db.session() as s:
            mailbox = await repo.get_mailbox(s, client_rows.mailbox.id)
            heartbeat = await repo.get_heartbeat(s, client_rows.mailbox.id)
            messages = await repo.list_recent_messages(s, [client_rows.mailbox.id])
            audit = await repo.list_audit(s, client_rows.mailbox.id)
            client_notes = await repo.list_notifications(s, client_rows.user.id)
            ana = await repo.get_user_by_email(s, "ana@rs.example")
            staff_notes = await repo.list_notifications(s, ana.id)
        assert mailbox.status == "error" and "released 2 held message(s)" in mailbox.last_error
        assert mailbox.labels == {"Secureddy": "L1"}  # _mode dropped: setup re-runs when re-activated
        assert repo.aware(heartbeat.released_by_deadman_at) == NOW  # SQLite hands back naive datetimes
        assert {m.state for m in messages} == {"released_by_deadman"}
        assert [a.action for a in audit] == ["deadman_release"]
        assert (
            audit[0].details == {"released": 2, "reason": "heartbeat stale"}
            and audit[0].actor_role == "system"
        )
        assert (
            len(client_notes) == 1
            and client_notes[0].level == "alert"
            and "NOT checked" in client_notes[0].body
        )
        assert len(staff_notes) == 1 and "Dead man's switch fired" in staff_notes[0].title

        # Error state removes it from the stale set: a second check does nothing.
        assert await switch.check_once() == []

    async def test_release_failure_alerts_concierge_and_continues(self, db, client_rows, make_settings):
        broken = FailingRelease()
        await held_mailbox(db, client_rows, broken, beat_minutes_ago=30)
        healthy = FakeMailbox()
        async with db.session() as s:
            other = await repo.create_mailbox(
                s, user_id=client_rows.user.id, provider="gmail", address="two@gmail.com", mode="hold"
            )
            await repo.set_mailbox_labels(s, other.id, {"Secureddy": "L1"})
            await repo.beat(s, other.id, at=NOW - timedelta(hours=1))
        healthy.mailbox_id = other.id
        await healthy.setup(ProtectionMode.HOLD)
        healthy.deliver(b"raw", "h1")
        switch = make_switch(db, make_settings(), {client_rows.mailbox.id: broken, other.id: healthy})

        released = await switch.check_once()

        assert released == [other.id]
        async with db.session() as s:
            first = await repo.get_mailbox(s, client_rows.mailbox.id)
            audit = [a.action for a in await repo.list_audit(s, client_rows.mailbox.id)]
            ana = await repo.get_user_by_email(s, "ana@rs.example")
            staff_notes = await repo.list_notifications(s, ana.id)
        assert first.status == "active"  # we could not prove the mail is out, so the alarm stays armed
        assert audit == ["deadman_release_failed"]
        assert any("URGENT" in n.title for n in staff_notes)

    async def test_teardown_failure_still_counts_as_release(self, db, client_rows, make_settings):
        fake = FailingTeardown()
        await held_mailbox(db, client_rows, fake, beat_minutes_ago=15)
        switch = make_switch(db, make_settings(), {client_rows.mailbox.id: fake})
        assert await switch.check_once() == [client_rows.mailbox.id]
        async with db.session() as s:
            mailbox = await repo.get_mailbox(s, client_rows.mailbox.id)
            (entry,) = await repo.list_audit(s, client_rows.mailbox.id)
        assert "hold rule could not be removed" in mailbox.last_error
        assert "filters api 403" in entry.details["reason"]

    async def test_manual_release_records_actor(self, db, client_rows, make_settings):
        fake = FakeMailbox()
        await held_mailbox(db, client_rows, fake, beat_minutes_ago=0)
        switch = make_switch(db, make_settings(), {client_rows.mailbox.id: fake})
        async with db.session() as s:
            mailbox = await repo.get_mailbox(s, client_rows.mailbox.id)
        assert (
            await switch.release_mailbox(
                mailbox, reason="operator request", actor_id="usr_admin", actor_role="admin"
            )
            == 2
        )
        async with db.session() as s:
            (entry,) = await repo.list_audit(s, client_rows.mailbox.id)
        assert (
            entry.actor_role == "admin"
            and entry.actor_id == "usr_admin"
            and entry.details["reason"] == "operator request"
        )


class TestRunForever:
    async def test_loop_checks_until_stopped_and_survives_crashes(self, db, client_rows, make_settings):
        stop = asyncio.Event()
        sleeps: list[float] = []
        calls = {"n": 0}

        async def fake_sleep(seconds: float) -> None:
            sleeps.append(seconds)
            if len(sleeps) == 3:
                stop.set()

        async def exploding_factory(mailbox):
            raise RuntimeError("factory bug")

        fake = FakeMailbox()
        await held_mailbox(db, client_rows, fake, beat_minutes_ago=60)
        switch = DeadManSwitch(
            db,
            make_settings(),
            connector_factory=exploding_factory,
            notifier=Notifier(db, make_settings()),
            clock=lambda: NOW,
            sleep=fake_sleep,
            interval_s=7.0,
        )
        original = switch.check_once

        async def counting() -> list[str]:
            calls["n"] += 1
            return await original()

        switch.check_once = counting  # type: ignore[method-assign]
        await asyncio.wait_for(switch.run_forever(stop), timeout=5)
        assert sleeps == [7.0, 7.0, 7.0] and calls["n"] == 3


async def test_run_forever_stops_without_sleeping_when_stopped_during_check(db, make_settings):
    stop = asyncio.Event()
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    async def noop_factory(mailbox):
        raise AssertionError("no mailboxes expected")

    switch = DeadManSwitch(
        db,
        make_settings(),
        connector_factory=noop_factory,
        notifier=Notifier(db, make_settings()),
        sleep=fake_sleep,
    )

    async def stopping_check() -> list[str]:
        stop.set()
        return []

    switch.check_once = stopping_check  # type: ignore[method-assign]
    await asyncio.wait_for(switch.run_forever(stop), timeout=5)
    assert sleeps == []

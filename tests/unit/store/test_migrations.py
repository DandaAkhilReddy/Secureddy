"""store.migrations on SQLite: duplicate mailboxes are merged and then made
impossible. (Column widening is PostgreSQL-only; see tests/postgres.)"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from reddysec.core.ids import new_id
from reddysec.store import repo
from reddysec.store.db import Database
from reddysec.store.migrations import upgrade
from reddysec.store.models import (
    MAILBOX_UNIQUE_INDEX,
    AuditLog,
    Contact,
    DetonationRow,
    FeedbackReasonRow,
    HoldHeartbeat,
    MailboxRow,
    MailboxSecret,
    MailboxTaskRow,
    MessageRow,
    NotificationRow,
    SenderFeedbackRow,
    SenderTrustStatsRow,
    UserRow,
)

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)


@pytest.fixture
async def old_db(tmp_path):
    """A database whose mailboxes table predates the unique index."""
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'old.db'}")
    await database.create_all()
    async with database.engine.begin() as conn:
        await conn.execute(text(f"DROP INDEX {MAILBOX_UNIQUE_INDEX}"))
    yield database
    await database.dispose()


def mailbox(user_id: str, address: str, *, status: str = "active", age_days: int = 0, provider: str = "yahoo"):
    return MailboxRow(
        id=new_id("mbx"), user_id=user_id, provider=provider, address=address, mode="scan", status=status,
        labels={}, policy={}, created_at=NOW - timedelta(days=age_days),
    )


async def test_upgrade_on_up_to_date_sqlite_does_nothing(db):
    async with db.engine.begin() as conn:
        assert await conn.run_sync(upgrade) == []
    assert await db.create_all() == []


async def test_duplicates_merge_into_the_working_row(old_db: Database):
    async with old_db.session() as s:
        user = UserRow(id=new_id("usr"), display_name="Owner", login_email="owner@example.com")
        other_user = UserRow(id=new_id("usr"), display_name="Other", login_email="other@example.com")
        s.add_all([user, other_user])
        await s.flush()
        stale = mailbox(user.id, "Danda@Yahoo.com", status="disconnected", age_days=2)
        keep = mailbox(user.id, "danda@yahoo.com", age_days=1)
        newer_no_secret = mailbox(user.id, "danda@yahoo.com", status="error", provider="imap")
        unrelated = mailbox(other_user.id, "danda@yahoo.com")  # another person's account: untouched
        s.add_all([stale, keep, newer_no_secret, unrelated])
        await s.flush()
        s.add(MailboxSecret(mailbox_id=keep.id, kind="imap_password", ciphertext="c", key_id="k"))
        s.add(MailboxSecret(mailbox_id=stale.id, kind="imap_password", ciphertext="c", key_id="k"))
        both = []
        for box in (stale, keep):
            row = MessageRow(id=new_id("msg"), mailbox_id=box.id, provider_message_id="INBOX:1:7", received_at=NOW)
            both.append(row)
            s.add(row)
            s.add(Contact(id=new_id("ctc"), mailbox_id=box.id, address="alice@example.com"))
            s.add(SenderTrustStatsRow(id=new_id("sts"), mailbox_id=box.id, scope="domain", value="bank.example"))
        only_stale = MessageRow(id=new_id("msg"), mailbox_id=stale.id, provider_message_id="INBOX:1:8", received_at=NOW)
        s.add(only_stale)
        await s.flush()
        s.add(DetonationRow(job_id="det_1", message_id=both[0].id, kind="url", target="https://x", status="ok"))
        s.add(FeedbackReasonRow(id=new_id("frs"), message_id=both[0].id, user_id=user.id, decision="safe"))
        s.add(NotificationRow(id=new_id("ntf"), user_id=user.id, message_id=both[0].id, channel="dashboard",
                              level="alert", title="t", body="b"))
        s.add(SenderFeedbackRow(id=new_id("sfb"), mailbox_id=stale.id, scope="address", value="x@y.example",
                                decision="blocked", source_message_id=both[0].id))
        s.add(HoldHeartbeat(mailbox_id=stale.id, beat_at=NOW))
        s.add(MailboxTaskRow(id=new_id("tsk"), mailbox_id=newer_no_secret.id, since=NOW))
        s.add(AuditLog(id=new_id("aud"), action="mailbox_connected", mailbox_id=stale.id))

    changes = await old_db.create_all()

    assert len([c for c in changes if c.startswith("merged duplicate mailbox")]) == 2
    assert f"created unique index {MAILBOX_UNIQUE_INDEX}" in changes
    async with old_db.session() as s:
        boxes = {m.id for m in (await s.execute(select(MailboxRow))).scalars()}
        assert boxes == {keep.id, unrelated.id}
        msgs = list((await s.execute(select(MessageRow).where(MessageRow.mailbox_id == keep.id))).scalars())
        assert sorted(m.provider_message_id for m in msgs) == ["INBOX:1:7", "INBOX:1:8"]
        kept_msg = next(m.id for m in msgs if m.provider_message_id == "INBOX:1:7")
        assert (await s.get(DetonationRow, "det_1")).message_id == kept_msg
        assert (await s.execute(select(FeedbackReasonRow))).scalar_one().message_id == kept_msg
        assert (await s.execute(select(NotificationRow))).scalar_one().message_id == kept_msg
        fb = (await s.execute(select(SenderFeedbackRow))).scalar_one()
        assert fb.mailbox_id == keep.id and fb.source_message_id == kept_msg
        assert [c.mailbox_id for c in (await s.execute(select(Contact))).scalars()] == [keep.id]
        assert [t.mailbox_id for t in (await s.execute(select(SenderTrustStatsRow))).scalars()] == [keep.id]
        assert (await s.execute(select(HoldHeartbeat))).first() is None
        assert (await s.execute(select(MailboxTaskRow))).scalar_one().mailbox_id == keep.id
        assert (await s.execute(select(AuditLog))).scalar_one().mailbox_id == keep.id
        assert [x.mailbox_id for x in (await s.execute(select(MailboxSecret))).scalars()] == [keep.id]
    with pytest.raises(IntegrityError):
        async with old_db.session() as s:
            s.add(mailbox(user.id, "DANDA@yahoo.com"))
    assert await old_db.create_all() == []


async def test_repo_create_mailbox_reuses_the_row(db):
    async with db.session() as s:
        user = await repo.create_user(s, email="owner@example.com", display_name="Owner")
        first = await repo.create_mailbox(s, user_id=user.id, provider="yahoo", address="Me@Yahoo.com")
        first.labels, first.cursor = {"Secureddy": "x"}, "1:2"
        first.status = "disconnected"
        await s.flush()
        again = await repo.create_mailbox(s, user_id=user.id, provider="yahoo", address="me@yahoo.com", mode="hold")
        assert again.id == first.id and again.status == "active" and again.labels == {} and again.cursor == "1:2"
        assert again.mode == "hold"
        switched = await repo.create_mailbox(
            s, user_id=user.id, provider="imap", address="me@yahoo.com", policy={"notify_at": "malicious"}
        )
        assert switched.id == first.id and switched.provider == "imap" and switched.cursor is None
        assert switched.policy == {"notify_at": "malicious"}
        assert await repo.find_mailbox_by_address(s, user.id, "nobody@yahoo.com") is None

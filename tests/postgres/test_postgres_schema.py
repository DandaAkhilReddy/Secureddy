"""Schema, migrations and the worker against a real PostgreSQL.

The production failure these reproduce: on PostgreSQL ``VARCHAR(n)`` is
enforced, so a long mailbox cursor crashed ``repo.update_cursor`` on every
worker cycle and the mailbox never left "Setting up". SQLite never noticed.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from reddysec.core.ids import new_id
from reddysec.models import RawMessage
from reddysec.store import repo
from reddysec.store.db import Database
from reddysec.store.migrations import ADVISORY_LOCK_KEY, pending_column_changes
from reddysec.store.models import (
    MAILBOX_UNIQUE_INDEX,
    AuditLog,
    Base,
    Contact,
    MailboxRow,
    MailboxSecret,
    MailboxTaskRow,
    MessageRow,
    SenderFeedbackRow,
)
from reddysec.testing.fakes import FakeMailbox
from tests.functional.worker.test_worker_flows import Harness, email_bytes

pytestmark = pytest.mark.postgres

# The column types production had before this fix.
OLD_TYPES = {
    ("mailboxes", "cursor"): "varchar(100)",
    ("messages", "provider_message_id"): "varchar(200)",
    ("messages", "thread_id"): "varchar(200)",
    ("messages", "rfc_message_id"): "varchar(500)",
    ("audit_log", "target"): "varchar(200)",
    ("user_identities", "subject"): "varchar(200)",
    ("users", "google_sub"): "varchar(64)",
}
EXPECTED_CHANGES = sorted(f"widened {t}.{c} from {old} to text" for (t, c), old in OLD_TYPES.items())


async def make_old_schema(db: Database) -> None:
    """The schema as the Azure database has it: built by the old models, so
    narrow columns, no unique mailbox index and no mailbox_tasks table."""
    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        for (table, column), old in OLD_TYPES.items():
            await conn.execute(text(f"ALTER TABLE {table} ALTER COLUMN {column} TYPE {old}"))
        await conn.execute(text(f"DROP INDEX {MAILBOX_UNIQUE_INDEX}"))
        await conn.execute(text("DROP TABLE mailbox_tasks"))


async def column_type(db: Database, table: str, column: str) -> str:
    async with db.engine.connect() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT data_type, character_maximum_length FROM information_schema.columns "
                    "WHERE table_name = :t AND column_name = :c"
                ),
                {"t": table, "c": column},
            )
        ).one()
    return row[0] if row[1] is None else f"{row[0]}({row[1]})"


async def add_user_and_mailbox(db: Database, *, address: str = "danda@yahoo.com", **kw) -> MailboxRow:
    async with db.session() as s:
        user = await repo.get_user_by_email(s, "owner@example.com") or await repo.create_user(
            s, email="owner@example.com", display_name="Owner"
        )
        row = MailboxRow(
            id=new_id("mbx"),
            user_id=user.id,
            provider=kw.pop("provider", "yahoo"),
            address=address,
            mode="scan",
            status=kw.pop("status", "active"),
            labels={},
            policy={},
            **kw,
        )
        s.add(row)
    return row


class TestMigrations:
    async def test_old_schema_reproduces_the_bug_and_migration_fixes_it(self, pg_db: Database):
        await make_old_schema(pg_db)
        mailbox = await add_user_and_mailbox(pg_db)
        long_cursor = "c" * 600
        with pytest.raises(DBAPIError, match="value too long for type character varying"):
            async with pg_db.session() as s:
                await repo.update_cursor(s, mailbox.id, long_cursor)

        changes = await pg_db.create_all()

        assert sorted(c for c in changes if c.startswith("widened")) == EXPECTED_CHANGES
        assert f"created unique index {MAILBOX_UNIQUE_INDEX}" in changes
        for table, column in OLD_TYPES:
            assert await column_type(pg_db, table, column) == "text"
        async with pg_db.session() as s:
            await repo.update_cursor(s, mailbox.id, long_cursor)
        async with pg_db.session() as s:
            assert (await repo.get_mailbox(s, mailbox.id)).cursor == long_cursor
            assert (await s.execute(select(MailboxTaskRow))).first() is None  # new table exists

    async def test_migration_is_idempotent(self, pg_db: Database):
        await make_old_schema(pg_db)
        assert len(await pg_db.create_all()) == len(OLD_TYPES) + 1
        assert await pg_db.create_all() == []
        async with pg_db.engine.connect() as conn:
            assert await conn.run_sync(pending_column_changes) == []

    async def test_fresh_database_needs_nothing(self, pg_db: Database):
        assert await pg_db.create_all() == []
        assert await column_type(pg_db, "mailboxes", "cursor") == "text"
        assert await column_type(pg_db, "mailboxes", "address") == "character varying(320)"

    async def test_concurrent_startups_migrate_once(self, pg_url: str):
        """Web app and worker starting together: the advisory lock makes one
        do the work and the other find nothing left."""
        setup = Database(pg_url)
        await make_old_schema(setup)
        await setup.dispose()
        dbs = [Database(pg_url) for _ in range(3)]
        try:
            results = await asyncio.gather(*(db.create_all() for db in dbs))
        finally:
            for db in dbs:
                await db.dispose()
        widened = sorted(c for r in results for c in r if c.startswith("widened"))
        assert widened == EXPECTED_CHANGES
        assert sum(1 for r in results if r) == 1

    async def test_lock_is_held_during_the_upgrade(self, pg_db: Database):
        """A second process blocks on the advisory lock while one migrates."""
        await pg_db.create_all()
        async with pg_db.engine.begin() as holder:
            await holder.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": ADVISORY_LOCK_KEY})
            other = Database(pg_db.url)
            try:
                waiting = asyncio.ensure_future(other.create_all())
                await asyncio.sleep(0.5)
                assert not waiting.done()
            finally:
                await holder.rollback()
        assert await asyncio.wait_for(waiting, 10) == []
        await other.dispose()


class TestDuplicateMailboxes:
    async def test_duplicates_are_merged_then_prevented(self, pg_db: Database):
        """The production state: one "Disconnected" row without a credential
        and one "Setting up" row with one, for the same Yahoo address."""
        await make_old_schema(pg_db)
        old = await add_user_and_mailbox(
            pg_db, address="Danda.Akhil@yahoo.com", status="disconnected",
            created_at=datetime.now(UTC) - timedelta(days=1),
        )
        new = await add_user_and_mailbox(pg_db, address="danda.akhil@yahoo.com", cursor="1:5")
        now = datetime.now(UTC)
        async with pg_db.session() as s:
            s.add(MailboxSecret(mailbox_id=new.id, kind="imap_password", ciphertext="x", key_id="k"))
            for mailbox, pid in ((old, "INBOX:1:1"), (old, "INBOX:1:2"), (new, "INBOX:1:2")):
                s.add(MessageRow(id=new_id("msg"), mailbox_id=mailbox.id, provider_message_id=pid, received_at=now))
            for mailbox in (old, new):
                s.add(Contact(id=new_id("ctc"), mailbox_id=mailbox.id, address="alice@example.com"))
                s.add(AuditLog(id=new_id("aud"), action="mailbox_connected", mailbox_id=mailbox.id))
            s.add(SenderFeedbackRow(id=new_id("sfb"), mailbox_id=old.id, scope="domain", value="bank.example",
                                    decision="trusted"))

        changes = await pg_db.create_all()

        assert any(f"merged duplicate mailbox {old.id} into {new.id}" in c for c in changes)
        async with pg_db.session() as s:
            mailboxes = list((await s.execute(select(MailboxRow))).scalars())
            messages = list((await s.execute(select(MessageRow))).scalars())
            contacts = list((await s.execute(select(Contact))).scalars())
            feedback = list((await s.execute(select(SenderFeedbackRow))).scalars())
            audit = list((await s.execute(select(AuditLog))).scalars())
            secrets = list((await s.execute(select(MailboxSecret))).scalars())
        assert [m.id for m in mailboxes] == [new.id] and mailboxes[0].cursor == "1:5"
        assert sorted(m.provider_message_id for m in messages) == ["INBOX:1:1", "INBOX:1:2"]
        assert {m.mailbox_id for m in messages} == {new.id}
        assert [c.mailbox_id for c in contacts] == [new.id]
        assert [f.mailbox_id for f in feedback] == [new.id]
        assert {a.mailbox_id for a in audit} == {new.id} and len(audit) == 2
        assert [x.mailbox_id for x in secrets] == [new.id]
        with pytest.raises(IntegrityError):
            await add_user_and_mailbox(pg_db, address="DANDA.AKHIL@yahoo.com")
        assert await pg_db.create_all() == []


class LongIdMailbox(FakeMailbox):
    """Ids and cursors the size real providers produce (Graph ids, delta links)."""

    async def poll(self, cursor):
        return [m for m in self.messages.values() if m.provider_message_id not in (cursor or "")], "d" * 500


class TestWorkerOnPostgres:
    async def test_cycle_with_long_cursor_and_ids_does_not_crash(self, pg_db: Database):
        await pg_db.create_all()
        from reddysec.config import Settings

        harness = Harness(pg_db, Settings(env="test", base_url="https://rs.example", secret_key="pg"))
        _user, mailbox, _ = await harness.add_client(address="someone@outlook.com", provider="microsoft")
        fake = LongIdMailbox(mailbox.id)
        harness.connectors[mailbox.id] = fake
        long_id = "AAMkAD" + "x" * 294
        fake.messages[long_id] = RawMessage(
            provider_message_id=long_id,
            mailbox_id=mailbox.id,
            received_at=datetime.now(UTC),
            raw=email_bytes("Lunch", message_id="<" + "m" * 700 + "@example.com>"),
            thread_id="AAQkAD" + "t" * 294,
        )

        stats = await harness.worker().run_cycle()

        assert stats.mailbox_errors == [] and stats.messages == 1
        row = await harness.mailbox_row(mailbox.id)
        assert row.status == "active" and row.last_error is None and row.cursor == "d" * 500
        messages = await harness.messages(mailbox.id)
        assert list(messages) == [long_id]
        assert len(messages[long_id].thread_id) == 300 and len(messages[long_id].rfc_message_id) > 700
        # A crashed message is audited with its provider id as the target.
        async with pg_db.session() as s:
            await repo.audit(s, None, "system", "message_failed", mailbox.id, long_id, {})
        assert long_id in [a.target for a in await _audit(pg_db, mailbox.id)]

    async def test_backfill_on_postgres(self, pg_db: Database):
        await pg_db.create_all()
        from reddysec.config import Settings

        harness = Harness(pg_db, Settings(env="test", base_url="https://rs.example", secret_key="pg"))
        _user, mailbox, fake = await harness.add_client()
        worker = harness.worker()
        await worker.run_cycle()  # set up; nothing in the mailbox yet
        for i in range(3):
            fake.deliver(email_bytes(f"Old {i}"), f"old{i}", received_at=datetime.now(UTC) - timedelta(days=3))
        async with pg_db.session() as s:
            await repo.update_cursor(s, mailbox.id, str(len(fake.messages)))  # poll will not see them
            await repo.request_backfill(s, mailbox.id, since=datetime.now(UTC) - timedelta(days=7), limit=200)
        stats = await worker.run_cycle()
        assert stats.backfilled == 3 and sorted(await harness.messages(mailbox.id)) == ["old0", "old1", "old2"]
        async with pg_db.session() as s:
            assert await repo.open_backfill(s, mailbox.id) is None


async def _audit(db: Database, mailbox_id: str) -> list[AuditLog]:
    async with db.session() as s:
        return await repo.list_audit(s, mailbox_id)

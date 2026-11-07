"""Small, idempotent schema upgrades for databases built with ``create_all``.

``create_all`` creates missing tables but never changes an existing one, so a
column the models widened (``String(100)`` -> ``Text``) or an index added to an
existing table would never reach the Azure database. ``upgrade`` closes that
gap. It runs inside ``Database.create_all`` (web app in dev, the worker at
startup, ``reddysec init-db`` / ``reddysec migrate``), every time, and does
only what is still missing:

1. Widen columns (PostgreSQL only; SQLite ignores lengths). Every column of
   every model table is compared with ``information_schema.columns``: a model
   ``Text`` column stored as ``character varying`` becomes ``text``; a
   ``String(n)`` stored narrower than ``n`` becomes ``varchar(n)``. Both are
   binary-compatible changes in PostgreSQL: no table rewrite, no index rebuild.
2. Merge duplicate mailboxes (one person, one address): keep the best row,
   move its twin's messages, contacts, sender choices, stats, tasks and audit
   rows onto it, then delete the twin and its credential.
3. Create the unique index that stops duplicates coming back.
4. Forget stored text-only emails (``purge_text_only_messages``). Secureddy
   only checks email with something to click or open
   (``analysis.actionable``); rows stored before that rule, with no link, no
   file and no money-scam (BEC) finding, are deleted with their
   notifications. Quarantined rows and rows waiting on the worker or the
   client are kept, so nothing can be trapped. Idempotent: a second run finds
   nothing. ``reddysec purge-text-only`` runs the same step by hand.
5. First admin (``promote_bootstrap_admin``): while no active account is an
   admin, the account whose email equals ``Settings.bootstrap_admin_email``
   becomes one. Nobody else is ever promoted automatically.

Concurrency: the web app and the worker may start together. On PostgreSQL the
whole upgrade (with ``create_all``) runs in one transaction that first takes
``pg_advisory_xact_lock``, so a second process waits, then finds nothing left
to do. PostgreSQL DDL is transactional, so a failure changes nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, String, Text, delete, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncEngine

from reddysec.core.logging import get_logger

from .models import (
    MAILBOX_UNIQUE_INDEX,
    AuditLog,
    Base,
    Contact,
    DetonationRow,
    FeedbackReasonRow,
    HoldHeartbeat,
    MailboxDailyCounterRow,
    MailboxRow,
    MailboxSecret,
    MailboxTaskRow,
    MessageRow,
    NotificationRow,
    ReadingRoomRow,
    SenderFeedbackRow,
    SenderTrustStatsRow,
    UserRow,
)

log = get_logger(__name__)

# Any constant shared by every Secureddy process; "SECUREDDY" in hex-ish.
ADVISORY_LOCK_KEY = 0x5EC0_DD1E_0001


@dataclass(frozen=True)
class ColumnChange:
    table: str
    column: str
    old: str
    new: str

    def __str__(self) -> str:
        return f"widened {self.table}.{self.column} from {self.old} to {self.new}"


async def migrate(
    engine: AsyncEngine, *, create_tables: bool = True, bootstrap_admin_email: str | None = None
) -> list[str]:
    """Create missing tables (optional) and apply every pending upgrade, under
    the advisory lock on PostgreSQL. Returns a line per change made.
    ``bootstrap_admin_email`` defaults to ``Settings.bootstrap_admin_email``."""
    if bootstrap_admin_email is None:
        from reddysec.config import get_settings  # lazy: tests build settings per case

        bootstrap_admin_email = get_settings().bootstrap_admin_email
    async with engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            await conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": ADVISORY_LOCK_KEY})
        if create_tables:
            await conn.run_sync(Base.metadata.create_all)
        return await conn.run_sync(lambda c: upgrade(c, bootstrap_admin_email=bootstrap_admin_email or ""))


def upgrade(conn: Connection, *, bootstrap_admin_email: str = "") -> list[str]:
    """Run every step on an open connection (inside the caller's transaction)."""
    changes: list[str] = []
    if conn.dialect.name == "postgresql":
        changes += [str(c) for c in widen_columns(conn)]
    changes += merge_duplicate_mailboxes(conn)
    if ensure_mailbox_unique_index(conn):
        changes.append(f"created unique index {MAILBOX_UNIQUE_INDEX}")
    purged = purge_text_only_messages(conn)
    if purged:
        changes.append(f"removed {purged} stored text-only email{'s' if purged != 1 else ''} (nothing to click or open)")
    changes += promote_bootstrap_admin(conn, bootstrap_admin_email)
    for change in changes:
        log.info("db.migrated", change=change)
    if not changes:
        log.debug("db.schema_up_to_date")
    return changes


# --------------------------------------------------------------- columns
def _wanted(column: Any) -> tuple[str, int | None] | None:
    """(postgres data_type, length) the model asks for, or None if we do not
    manage this column's type."""
    if isinstance(column.type, Text):
        return "text", None
    if isinstance(column.type, String) and column.type.length:
        return "character varying", int(column.type.length)
    return None


def pending_column_changes(conn: Connection) -> list[ColumnChange]:
    """Columns whose database type is narrower than the model's (PostgreSQL)."""
    rows = conn.execute(
        text(
            "SELECT table_name, column_name, data_type, character_maximum_length "
            "FROM information_schema.columns WHERE table_schema = current_schema()"
        )
    ).all()
    actual = {(r[0], r[1]): (r[2], r[3]) for r in rows}
    out: list[ColumnChange] = []
    for table in Base.metadata.sorted_tables:
        for column in table.columns:
            wanted = _wanted(column)
            current = actual.get((table.name, column.name))
            if wanted is None or current is None:
                continue
            data_type, length = current
            if data_type != "character varying":
                continue  # already text (or a type we do not touch)
            old = f"varchar({length})" if length else "varchar"
            if wanted[0] == "text":
                out.append(ColumnChange(table.name, column.name, old, "text"))
            elif length is not None and wanted[1] is not None and length < wanted[1]:
                out.append(ColumnChange(table.name, column.name, old, f"varchar({wanted[1]})"))
    return out


def widen_columns(conn: Connection) -> list[ColumnChange]:
    changes = pending_column_changes(conn)
    prep = conn.dialect.identifier_preparer
    for change in changes:
        conn.execute(
            text(
                f"ALTER TABLE {prep.quote(change.table)} ALTER COLUMN {prep.quote(change.column)} "
                f"TYPE {change.new}"
            )
        )
    return changes


# ------------------------------------------------------------ duplicates
def _keep_order(row: Any) -> tuple[bool, bool, bool, Any]:
    """Best first: a usable credential, then active, then newest."""
    live = row.status != "disconnected"
    return (bool(row.has_secret) and live, row.status == "active", live, row.created_at)


def merge_duplicate_mailboxes(conn: Connection) -> list[str]:
    """Collapse rows that share (user, lower(address)) into one. Returns a line
    per merged row."""
    m = MailboxRow.__table__
    dupes = conn.execute(
        select(m.c.user_id, func.lower(m.c.address).label("addr"))
        .group_by(m.c.user_id, func.lower(m.c.address))
        .having(func.count() > 1)
    ).all()
    changes: list[str] = []
    secrets = MailboxSecret.__table__
    for user_id, addr in dupes:
        rows = conn.execute(
            select(
                m.c.id,
                m.c.status,
                m.c.created_at,
                select(func.count())
                .select_from(secrets)
                .where(secrets.c.mailbox_id == m.c.id)
                .scalar_subquery()
                .label("has_secret"),
            ).where(m.c.user_id == user_id, func.lower(m.c.address) == addr)
        ).all()
        ordered = sorted(rows, key=_keep_order, reverse=True)
        keep = ordered[0].id
        for stale in ordered[1:]:
            moved = _merge_mailbox(conn, keep=keep, stale=stale.id)
            changes.append(f"merged duplicate mailbox {stale.id} into {keep} ({addr}; {moved} messages moved)")
    return changes


def _merge_mailbox(conn: Connection, *, keep: str, stale: str) -> int:
    msgs = MessageRow.__table__
    kept = msgs.alias("kept")
    # Messages both rows know: the kept copy wins; references follow it.
    clashes = conn.execute(
        select(msgs.c.id, kept.c.id).join(
            kept,
            (kept.c.mailbox_id == keep) & (kept.c.provider_message_id == msgs.c.provider_message_id),
        ).where(msgs.c.mailbox_id == stale)
    ).all()
    for stale_msg, kept_msg in clashes:
        for table, column in (
            (DetonationRow.__table__, "message_id"),
            (FeedbackReasonRow.__table__, "message_id"),
            (NotificationRow.__table__, "message_id"),
            (ReadingRoomRow.__table__, "message_id"),
            (SenderFeedbackRow.__table__, "source_message_id"),
        ):
            conn.execute(update(table).where(table.c[column] == stale_msg).values({column: kept_msg}))
        conn.execute(delete(msgs).where(msgs.c.id == stale_msg))
    moved = conn.execute(update(msgs).where(msgs.c.mailbox_id == stale).values(mailbox_id=keep)).rowcount or 0

    # Per-mailbox unique rows: the kept mailbox's entry wins a clash.
    for table, keys in (
        (Contact.__table__, ("address",)),
        (SenderFeedbackRow.__table__, ("scope", "value")),
        (SenderTrustStatsRow.__table__, ("scope", "value")),
    ):
        mine = table.alias("mine")
        clash = (
            select(mine.c.id)
            .where(mine.c.mailbox_id == keep, *[mine.c[k] == table.c[k] for k in keys])
            .exists()
        )
        conn.execute(delete(table).where(table.c.mailbox_id == stale, clash))
        conn.execute(update(table).where(table.c.mailbox_id == stale).values(mailbox_id=keep))

    for table in (AuditLog.__table__, MailboxTaskRow.__table__):
        conn.execute(update(table).where(table.c.mailbox_id == stale).values(mailbox_id=keep))
    hb = HoldHeartbeat.__table__
    conn.execute(delete(hb).where(hb.c.mailbox_id == stale))
    # Operations-only counters: the twin's are simply dropped.
    counters = MailboxDailyCounterRow.__table__
    conn.execute(delete(counters).where(counters.c.mailbox_id == stale))
    # A credential is encrypted to its mailbox id, so it cannot move; the kept
    # row was chosen for having one whenever any row did.
    conn.execute(delete(MailboxSecret.__table__).where(MailboxSecret.__table__.c.mailbox_id == stale))
    conn.execute(delete(MailboxRow.__table__).where(MailboxRow.__table__.c.id == stale))
    return int(moved) + len(clashes)


# ----------------------------------------------------------------- index
def _index_exists(conn: Connection, name: str) -> bool:
    if conn.dialect.name == "postgresql":
        sql = "SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND indexname = :name"
    else:
        sql = "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = :name"
    return conn.execute(text(sql), {"name": name}).first() is not None


def ensure_mailbox_unique_index(conn: Connection) -> bool:
    """True when the index was created now."""
    if _index_exists(conn, MAILBOX_UNIQUE_INDEX):
        return False
    conn.execute(
        text(f"CREATE UNIQUE INDEX IF NOT EXISTS {MAILBOX_UNIQUE_INDEX} ON mailboxes (user_id, lower(address))")
    )
    return True


# ------------------------------------------------------- text-only email
# Analysed states a text-only row may be forgotten in. Rows waiting on the
# worker (pending, analyzing, held_for_review) or on a client request, and
# failed rows, stay: deleting them could hide a held or quarantined email.
PURGEABLE_STATES = ("done", "reviewed", "released_by_deadman")


def text_only_message_ids(conn: Connection) -> list[str]:
    """Stored emails with no link, no file and no BEC finding (see step 4)."""
    from reddysec.analysis.actionable import stored_verdict_is_text_only  # lazy: analysis is heavy

    m = MessageRow.__table__
    rows = conn.execute(
        select(m.c.id, m.c.verdict).where(
            m.c.url_count == 0,
            m.c.attachment_count == 0,
            m.c.quarantined.is_(False),
            m.c.state.in_(PURGEABLE_STATES),
            m.c.verdict.is_not(None),
        )
    ).all()
    return [row.id for row in rows if stored_verdict_is_text_only(row.verdict)]


def purge_text_only_messages(conn: Connection, *, dry_run: bool = False) -> int:
    """Delete stored text-only emails and what hangs off them: notifications,
    feedback reasons, detonation records and their "verdict" audit entries
    (the emails are not counted anywhere any more). Our mailbox label on them
    is left alone. Returns how many emails were (or, dry run, would be) removed."""
    ids = text_only_message_ids(conn)
    if dry_run or not ids:
        return len(ids)
    for start in range(0, len(ids), 500):
        chunk = ids[start: start + 500]
        conn.execute(delete(NotificationRow.__table__).where(NotificationRow.__table__.c.message_id.in_(chunk)))
        conn.execute(delete(FeedbackReasonRow.__table__).where(FeedbackReasonRow.__table__.c.message_id.in_(chunk)))
        conn.execute(delete(DetonationRow.__table__).where(DetonationRow.__table__.c.message_id.in_(chunk)))
        audit = AuditLog.__table__
        conn.execute(delete(audit).where(audit.c.action == "verdict", audit.c.target.in_(chunk)))
        conn.execute(delete(MessageRow.__table__).where(MessageRow.__table__.c.id.in_(chunk)))
    log.info("db.purged_text_only", count=len(ids))
    return len(ids)


# ------------------------------------------------------------ first admin
def promote_bootstrap_admin(conn: Connection, email: str) -> list[str]:
    """While no active account is an admin, make the account with the
    bootstrap email one. Existing production accounts keep working: they are
    never disabled or demoted here."""
    email = (email or "").strip().lower()
    if not email:
        return []
    users = UserRow.__table__
    admins = conn.execute(
        select(func.count()).select_from(users).where(users.c.role == "admin", users.c.disabled.is_(False))
    ).scalar_one()
    if admins:
        return []
    result = conn.execute(
        update(users).where(users.c.login_email == email, users.c.disabled.is_(False)).values(role="admin")
    )
    if not result.rowcount:
        return []
    return [f"made {email} an admin (bootstrap admin email)"]


__all__ = [
    "ADVISORY_LOCK_KEY",
    "PURGEABLE_STATES",
    "promote_bootstrap_admin",
    "purge_text_only_messages",
    "text_only_message_ids",
    "ColumnChange",
    "ensure_mailbox_unique_index",
    "merge_duplicate_mailboxes",
    "migrate",
    "pending_column_changes",
    "upgrade",
    "widen_columns",
]

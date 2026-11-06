"""Repository functions: every database access the worker, web app and CLI need.

All functions take an ``AsyncSession`` and never commit; the caller owns the
transaction (``Database.session()`` commits on success). They flush so that
ids and defaults are available immediately.

Timestamps: SQLite drops timezone information, PostgreSQL keeps it. Everything
written here is UTC and everything read back is normalised to aware UTC via
``aware`` so comparisons never mix naive and aware datetimes.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from reddysec.core.ids import new_id
from reddysec.models import DetonationResult, ParsedMessage, RawMessage, SenderHistory, Verdict
from reddysec.store.models import (
    AuditLog,
    Contact,
    DetonationRow,
    HoldHeartbeat,
    MailboxRow,
    MailboxSecret,
    MessageRow,
    NotificationRow,
    UserRow,
    utcnow,
)

# Message lifecycle states. "pending"/"analyzing" are re-processed if a worker
# dies mid-flight; the rest are terminal for the worker.
STATE_PENDING = "pending"
STATE_ANALYZING = "analyzing"
STATE_DONE = "done"
STATE_FAILED = "failed"
STATE_HELD_FOR_REVIEW = "held_for_review"
STATE_RESTORE_REQUESTED = "restore_requested"
STATE_RESTORE_FAILED = "restore_failed"
STATE_RELEASED_BY_DEADMAN = "released_by_deadman"
REPROCESSABLE_STATES = frozenset({STATE_PENDING, STATE_ANALYZING})

MAX_DISPLAY_NAMES = 5


def aware(value: datetime | None) -> datetime | None:
    """Normalise a datetime read from the database to aware UTC."""
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


# ------------------------------------------------------------------- users
async def get_user(session: AsyncSession, user_id: str) -> UserRow | None:
    return await session.get(UserRow, user_id)


async def get_user_by_google_sub(session: AsyncSession, google_sub: str) -> UserRow | None:
    return (
        await session.execute(select(UserRow).where(UserRow.google_sub == google_sub))
    ).scalar_one_or_none()


async def get_user_by_email(session: AsyncSession, email: str) -> UserRow | None:
    return (
        await session.execute(select(UserRow).where(UserRow.login_email == email.strip().lower()))
    ).scalar_one_or_none()


async def create_user(
    session: AsyncSession,
    *,
    email: str,
    display_name: str,
    role: str = "principal",
    google_sub: str | None = None,
    principal_id: str | None = None,
    password_hash: str | None = None,
) -> UserRow:
    row = UserRow(
        id=new_id("usr"),
        display_name=display_name.strip(),
        login_email=email.strip().lower(),
        role=role,
        google_sub=google_sub,
        principal_id=principal_id,
        password_hash=password_hash,
    )
    session.add(row)
    await session.flush()
    return row


async def list_users(session: AsyncSession, *, roles: Iterable[str] | None = None) -> list[UserRow]:
    stmt = select(UserRow).where(UserRow.disabled.is_(False)).order_by(UserRow.created_at)
    if roles is not None:
        stmt = stmt.where(UserRow.role.in_(list(roles)))
    return list((await session.execute(stmt)).scalars())


# --------------------------------------------------------------- mailboxes
async def create_mailbox(
    session: AsyncSession,
    *,
    user_id: str,
    provider: str,
    address: str,
    mode: str = "scan",
    policy: dict[str, Any] | None = None,
) -> MailboxRow:
    """``labels`` starts empty on purpose: the worker performs ``connector.setup``
    on its first cycle and persists the label map. Onboarding therefore never
    needs mailbox write access from the web process."""
    row = MailboxRow(
        id=new_id("mbx"),
        user_id=user_id,
        provider=provider,
        address=address.strip().lower(),
        mode=mode,
        status="active",
        labels={},
        policy=dict(policy or {}),
    )
    session.add(row)
    await session.flush()
    return row


async def get_mailbox(session: AsyncSession, mailbox_id: str) -> MailboxRow | None:
    return (
        await session.execute(
            select(MailboxRow).where(MailboxRow.id == mailbox_id).options(selectinload(MailboxRow.secret))
        )
    ).scalar_one_or_none()


async def list_active_mailboxes(session: AsyncSession) -> list[MailboxRow]:
    stmt = (
        select(MailboxRow)
        .where(MailboxRow.status == "active")
        .options(selectinload(MailboxRow.secret))
        .order_by(MailboxRow.created_at)
    )
    return list((await session.execute(stmt)).scalars())


async def list_mailboxes(session: AsyncSession, *, user_id: str | None = None) -> list[MailboxRow]:
    stmt = select(MailboxRow).options(selectinload(MailboxRow.secret)).order_by(MailboxRow.created_at)
    if user_id is not None:
        stmt = stmt.where(MailboxRow.user_id == user_id)
    return list((await session.execute(stmt)).scalars())


async def update_cursor(session: AsyncSession, mailbox_id: str, cursor: str | None) -> None:
    await session.execute(
        update(MailboxRow).where(MailboxRow.id == mailbox_id).values(cursor=cursor, last_sync_at=utcnow())
    )


async def set_mailbox_status(
    session: AsyncSession, mailbox_id: str, status: str, error: str | None = None
) -> None:
    await session.execute(
        update(MailboxRow).where(MailboxRow.id == mailbox_id).values(status=status, last_error=error)
    )


async def set_mailbox_labels(session: AsyncSession, mailbox_id: str, labels: dict[str, str]) -> None:
    await session.execute(update(MailboxRow).where(MailboxRow.id == mailbox_id).values(labels=dict(labels)))


async def set_mode(session: AsyncSession, mailbox_id: str, mode: str) -> None:
    await session.execute(update(MailboxRow).where(MailboxRow.id == mailbox_id).values(mode=mode))


async def set_policy(session: AsyncSession, mailbox_id: str, policy: dict[str, Any]) -> None:
    await session.execute(update(MailboxRow).where(MailboxRow.id == mailbox_id).values(policy=dict(policy)))


async def get_secret_row(session: AsyncSession, mailbox_id: str) -> MailboxSecret | None:
    return await session.get(MailboxSecret, mailbox_id)


# ---------------------------------------------------------------- messages
async def get_message(session: AsyncSession, message_id: str) -> MessageRow | None:
    return await session.get(MessageRow, message_id)


async def get_message_by_provider_id(
    session: AsyncSession, mailbox_id: str, provider_message_id: str
) -> MessageRow | None:
    stmt = select(MessageRow).where(
        MessageRow.mailbox_id == mailbox_id, MessageRow.provider_message_id == provider_message_id
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def upsert_message(
    session: AsyncSession, parsed: ParsedMessage, raw: RawMessage, state: str = STATE_PENDING
) -> MessageRow:
    """Insert or refresh the metadata row for (mailbox, provider message id).
    Only metadata is stored; the body never reaches the database."""
    row = await get_message_by_provider_id(session, parsed.mailbox_id, parsed.provider_message_id)
    if row is None:
        row = MessageRow(
            id=new_id("msg"), mailbox_id=parsed.mailbox_id, provider_message_id=parsed.provider_message_id
        )
        session.add(row)
    row.thread_id = raw.thread_id
    row.rfc_message_id = parsed.rfc_message_id[:500] if parsed.rfc_message_id else None
    row.from_address = parsed.from_address[:320]
    row.from_name = parsed.from_name[:300] if parsed.from_name else None
    row.subject = parsed.subject[:1000]
    row.received_at = raw.received_at
    row.url_count = len(parsed.urls)
    row.attachment_count = len(parsed.real_attachments)
    row.state = state
    await session.flush()
    return row


async def set_message_state(session: AsyncSession, message_row: MessageRow, state: str) -> MessageRow:
    message_row.state = state
    await session.flush()
    return message_row


async def record_verdict(
    session: AsyncSession,
    message_row: MessageRow,
    verdict: Verdict,
    quarantined: bool,
    *,
    state: str = STATE_DONE,
) -> MessageRow:
    message_row.lane = verdict.lane.value
    message_row.level = verdict.level.value
    message_row.score = verdict.score
    message_row.verdict = verdict.model_dump(mode="json")
    message_row.quarantined = quarantined
    message_row.analyzed_at = verdict.analyzed_at or utcnow()
    message_row.state = state
    await session.flush()
    return message_row


async def list_recent_messages(
    session: AsyncSession, mailbox_ids: Sequence[str], limit: int = 50, level: str | None = None
) -> list[MessageRow]:
    if not mailbox_ids:
        return []
    stmt = (
        select(MessageRow)
        .where(MessageRow.mailbox_id.in_(list(mailbox_ids)))
        .order_by(MessageRow.received_at.desc(), MessageRow.created_at.desc())
        .limit(limit)
    )
    if level is not None:
        stmt = stmt.where(MessageRow.level == level)
    return list((await session.execute(stmt)).scalars())


async def request_restore(session: AsyncSession, message_id: str) -> MessageRow | None:
    """The web app flags a quarantined message; the worker, which owns mailbox
    access, performs the move on its next cycle."""
    row = await session.get(MessageRow, message_id)
    if row is None:
        return None
    row.state = STATE_RESTORE_REQUESTED
    await session.flush()
    return row


async def list_restore_requests(session: AsyncSession, mailbox_id: str | None = None) -> list[MessageRow]:
    stmt = (
        select(MessageRow).where(MessageRow.state == STATE_RESTORE_REQUESTED).order_by(MessageRow.created_at)
    )
    if mailbox_id is not None:
        stmt = stmt.where(MessageRow.mailbox_id == mailbox_id)
    return list((await session.execute(stmt)).scalars())


async def mark_restored(session: AsyncSession, message_row: MessageRow) -> MessageRow:
    message_row.state = STATE_DONE
    message_row.quarantined = False
    message_row.restored_by_client = True
    await session.flush()
    return message_row


async def mark_failed(session: AsyncSession, message_row: MessageRow, error: str | None = None) -> MessageRow:
    """Terminal failure. The error text goes to the audit log by the caller;
    the row itself only records the state so no stack traces reach the UI."""
    message_row.state = STATE_FAILED
    if error and message_row.verdict is None:
        message_row.verdict = {"error": error[:500]}
    await session.flush()
    return message_row


async def mark_released_by_deadman(session: AsyncSession, mailbox_id: str) -> int:
    """Every message still waiting for a verdict was just put back in the inbox."""
    result = await session.execute(
        update(MessageRow)
        .where(
            MessageRow.mailbox_id == mailbox_id,
            MessageRow.state.in_([STATE_PENDING, STATE_ANALYZING, STATE_HELD_FOR_REVIEW]),
        )
        .values(state=STATE_RELEASED_BY_DEADMAN)
    )
    return int(result.rowcount or 0)


# ---------------------------------------------------------------- contacts
async def touch_contact(
    session: AsyncSession,
    mailbox_id: str,
    address: str,
    display_name: str | None = None,
    *,
    replied_to: bool = False,
    seen_at: datetime | None = None,
) -> Contact:
    address = address.strip().lower()
    seen_at = seen_at or utcnow()
    stmt = select(Contact).where(Contact.mailbox_id == mailbox_id, Contact.address == address)
    row = (await session.execute(stmt)).scalar_one_or_none()
    if row is None:
        row = Contact(
            id=new_id("ctc"),
            mailbox_id=mailbox_id,
            address=address,
            display_names=[],
            message_count=0,
            first_seen=seen_at,
            last_seen=seen_at,
        )
        session.add(row)
    row.message_count += 1
    row.last_seen = max(aware(row.last_seen) or seen_at, seen_at)
    row.replied_to = bool(row.replied_to or replied_to)
    name = (display_name or "").strip()
    if name and name not in (row.display_names or []):
        # Reassign (not mutate) so SQLAlchemy sees the JSON change.
        row.display_names = ([*(row.display_names or []), name])[-MAX_DISPLAY_NAMES:]
    await session.flush()
    return row


async def sender_history(session: AsyncSession, mailbox_id: str, address: str) -> SenderHistory | None:
    stmt = select(Contact).where(Contact.mailbox_id == mailbox_id, Contact.address == address.strip().lower())
    row = (await session.execute(stmt)).scalar_one_or_none()
    if row is None:
        return None
    return SenderHistory(
        address=row.address,
        display_names=list(row.display_names or []),
        message_count=row.message_count,
        first_seen=aware(row.first_seen),
        last_seen=aware(row.last_seen),
        replied_to=row.replied_to,
    )


# ------------------------------------------------------------- detonations
async def save_detonation(
    session: AsyncSession, message_id: str | None, kind: str, target: str, result: DetonationResult
) -> DetonationRow:
    row = await session.get(DetonationRow, result.job_id)
    if row is None:
        row = DetonationRow(job_id=result.job_id, kind=kind, target=target, status=result.status.value)
        session.add(row)
    row.message_id = message_id or row.message_id
    row.kind = kind
    row.target = target
    row.status = result.status.value
    row.result = result.model_dump(mode="json")
    row.sandbox_backend = result.sandbox_backend
    row.duration_ms = result.duration_ms
    await session.flush()
    return row


async def record_detonation_ref(
    session: AsyncSession, message_id: str, job_id: str, kind: str, target: str, *, status: str = "unknown"
) -> DetonationRow:
    """Link a detonation job id found in a Verdict to its message. If the
    pipeline already saved the full result, only the missing link is filled."""
    row = await session.get(DetonationRow, job_id)
    if row is None:
        row = DetonationRow(job_id=job_id, message_id=message_id, kind=kind, target=target, status=status)
        session.add(row)
    elif row.message_id is None:
        row.message_id = message_id
    await session.flush()
    return row


async def list_detonations(session: AsyncSession, message_id: str) -> list[DetonationRow]:
    stmt = (
        select(DetonationRow).where(DetonationRow.message_id == message_id).order_by(DetonationRow.created_at)
    )
    return list((await session.execute(stmt)).scalars())


# ----------------------------------------------------------- notifications
async def create_notification(
    session: AsyncSession,
    *,
    user_id: str,
    channel: str,
    level: str,
    title: str,
    body: str,
    message_id: str | None = None,
) -> NotificationRow:
    row = NotificationRow(
        id=new_id("ntf"),
        user_id=user_id,
        message_id=message_id,
        channel=channel,
        level=level,
        title=title[:300],
        body=body,
    )
    session.add(row)
    await session.flush()
    return row


async def mark_notification_sent(
    session: AsyncSession, notification_id: str, error: str | None = None
) -> None:
    await session.execute(
        update(NotificationRow)
        .where(NotificationRow.id == notification_id)
        .values(sent_at=None if error else utcnow(), error=error)
    )


async def list_unsent(
    session: AsyncSession, channel: str | None = None, limit: int = 100
) -> list[NotificationRow]:
    stmt = (
        select(NotificationRow)
        .where(NotificationRow.sent_at.is_(None), NotificationRow.error.is_(None))
        .order_by(NotificationRow.created_at)
        .limit(limit)
    )
    if channel is not None:
        stmt = stmt.where(NotificationRow.channel == channel)
    return list((await session.execute(stmt)).scalars())


async def list_notifications(session: AsyncSession, user_id: str, limit: int = 50) -> list[NotificationRow]:
    stmt = (
        select(NotificationRow)
        .where(NotificationRow.user_id == user_id)
        .order_by(NotificationRow.created_at.desc())
        .limit(limit)
    )
    return list((await session.execute(stmt)).scalars())


# -------------------------------------------------------------------- audit
async def audit(
    session: AsyncSession,
    actor_id: str | None,
    actor_role: str,
    action: str,
    mailbox_id: str | None = None,
    target: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    row = AuditLog(
        id=new_id("aud"),
        actor_id=actor_id,
        actor_role=actor_role,
        action=action,
        mailbox_id=mailbox_id,
        target=target,
        details=dict(details or {}),
    )
    session.add(row)
    await session.flush()
    return row


async def list_audit(
    session: AsyncSession, mailbox_id: str | None = None, limit: int = 100
) -> list[AuditLog]:
    stmt = select(AuditLog).order_by(AuditLog.at.desc()).limit(limit)
    if mailbox_id is not None:
        stmt = stmt.where(AuditLog.mailbox_id == mailbox_id)
    return list((await session.execute(stmt)).scalars())


# ---------------------------------------------------------------- heartbeat
async def beat(session: AsyncSession, mailbox_id: str, at: datetime | None = None) -> HoldHeartbeat:
    at = at or utcnow()
    row = await session.get(HoldHeartbeat, mailbox_id)
    if row is None:
        row = HoldHeartbeat(mailbox_id=mailbox_id, beat_at=at)
        session.add(row)
    else:
        row.beat_at = at
        row.released_by_deadman_at = None  # a live worker clears the alarm
    await session.flush()
    return row


async def get_heartbeat(session: AsyncSession, mailbox_id: str) -> HoldHeartbeat | None:
    return await session.get(HoldHeartbeat, mailbox_id)


async def stale_hold_mailboxes(
    session: AsyncSession, older_than: timedelta, now: datetime | None = None
) -> list[MailboxRow]:
    """Active HOLD mailboxes whose worker heartbeat is older than ``older_than``.

    A mailbox that was set up (labels persisted, so a hold rule may exist) but
    never heart-beaten counts as stale once it is old enough: that is exactly
    the "worker died between setup and first beat" case that would otherwise
    trap mail forever.
    """
    cutoff = (now or utcnow()) - older_than
    stmt = (
        select(MailboxRow, HoldHeartbeat.beat_at)
        .outerjoin(HoldHeartbeat, HoldHeartbeat.mailbox_id == MailboxRow.id)
        .where(MailboxRow.mode == "hold", MailboxRow.status == "active")
        .options(selectinload(MailboxRow.secret))
        .order_by(MailboxRow.created_at)
    )
    # The set of HOLD mailboxes is small (private clients), so the age check is
    # done in Python: it keeps the JSON "labels is empty" test portable across
    # SQLite and PostgreSQL and avoids naive/aware datetime surprises in SQL.
    stale: list[MailboxRow] = []
    for mailbox, beat_at in (await session.execute(stmt)).all():
        if beat_at is not None:
            if aware(beat_at) < cutoff:
                stale.append(mailbox)
        elif mailbox.labels and (aware(mailbox.created_at) or cutoff) < cutoff:
            stale.append(mailbox)
    return stale


async def mark_deadman_release(
    session: AsyncSession, mailbox_id: str, at: datetime | None = None
) -> HoldHeartbeat:
    at = at or utcnow()
    row = await session.get(HoldHeartbeat, mailbox_id)
    if row is None:
        row = HoldHeartbeat(mailbox_id=mailbox_id, beat_at=at)
        session.add(row)
    row.released_by_deadman_at = at
    await session.flush()
    return row


async def count_messages(session: AsyncSession, mailbox_id: str, state: str | None = None) -> int:
    stmt = select(func.count()).select_from(MessageRow).where(MessageRow.mailbox_id == mailbox_id)
    if state is not None:
        stmt = stmt.where(MessageRow.state == state)
    return int((await session.execute(stmt)).scalar_one())

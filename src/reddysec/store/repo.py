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
from reddysec.models import (
    ClientFeedback,
    DetonationResult,
    ParsedMessage,
    RawMessage,
    SenderHistory,
    TrustCheck,
    Verdict,
)
from reddysec.models.reasons import reason_words
from reddysec.store.models import (
    AuditLog,
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
    SenderFeedbackRow,
    SenderTrustStatsRow,
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
# Client requests the web app records and the worker (which owns mailbox
# access) carries out on its next cycle.
STATE_QUARANTINE_REQUESTED = "quarantine_requested"  # "This is fake"
STATE_RELABEL_SAFE_REQUESTED = "relabel_safe_requested"  # "This is safe" on a message in the inbox
STATE_RESCORE_REQUESTED = "rescore_requested"  # "Check again"
CLIENT_REQUEST_STATES = frozenset(
    {STATE_RESTORE_REQUESTED, STATE_QUARANTINE_REQUESTED, STATE_RELABEL_SAFE_REQUESTED, STATE_RESCORE_REQUESTED}
)
REPROCESSABLE_STATES = frozenset({STATE_PENDING, STATE_ANALYZING})

MAX_DISPLAY_NAMES = 5

# Mailbox tasks (``mailbox_tasks``): "check my recent mail".
TASK_BACKFILL = "backfill"
TASK_BACKFILL_REQUESTED = "backfill_requested"
TASK_BACKFILL_RUNNING = "backfill_running"
TASK_DONE = "done"
TASK_FAILED = "failed"
OPEN_TASK_STATES = (TASK_BACKFILL_REQUESTED, TASK_BACKFILL_RUNNING)


def address_key(address: str) -> str:
    """How a mailbox address is compared: trimmed and lower case."""
    return address.strip().lower()


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
    """Create the mailbox, or take over the person's existing row for the same
    address (one mailbox per person and address; see ``models``).

    ``labels`` starts empty on purpose: the worker performs ``connector.setup``
    on its first cycle and persists the label map. Onboarding therefore never
    needs mailbox write access from the web process. Taking over an existing
    row also empties ``labels`` (and the cursor when the provider changes) so
    the worker sets it up again."""
    existing = await find_mailbox_by_address(session, user_id, address)
    if existing is not None:
        reset_mailbox_for_reconnect(existing, provider=provider)
        existing.mode = mode
        if policy is not None:
            existing.policy = dict(policy)
        await session.flush()
        return existing
    row = MailboxRow(
        id=new_id("mbx"),
        user_id=user_id,
        provider=provider,
        address=address_key(address),
        mode=mode,
        status="active",
        labels={},
        policy=dict(policy or {}),
    )
    session.add(row)
    await session.flush()
    return row


async def find_mailbox_by_address(session: AsyncSession, user_id: str, address: str) -> MailboxRow | None:
    """The person's mailbox for ``address``, whatever its provider or status.
    Should a database still hold duplicates (before ``store.migrations`` ran),
    the most useful row wins: active first, then newest."""
    rows = list(
        (
            await session.execute(
                select(MailboxRow)
                .where(MailboxRow.user_id == user_id, func.lower(MailboxRow.address) == address_key(address))
                .order_by(MailboxRow.created_at.desc())
            )
        ).scalars()
    )
    if not rows:
        return None
    return next((r for r in rows if r.status == "active"), rows[0])


def reset_mailbox_for_reconnect(mailbox: MailboxRow, *, provider: str) -> None:
    """A reconnect (new password or token, or a different way in) reuses the
    row. A new provider means new folder ids and a cursor in another format,
    so both are dropped; a disconnected row is set up again from scratch."""
    if mailbox.provider != provider:
        mailbox.provider = provider
        mailbox.labels = {}
        mailbox.cursor = None
    elif mailbox.status == "disconnected":
        mailbox.labels = {}
    mailbox.status = "active"
    mailbox.last_error = None


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


async def list_retrying_mailboxes(session: AsyncSession, errors: Iterable[str]) -> list[MailboxRow]:
    """Mailboxes the worker itself put in error after repeated failures (it
    knows them by its own ``last_error`` wording) and keeps retrying. Errors
    only the client can fix, such as a revoked password, are not listed."""
    stmt = (
        select(MailboxRow)
        .where(MailboxRow.status == "error", MailboxRow.last_error.in_(list(errors)))
        .options(selectinload(MailboxRow.secret))
        .order_by(MailboxRow.created_at)
    )
    return list((await session.execute(stmt)).scalars())


async def list_paused_hold_mailboxes(session: AsyncSession) -> list[MailboxRow]:
    """Paused HOLD mailboxes whose hold rule may still be installed (labels set
    up). Nobody checks their mail while paused, so the worker removes the rule
    and releases what is held; resuming sets the mailbox up again."""
    stmt = (
        select(MailboxRow)
        .where(MailboxRow.status == "paused", MailboxRow.mode == "hold")
        .options(selectinload(MailboxRow.secret))
        .order_by(MailboxRow.created_at)
    )
    return [m for m in (await session.execute(stmt)).scalars() if m.labels]


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
    # Text: kept whole because IMAP finds a moved message by it; the cap only
    # guards against a hostile multi-megabyte header.
    row.rfc_message_id = parsed.rfc_message_id[:2000] if parsed.rfc_message_id else None
    row.from_address = parsed.from_address[:320]
    row.from_name = parsed.from_name[:300] if parsed.from_name else None
    row.subject = (parsed.subject or "")[:1000]
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
    if client_decision(message_row) == "safe":
        message_row.level = "safe"
    await session.flush()
    return message_row


def client_decision(message_row: MessageRow) -> str | None:
    """``"safe"`` / ``"fake"`` when the client judged this message, else ``None``."""
    raw = message_row.verdict if isinstance(message_row.verdict, dict) else {}
    decision = raw.get("client_decision")
    return str(decision.get("decision")) if isinstance(decision, dict) and decision.get("decision") else None


async def list_requests(
    session: AsyncSession, mailbox_id: str, state: str, *, limit: int | None = None
) -> list[MessageRow]:
    """Messages of one mailbox waiting in a client-request state, newest message first."""
    stmt = (
        select(MessageRow)
        .where(MessageRow.mailbox_id == mailbox_id, MessageRow.state == state)
        .order_by(MessageRow.received_at.desc())
    )
    if limit is not None:
        stmt = stmt.limit(limit)
    return list((await session.execute(stmt)).scalars())


async def mark_quarantined_by_client(session: AsyncSession, message_row: MessageRow) -> MessageRow:
    """The worker moved a message the client called fake into Quarantine."""
    message_row.state = STATE_DONE
    message_row.quarantined = True
    message_row.level = "malicious"
    await session.flush()
    return message_row


async def mark_relabeled_safe(session: AsyncSession, message_row: MessageRow) -> MessageRow:
    """The worker swapped the mailbox label to Checked after "This is safe"."""
    message_row.state = STATE_DONE
    message_row.quarantined = False
    message_row.level = "safe"
    await session.flush()
    return message_row


async def record_rescore(
    session: AsyncSession, message_row: MessageRow, verdict: Verdict, quarantined: bool
) -> MessageRow:
    """Store a re-check's verdict, keeping the one it replaces under ``previous``
    (one level deep, so repeated re-checks do not grow the row)."""
    old = dict(message_row.verdict or {})
    old.pop("previous", None)
    keep = {k: old[k] for k in ("client_decision", "review", "review_request", "override") if k in old}
    await record_verdict(session, message_row, verdict, quarantined, state=STATE_DONE)
    message_row.verdict = {**(message_row.verdict or {}), **keep, "previous": old or None}
    await session.flush()
    return message_row


# --------------------------------------------------------- sender feedback
async def load_client_feedback(session: AsyncSession, mailbox_id: str) -> ClientFeedback:
    """Everything the client said about senders of one mailbox, in the shape
    ``AnalysisContext.feedback`` expects."""
    rows = list(
        (
            await session.execute(select(SenderFeedbackRow).where(SenderFeedbackRow.mailbox_id == mailbox_id))
        ).scalars()
    )
    fb = ClientFeedback()
    trusted_ids = {row.id: row.value for row in rows if row.decision == "trusted"}
    if trusted_ids:
        reasons = (
            await session.execute(
                select(FeedbackReasonRow)
                .where(FeedbackReasonRow.sender_feedback_id.in_(list(trusted_ids)))
                .where(FeedbackReasonRow.decision == "safe")
                .order_by(FeedbackReasonRow.created_at, FeedbackReasonRow.id)
            )
        ).scalars()
        for reason in reasons:  # oldest first, so the newest reason wins
            words = reason_words("safe", reason.reason_code or "", reason.reason_text or "")
            if words:
                fb.reasons[trusted_ids[reason.sender_feedback_id or ""].lower()] = words
    for row in rows:
        if row.decision == "blocked":
            if row.scope == "domain":
                fb.blocked_domains.append(row.value)
            elif row.authenticated:
                fb.blocked_addresses.append(row.value)
            else:
                fb.blocked_unverified_addresses.append(row.value)
        elif row.scope == "domain":
            fb.trusted_domains.append(row.value)
        elif row.authenticated:
            fb.verified_addresses.append(row.value)
        else:
            fb.trusted_addresses.append(row.value)
    return fb


async def record_trust_check(
    session: AsyncSession, mailbox_id: str, check: TrustCheck, *, at: datetime | None = None
) -> SenderTrustStatsRow | None:
    """Count one re-check of a client-trusted sender (``sender_trust_stats``).
    Only client trust is counted: the Mailboxes page shows these numbers next
    to the client's own "trusted" entries."""
    if not check.trusted_by_client or not check.scope or not check.value:
        return None
    when = at or utcnow()
    value = check.value.lower()[:320]
    row = (
        await session.execute(
            select(SenderTrustStatsRow).where(
                SenderTrustStatsRow.mailbox_id == mailbox_id,
                SenderTrustStatsRow.scope == check.scope,
                SenderTrustStatsRow.value == value,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        row = SenderTrustStatsRow(
            id=new_id("sts"), mailbox_id=mailbox_id, scope=check.scope, value=value, emails_checked=0
        )
        session.add(row)
    row.emails_checked = (row.emails_checked or 0) + 1
    row.last_checked_at = when
    row.last_outcome = check.outcome
    if check.outcome == "confirmed":
        row.last_confirmed_at = when
    await session.flush()
    return row


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
    address = address.strip().lower()[:320]
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
    name = (display_name or "").strip()[:300]
    if name and name not in (row.display_names or []):
        # Reassign (not mutate) so SQLAlchemy sees the JSON change.
        row.display_names = ([*(row.display_names or []), name])[-MAX_DISPLAY_NAMES:]
    await session.flush()
    return row


async def sender_history(session: AsyncSession, mailbox_id: str, address: str) -> SenderHistory | None:
    stmt = select(Contact).where(Contact.mailbox_id == mailbox_id, Contact.address == address.strip().lower()[:320])
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
        row = DetonationRow(job_id=result.job_id, kind=kind[:10], target=target, status=result.status.value[:20])
        session.add(row)
    row.message_id = message_id or row.message_id
    row.kind = kind[:10]
    row.target = target
    row.status = result.status.value[:20]
    row.result = result.model_dump(mode="json")
    row.sandbox_backend = (result.sandbox_backend or "")[:20]
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
        row = DetonationRow(job_id=job_id, message_id=message_id, kind=kind[:10], target=target, status=status[:20])
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
        actor_role=actor_role[:20],
        action=action[:60],
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


async def provider_ids_since(session: AsyncSession, mailbox_id: str, since: datetime) -> set[str]:
    """Provider ids of this mailbox's messages received since ``since``: what
    a backfill must not fetch again."""
    stmt = select(MessageRow.provider_message_id).where(
        MessageRow.mailbox_id == mailbox_id, MessageRow.received_at >= since
    )
    return set((await session.execute(stmt)).scalars())


# ------------------------------------------------ text-only email (skipped)
# The per-person choice "Also watch text-only emails for money scams" lives in
# ``user_preferences`` under this key ("on" / "off"; default off). The web
# layer (``web.preferences``) owns the allowed values; the worker only reads.
PREF_WATCH_TEXT_SCAMS = "text_scams"


async def get_user_preference(session: AsyncSession, user_id: str, key: str) -> str:
    """The stored value of one preference, or ``""``."""
    from reddysec.store.models import UserPreferenceRow

    value = (
        await session.execute(
            select(UserPreferenceRow.value).where(UserPreferenceRow.user_id == user_id, UserPreferenceRow.key == key)
        )
    ).scalar_one_or_none()
    return value or ""


async def watches_text_scams(session: AsyncSession, user_id: str) -> bool:
    return await get_user_preference(session, user_id, PREF_WATCH_TEXT_SCAMS) == "on"


def utc_day(at: datetime | None = None) -> str:
    return (aware(at) or utcnow()).strftime("%Y-%m-%d")


async def bump_skipped_text_only(
    session: AsyncSession, mailbox_id: str, *, at: datetime | None = None, by: int = 1
) -> MailboxDailyCounterRow:
    """Add to today's operations-only count of ignored text-only emails."""
    day = utc_day(at)
    row = (
        await session.execute(
            select(MailboxDailyCounterRow).where(
                MailboxDailyCounterRow.mailbox_id == mailbox_id, MailboxDailyCounterRow.day == day
            )
        )
    ).scalar_one_or_none()
    if row is None:
        row = MailboxDailyCounterRow(id=new_id("cnt"), mailbox_id=mailbox_id, day=day, skipped_text_only=0)
        session.add(row)
    row.skipped_text_only = (row.skipped_text_only or 0) + by
    row.updated_at = utcnow()
    await session.flush()
    return row


async def skipped_text_only(session: AsyncSession, mailbox_id: str, *, since_day: str = "") -> int:
    """Operations: ignored text-only emails of one mailbox since ``since_day``."""
    stmt = select(func.coalesce(func.sum(MailboxDailyCounterRow.skipped_text_only), 0)).where(
        MailboxDailyCounterRow.mailbox_id == mailbox_id, MailboxDailyCounterRow.day >= since_day
    )
    return int((await session.execute(stmt)).scalar_one())


async def forget_message(session: AsyncSession, message_row: MessageRow) -> None:
    """Delete one stored email and what hangs off it (notifications, feedback
    reasons, detonation records, its "verdict" audit entries). Used when a
    re-check finds an email has nothing to click or open."""
    from sqlalchemy import delete

    mid = message_row.id
    await session.execute(delete(NotificationRow).where(NotificationRow.message_id == mid))
    await session.execute(delete(FeedbackReasonRow).where(FeedbackReasonRow.message_id == mid))
    await session.execute(delete(DetonationRow).where(DetonationRow.message_id == mid))
    await session.execute(delete(AuditLog).where(AuditLog.action == "verdict", AuditLog.target == mid))
    await session.execute(delete(MessageRow).where(MessageRow.id == mid))
    await session.flush()


# ------------------------------------------------------------ mailbox tasks
async def request_backfill(
    session: AsyncSession,
    mailbox_id: str,
    *,
    since: datetime,
    limit: int,
    reason: str = "",
    requested_by: str | None = None,
) -> tuple[MailboxTaskRow, bool]:
    """Ask the worker to check mail received since ``since`` that we have not
    seen (at most ``limit``, newest first). Idempotent: while a backfill is
    still open, a second request widens it instead of queueing another.
    Returns (task, created)."""
    open_task = await open_backfill(session, mailbox_id)
    now = utcnow()
    if open_task is not None:
        open_task.since = min(aware(open_task.since) or since, since)
        open_task.max_messages = max(open_task.max_messages, open_task.processed + limit)
        open_task.updated_at = now
        await session.flush()
        return open_task, False
    task = MailboxTaskRow(
        id=new_id("tsk"),
        mailbox_id=mailbox_id,
        kind=TASK_BACKFILL,
        state=TASK_BACKFILL_REQUESTED,
        since=since,
        max_messages=limit,
        processed=0,
        batches=0,
        reason=reason[:30],
        requested_by=requested_by,
        created_at=now,
        updated_at=now,
    )
    session.add(task)
    await session.flush()
    return task, True


async def open_backfill(session: AsyncSession, mailbox_id: str) -> MailboxTaskRow | None:
    stmt = (
        select(MailboxTaskRow)
        .where(
            MailboxTaskRow.mailbox_id == mailbox_id,
            MailboxTaskRow.kind == TASK_BACKFILL,
            MailboxTaskRow.state.in_(OPEN_TASK_STATES),
        )
        .order_by(MailboxTaskRow.created_at)
        .limit(1)
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def has_backfill(session: AsyncSession, mailbox_id: str) -> bool:
    """Whether this mailbox ever had a backfill (open or finished)."""
    stmt = select(func.count()).select_from(MailboxTaskRow).where(
        MailboxTaskRow.mailbox_id == mailbox_id, MailboxTaskRow.kind == TASK_BACKFILL
    )
    return int((await session.execute(stmt)).scalar_one()) > 0


async def record_backfill_batch(
    session: AsyncSession, task_id: str, *, processed: int, finished: bool, error: str | None = None
) -> MailboxTaskRow | None:
    task = await session.get(MailboxTaskRow, task_id)
    if task is None:
        return None
    now = utcnow()
    task.processed = (task.processed or 0) + processed
    task.batches = (task.batches or 0) + 1
    task.updated_at = now
    if error is not None:
        task.state = TASK_FAILED
        task.error = error[:1000]
        task.finished_at = now
    elif finished or task.processed >= task.max_messages:
        task.state = TASK_DONE
        task.finished_at = now
    else:
        task.state = TASK_BACKFILL_RUNNING
    await session.flush()
    return task

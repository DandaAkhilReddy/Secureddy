"""Thin async query helpers over the store models.

Why a module of small functions rather than a repository class: the pages
need a few dozen narrowly scoped reads and writes, each short enough to audit
at a glance. Every mutation writes its audit row inside the same transaction,
so the client's glass-box log can never drift from what actually happened.
Nothing here knows about HTTP; another agent's repository layer may absorb
these functions later without touching the routes.

Conventions this module relies on (shared with the worker):

* ``MailboxRow.labels == {}`` means "not set up yet"; the worker runs
  ``connector.setup()`` on its next cycle. Changing the protection mode resets
  labels to ``{}`` for the same reason: the connector must install or remove
  the HOLD rule.
* ``MessageRow.state`` values: ``pending``, ``analyzing``, ``done``,
  ``failed``, ``released_by_deadman`` (worker), plus ``restore_requested``
  (client asked for a quarantined message back; the worker performs it) and
  ``reviewed`` (a concierge closed the human-review request).
* Secrets are written through :func:`write_mailbox_secret` only, so the
  integrator can swap in ``mail.vault.CredentialVault`` in one place.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import case, delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from reddysec.core.crypto import DecryptError, TokenCipher
from reddysec.core.ids import new_id
from reddysec.models import MALICIOUS_THRESHOLD, SUSPICIOUS_THRESHOLD, Role
from reddysec.store.models import (
    AuditLog,
    MailboxRow,
    MailboxSecret,
    MessageRow,
    NotificationRow,
    UserRow,
)

STAFF_ROLES = frozenset({Role.CONCIERGE.value, Role.ADMIN.value})
SECRET_KINDS = frozenset({"google_oauth", "imap_password"})
STATE_RESTORE_REQUESTED = "restore_requested"
STATE_REVIEWED = "reviewed"
ANALYZED_STATES = ("done", STATE_REVIEWED, STATE_RESTORE_REQUESTED, "released_by_deadman")

# Representative scores for an analyst override so the stored score always
# agrees with the stored level.
OVERRIDE_SCORES = {"safe": 0, "suspicious": SUSPICIOUS_THRESHOLD, "malicious": MALICIOUS_THRESHOLD}


def utcnow() -> datetime:
    return datetime.now(UTC)


# --------------------------------------------------------------------------
# Visibility rules
# --------------------------------------------------------------------------


def is_staff(user: UserRow) -> bool:
    return user.role in STAFF_ROLES


def visible_owner_ids(user: UserRow) -> list[str]:
    """Mailbox owners whose mail this user may read: themselves, plus the
    principal a family member or assistant account is attached to."""
    ids = [user.id]
    if user.principal_id and user.principal_id != user.id:
        ids.append(user.principal_id)
    return ids


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------


def audit(
    session: AsyncSession,
    *,
    actor: UserRow | None,
    action: str,
    mailbox_id: str | None = None,
    target: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Append one audit row. Callers pass the acting user (or ``None`` for the
    system) so the client can always see *who* did something, not just what."""
    entry = AuditLog(
        id=new_id("aud"),
        actor_id=actor.id if actor else None,
        actor_role=actor.role if actor else "system",
        action=action,
        mailbox_id=mailbox_id,
        target=target,
        details=details or {},
        at=utcnow(),
    )
    session.add(entry)
    return entry


async def list_audit(
    session: AsyncSession, user: UserRow, *, page: int = 1, per_page: int = 50
) -> tuple[list[AuditLog], int]:
    """The client's view of the log: everything that touched their mailboxes
    (including what our staff did) plus their own account actions."""
    mailbox_ids = select(MailboxRow.id).where(MailboxRow.user_id.in_(visible_owner_ids(user)))
    scope = or_(AuditLog.mailbox_id.in_(mailbox_ids), AuditLog.actor_id.in_(visible_owner_ids(user)))
    total = (await session.execute(select(func.count()).select_from(AuditLog).where(scope))).scalar_one()
    page = max(1, page)
    rows = (
        await session.execute(
            select(AuditLog)
            .where(scope)
            .order_by(AuditLog.at.desc())
            .offset((page - 1) * per_page)
            .limit(per_page)
        )
    ).scalars()
    return list(rows), int(total)


# --------------------------------------------------------------------------
# Users
# --------------------------------------------------------------------------


def normalize_email(email: str) -> str:
    return email.strip().lower()


async def get_user(session: AsyncSession, user_id: str) -> UserRow | None:
    return await session.get(UserRow, user_id)


async def get_user_by_email(session: AsyncSession, email: str) -> UserRow | None:
    result = await session.execute(select(UserRow).where(UserRow.login_email == normalize_email(email)))
    return result.scalar_one_or_none()


async def get_or_create_user(
    session: AsyncSession, *, email: str, display_name: str | None = None, role: str = Role.PRINCIPAL.value
) -> tuple[UserRow, bool]:
    """Returns ``(user, created)``. Used by the dev sign-in and by the Google
    callback when the account has no Google subject yet."""
    email = normalize_email(email)
    user = await get_user_by_email(session, email)
    if user is not None:
        return user, False
    user = UserRow(
        id=new_id("usr"),
        display_name=(display_name or email.split("@", 1)[0]).strip()[:200],
        login_email=email,
        role=role,
        created_at=utcnow(),
    )
    session.add(user)
    await session.flush()
    return user, True


async def upsert_google_user(
    session: AsyncSession, *, sub: str, email: str, name: str | None
) -> tuple[UserRow, bool]:
    """Find by Google subject first (stable even if the client renames their
    address), then by email (links a pre-provisioned account), else create."""
    result = await session.execute(select(UserRow).where(UserRow.google_sub == sub))
    user = result.scalar_one_or_none()
    if user is not None:
        return user, False
    user, created = await get_or_create_user(session, email=email, display_name=name)
    user.google_sub = sub
    if name and created:
        user.display_name = name[:200]
    await session.flush()
    return user, created


async def staff_users(session: AsyncSession) -> list[UserRow]:
    result = await session.execute(
        select(UserRow).where(UserRow.role.in_(STAFF_ROLES), UserRow.disabled.is_(False))
    )
    return list(result.scalars())


# --------------------------------------------------------------------------
# Mailboxes and their secrets
# --------------------------------------------------------------------------


async def list_mailboxes(session: AsyncSession, user: UserRow) -> list[MailboxRow]:
    result = await session.execute(
        select(MailboxRow)
        .where(MailboxRow.user_id.in_(visible_owner_ids(user)))
        .order_by(MailboxRow.created_at)
    )
    return list(result.scalars())


async def get_mailbox(
    session: AsyncSession, user: UserRow, mailbox_id: str, *, manage: bool = False
) -> MailboxRow | None:
    """``manage=True`` restricts to mailboxes the user owns outright: an
    assistant may read the principal's mail but not change its protection."""
    mailbox = await session.get(MailboxRow, mailbox_id)
    if mailbox is None:
        return None
    allowed = [user.id] if manage else visible_owner_ids(user)
    return mailbox if mailbox.user_id in allowed else None


def write_mailbox_secret(
    session: AsyncSession, cipher: TokenCipher, mailbox_id: str, kind: str, secret: dict[str, Any]
) -> MailboxSecret:
    """The single place a credential is written. AAD binds the ciphertext to
    the mailbox id so a row copied onto another mailbox fails to decrypt."""
    if kind not in SECRET_KINDS:
        raise ValueError(f"unknown secret kind {kind!r}")
    ciphertext = cipher.encrypt(json.dumps(secret, separators=(",", ":"), default=str), aad=mailbox_id)
    row = MailboxSecret(mailbox_id=mailbox_id, kind=kind, ciphertext=ciphertext, key_id=cipher.current_key_id)
    session.add(row)
    return row


async def read_mailbox_secret(
    session: AsyncSession, cipher: TokenCipher, mailbox_id: str
) -> dict[str, Any] | None:
    row = await session.get(MailboxSecret, mailbox_id)
    if row is None:
        return None
    try:
        data = json.loads(cipher.decrypt(row.ciphertext, aad=mailbox_id))
    except (DecryptError, ValueError):
        # ValueError covers malformed base64 (binascii.Error) and bad JSON. A
        # corrupt row must read as "no credential", never as a crash.
        return None
    return data if isinstance(data, dict) else None


async def _replace_secret(
    session: AsyncSession, cipher: TokenCipher, mailbox_id: str, kind: str, secret: dict[str, Any]
) -> None:
    await session.execute(delete(MailboxSecret).where(MailboxSecret.mailbox_id == mailbox_id))
    await session.flush()
    write_mailbox_secret(session, cipher, mailbox_id, kind, secret)


async def connect_gmail_mailbox(
    session: AsyncSession, cipher: TokenCipher, user: UserRow, address: str, token_payload: dict[str, Any]
) -> MailboxRow:
    """Create or re-activate the Gmail mailbox for ``address`` and store the
    OAuth tokens. Google returns a refresh token only on first consent, so a
    re-connect without one keeps the previously stored refresh token."""
    address = normalize_email(address)
    result = await session.execute(
        select(MailboxRow).where(
            MailboxRow.user_id == user.id, MailboxRow.provider == "gmail", MailboxRow.address == address
        )
    )
    mailbox = result.scalar_one_or_none()
    created = mailbox is None
    if mailbox is None:
        mailbox = MailboxRow(
            id=new_id("mbx"),
            user_id=user.id,
            provider="gmail",
            address=address,
            mode="scan",
            status="active",
            labels={},
            policy={},
            created_at=utcnow(),
        )
        session.add(mailbox)
        await session.flush()
    else:
        existing = await read_mailbox_secret(session, cipher, mailbox.id)
        if not token_payload.get("refresh_token") and existing and existing.get("refresh_token"):
            token_payload = {**token_payload, "refresh_token": existing["refresh_token"]}
        mailbox.status = "active"
        mailbox.last_error = None
    await _replace_secret(session, cipher, mailbox.id, "google_oauth", token_payload)
    audit(
        session,
        actor=user,
        action="mailbox_connected",
        mailbox_id=mailbox.id,
        target=address,
        details={"provider": "gmail", "created": created, "scopes": token_payload.get("scopes", [])},
    )
    return mailbox


async def add_imap_mailbox(
    session: AsyncSession,
    cipher: TokenCipher,
    user: UserRow,
    *,
    provider: str,
    address: str,
    host: str,
    port: int,
    password: str,
) -> MailboxRow:
    """IMAP connection details travel with the password inside the encrypted
    secret: the connector needs both at once and the schema has no host column."""
    address = normalize_email(address)
    mailbox = MailboxRow(
        id=new_id("mbx"),
        user_id=user.id,
        provider=provider,
        address=address,
        mode="scan",
        status="active",
        labels={},
        policy={},
        created_at=utcnow(),
    )
    session.add(mailbox)
    await session.flush()
    secret = {"host": host, "port": port, "username": address, "password": password}
    write_mailbox_secret(session, cipher, mailbox.id, "imap_password", secret)
    audit(
        session,
        actor=user,
        action="mailbox_connected",
        mailbox_id=mailbox.id,
        target=address,
        details={"provider": provider, "host": host, "port": port},
    )
    return mailbox


async def set_mailbox_mode(session: AsyncSession, user: UserRow, mailbox: MailboxRow, mode: str) -> None:
    previous = mailbox.mode
    mailbox.mode = mode
    # Force the connector to re-run setup(mode): HOLD needs its catch-all rule
    # installed, SCAN needs it removed. The worker treats {} as "set me up".
    mailbox.labels = {}
    audit(
        session,
        actor=user,
        action="mode_changed",
        mailbox_id=mailbox.id,
        target=mailbox.address,
        details={"from": previous, "to": mode},
    )


async def set_mailbox_status(
    session: AsyncSession, user: UserRow, mailbox: MailboxRow, status: str, action: str
) -> None:
    previous = mailbox.status
    mailbox.status = status
    if status == "active":
        mailbox.last_error = None
    audit(
        session,
        actor=user,
        action=action,
        mailbox_id=mailbox.id,
        target=mailbox.address,
        details={"from": previous, "to": status},
    )


async def disconnect_mailbox(session: AsyncSession, user: UserRow, mailbox: MailboxRow) -> None:
    """Stop protecting a mailbox and forget its credential. The worker skips
    non-active mailboxes; revoking the Google grant is the connector's job."""
    mailbox.status = "disconnected"
    await session.execute(delete(MailboxSecret).where(MailboxSecret.mailbox_id == mailbox.id))
    audit(session, actor=user, action="mailbox_disconnected", mailbox_id=mailbox.id, target=mailbox.address)


# --------------------------------------------------------------------------
# Messages
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class WeeklyCounts:
    checked: int = 0
    suspicious: int = 0
    quarantined: int = 0


async def weekly_counts(session: AsyncSession, user: UserRow, *, now: datetime | None = None) -> WeeklyCounts:
    since = (now or utcnow()) - timedelta(days=7)
    stmt = (
        select(
            func.count(MessageRow.id),
            func.coalesce(func.sum(case((MessageRow.level == "suspicious", 1), else_=0)), 0),
            func.coalesce(func.sum(case((MessageRow.quarantined.is_(True), 1), else_=0)), 0),
        )
        .join(MailboxRow, MailboxRow.id == MessageRow.mailbox_id)
        .where(
            MailboxRow.user_id.in_(visible_owner_ids(user)),
            MessageRow.received_at >= since,
            MessageRow.level.is_not(None),
        )
    )
    checked, suspicious, quarantined = (await session.execute(stmt)).one()
    return WeeklyCounts(int(checked), int(suspicious), int(quarantined))


async def list_messages(
    session: AsyncSession,
    user: UserRow,
    *,
    limit: int = 20,
    mailbox_id: str | None = None,
    level: str | None = None,
    quarantined: bool | None = None,
) -> list[tuple[MessageRow, MailboxRow]]:
    stmt = (
        select(MessageRow, MailboxRow)
        .join(MailboxRow, MailboxRow.id == MessageRow.mailbox_id)
        .where(MailboxRow.user_id.in_(visible_owner_ids(user)))
        .order_by(MessageRow.received_at.desc())
        .limit(limit)
    )
    if mailbox_id:
        stmt = stmt.where(MessageRow.mailbox_id == mailbox_id)
    if level:
        stmt = stmt.where(MessageRow.level == level)
    if quarantined is not None:
        stmt = stmt.where(MessageRow.quarantined.is_(quarantined))
    return [(row[0], row[1]) for row in (await session.execute(stmt)).all()]


async def get_message(
    session: AsyncSession, user: UserRow, message_id: str
) -> tuple[MessageRow, MailboxRow] | None:
    """Authorisation lives here, once: owners and their helpers see their own
    mail; concierge and admin see everything (they review it)."""
    stmt = (
        select(MessageRow, MailboxRow)
        .join(MailboxRow, MailboxRow.id == MessageRow.mailbox_id)
        .where(MessageRow.id == message_id)
    )
    if not is_staff(user):
        stmt = stmt.where(MailboxRow.user_id.in_(visible_owner_ids(user)))
    row = (await session.execute(stmt)).first()
    return (row[0], row[1]) if row else None


def _update_verdict(message: MessageRow, **changes: Any) -> None:
    """JSON columns only notice reassignment, never in-place mutation."""
    message.verdict = {**(message.verdict or {}), **changes}


def _subject(message: MessageRow, limit: int) -> str:
    return (message.subject or "")[:limit]


async def request_restore(
    session: AsyncSession, user: UserRow, message: MessageRow, mailbox: MailboxRow
) -> bool:
    """Ask the worker to put a quarantined message back in the inbox. Returns
    False when there is nothing to restore (not quarantined, or already asked)."""
    if not message.quarantined or message.state == STATE_RESTORE_REQUESTED:
        return False
    message.state = STATE_RESTORE_REQUESTED
    message.restored_by_client = True
    audit(
        session,
        actor=user,
        action="restore_requested",
        mailbox_id=mailbox.id,
        target=message.id,
        details={"subject": _subject(message, 120), "level": message.level},
    )
    return True


async def request_review(
    session: AsyncSession, user: UserRow, message: MessageRow, mailbox: MailboxRow, note: str
) -> None:
    """Flag the message for a human and tell every concierge on the dashboard."""
    _update_verdict(
        message,
        needs_human_review=True,
        review_request={"by": user.id, "at": utcnow().isoformat(), "note": note[:500]},
    )
    for staff in await staff_users(session):
        notify(
            session,
            user_id=staff.id,
            message_id=message.id,
            level=message.level or "unknown",
            title="A client asked for a second look",
            body=f'{mailbox.address}: "{_subject(message, 80)}". {note[:200]}'.strip(),
        )
    audit(
        session,
        actor=user,
        action="review_requested",
        mailbox_id=mailbox.id,
        target=message.id,
        details={"note": note[:500]},
    )


async def record_feedback(
    session: AsyncSession, user: UserRow, message: MessageRow, mailbox: MailboxRow, feedback: str
) -> None:
    audit(
        session,
        actor=user,
        action="client_feedback",
        mailbox_id=mailbox.id,
        target=message.id,
        details={"feedback": feedback, "level": message.level},
    )


# --------------------------------------------------------------------------
# Concierge
# --------------------------------------------------------------------------


async def concierge_queue(
    session: AsyncSession, *, limit: int = 100
) -> list[tuple[MessageRow, MailboxRow, UserRow]]:
    """Messages the engine or a client flagged for a human, not yet closed."""
    stmt = (
        select(MessageRow, MailboxRow, UserRow)
        .join(MailboxRow, MailboxRow.id == MessageRow.mailbox_id)
        .join(UserRow, UserRow.id == MailboxRow.user_id)
        .where(
            MessageRow.verdict["needs_human_review"].as_boolean().is_(True),
            MessageRow.verdict["review"].as_string().is_(None),
            MessageRow.state != STATE_REVIEWED,
        )
        .order_by(MessageRow.received_at.desc())
        .limit(limit)
    )
    return [(row[0], row[1], row[2]) for row in (await session.execute(stmt)).all()]


async def mark_reviewed(
    session: AsyncSession, actor: UserRow, message: MessageRow, mailbox: MailboxRow, note: str
) -> None:
    """Close a review. The state becomes ``reviewed`` unless a client restore is
    still waiting for the worker, in which case only the verdict JSON records
    the review so the restore is not lost."""
    _update_verdict(message, review={"by": actor.id, "at": utcnow().isoformat(), "note": note[:500]})
    if message.state != STATE_RESTORE_REQUESTED:
        message.state = STATE_REVIEWED
    audit(
        session,
        actor=actor,
        action="concierge_reviewed",
        mailbox_id=mailbox.id,
        target=message.id,
        details={"note": note[:500]},
    )


async def override_verdict(
    session: AsyncSession, actor: UserRow, message: MessageRow, mailbox: MailboxRow, level: str, note: str
) -> None:
    """An analyst's call replaces the engine's. The report keeps the original
    level and the analyst's note so the client can see both sides."""
    if level not in OVERRIDE_SCORES:
        raise ValueError(f"unknown verdict level {level!r}")
    previous_level = message.level
    score = OVERRIDE_SCORES[level]
    summary = (
        f"Reviewed by a Secureddy analyst: {note.strip()}"
        if note.strip()
        else ("Reviewed by a Secureddy analyst.")
    )
    _update_verdict(
        message,
        level=level,
        score=score,
        summary=summary,
        override={
            "by": actor.id,
            "at": utcnow().isoformat(),
            "from_level": previous_level,
            "to_level": level,
            "note": note[:500],
        },
    )
    message.level = level
    message.score = score
    await mark_reviewed(session, actor, message, mailbox, note)
    notify(
        session,
        user_id=mailbox.user_id,
        message_id=message.id,
        level=level,
        title="Our analyst reviewed one of your emails",
        body=f'"{_subject(message, 80)}" is now marked {level}. {note[:200]}'.strip(),
    )
    audit(
        session,
        actor=actor,
        action="verdict_override",
        mailbox_id=mailbox.id,
        target=message.id,
        details={"from": previous_level, "to": level, "note": note[:500]},
    )


# --------------------------------------------------------------------------
# Notifications
# --------------------------------------------------------------------------


def notify(
    session: AsyncSession,
    *,
    user_id: str,
    message_id: str | None,
    level: str,
    title: str,
    body: str,
    channel: str = "dashboard",
) -> NotificationRow:
    row = NotificationRow(
        id=new_id("ntf"),
        user_id=user_id,
        message_id=message_id,
        channel=channel,
        level=level,
        title=title[:300],
        body=body,
        created_at=utcnow(),
    )
    session.add(row)
    return row


async def list_notifications(
    session: AsyncSession, user: UserRow, *, limit: int = 100, since: datetime | None = None
) -> list[NotificationRow]:
    stmt = (
        select(NotificationRow)
        .where(NotificationRow.user_id.in_(visible_owner_ids(user)))
        .order_by(NotificationRow.created_at.desc())
        .limit(limit)
    )
    if since is not None:
        stmt = stmt.where(NotificationRow.created_at >= since)
    return list((await session.execute(stmt)).scalars())

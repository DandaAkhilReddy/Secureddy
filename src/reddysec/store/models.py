"""Database schema.

Data minimization is a design rule, not a setting: we store message
*metadata* and *verdicts*, never bodies. Bodies and attachments live in memory
during analysis and in the client's own mailbox afterwards. Screenshots and
sanitized copies go to the artifact store with a retention window.

Column sizes. SQLite ignores ``VARCHAR(n)`` and PostgreSQL enforces it, so a
length that is too small only fails in production. The rule: anything a
provider hands us that we do not control (sync cursors, message, thread and
identity ids) is ``Text``. ``String(n)`` is for our own ids and enums, and for
human text that its writer truncates to fit. ``tests/unit/store/
test_column_sizes.py`` enforces this, and ``store.migrations`` widens the
columns of databases created before a column became ``Text``.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class UserRow(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(200))
    login_email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(20), default="principal")
    # Optional local credential for clients without a Google login (Yahoo-only).
    password_hash: Mapped[str | None] = mapped_column(String(300), nullable=True)
    totp_secret_enc: Mapped[str | None] = mapped_column(String(300), nullable=True)
    # Opaque provider id: Text (see "Column sizes" in the module docstring).
    google_sub: Mapped[str | None] = mapped_column(Text, nullable=True, unique=True)
    # Family/assistant accounts point at the principal they help.
    principal_id: Mapped[str | None] = mapped_column(String(40), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)

    mailboxes: Mapped[list[MailboxRow]] = relationship(back_populates="owner", cascade="all, delete-orphan")


class MailboxRow(Base):
    __tablename__ = "mailboxes"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(40), ForeignKey("users.id"), index=True)
    provider: Mapped[str] = mapped_column(String(20))
    address: Mapped[str] = mapped_column(String(320), index=True)
    mode: Mapped[str] = mapped_column(String(10), default="scan")
    status: Mapped[str] = mapped_column(String(20), default="active")
    # Opaque provider sync token: a Gmail historyId, an IMAP "uv:uid|uv:uid"
    # or a Graph JSON document holding two delta links (well over 1 KB).
    cursor: Mapped[str | None] = mapped_column(Text, nullable=True)
    labels: Mapped[dict] = mapped_column(JSON, default=dict)
    policy: Mapped[dict] = mapped_column(JSON, default=dict)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    owner: Mapped[UserRow] = relationship(back_populates="mailboxes")
    secret: Mapped[MailboxSecret | None] = relationship(
        back_populates="mailbox", uselist=False, cascade="all, delete-orphan"
    )


# One mailbox per person and address, whichever way it was connected (Gmail,
# Microsoft, an app password): two rows for one mailbox would check and label
# every message twice. Created by ``create_all`` on a fresh database and by
# ``store.migrations`` (after merging duplicates) on an existing one.
MAILBOX_UNIQUE_INDEX = "uq_mailboxes_user_address"
Index(MAILBOX_UNIQUE_INDEX, MailboxRow.user_id, func.lower(MailboxRow.address), unique=True)


class MailboxSecret(Base):
    """Encrypted credential blob: Google refresh token JSON or IMAP app password."""

    __tablename__ = "mailbox_secrets"

    mailbox_id: Mapped[str] = mapped_column(String(40), ForeignKey("mailboxes.id"), primary_key=True)
    kind: Mapped[str] = mapped_column(String(20))  # google_oauth | microsoft_oauth | imap_password
    ciphertext: Mapped[str] = mapped_column(Text)
    key_id: Mapped[str] = mapped_column(String(20))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    mailbox: Mapped[MailboxRow] = relationship(back_populates="secret")


class MessageRow(Base):
    """Metadata + verdict for one scanned message. No body."""

    __tablename__ = "messages"
    __table_args__ = (
        Index("ix_messages_mailbox_received", "mailbox_id", "received_at"),
        Index("ix_messages_mailbox_provider", "mailbox_id", "provider_message_id", unique=True),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    mailbox_id: Mapped[str] = mapped_column(String(40), ForeignKey("mailboxes.id"), index=True)
    # Gmail ids are 16 hex chars, but Graph immutable ids and conversation ids
    # run to 150+ and IMAP ids embed the folder name: all opaque, all Text.
    provider_message_id: Mapped[str] = mapped_column(Text)
    thread_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    rfc_message_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    from_address: Mapped[str] = mapped_column(String(320), default="")
    from_name: Mapped[str | None] = mapped_column(String(300), nullable=True)
    subject: Mapped[str] = mapped_column(String(1000), default="")
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    url_count: Mapped[int] = mapped_column(Integer, default=0)
    attachment_count: Mapped[int] = mapped_column(Integer, default=0)
    # analysis lifecycle: pending -> analyzing -> done | failed | released_by_deadman
    state: Mapped[str] = mapped_column(String(30), default="pending", index=True)
    lane: Mapped[str | None] = mapped_column(String(20), nullable=True)
    level: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    verdict: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # Verdict.model_dump()
    quarantined: Mapped[bool] = mapped_column(Boolean, default=False)
    restored_by_client: Mapped[bool] = mapped_column(Boolean, default=False)
    analyzed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DetonationRow(Base):
    __tablename__ = "detonations"

    job_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    message_id: Mapped[str | None] = mapped_column(String(40), ForeignKey("messages.id"), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(10))
    target: Mapped[str] = mapped_column(Text)  # url or filename
    status: Mapped[str] = mapped_column(String(20))
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)  # DetonationResult.model_dump()
    sandbox_backend: Mapped[str] = mapped_column(String(20), default="")
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Contact(Base):
    """Per-mailbox sender history, the basis of the 'first time sender' signal."""

    __tablename__ = "contacts"
    __table_args__ = (Index("ix_contacts_mailbox_address", "mailbox_id", "address", unique=True),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    mailbox_id: Mapped[str] = mapped_column(String(40), ForeignKey("mailboxes.id"), index=True)
    address: Mapped[str] = mapped_column(String(320))
    display_names: Mapped[list] = mapped_column(JSON, default=list)
    message_count: Mapped[int] = mapped_column(Integer, default=0)
    replied_to: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SenderFeedbackRow(Base):
    """What the client told us about a sender: "This is safe" or "This is fake".

    A separate table on purpose: deployments that build their schema with
    ``create_all`` (the Azure dev database) only create missing tables, so new
    columns on existing tables would never appear there.

    ``scope`` is ``domain`` (a registrable domain, only ever recorded from a
    message Google verified) or ``address`` (one full address). ``authenticated``
    records whether the message the client judged was verified; an address
    trusted from an unverified message is weak trust (see analysis.trust).
    """

    __tablename__ = "sender_feedback"
    __table_args__ = (UniqueConstraint("mailbox_id", "scope", "value", name="uq_sender_feedback_entry"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    mailbox_id: Mapped[str] = mapped_column(String(40), ForeignKey("mailboxes.id"), index=True)
    scope: Mapped[str] = mapped_column(String(10))  # domain | address
    value: Mapped[str] = mapped_column(String(320))
    decision: Mapped[str] = mapped_column(String(10))  # trusted | blocked
    authenticated: Mapped[bool] = mapped_column(Boolean, default=False)
    source_message_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class UserIdentityRow(Base):
    """A sign-in identity (Google, Microsoft, Yahoo) attached to an account.

    A separate table rather than new columns on ``users`` for the same
    ``create_all`` reason as ``sender_feedback``. ``subject`` is the provider's
    stable id for the person (Google ``sub``, Microsoft ``oid``, Yahoo
    ``sub``). ``email_verified`` records whether the provider vouched for the
    address; only verified identities may ever be matched to an existing
    account by email (see web.queries.resolve_identity). ``tenant`` is the
    Microsoft directory id (``tid``), empty for other providers.
    """

    __tablename__ = "user_identities"
    __table_args__ = (UniqueConstraint("provider", "subject", name="uq_user_identity_subject"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(40), ForeignKey("users.id"), index=True)
    provider: Mapped[str] = mapped_column(String(20))  # google | microsoft | yahoo
    subject: Mapped[str] = mapped_column(Text)
    email: Mapped[str] = mapped_column(String(320), default="", index=True)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    tenant: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SenderTrustStatsRow(Base):
    """How often we re-checked mail from a sender the client trusts, and how
    the last check went. Updated by the worker; shown on the Mailboxes page as
    "last confirmed 2 days ago · 5 emails checked since". Keyed like
    ``sender_feedback`` (mailbox, scope, value) and reset when the client
    trusts the sender again or removes the entry."""

    __tablename__ = "sender_trust_stats"
    __table_args__ = (UniqueConstraint("mailbox_id", "scope", "value", name="uq_sender_trust_stats_entry"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    mailbox_id: Mapped[str] = mapped_column(String(40), ForeignKey("mailboxes.id"), index=True)
    scope: Mapped[str] = mapped_column(String(10))  # domain | address
    value: Mapped[str] = mapped_column(String(320))
    emails_checked: Mapped[int] = mapped_column(Integer, default=0)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_outcome: Mapped[str] = mapped_column(String(20), default="")  # confirmed | changed | incomplete
    last_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ReadingRoomRow(Base):
    __tablename__ = "reading_rooms"

    session_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(40), ForeignKey("users.id"), index=True)
    message_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    url: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(20), default="starting")
    downloads: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class HoldHeartbeat(Base):
    """One row per mailbox in HOLD mode. The worker updates ``beat_at`` on every
    successful cycle. A watchdog that finds a stale beat releases all pending mail."""

    __tablename__ = "hold_heartbeats"

    mailbox_id: Mapped[str] = mapped_column(String(40), ForeignKey("mailboxes.id"), primary_key=True)
    beat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    released_by_deadman_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class NotificationRow(Base):
    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(40), ForeignKey("users.id"), index=True)
    message_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    channel: Mapped[str] = mapped_column(String(20))  # email | webhook | dashboard
    level: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(300))
    body: Mapped[str] = mapped_column(Text)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    """Every privileged action, client-visible. Who did what to which mailbox."""

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    actor_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    actor_role: Mapped[str] = mapped_column(String(20), default="system")
    action: Mapped[str] = mapped_column(String(60), index=True)
    mailbox_id: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    target: Mapped[str | None] = mapped_column(Text, nullable=True)  # may be a provider message id
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class FeedbackReasonRow(Base):
    """Why the client said "This is safe" / "This is fake" about one message.

    A new table, not new columns on ``sender_feedback``, for the same
    ``create_all`` reason. ``sender_feedback_id`` points at the sender entry
    the click created or updated (it may later be removed from the Mailboxes
    page, so it is a plain nullable id, not a foreign key). The reason never
    changes the trust math; it is shown to the client, the concierge and the
    audit log. ``reason_text`` is the client's own words, at most 500
    characters, and is always rendered escaped.
    """

    __tablename__ = "feedback_reasons"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    sender_feedback_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    message_id: Mapped[str] = mapped_column(String(40), index=True)
    user_id: Mapped[str] = mapped_column(String(40), index=True)
    decision: Mapped[str] = mapped_column(String(10))  # safe | fake
    reason_code: Mapped[str] = mapped_column(String(30), default="")
    reason_text: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class AssistantConversationRow(Base):
    """One "Ask Secureddy" chat. Only its owner can read it."""

    __tablename__ = "assistant_conversations"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(40), ForeignKey("users.id"), index=True)
    title: Mapped[str] = mapped_column(String(200), default="New conversation")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class AssistantMessageRow(Base):
    """One entry of a chat: ``user`` (the question), ``assistant`` (a reply or
    a tool request) or ``tool`` (what our read-only tools returned)."""

    __tablename__ = "assistant_messages"
    __table_args__ = (Index("ix_assistant_messages_conv_seq", "conversation_id", "seq"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    conversation_id: Mapped[str] = mapped_column(String(40), ForeignKey("assistant_conversations.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer, default=0)  # order inside the conversation
    role: Mapped[str] = mapped_column(String(10))  # user | assistant | tool
    content: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MailboxTaskRow(Base):
    """Work the client asked for on a whole mailbox, carried out by the worker
    a batch at a time. Today one kind: ``backfill`` ("check my recent mail"),
    which fetches mail received since ``since`` that we have never seen, at
    most ``max_messages`` of it, newest first.

    A separate table for the same ``create_all`` reason as ``sender_feedback``.
    ``state``: ``backfill_requested`` -> ``backfill_running`` -> ``done`` |
    ``failed``.
    """

    __tablename__ = "mailbox_tasks"
    __table_args__ = (Index("ix_mailbox_tasks_mailbox_state", "mailbox_id", "state"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    mailbox_id: Mapped[str] = mapped_column(String(40), ForeignKey("mailboxes.id"), index=True)
    kind: Mapped[str] = mapped_column(String(20), default="backfill")
    state: Mapped[str] = mapped_column(String(30), default="backfill_requested")
    since: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    max_messages: Mapped[int] = mapped_column(Integer, default=50)
    processed: Mapped[int] = mapped_column(Integer, default=0)
    batches: Mapped[int] = mapped_column(Integer, default=0)
    reason: Mapped[str] = mapped_column(String(30), default="")  # first_setup | recheck | cli
    requested_by: Mapped[str | None] = mapped_column(String(40), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ---------------------------------------------------------------------------
# Accounts: sign-in sessions, app lock, passkeys, preferences
#
# New tables (not new columns) for the same ``create_all`` reason as
# ``sender_feedback``: ``store.migrations`` creates them on existing databases.
# ---------------------------------------------------------------------------


class UserPreferenceRow(Base):
    """Small per-person choices, key/value: "show my accounts together or
    separately", the inbox picked in the "All inboxes" switch, and so on.
    Keys and values come from fixed sets in ``web.preferences``."""

    __tablename__ = "user_preferences"
    __table_args__ = (UniqueConstraint("user_id", "key", name="uq_user_preference_key"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(40), ForeignKey("users.id"), index=True)
    key: Mapped[str] = mapped_column(String(40))
    value: Mapped[str] = mapped_column(String(200), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class UserSessionRow(Base):
    """One signed-in device. The browser holds a random 256-bit token; we keep
    only its SHA-256 (``id``), so a database leak gives no working cookie.
    ``handle`` is a short public name for the row (Settings → Devices).

    Lifetimes: ``expires_at`` slides forward with use (90 days idle), capped by
    ``absolute_expires_at`` (1 year after sign-in). ``revoked_at`` ends it at
    once (sign out, sign out everywhere, a PIN or password change).

    App lock state lives here too, on the server: ``unlocked_at`` is the last
    full sign-in or PIN/passkey unlock (``None`` = locked) and
    ``last_active_at`` drives the inactivity timeout.
    """

    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # sha256(token) hex
    handle: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    user_id: Mapped[str] = mapped_column(String(40), ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    absolute_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    user_agent: Mapped[str] = mapped_column(String(120), default="")
    ip_prefix: Mapped[str] = mapped_column(String(64), default="")
    auth_method: Mapped[str] = mapped_column(String(20), default="")
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[str] = mapped_column(String(30), default="")
    unlocked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_active_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AppLockRow(Base):
    """Optional app lock for one person: a 6-digit PIN or a password (argon2id)
    and/or passkeys (``user_passkeys``), and how long the app may stay open
    without use. Wrong answers are counted here, per person, so opening a new
    session does not reset them."""

    __tablename__ = "app_locks"

    user_id: Mapped[str] = mapped_column(String(40), ForeignKey("users.id"), primary_key=True)
    kind: Mapped[str] = mapped_column(String(10), default="pin")  # pin | password | passkey
    secret_hash: Mapped[str | None] = mapped_column(String(300), nullable=True)
    timeout_s: Mapped[int] = mapped_column(Integer, default=300)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PasskeyRow(Base):
    """A WebAuthn credential that can unlock the app (not sign in: signing in
    is Google, Microsoft, Yahoo or a password). ``credential_id`` and
    ``public_key`` are base64url as the authenticator produced them."""

    __tablename__ = "user_passkeys"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(40), ForeignKey("users.id"), index=True)
    credential_id: Mapped[str] = mapped_column(Text)
    public_key: Mapped[str] = mapped_column(Text)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String(100), default="Passkey")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class MfaStateRow(Base):
    """Two-step sign-in bookkeeping for one person (the authenticator secret
    itself is ``users.totp_secret_enc``). ``last_step`` is the 30-second time
    step of the last code accepted, so the same code cannot be used twice;
    wrong codes are counted per person over a 15-minute window."""

    __tablename__ = "user_mfa"

    user_id: Mapped[str] = mapped_column(String(40), ForeignKey("users.id"), primary_key=True)
    last_step: Mapped[int] = mapped_column(BigInteger, default=0)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    window_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RecoveryCodeRow(Base):
    """One single-use recovery code (argon2id hash only; shown once)."""

    __tablename__ = "mfa_recovery_codes"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(40), ForeignKey("users.id"), index=True)
    code_hash: Mapped[str] = mapped_column(String(300))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class TrustedDeviceRow(Base):
    """"Remember this device for 30 days": the browser holds a random token in
    ``rs_mfa_dev``; we keep its SHA-256. ``session_id`` is the sign-in that
    created it, so signing that device out forgets it too."""

    __tablename__ = "mfa_trusted_devices"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # sha256(token) hex
    user_id: Mapped[str] = mapped_column(String(40), ForeignKey("users.id"), index=True)
    session_id: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

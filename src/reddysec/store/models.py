"""Database schema.

Data minimization is a design rule, not a setting: we store message
*metadata* and *verdicts*, never bodies. Bodies and attachments live in memory
during analysis and in the client's own mailbox afterwards. Screenshots and
sanitized copies go to the artifact store with a retention window.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
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
    google_sub: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True)
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
    cursor: Mapped[str | None] = mapped_column(String(100), nullable=True)
    labels: Mapped[dict] = mapped_column(JSON, default=dict)
    policy: Mapped[dict] = mapped_column(JSON, default=dict)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    owner: Mapped[UserRow] = relationship(back_populates="mailboxes")
    secret: Mapped[MailboxSecret | None] = relationship(
        back_populates="mailbox", uselist=False, cascade="all, delete-orphan"
    )


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
    provider_message_id: Mapped[str] = mapped_column(String(200))
    thread_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    rfc_message_id: Mapped[str | None] = mapped_column(String(500), nullable=True)
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
    subject: Mapped[str] = mapped_column(String(200))
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
    target: Mapped[str | None] = mapped_column(String(200), nullable=True)
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

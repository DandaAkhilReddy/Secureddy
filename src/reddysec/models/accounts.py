"""Account-side contracts: who we protect and how they want it done."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field

from .mail import ProtectionMode, Provider
from .verdict import VerdictLevel


class Role(str, Enum):
    PRINCIPAL = "principal"  # the protected person
    FAMILY = "family"
    ASSISTANT = "assistant"  # reads the principal's mail on their behalf
    CONCIERGE = "concierge"  # our analyst
    ADMIN = "admin"


class Principal(BaseModel):
    id: str
    display_name: str
    login_email: str
    role: Role = Role.PRINCIPAL
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class MailboxStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    ERROR = "error"
    DISCONNECTED = "disconnected"


# What the Mailboxes page shows while the worker keeps retrying a mailbox that
# failed several cycles in a row. The worker recognises its own wording to know
# which errors it may retry (a revoked password needs the client instead).
MAILBOX_ERROR_SAVE_PLACE = "We couldn't save our place in your mailbox. We're fixing it."
MAILBOX_ERROR_CHECK_FAILED = "We couldn't check this mailbox just now. We're fixing it."
MAILBOX_ERROR_UNREACHABLE = "We couldn't reach your mail provider for a while. We keep trying."
MAILBOX_RETRYING_ERRORS = (MAILBOX_ERROR_SAVE_PLACE, MAILBOX_ERROR_CHECK_FAILED, MAILBOX_ERROR_UNREACHABLE)


class Mailbox(BaseModel):
    id: str
    principal_id: str
    provider: Provider
    address: str
    mode: ProtectionMode = ProtectionMode.SCAN
    status: MailboxStatus = MailboxStatus.ACTIVE
    cursor: str | None = None  # Gmail historyId, IMAP "uv:uid", Graph delta links (JSON)
    labels: dict[str, str] = Field(default_factory=dict)  # our label name -> provider id
    last_sync_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SenderHistory(BaseModel):
    """What we know about a sender from this mailbox's own history."""

    address: str
    display_names: list[str] = Field(default_factory=list)
    message_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    replied_to: bool = False  # the client has written to this address


class PolicyConfig(BaseModel):
    mode: ProtectionMode = ProtectionMode.SCAN
    detonate_all_links: bool = True
    hold_timeout_s: int = 120
    # If analysis exceeds hold_timeout_s: True releases with links flagged as
    # "still checking"; False keeps the message held and pages the concierge.
    release_on_timeout: bool = True
    always_isolate_clicks: bool = True
    quarantine_at: VerdictLevel = VerdictLevel.MALICIOUS
    notify_at: VerdictLevel = VerdictLevel.SUSPICIOUS
    trusted_domains: list[str] = Field(default_factory=list)
    blocked_senders: list[str] = Field(default_factory=list)
    # Domains whose one-time links must never be followed by the detonator.
    never_detonate_domains: list[str] = Field(default_factory=list)


class ClientFeedback(BaseModel):
    """What the client told us about senders ("This is safe" / "This is fake").

    Values are lowercase. Domains are registrable domains (``walmart.com``),
    addresses are full addresses. The engine decides what each entry is worth
    (see ``reddysec.analysis.trust``); this object only carries the lists.

    * ``trusted_domains``: apply only to mail that Google (DMARC) confirmed
      came from that domain. A message that merely claims the domain gets
      nothing, so a spoof cannot ride the client's trust.
    * ``verified_addresses``: one address trusted from a verified message
      (for example a person's Gmail address); applies only when the new
      message is verified too.
    * ``trusted_addresses``: weak trust from an unverified message. It lowers
      the score a little; links are still opened in the sandbox.
    * ``blocked_domains`` / ``blocked_addresses``: always apply, verified or
      not. Blocking can only make us stricter.
    * ``blocked_unverified_addresses``: "This is fake" on a message Google
      could not verify. Someone may have forged the address, so only mail
      from it that is *also* unverified is blocked; the real sender's verified
      mail still gets through.
    """

    trusted_domains: list[str] = Field(default_factory=list)
    verified_addresses: list[str] = Field(default_factory=list)
    trusted_addresses: list[str] = Field(default_factory=list)
    blocked_domains: list[str] = Field(default_factory=list)
    blocked_addresses: list[str] = Field(default_factory=list)
    blocked_unverified_addresses: list[str] = Field(default_factory=list)
    # value (domain or address, lowercase) -> the client's reason in words
    # ("I ordered this"). Context only: it never changes what an entry is worth.
    reasons: dict[str, str] = Field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        return not (
            self.trusted_domains
            or self.verified_addresses
            or self.trusted_addresses
            or self.blocked_domains
            or self.blocked_addresses
            or self.blocked_unverified_addresses
        )

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


class Mailbox(BaseModel):
    id: str
    principal_id: str
    provider: Provider
    address: str
    mode: ProtectionMode = ProtectionMode.SCAN
    status: MailboxStatus = MailboxStatus.ACTIVE
    cursor: str | None = None  # Gmail historyId or IMAP UIDNEXT
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

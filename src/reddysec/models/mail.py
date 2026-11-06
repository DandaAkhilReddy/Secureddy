"""Mail-side contracts: what a message looks like after we fetch and parse it."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Provider(str, Enum):
    GMAIL = "gmail"
    YAHOO = "yahoo"
    ICLOUD = "icloud"
    OUTLOOK = "outlook"  # consumer Outlook.com / Hotmail via IMAP
    GENERIC_IMAP = "imap"
    # Outlook.com, Hotmail and Microsoft 365 through "Sign in with Microsoft"
    # and the Microsoft Graph API (mail.outlook_graph). OUTLOOK stays the IMAP path.
    MICROSOFT = "microsoft"

    @property
    def uses_imap(self) -> bool:
        return self not in (Provider.GMAIL, Provider.MICROSOFT)


class ProtectionMode(str, Enum):
    """SCAN: mail lands normally and is labeled within seconds.
    HOLD: mail is parked before the inbox and released only after a verdict
    (with a dead man's switch so a dead pipeline can never trap mail)."""

    SCAN = "scan"
    HOLD = "hold"


class UrlSource(str, Enum):
    HTML_HREF = "html_href"
    HTML_TEXT = "html_text"
    TEXT = "text"
    PDF = "pdf"
    QR = "qr"
    ATTACHMENT_TEXT = "attachment_text"
    HEADER = "header"


class ExtractedUrl(BaseModel):
    raw: str
    normalized: str
    source: UrlSource
    display_text: str | None = None
    host: str = ""
    registrable_domain: str = ""
    is_ip_literal: bool = False
    is_shortener: bool = False
    is_punycode: bool = False
    # A long random-looking token in the path/query. Likely a one-time or
    # tracking link: detonating it may burn it (magic links) or confirm the
    # target address to an attacker. The policy engine treats these specially.
    has_opaque_token: bool = False
    # The visible link text names a different domain than the href.
    display_mismatch: bool = False


class Attachment(BaseModel):
    filename: str
    content_type: str
    size: int
    sha256: str
    declared_extension: str = ""
    sniffed_type: str | None = None
    content_id: str | None = None
    is_inline: bool = False
    # Raw bytes travel in-process only; never serialized to JSON or the DB.
    data: bytes | None = Field(default=None, exclude=True, repr=False)


class AuthResults(BaseModel):
    """Parsed from the receiving provider's Authentication-Results header."""

    spf: str | None = None  # pass / fail / softfail / neutral / none
    dkim: str | None = None
    dmarc: str | None = None
    dkim_domain: str | None = None
    aligned: bool | None = None  # DKIM/SPF domain aligns with From domain
    # The ``header.from`` the DMARC verdict was computed for, when the receiver
    # recorded it. A DMARC pass only vouches for this domain.
    dmarc_from: str | None = None
    raw: str | None = None


class RawMessage(BaseModel):
    provider_message_id: str
    mailbox_id: str
    received_at: datetime
    raw: bytes = Field(exclude=True, repr=False)
    provider_labels: list[str] = Field(default_factory=list)
    thread_id: str | None = None


class ParsedMessage(BaseModel):
    provider_message_id: str
    mailbox_id: str
    rfc_message_id: str | None = None
    from_address: str = ""
    from_name: str | None = None
    reply_to: list[str] = Field(default_factory=list)
    to: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    subject: str = ""
    date: datetime | None = None
    received_at: datetime
    text_body: str = ""
    html_body: str | None = None
    urls: list[ExtractedUrl] = Field(default_factory=list)
    attachments: list[Attachment] = Field(default_factory=list)
    auth: AuthResults = Field(default_factory=AuthResults)
    headers: dict[str, str] = Field(default_factory=dict)
    raw_size: int = 0
    raw_sha256: str = ""
    has_list_unsubscribe: bool = False
    has_calendar_invite: bool = False

    @property
    def from_domain(self) -> str:
        return self.from_address.rsplit("@", 1)[-1].lower() if "@" in self.from_address else ""

    @property
    def has_links(self) -> bool:
        return bool(self.urls)

    @property
    def real_attachments(self) -> list[Attachment]:
        return [a for a in self.attachments if not a.is_inline]

    @property
    def has_attachments(self) -> bool:
        return bool(self.real_attachments)

    @property
    def needs_deep_analysis(self) -> bool:
        return self.has_links or self.has_attachments

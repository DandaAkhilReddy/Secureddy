"""The connector contract every mailbox provider implements.

Label/folder names we create in the client's mailbox. They are visible to the
client on purpose: the product should feel like a bodyguard standing in the
room, not a hidden camera.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime
from email.utils import parseaddr
from typing import Protocol, runtime_checkable

from reddysec.models import PolicyConfig, ProtectionMode, Provider, RawMessage, Verdict

LABEL_ROOT = "Secureddy"
LABEL_PENDING = f"{LABEL_ROOT}/Checking"
LABEL_SAFE = f"{LABEL_ROOT}/Checked"
LABEL_SUSPICIOUS = f"{LABEL_ROOT}/Suspicious"
LABEL_QUARANTINE = f"{LABEL_ROOT}/Quarantine"
LABEL_RELEASED = f"{LABEL_ROOT}/Released by you"
ALL_LABELS = [LABEL_ROOT, LABEL_PENDING, LABEL_SAFE, LABEL_SUSPICIOUS, LABEL_QUARANTINE, LABEL_RELEASED]


class ConnectorError(Exception):
    """Transient or permanent provider failure. ``retryable`` guides the worker."""

    def __init__(self, message: str, *, retryable: bool = True):
        super().__init__(message)
        self.retryable = retryable


class AuthExpired(ConnectorError):
    def __init__(self, message: str = "mailbox credentials expired or revoked"):
        super().__init__(message, retryable=False)


@runtime_checkable
class MailboxConnector(Protocol):
    provider: Provider
    mailbox_id: str

    async def setup(self, mode: ProtectionMode) -> dict[str, str]:
        """Create our labels/folders. In HOLD mode also install the catch-all
        rule that parks new mail under LABEL_PENDING, out of the inbox.
        Returns {label_name: provider_label_id}."""
        ...

    async def poll(self, cursor: str | None) -> tuple[list[RawMessage], str | None]:
        """Return messages that arrived since ``cursor`` and the new cursor.
        Must be idempotent: polling twice with the same cursor returns the same set."""
        ...

    async def fetch_raw(self, provider_message_id: str) -> bytes:
        """Full RFC 5322 bytes of one message."""
        ...

    async def backfill(self, since: datetime, limit: int, *, skip: Collection[str] = ()) -> list[RawMessage]:
        """Mail already in the inbox that was received at or after ``since``,
        newest first, at most ``limit`` messages. Ids in ``skip`` (mail we
        already checked) are left out *before* any body is downloaded, so a
        batched backfill only pays for what it returns. Read-only, and
        idempotent by ``provider_message_id``: the ids are the ones ``poll``
        reports for the same messages."""
        ...

    async def apply_verdict(
        self, msg: RawMessage, verdict: Verdict, policy: PolicyConfig, *, relabel: bool = False
    ) -> None:
        """Label the message by verdict; quarantine it if level >= policy.quarantine_at;
        in HOLD mode move it from LABEL_PENDING to the inbox unless quarantined.
        ``relabel`` (re-checks) also removes a previous Checked/Suspicious label."""
        ...

    async def release(self, provider_message_id: str) -> None:
        """Move a held message to the inbox (keeps our labels)."""
        ...

    async def quarantine(self, provider_message_id: str) -> None: ...

    async def restore(self, provider_message_id: str) -> None:
        """Undo a quarantine at the client's request; adds LABEL_RELEASED."""
        ...

    async def mark_safe(self, provider_message_id: str) -> None:
        """The client said "This is safe" (or a re-check found it safe): swap our
        verdict label to LABEL_SAFE, drop Suspicious/Quarantine/Checking and make
        sure the message is in the inbox. Idempotent."""
        ...

    async def release_all_pending(self) -> int:
        """Dead man's switch: put every held message back in the inbox. Returns count."""
        ...

    async def teardown(self) -> None:
        """Remove the HOLD rule so mail flows normally. Labels stay."""
        ...


# ---------------------------------------------------------------------------
# Reading and tidying mail from inside Secureddy
# ---------------------------------------------------------------------------

SEARCH_MAX = 25


@dataclass(frozen=True)
class SearchHit:
    """One result of a live provider search. Nothing here is stored: the web
    page shows it, matches it to a checked email by ``provider_message_id``
    and offers "Check now" for the rest."""

    provider_message_id: str
    from_name: str
    from_address: str
    subject: str
    received_at: datetime | None
    snippet: str = ""
    unread: bool = False


def split_from(value: str | None) -> tuple[str, str]:
    """``"Ann <ann@x.com>"`` -> ("Ann", "ann@x.com")."""
    name, address = parseaddr(value or "")
    return name.strip(), address.strip().lower()


def clean_query(query: str, limit: int = 200) -> str:
    """A search phrase safe to hand to any provider: no quotes, backslashes or
    control characters, single spaces, at most ``limit`` characters."""
    text = "".join(ch for ch in (query or "") if ch.isprintable() and ch not in '"\\')
    return " ".join(text.split())[:limit]


@runtime_checkable
class MailActions(Protocol):
    """What the web app asks of a connector beyond checking mail: search,
    archive, read/unread, move to the provider's Trash, a link to the message
    in the provider's own web app, and revoking our access ("Sign out of this
    mailbox"). Gmail, Microsoft Graph and IMAP implement it."""

    async def search(self, query: str, limit: int = 20) -> list[SearchHit]: ...

    async def archive(self, provider_message_id: str) -> None: ...

    async def set_read(self, provider_message_id: str, read: bool) -> None: ...

    async def trash(self, provider_message_id: str) -> None: ...

    async def web_link(self, provider_message_id: str) -> str: ...

    async def revoke(self) -> bool:
        """Revoke our grant where the provider allows it. True when revoked."""
        ...

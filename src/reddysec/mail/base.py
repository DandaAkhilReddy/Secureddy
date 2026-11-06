"""The connector contract every mailbox provider implements.

Label/folder names we create in the client's mailbox. They are visible to the
client on purpose: the product should feel like a bodyguard standing in the
room, not a hidden camera.
"""

from __future__ import annotations

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

    async def apply_verdict(self, msg: RawMessage, verdict: Verdict, policy: PolicyConfig) -> None:
        """Label the message by verdict; quarantine it if level >= policy.quarantine_at;
        in HOLD mode move it from LABEL_PENDING to the inbox unless quarantined."""
        ...

    async def release(self, provider_message_id: str) -> None:
        """Move a held message to the inbox (keeps our labels)."""
        ...

    async def quarantine(self, provider_message_id: str) -> None: ...

    async def restore(self, provider_message_id: str) -> None:
        """Undo a quarantine at the client's request; adds LABEL_RELEASED."""
        ...

    async def release_all_pending(self) -> int:
        """Dead man's switch: put every held message back in the inbox. Returns count."""
        ...

    async def teardown(self) -> None:
        """Remove the HOLD rule so mail flows normally. Labels stay."""
        ...

"""Credential vault: encrypted mailbox secrets at rest.

A mailbox secret is a small JSON document (Google refresh token, IMAP app
password). It is encrypted with the envelope cipher in ``core.crypto`` using
the mailbox id as additional authenticated data, so a ciphertext copied from
one mailbox row to another fails to decrypt instead of silently granting
access to the wrong account. The vault never logs or returns ciphertext.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from reddysec.config import Settings
from reddysec.core.crypto import DecryptError, TokenCipher
from reddysec.store.models import MailboxSecret, utcnow

KIND_GOOGLE_OAUTH = "google_oauth"
KIND_IMAP_PASSWORD = "imap_password"
KIND_IMAP_OAUTH = "imap_oauth"


class VaultError(Exception):
    """The secret exists but cannot be used (undecryptable, corrupt)."""


class SecretNotFound(VaultError, LookupError):
    """No secret is stored for this mailbox."""


def cipher_from_settings(settings: Settings) -> TokenCipher:
    """Production uses RS_TOKEN_KEK (32 random bytes); development derives a
    key from RS_SECRET_KEY so a fresh checkout works without ceremony."""
    return TokenCipher.from_settings(
        settings.token_kek.get_secret_value(),
        settings.secret_key.get_secret_value(),
        settings.token_kek_previous.get_secret_value(),
    )


class CredentialVault:
    def __init__(self, cipher: TokenCipher):
        self._cipher = cipher

    async def store(
        self, session: AsyncSession, mailbox_id: str, kind: str, secret: Mapping[str, Any]
    ) -> MailboxSecret:
        """Encrypt and upsert. The row is flushed, not committed: the caller's
        transaction decides when it becomes visible, so a failed onboarding
        does not leave a secret behind for a mailbox row that was rolled back."""
        plaintext = json.dumps(dict(secret), separators=(",", ":"), sort_keys=True)
        ciphertext = self._cipher.encrypt(plaintext, aad=mailbox_id)
        row = await session.get(MailboxSecret, mailbox_id)
        if row is None:
            row = MailboxSecret(
                mailbox_id=mailbox_id, kind=kind, ciphertext=ciphertext, key_id=self._cipher.current_key_id
            )
            session.add(row)
        else:
            row.kind = kind
            row.ciphertext = ciphertext
            row.key_id = self._cipher.current_key_id
            row.updated_at = utcnow()
        await session.flush()
        return row

    def open(self, row: MailboxSecret) -> tuple[str, dict[str, Any]]:
        """Decrypt an already-loaded row (no session needed)."""
        try:
            plaintext = self._cipher.decrypt(row.ciphertext, aad=row.mailbox_id)
            secret = json.loads(plaintext)
        except (DecryptError, json.JSONDecodeError) as exc:
            raise VaultError(f"secret for mailbox {row.mailbox_id} cannot be decrypted") from exc
        if not isinstance(secret, dict):
            raise VaultError(f"secret for mailbox {row.mailbox_id} has an unexpected shape")
        return row.kind, secret

    async def load(self, session: AsyncSession, mailbox_id: str) -> tuple[str, dict[str, Any]]:
        row = await session.get(MailboxSecret, mailbox_id)
        if row is None:
            raise SecretNotFound(f"no credentials stored for mailbox {mailbox_id}")
        return self.open(row)

    async def delete(self, session: AsyncSession, mailbox_id: str) -> bool:
        row = await session.get(MailboxSecret, mailbox_id)
        if row is None:
            return False
        await session.delete(row)
        await session.flush()
        return True

    async def rotate_if_needed(self, session: AsyncSession, mailbox_id: str) -> bool:
        """Re-encrypt under the current key if the row still uses an old one.
        Returns True when a rewrite happened. Called by a background job after
        a KEK rotation; cheap to call any time."""
        row = await session.get(MailboxSecret, mailbox_id)
        if row is None:
            raise SecretNotFound(f"no credentials stored for mailbox {mailbox_id}")
        if not self._cipher.needs_rotation(row.ciphertext):
            return False
        kind, secret = self.open(row)
        await self.store(session, mailbox_id, kind, secret)
        return True

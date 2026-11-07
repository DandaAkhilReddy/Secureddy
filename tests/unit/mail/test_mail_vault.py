"""CredentialVault against the real schema on SQLite."""

from __future__ import annotations

import os

import pytest

from reddysec.config import Settings
from reddysec.core.crypto import TokenCipher
from reddysec.mail.vault import (
    KIND_GOOGLE_OAUTH,
    KIND_IMAP_PASSWORD,
    CredentialVault,
    SecretNotFound,
    VaultError,
    cipher_from_settings,
)
from reddysec.store import repo
from reddysec.store.models import MailboxSecret


async def _mailbox(db) -> str:
    async with db.session() as s:
        user = await repo.create_user(s, email="c@example.com", display_name="C")
        mbx = await repo.create_mailbox(s, user_id=user.id, provider="gmail", address="c@gmail.com")
        return mbx.id


class TestVault:
    async def test_store_load_roundtrip_and_upsert(self, db):
        vault = CredentialVault(TokenCipher({"k1": os.urandom(32)}, "k1"))
        mailbox_id = await _mailbox(db)
        async with db.session() as s:
            row = await vault.store(s, mailbox_id, KIND_GOOGLE_OAUTH, {"refresh_token": "refresh-r1", "n": 1})
            assert row.key_id == "k1" and row.ciphertext.startswith("v1.k1.")
            assert "refresh-r1" not in row.ciphertext  # (a 2-letter needle matched random base64 now and then)
        async with db.session() as s:
            assert await vault.load(s, mailbox_id) == (KIND_GOOGLE_OAUTH, {"refresh_token": "refresh-r1", "n": 1})
            await vault.store(s, mailbox_id, KIND_IMAP_PASSWORD, {"username": "u", "password": "p"})
        async with db.session() as s:
            kind, secret = await vault.load(s, mailbox_id)
            assert kind == KIND_IMAP_PASSWORD and secret == {"username": "u", "password": "p"}
            # exactly one row per mailbox
            assert (await s.get(MailboxSecret, mailbox_id)) is not None

    async def test_missing_secret(self, db):
        vault = CredentialVault(TokenCipher({"k1": os.urandom(32)}, "k1"))
        mailbox_id = await _mailbox(db)
        async with db.session() as s:
            with pytest.raises(SecretNotFound):
                await vault.load(s, mailbox_id)
            with pytest.raises(SecretNotFound):
                await vault.rotate_if_needed(s, mailbox_id)
            assert await vault.delete(s, mailbox_id) is False

    async def test_ciphertext_is_bound_to_mailbox_id(self, db):
        """Copying a ciphertext from one mailbox row to another must fail."""
        cipher = TokenCipher({"k1": os.urandom(32)}, "k1")
        vault = CredentialVault(cipher)
        a = await _mailbox(db)
        async with db.session() as s:
            user = await repo.create_user(s, email="d@example.com", display_name="D")
            b = (await repo.create_mailbox(s, user_id=user.id, provider="gmail", address="d@gmail.com")).id
            row_a = await vault.store(s, a, KIND_GOOGLE_OAUTH, {"refresh_token": "secret"})
            s.add(
                MailboxSecret(mailbox_id=b, kind=KIND_GOOGLE_OAUTH, ciphertext=row_a.ciphertext, key_id="k1")
            )
        async with db.session() as s:
            with pytest.raises(VaultError):
                await vault.load(s, b)

    async def test_corrupt_shapes_raise_vault_error(self, db):
        cipher = TokenCipher({"k1": os.urandom(32)}, "k1")
        vault = CredentialVault(cipher)
        mailbox_id = await _mailbox(db)
        async with db.session() as s:
            s.add(
                MailboxSecret(
                    mailbox_id=mailbox_id,
                    kind="x",
                    ciphertext=cipher.encrypt("[1,2]", aad=mailbox_id),
                    key_id="k1",
                )
            )
        async with db.session() as s:
            with pytest.raises(VaultError, match="shape"):
                await vault.load(s, mailbox_id)
            row = await s.get(MailboxSecret, mailbox_id)
            row.ciphertext = cipher.encrypt("not json", aad=mailbox_id)
        async with db.session() as s:
            with pytest.raises(VaultError, match="decrypted"):
                await vault.load(s, mailbox_id)

    async def test_delete(self, db):
        vault = CredentialVault(TokenCipher({"k1": os.urandom(32)}, "k1"))
        mailbox_id = await _mailbox(db)
        async with db.session() as s:
            await vault.store(s, mailbox_id, KIND_GOOGLE_OAUTH, {"refresh_token": "r1"})
        async with db.session() as s:
            assert await vault.delete(s, mailbox_id) is True
        async with db.session() as s:
            with pytest.raises(SecretNotFound):
                await vault.load(s, mailbox_id)

    async def test_rotate_if_needed(self, db):
        old, new = os.urandom(32), os.urandom(32)
        mailbox_id = await _mailbox(db)
        async with db.session() as s:
            await CredentialVault(TokenCipher({"k1": old}, "k1")).store(
                s, mailbox_id, KIND_GOOGLE_OAUTH, {"t": 1}
            )
        rotated = CredentialVault(TokenCipher({"k1": old, "k2": new}, "k2"))
        async with db.session() as s:
            assert await rotated.rotate_if_needed(s, mailbox_id) is True
        async with db.session() as s:
            row = await s.get(MailboxSecret, mailbox_id)
            assert row.key_id == "k2"
            assert await rotated.load(s, mailbox_id) == (KIND_GOOGLE_OAUTH, {"t": 1})
            assert await rotated.rotate_if_needed(s, mailbox_id) is False


def test_cipher_from_settings_dev_and_prod():
    dev = cipher_from_settings(Settings(secret_key="abc", token_kek=""))
    assert dev.current_key_id == "dev"
    import base64

    new_kek = base64.b64encode(os.urandom(32)).decode()
    old_kek = base64.b64encode(os.urandom(32)).decode()
    prod = cipher_from_settings(Settings(secret_key="abc", token_kek=new_kek))
    assert prod.current_key_id.startswith("k") and prod.current_key_id != "dev"
    # A rotation window: the previous key still decrypts, the new key signs.
    rotating = cipher_from_settings(Settings(secret_key="abc", token_kek=new_kek, token_kek_previous=old_kek))
    legacy = cipher_from_settings(Settings(secret_key="abc", token_kek=old_kek)).encrypt("t", aad="m")
    assert rotating.decrypt(legacy, aad="m") == "t" and rotating.needs_rotation(legacy)
    assert rotating.current_key_id == prod.current_key_id

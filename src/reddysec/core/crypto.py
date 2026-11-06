"""Envelope encryption for secrets at rest (OAuth refresh tokens, IMAP app
passwords).

Format of a ciphertext: ``v1.<key_id>.<base64(nonce || aes-gcm ciphertext)>``.
The key id lets us rotate the KEK: new writes use the current key, old rows
still decrypt until re-encrypted by a background job.

In production the KEK comes from Azure Key Vault (see infra/azure). In
development it is derived from RS_SECRET_KEY so nothing breaks out of the box.
"""

from __future__ import annotations

import base64
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class DecryptError(Exception):
    pass


def derive_dev_key(secret: str) -> bytes:
    """Deterministic 32-byte key for development only."""
    return hashlib.sha256(b"reddysec-dev-kek:" + secret.encode()).digest()


def key_id_for(key: bytes) -> str:
    """Stable, non-secret identifier for a key: a short hash of its bytes."""
    return "k" + hashlib.sha256(b"reddysec-kek-id:" + key).hexdigest()[:8]


def key_from_b64(value: str) -> bytes:
    raw = base64.b64decode(value)
    if len(raw) != 32:
        raise ValueError("KEK must be exactly 32 bytes")
    return raw


class TokenCipher:
    def __init__(self, keys: dict[str, bytes], current_key_id: str):
        if current_key_id not in keys:
            raise ValueError("current_key_id must be present in keys")
        for kid, key in keys.items():
            if len(key) != 32:
                raise ValueError(f"key {kid!r} must be 32 bytes")
        self._keys = dict(keys)
        self._current = current_key_id

    @classmethod
    def from_settings(cls, token_kek_b64: str, secret_key: str, previous_kek_b64: str = "") -> TokenCipher:
        """Build the cipher from configuration.

        Key ids are derived from the key material (first 8 hex chars of its
        SHA-256), so a ciphertext written under a KEK stays decryptable by any
        process that still holds that KEK, under any name. Rotation: set the
        new key as ``token_kek`` and the old one as ``token_kek_previous``,
        re-encrypt rows where ``needs_rotation`` is true, then drop the old key.
        """
        if token_kek_b64:
            current = key_from_b64(token_kek_b64)
            keys = {key_id_for(current): current}
            if previous_kek_b64:
                previous = key_from_b64(previous_kek_b64)
                keys.setdefault(key_id_for(previous), previous)
            return cls(keys, key_id_for(current))
        return cls({"dev": derive_dev_key(secret_key)}, "dev")

    @property
    def current_key_id(self) -> str:
        return self._current

    def encrypt(self, plaintext: str, aad: str = "") -> str:
        nonce = os.urandom(12)
        ct = AESGCM(self._keys[self._current]).encrypt(nonce, plaintext.encode(), aad.encode())
        return f"v1.{self._current}." + base64.urlsafe_b64encode(nonce + ct).decode()

    def decrypt(self, token: str, aad: str = "") -> str:
        try:
            version, kid, body = token.split(".", 2)
        except ValueError as e:
            raise DecryptError("malformed ciphertext") from e
        if version != "v1":
            raise DecryptError(f"unsupported version {version!r}")
        key = self._keys.get(kid)
        if key is None:
            raise DecryptError(f"unknown key id {kid!r}")
        raw = base64.urlsafe_b64decode(body)
        if len(raw) < 13:
            raise DecryptError("ciphertext too short")
        try:
            return AESGCM(key).decrypt(raw[:12], raw[12:], aad.encode()).decode()
        except InvalidTag as e:
            raise DecryptError("authentication failed") from e

    def needs_rotation(self, token: str) -> bool:
        parts = token.split(".", 2)
        return len(parts) == 3 and parts[1] != self._current


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

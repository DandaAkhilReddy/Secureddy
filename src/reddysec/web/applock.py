"""App lock: a PIN, a password or a passkey between an unlocked phone and
someone's mail.

* The secret is a 6-digit PIN or a password of 8+ characters, stored as an
  argon2id hash in ``app_locks``. Passkeys (WebAuthn, ``user_passkeys``) can
  unlock too, alone or alongside it.
* When the app locks: after a chosen time without use ("When I open the app"
  = one minute away, 5 minutes, 1 hour, 1 day). Lock state is on the server
  session (``web.sessions``), never a flag in the browser.
* Wrong answers are counted per person: after 5, a 15-minute pause; after 10,
  every device is signed out and the person must sign in again with Google,
  Microsoft, Yahoo or their password. "Forgot PIN" is the same sign-in.
* Changing or removing the lock signs out every other device.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from reddysec.core.ids import new_id
from reddysec.store.models import AppLockRow, PasskeyRow, UserRow, UserSessionRow

from .sessions import revoke_user_sessions

PIN_RE = re.compile(r"^\d{6}$")
PASSWORD_MIN = 8
COOLDOWN_AFTER = 5
COOLDOWN = timedelta(minutes=15)
SIGN_OUT_AFTER = 10
CHALLENGE_TTL_S = 300
SESSION_CHALLENGE = "webauthn"

TIMEOUTS: tuple[tuple[str, int, str], ...] = (
    ("open", 60, "When I open the app"),
    ("5m", 300, "After 5 minutes"),
    ("1h", 3600, "After 1 hour"),
    ("1d", 86400, "After 1 day"),
)
TIMEOUT_SECONDS = {key: seconds for key, seconds, _ in TIMEOUTS}
KINDS = ("pin", "password", "passkey")

_hasher = PasswordHasher()  # argon2id


def timeout_key(seconds: int) -> str:
    for key, value, _label in TIMEOUTS:
        if value == seconds:
            return key
    return "5m"


def hash_secret(value: str) -> str:
    return _hasher.hash(value)


def verify_secret(stored: str | None, value: str) -> bool:
    if not stored or not value:
        return False
    try:
        return _hasher.verify(stored, value)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def validate_secret(kind: str, value: str, confirm: str) -> str | None:
    """A plain-English problem with a new PIN or password, or None."""
    if kind == "pin":
        if not PIN_RE.match(value):
            return "Your PIN must be exactly 6 digits."
        if len(set(value)) == 1 or value in ("123456", "654321", "012345"):
            return "That PIN is too easy to guess. Please choose another."
    elif kind == "password":
        if len(value) < PASSWORD_MIN:
            return f"Your password must be at least {PASSWORD_MIN} characters."
    else:
        return "Please choose a PIN or a password."
    if value != confirm:
        return "The two entries did not match."
    return None


async def get_lock(session: AsyncSession, user_id: str) -> AppLockRow | None:
    return await session.get(AppLockRow, user_id)


async def list_passkeys(session: AsyncSession, user_id: str) -> list[PasskeyRow]:
    rows = await session.execute(select(PasskeyRow).where(PasskeyRow.user_id == user_id).order_by(PasskeyRow.created_at))
    return list(rows.scalars())


async def set_lock(
    session: AsyncSession, user: UserRow, *, kind: str, secret: str | None, timeout_s: int, keep_session: str | None
) -> int:
    """Turn the lock on or change it. Signs out every other device; returns how many."""
    now = datetime.now(UTC)
    lock = await get_lock(session, user.id)
    if lock is None:
        lock = AppLockRow(user_id=user.id, created_at=now)
        session.add(lock)
    lock.kind = kind
    lock.secret_hash = hash_secret(secret) if secret else None
    lock.timeout_s = timeout_s
    lock.failed_attempts = 0
    lock.locked_until = None
    lock.updated_at = now
    return await revoke_user_sessions(session, user.id, "app_lock_changed", keep=keep_session, now=now)


async def remove_lock(session: AsyncSession, user: UserRow, *, keep_session: str | None) -> int:
    lock = await get_lock(session, user.id)
    if lock is None:
        return 0
    await session.delete(lock)
    return await revoke_user_sessions(session, user.id, "app_lock_changed", keep=keep_session)


@dataclass(frozen=True)
class UnlockResult:
    outcome: str  # ok | wrong | cooldown | signed_out | not_locked
    until: datetime | None = None
    left: int = 0


async def try_unlock(
    session: AsyncSession, user_id: str, session_id: str, value: str, *, now: datetime | None = None
) -> UnlockResult:
    """Check a PIN or password for a locked session, counting failures."""
    now = now or datetime.now(UTC)
    lock = await get_lock(session, user_id)
    if lock is None:
        await mark_unlocked(session, session_id, now)
        return UnlockResult("not_locked")
    until = lock.locked_until if lock.locked_until is None or lock.locked_until.tzinfo else lock.locked_until.replace(tzinfo=UTC)
    if until is not None and until > now:
        return UnlockResult("cooldown", until=until)
    if lock.secret_hash and verify_secret(lock.secret_hash, value):
        lock.failed_attempts = 0
        lock.locked_until = None
        await mark_unlocked(session, session_id, now)
        return UnlockResult("ok")
    return await record_failure(session, lock, user_id, now)


async def record_failure(session: AsyncSession, lock: AppLockRow, user_id: str, now: datetime) -> UnlockResult:
    lock.failed_attempts = int(lock.failed_attempts or 0) + 1
    if lock.failed_attempts >= SIGN_OUT_AFTER:
        lock.failed_attempts = 0
        lock.locked_until = None
        await revoke_user_sessions(session, user_id, "too_many_pins", now=now)
        return UnlockResult("signed_out")
    if lock.failed_attempts % COOLDOWN_AFTER == 0:
        lock.locked_until = now + COOLDOWN
        return UnlockResult("cooldown", until=lock.locked_until)
    left = COOLDOWN_AFTER - (lock.failed_attempts % COOLDOWN_AFTER)
    return UnlockResult("wrong", left=left)


async def mark_unlocked(session: AsyncSession, session_id: str, now: datetime) -> None:
    row = await session.get(UserSessionRow, session_id)
    if row is not None:
        row.unlocked_at = now
        row.last_active_at = now


async def lock_now(session: AsyncSession, session_id: str) -> None:
    row = await session.get(UserSessionRow, session_id)
    if row is not None:
        row.unlocked_at = None


# --------------------------------------------------------------------------- passkeys (WebAuthn)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def relying_party(base_url: str) -> tuple[str, str]:
    """(rp id, expected origin) from the public base URL."""
    parts = urlsplit(base_url)
    return (parts.hostname or "localhost"), f"{parts.scheme}://{parts.netloc}"


def remember_challenge(flow: dict[str, Any], challenge: bytes, purpose: str) -> None:
    flow[SESSION_CHALLENGE] = {"c": b64url(challenge), "p": purpose, "exp": int(time.time()) + CHALLENGE_TTL_S}


def take_challenge(flow: dict[str, Any], purpose: str) -> bytes | None:
    """The pending challenge for ``purpose``, used once."""
    data = flow.pop(SESSION_CHALLENGE, None)
    if not isinstance(data, dict) or data.get("p") != purpose or int(data.get("exp", 0)) < time.time():
        return None
    try:
        return b64url_decode(str(data.get("c", "")))
    except (ValueError, TypeError):
        return None


def registration_options(base_url: str, user: UserRow, existing: list[PasskeyRow]) -> tuple[str, bytes]:
    from webauthn import generate_registration_options, options_to_json
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        PublicKeyCredentialDescriptor,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )

    rp_id, _origin = relying_party(base_url)
    challenge = secrets.token_bytes(32)
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name="Secureddy",
        user_id=user.id.encode(),
        user_name=user.login_email,
        user_display_name=user.display_name,
        challenge=challenge,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=b64url_decode(p.credential_id)) for p in existing],
    )
    return options_to_json(options), challenge


def verify_registration(base_url: str, credential: dict[str, Any] | str, challenge: bytes) -> tuple[str, str, int]:
    """(credential id, public key, sign count), base64url. Raises on any problem."""
    from webauthn import verify_registration_response

    rp_id, origin = relying_party(base_url)
    verified = verify_registration_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=rp_id,
        expected_origin=origin,
        require_user_verification=True,
    )
    return b64url(verified.credential_id), b64url(verified.credential_public_key), int(verified.sign_count)


def authentication_options(base_url: str, passkeys: list[PasskeyRow]) -> tuple[str, bytes]:
    from webauthn import generate_authentication_options, options_to_json
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement

    rp_id, _origin = relying_party(base_url)
    challenge = secrets.token_bytes(32)
    options = generate_authentication_options(
        rp_id=rp_id,
        challenge=challenge,
        allow_credentials=[PublicKeyCredentialDescriptor(id=b64url_decode(p.credential_id)) for p in passkeys],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return options_to_json(options), challenge


def credential_id_of(credential: dict[str, Any] | str) -> str:
    data = json.loads(credential) if isinstance(credential, str) else credential
    raw = data.get("rawId") or data.get("id") or ""
    return str(raw)


def verify_authentication(
    base_url: str, credential: dict[str, Any] | str, challenge: bytes, passkey: PasskeyRow
) -> int:
    """The new sign count. Raises on any problem."""
    from webauthn import verify_authentication_response

    rp_id, origin = relying_party(base_url)
    verified = verify_authentication_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=rp_id,
        expected_origin=origin,
        credential_public_key=b64url_decode(passkey.public_key),
        credential_current_sign_count=int(passkey.sign_count or 0),
        require_user_verification=True,
    )
    return int(verified.new_sign_count)


async def add_passkey(
    session: AsyncSession, user: UserRow, *, credential_id: str, public_key: str, sign_count: int, name: str
) -> PasskeyRow:
    row = PasskeyRow(
        id=new_id("pky"),
        user_id=user.id,
        credential_id=credential_id,
        public_key=public_key,
        sign_count=sign_count,
        name=(name.strip() or "Passkey")[:100],
        created_at=datetime.now(UTC),
    )
    session.add(row)
    return row


__all__ = [
    "KINDS",
    "TIMEOUTS",
    "TIMEOUT_SECONDS",
    "UnlockResult",
    "add_passkey",
    "authentication_options",
    "get_lock",
    "list_passkeys",
    "lock_now",
    "registration_options",
    "remove_lock",
    "set_lock",
    "try_unlock",
    "validate_secret",
    "verify_authentication",
    "verify_registration",
]

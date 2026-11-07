"""Two-step sign-in with an authenticator app (TOTP, RFC 6238).

Works with Microsoft Authenticator, Google Authenticator, Authy, 1Password and
any app that reads an ``otpauth://totp/...`` QR code: 6 digits, 30 seconds,
SHA-1 (the defaults every app supports).

* **Setup** (Settings → Security → Two-step sign-in): a secret is parked in
  the flow cookie, shown as a QR code (inline SVG, drawn here) and as a key in
  groups of four, and stored (encrypted, ``users.totp_secret_enc``) only after
  the person types a code from their app. Ten recovery codes are shown once
  and kept as argon2id hashes.
* **Every sign-in** (Google, Microsoft, Yahoo, password) of a person with it
  on stops at ``/auth/mfa`` before any session exists: who is signing in, the
  method and where to go next wait in the signed flow cookie for ten minutes.
  A code or a recovery code finishes the sign-in. "Remember this device for 30
  days" stores a random token's hash (``mfa_trusted_devices``), so that
  browser skips the step until it expires, the device is signed out, or
  two-step sign-in is turned off.
* **Codes are accepted once.** ``user_mfa.last_step`` is the time step of the
  last accepted code: the same code (or an older one) is refused, even within
  its 30 seconds. One step of clock drift either way is allowed.
* **Rate limit**: 5 wrong codes in 15 minutes pause code entry for the rest of
  those 15 minutes, per person (not per device), for sign-in, unlocking and
  turning the feature off alike.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from reddysec.core.ids import new_id
from reddysec.store.models import MfaStateRow, RecoveryCodeRow, TrustedDeviceRow, UserRow

ISSUER = "Secureddy"
STEP_S = 30
DRIFT_STEPS = 1
MAX_ATTEMPTS = 5
WINDOW = timedelta(minutes=15)
RECOVERY_COUNT = 10
RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o, 1/l/i
RECOVERY_HALF = 5
REMEMBER_DAYS = 30
PENDING_TTL_S = 600
SESSION_KEY = "mfa"  # pending sign-in in the flow cookie
SETUP_KEY = "totp_pending"  # secret being set up, in the flow cookie
TRUST_COOKIE = "rs_mfa_dev"

# Recovery codes are 50 random bits each, so a light argon2id setting is
# plenty and keeps checking ten of them quick.
_recovery_hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)


def utcnow() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


# --------------------------------------------------------------------------- codes


def new_secret() -> str:
    return pyotp.random_base32()


def otpauth_uri(secret: str, account: str) -> str:
    """``otpauth://totp/Secureddy:<email>?secret=...&issuer=Secureddy``."""
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name=ISSUER)


def grouped(secret: str) -> str:
    """Base32 in groups of four is what people can actually type."""
    return " ".join(secret[i : i + 4] for i in range(0, len(secret), 4))


def digits_of(code: str | None) -> str:
    return "".join(ch for ch in (code or "") if ch.isdigit())


def matching_step(secret: str, code: str | None, *, now: float | None = None) -> int | None:
    """The time step whose code is ``code`` (now, or one step either side),
    or None. Compared in constant time."""
    digits = digits_of(code)
    if not secret or len(digits) != 6 or len(code or "") > 12:
        return None
    totp = pyotp.TOTP(secret)
    at = time.time() if now is None else now
    current = int(at // STEP_S)
    found = None
    for step in range(current - DRIFT_STEPS, current + DRIFT_STEPS + 1):
        if hmac.compare_digest(totp.generate_otp(step), digits):
            found = step
    return found


def qr_svg(data: str, *, label: str = "QR code") -> str:
    """The QR code as one inline SVG ``<path>`` (no styles, no scripts, so it
    passes our CSP), dark modules on a white quiet zone."""
    import qrcode
    from markupsafe import escape

    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=4, box_size=1)
    qr.add_data(data)
    qr.make(fit=True)
    matrix = qr.get_matrix()  # includes the border
    size = len(matrix)
    parts = []
    for y, row in enumerate(matrix):
        x = 0
        while x < size:
            if row[x]:
                start = x
                while x < size and row[x]:
                    x += 1
                parts.append(f"M{start} {y}h{x - start}v1h-{x - start}z")
            else:
                x += 1
    return (
        f'<svg class="qr" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" '
        f'role="img" aria-label="{escape(label)}" shape-rendering="crispEdges">'
        f'<rect class="qr-bg" width="{size}" height="{size}"/>'
        f'<path class="qr-fg" d="{"".join(parts)}"/></svg>'
    )


# --------------------------------------------------------------------------- recovery codes


def new_recovery_codes(n: int = RECOVERY_COUNT) -> list[str]:
    """``abcde-fghjk``: easy to read aloud and to type on a phone."""
    out = []
    for _ in range(n):
        raw = "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(2 * RECOVERY_HALF))
        out.append(f"{raw[:RECOVERY_HALF]}-{raw[RECOVERY_HALF:]}")
    return out


def normalize_recovery(code: str | None) -> str:
    raw = "".join(ch for ch in (code or "").lower() if ch.isalnum())
    if len(raw) != 2 * RECOVERY_HALF or any(ch not in RECOVERY_ALPHABET for ch in raw):
        return ""
    return f"{raw[:RECOVERY_HALF]}-{raw[RECOVERY_HALF:]}"


async def replace_recovery_codes(session: AsyncSession, user_id: str, codes: list[str]) -> None:
    await session.execute(delete(RecoveryCodeRow).where(RecoveryCodeRow.user_id == user_id))
    now = utcnow()
    for code in codes:
        session.add(RecoveryCodeRow(id=new_id("rcv"), user_id=user_id, code_hash=_recovery_hasher.hash(code),
                                    created_at=now))


async def recovery_codes_left(session: AsyncSession, user_id: str) -> int:
    rows = await session.execute(
        select(RecoveryCodeRow.id).where(RecoveryCodeRow.user_id == user_id, RecoveryCodeRow.used_at.is_(None))
    )
    return len(rows.all())


async def _use_recovery_code(session: AsyncSession, user_id: str, code: str, now: datetime) -> bool:
    rows = (
        await session.execute(
            select(RecoveryCodeRow).where(RecoveryCodeRow.user_id == user_id, RecoveryCodeRow.used_at.is_(None))
        )
    ).scalars()
    for row in rows:
        try:
            if _recovery_hasher.verify(row.code_hash, code):
                row.used_at = now
                return True
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            continue
    return False


def recovery_text(codes: list[str], account: str) -> str:
    """The .txt a person downloads next to the codes."""
    lines = [
        "Secureddy recovery codes",
        f"Account: {account}",
        "",
        "Each code works once, if you cannot use your authenticator app.",
        "Keep them somewhere safe, like a password manager or a printed copy at home.",
        "",
        *codes,
        "",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------- checking a code


@dataclass(frozen=True)
class CheckResult:
    outcome: str  # ok | recovery | wrong | reused | limited
    left: int = 0  # tries left before the pause (wrong / reused)
    until: datetime | None = None  # end of the pause (limited)
    recovery_left: int = 0  # codes left after a recovery code was used

    @property
    def ok(self) -> bool:
        return self.outcome in ("ok", "recovery")


async def _state(session: AsyncSession, user_id: str) -> MfaStateRow:
    row = await session.get(MfaStateRow, user_id)
    if row is None:
        row = MfaStateRow(user_id=user_id, last_step=0, failed_attempts=0, updated_at=utcnow())
        session.add(row)
    return row


def _paused(state: MfaStateRow, now: datetime) -> datetime | None:
    until = _aware(state.locked_until)
    return until if until is not None and until > now else None


async def _fail(state: MfaStateRow, outcome: str, now: datetime) -> CheckResult:
    started = _aware(state.window_started_at)
    if started is None or now - started >= WINDOW:
        state.window_started_at = now
        state.failed_attempts = 0
        started = now
    state.failed_attempts = int(state.failed_attempts or 0) + 1
    state.updated_at = now
    if state.failed_attempts >= MAX_ATTEMPTS:
        state.locked_until = started + WINDOW
        return CheckResult("limited", until=state.locked_until)
    return CheckResult(outcome, left=MAX_ATTEMPTS - state.failed_attempts)


def _succeed(state: MfaStateRow, now: datetime) -> None:
    state.failed_attempts = 0
    state.window_started_at = None
    state.locked_until = None
    state.updated_at = now


async def check_code(
    session: AsyncSession,
    user: UserRow,
    secret: str,
    code: str | None,
    *,
    allow_recovery: bool = True,
    now: datetime | None = None,
) -> CheckResult:
    """Check an authenticator code (or, when allowed, a recovery code) for
    ``user``, applying the replay rule and the rate limit."""
    now = now or utcnow()
    state = await _state(session, user.id)
    until = _paused(state, now)
    if until is not None:
        return CheckResult("limited", until=until)
    if digits_of(code) and len(digits_of(code)) == 6 and not normalize_recovery(code):
        step = matching_step(secret, code, now=now.timestamp())
        if step is None:
            return await _fail(state, "wrong", now)
        if step <= int(state.last_step or 0):
            return await _fail(state, "reused", now)
        state.last_step = step
        _succeed(state, now)
        return CheckResult("ok")
    recovery = normalize_recovery(code) if allow_recovery else ""
    if recovery and await _use_recovery_code(session, user.id, recovery, now):
        _succeed(state, now)
        await session.flush()
        return CheckResult("recovery", recovery_left=await recovery_codes_left(session, user.id))
    return await _fail(state, "wrong", now)


def result_message(result: CheckResult, *, what: str = "code") -> str:
    """Plain words for a refused code."""
    if result.outcome == "limited":
        minutes = 15
        if result.until is not None:
            minutes = max(1, int((result.until - utcnow()).total_seconds() // 60) + 1)
        return f"Too many wrong codes. Please wait {minutes} minute{'s' if minutes != 1 else ''} and try again."
    tries = f" {result.left} {'try' if result.left == 1 else 'tries'} left."
    if result.outcome == "reused":
        return "That code was already used. Wait for the next one in your app, then enter it." + tries
    return f"That {what} did not match. Check the time on your phone is set automatically." + tries


# --------------------------------------------------------------------------- remembered devices


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def trust_device(
    session: AsyncSession, user_id: str, *, session_id: str, user_agent: str, now: datetime | None = None
) -> str:
    """Remember this browser for 30 days. Returns the raw cookie token."""
    now = now or utcnow()
    token = secrets.token_urlsafe(32)
    session.add(TrustedDeviceRow(
        id=hash_token(token), user_id=user_id, session_id=session_id, user_agent=user_agent[:120],
        created_at=now, expires_at=now + timedelta(days=REMEMBER_DAYS),
    ))
    return token


async def device_is_trusted(session: AsyncSession, user_id: str, token: str | None, *, now: datetime | None = None) -> bool:
    if not token or len(token) > 200:
        return False
    row = await session.get(TrustedDeviceRow, hash_token(token))
    if row is None or row.user_id != user_id:
        return False
    expires = _aware(row.expires_at)
    return expires is not None and expires > (now or utcnow())


async def forget_devices(session: AsyncSession, user_id: str, *, session_id: str | None = None) -> int:
    """Forget every remembered device (or the one a signed-out session made)."""
    stmt = delete(TrustedDeviceRow).where(TrustedDeviceRow.user_id == user_id)
    if session_id is not None:
        stmt = stmt.where(TrustedDeviceRow.session_id == session_id)
    result = await session.execute(stmt)
    return int(result.rowcount or 0)


async def remembered_devices(session: AsyncSession, user_id: str, *, now: datetime | None = None) -> int:
    rows = await session.execute(
        select(TrustedDeviceRow.id).where(TrustedDeviceRow.user_id == user_id, TrustedDeviceRow.expires_at > (now or utcnow()))
    )
    return len(rows.all())


async def turn_off(session: AsyncSession, user: UserRow) -> None:
    """Remove the secret, the recovery codes, remembered devices and counters."""
    user.totp_secret_enc = None
    await session.execute(delete(RecoveryCodeRow).where(RecoveryCodeRow.user_id == user.id))
    await forget_devices(session, user.id)
    await session.execute(delete(MfaStateRow).where(MfaStateRow.user_id == user.id))


# --------------------------------------------------------------------------- pending sign-in


def _clock() -> float:
    return time.time()


def remember_pending(flow: dict[str, Any], user_id: str, method: str, next_url: str) -> None:
    flow[SESSION_KEY] = {"uid": user_id, "m": method[:12], "next": next_url, "exp": int(_clock()) + PENDING_TTL_S}


def pending_of(flow: dict[str, Any]) -> dict[str, Any] | None:
    data = flow.get(SESSION_KEY)
    if not isinstance(data, dict) or int(data.get("exp", 0)) < _clock() or not data.get("uid"):
        return None
    return data


__all__ = [
    "ISSUER",
    "MAX_ATTEMPTS",
    "RECOVERY_COUNT",
    "REMEMBER_DAYS",
    "TRUST_COOKIE",
    "CheckResult",
    "check_code",
    "device_is_trusted",
    "forget_devices",
    "grouped",
    "matching_step",
    "new_recovery_codes",
    "new_secret",
    "normalize_recovery",
    "otpauth_uri",
    "pending_of",
    "qr_svg",
    "recovery_codes_left",
    "recovery_text",
    "remember_pending",
    "replace_recovery_codes",
    "result_message",
    "trust_device",
    "turn_off",
]

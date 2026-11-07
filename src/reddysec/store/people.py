"""Who may have a Secureddy account: invites, the user cap and the first admin.

Secureddy is free (no payments anywhere) and run for a handful of people:
``Settings.max_users`` (5) accounts at most. With ``signup_mode`` =
``invite_only`` (the default) a sign-in that would *create* an account is let
in only when

* the identity provider verified the email (Google always does; Microsoft and
  Yahoo say so in ``email_verified``), and
* an invite for exactly that email is open (not revoked), and
* fewer than ``max_users`` accounts are active (not disabled).

``open`` (for self-hosters) drops the invite, keeps the cap. People who
already have an account are never refused here, whatever the count: this
module is consulted only when a new account would be created.

The first admin: while no active account is an admin, the account whose email
equals ``bootstrap_admin_email`` becomes admin at sign-in (and the startup
migration promotes an existing one, see ``store.migrations``). Nobody else is
ever made admin automatically. The bootstrap email counts as invited, and
while there is no admin it may sign up even when the places are full, so the
owner can always get in to run things.

Every function takes an ``AsyncSession`` and never commits (see ``store.repo``).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from reddysec.core.ids import new_id
from reddysec.store.models import InviteRow, UserRow

SIGNUP_INVITE_ONLY = "invite_only"
SIGNUP_OPEN = "open"
MAX_EMAIL = 320


def utcnow() -> datetime:
    return datetime.now(UTC)


def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def looks_like_email(email: str) -> bool:
    email = normalize_email(email)
    if not email or len(email) > MAX_EMAIL or " " in email or email.count("@") != 1:
        return False
    local, _, domain = email.partition("@")
    return bool(local) and "." in domain and not domain.startswith(".") and not domain.endswith(".")


@dataclass(frozen=True)
class SignupPolicy:
    mode: str = SIGNUP_INVITE_ONLY
    max_users: int = 5
    bootstrap_admin_email: str = ""

    @classmethod
    def from_settings(cls, settings: Any) -> SignupPolicy:
        return cls(
            mode=str(getattr(settings, "signup_mode", SIGNUP_INVITE_ONLY) or SIGNUP_INVITE_ONLY),
            max_users=max(0, int(getattr(settings, "max_users", 5))),
            bootstrap_admin_email=normalize_email(str(getattr(settings, "bootstrap_admin_email", "") or "")),
        )

    @property
    def invite_only(self) -> bool:
        return self.mode != SIGNUP_OPEN


class SignupRefused(Exception):
    """A new account may not be created. ``reason``: ``invite_needed`` (no
    open invite for this email, or the provider did not verify it) or
    ``full`` (every place is taken)."""

    def __init__(self, reason: str, email: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.email = email


# --------------------------------------------------------------------- counts
async def active_user_count(session: AsyncSession) -> int:
    """Accounts that hold a place: every account that is not disabled
    (admins included)."""
    stmt = select(func.count()).select_from(UserRow).where(UserRow.disabled.is_(False))
    return int((await session.execute(stmt)).scalar_one())


async def admin_count(session: AsyncSession) -> int:
    stmt = select(func.count()).select_from(UserRow).where(UserRow.role == "admin", UserRow.disabled.is_(False))
    return int((await session.execute(stmt)).scalar_one())


# -------------------------------------------------------------------- invites
async def open_invite_for(session: AsyncSession, email: str) -> InviteRow | None:
    """The open (not revoked, not yet used) invite for exactly this email."""
    stmt = (
        select(InviteRow)
        .where(
            InviteRow.email == normalize_email(email),
            InviteRow.revoked_at.is_(None),
            InviteRow.accepted_at.is_(None),
        )
        .order_by(InviteRow.created_at.desc())
        .limit(1)
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def create_invite(session: AsyncSession, email: str, *, invited_by: str | None) -> tuple[InviteRow, bool]:
    """Invite one email address. Idempotent: an open invite for the same
    address is returned as is. Returns (invite, created). The caller checks
    the address with :func:`looks_like_email` first."""
    email = normalize_email(email)
    if not looks_like_email(email):
        raise ValueError("not an email address")
    existing = await open_invite_for(session, email)
    if existing is not None:
        return existing, False
    row = InviteRow(id=new_id("inv"), email=email, invited_by=invited_by, created_at=utcnow())
    session.add(row)
    await session.flush()
    return row, True


async def get_invite(session: AsyncSession, invite_id: str) -> InviteRow | None:
    return await session.get(InviteRow, invite_id)


async def revoke_invite(session: AsyncSession, invite: InviteRow) -> bool:
    """Close an open invite. False when it was already used or revoked."""
    if invite.revoked_at is not None or invite.accepted_at is not None:
        return False
    invite.revoked_at = utcnow()
    await session.flush()
    return True


async def list_invites(session: AsyncSession, *, open_only: bool = True) -> list[InviteRow]:
    stmt = select(InviteRow).order_by(InviteRow.created_at.desc())
    if open_only:
        stmt = stmt.where(InviteRow.revoked_at.is_(None), InviteRow.accepted_at.is_(None))
    return list((await session.execute(stmt)).scalars())


async def accept_invite(session: AsyncSession, user: UserRow) -> InviteRow | None:
    """Mark the open invite for this account's email as used by it."""
    invite = await open_invite_for(session, user.login_email)
    if invite is not None:
        invite.accepted_at = utcnow()
        invite.accepted_by = user.id
        await session.flush()
    return invite


# --------------------------------------------------------------------- signup
async def check_signup(session: AsyncSession, policy: SignupPolicy, email: str, *, email_verified: bool) -> None:
    """Raise :class:`SignupRefused` unless a new account for ``email`` may be
    created now. Only ever called when no account has that email."""
    email = normalize_email(email)
    is_bootstrap = bool(policy.bootstrap_admin_email) and email == policy.bootstrap_admin_email
    bootstrap_now = is_bootstrap and email_verified and await admin_count(session) == 0
    if policy.invite_only:
        if not email_verified:
            raise SignupRefused("invite_needed", email)
        if not is_bootstrap and await open_invite_for(session, email) is None:
            raise SignupRefused("invite_needed", email)
    if not bootstrap_now and await active_user_count(session) >= policy.max_users:
        raise SignupRefused("full", email)


async def maybe_bootstrap_admin(session: AsyncSession, policy: SignupPolicy, user: UserRow, *, trusted: bool) -> bool:
    """Make ``user`` the first admin when no active admin exists and its email
    is the bootstrap admin email. ``trusted``: the caller confirmed the email
    of this account was verified (``web.queries.account_email_is_trusted``)."""
    if not trusted or user.disabled or user.role == "admin":
        return False
    if not policy.bootstrap_admin_email or normalize_email(user.login_email) != policy.bootstrap_admin_email:
        return False
    if await admin_count(session) > 0:
        return False
    user.role = "admin"
    await session.flush()
    return True


__all__ = [
    "SIGNUP_INVITE_ONLY",
    "SIGNUP_OPEN",
    "SignupPolicy",
    "SignupRefused",
    "accept_invite",
    "active_user_count",
    "admin_count",
    "check_signup",
    "create_invite",
    "get_invite",
    "list_invites",
    "looks_like_email",
    "maybe_bootstrap_admin",
    "normalize_email",
    "open_invite_for",
    "revoke_invite",
]

"""Admin: the people who use this Secureddy (``/admin/users``, admins only).

Secureddy is free and invite-only for a handful of people (``max_users``, 5
by default; see ``store.people``). From here an admin can:

* see everyone: name, email, ways to sign in, mailboxes, last active;
* invite someone by email ("3 of 5 places used") and withdraw an invite;
* turn an account off (its devices are signed out at once and its mailboxes
  paused) and back on (the mailboxes we paused are resumed);
* change what an account can do (member, analyst, admin).

Guard rails: nobody can turn off or demote themselves, and the last admin
stays an admin. Every action is written to the audit log. There is no
payment anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from fastapi import Depends, Form, HTTPException, Request, status
from sqlalchemy import func, select
from starlette.responses import RedirectResponse, Response

from reddysec.models import Role
from reddysec.store import people
from reddysec.store.models import AuditLog, InviteRow, MailboxRow, UserIdentityRow, UserRow, UserSessionRow

from .. import mfa, presenters, queries
from ..auth import PROVIDER_NAMES, require_role
from ..security import flash
from ..sessions import revoke_user_sessions
from ..templating import render
from . import protected_router

router = protected_router()

admin_only = require_role(Role.ADMIN)
# Roles an admin can give here. Family and assistant accounts are tied to a
# principal and are set up with ``reddysec add-user``.
ASSIGNABLE_ROLES = (Role.PRINCIPAL.value, Role.CONCIERGE.value, Role.ADMIN.value)
ROLE_HELP = {
    Role.PRINCIPAL.value: "Uses Secureddy for their own email.",
    Role.CONCIERGE.value: "Also reviews email people send to the concierge.",
    Role.ADMIN.value: "Also invites people and manages accounts here.",
}


def _see_other() -> RedirectResponse:
    return RedirectResponse("/admin/users", status_code=status.HTTP_303_SEE_OTHER)


@dataclass(frozen=True)
class PersonView:
    row: UserRow
    sign_in: list[str]
    mailboxes: list[MailboxRow]
    last_active: datetime | None
    role_name: str
    is_me: bool


async def _people(session: Any, me: UserRow) -> list[PersonView]:
    users = list((await session.execute(select(UserRow).order_by(UserRow.created_at))).scalars())
    identities: dict[str, set[str]] = {}
    for ident in (await session.execute(select(UserIdentityRow))).scalars():
        identities.setdefault(ident.user_id, set()).add(ident.provider)
    mailboxes: dict[str, list[MailboxRow]] = {}
    for mbx in (await session.execute(select(MailboxRow).order_by(MailboxRow.created_at))).scalars():
        mailboxes.setdefault(mbx.user_id, []).append(mbx)
    last_seen = dict(
        (
            await session.execute(
                select(UserSessionRow.user_id, func.max(UserSessionRow.last_seen_at)).group_by(UserSessionRow.user_id)
            )
        ).all()
    )
    out: list[PersonView] = []
    for user in users:
        providers = set(identities.get(user.id, set()))
        if user.google_sub:
            providers.add("google")
        ways = [PROVIDER_NAMES[p] for p in ("google", "microsoft", "yahoo") if p in providers]
        if user.password_hash:
            ways.append("Password")
        out.append(
            PersonView(
                row=user,
                sign_in=ways,
                mailboxes=mailboxes.get(user.id, []),
                last_active=last_seen.get(user.id),
                role_name=presenters.ROLE_NAMES.get(user.role, user.role.title()),
                is_me=user.id == me.id,
            )
        )
    return out


@router.get("/admin/users", name="admin_users")
async def admin_users(request: Request, user: UserRow = Depends(admin_only)) -> Response:
    policy = people.SignupPolicy.from_settings(request.app.state.settings)
    async with request.app.state.db.session() as session:
        persons = await _people(session, user)
        invites = await people.list_invites(session)
        used = await people.active_user_count(session)
    return render(
        request,
        "admin_users.html",
        {
            "people": persons,
            "invites": invites,
            "used": used,
            "max_users": policy.max_users,
            "full": used >= policy.max_users,
            "invite_only": policy.invite_only,
            "roles": [(r, presenters.ROLE_NAMES[r], ROLE_HELP[r]) for r in ASSIGNABLE_ROLES],
        },
    )


@router.post("/admin/invites", name="admin_invite")
async def admin_invite(request: Request, email: str = Form(""), user: UserRow = Depends(admin_only)) -> Response:
    address = people.normalize_email(email)
    if not people.looks_like_email(address):
        flash(request, "Please enter one email address, like name@gmail.com.", "error")
        return _see_other()
    policy = people.SignupPolicy.from_settings(request.app.state.settings)
    async with request.app.state.db.session() as session:
        if await queries.get_user_by_email(session, address) is not None:
            flash(request, f"{address} already has an account.", "warn")
            return _see_other()
        used = await people.active_user_count(session)
        if used >= policy.max_users:
            flash(request, f"All {policy.max_users} places are used. Turn an account off first to make room.",
                  "error")
            return _see_other()
        invite, created = await people.create_invite(session, address, invited_by=user.id)
        if created:
            queries.audit(session, actor=user, action="invite_created", target=invite.id,
                          details={"email": address})
    if created:
        flash(request, f"{address} is invited. They can now sign in with Google, Microsoft or Yahoo using that "
                       "address.")
    else:
        flash(request, f"{address} is already invited.")
    return _see_other()


@router.post("/admin/invites/{invite_id}/revoke", name="admin_invite_revoke")
async def admin_invite_revoke(request: Request, invite_id: str, user: UserRow = Depends(admin_only)) -> Response:
    async with request.app.state.db.session() as session:
        invite = await session.get(InviteRow, invite_id)
        if invite is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="We could not find that invitation.")
        revoked = await people.revoke_invite(session, invite)
        if revoked:
            queries.audit(session, actor=user, action="invite_revoked", target=invite.id,
                          details={"email": invite.email})
    flash(request, f"The invitation for {invite.email} is withdrawn." if revoked else
          "That invitation was already used or withdrawn.")
    return _see_other()


async def _target(session: Any, user_id: str) -> UserRow:
    target = await session.get(UserRow, user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="We could not find that account.")
    return target


async def _is_last_admin(session: Any, target: UserRow) -> bool:
    return target.role == Role.ADMIN.value and not target.disabled and await people.admin_count(session) <= 1


@router.post("/admin/users/{user_id}/disable", name="admin_user_disable")
async def admin_user_disable(request: Request, user_id: str, user: UserRow = Depends(admin_only)) -> Response:
    async with request.app.state.db.session() as session:
        target = await _target(session, user_id)
        if target.id == user.id:
            flash(request, "You cannot turn off your own account.", "error")
            return _see_other()
        if target.disabled:
            return _see_other()
        if await _is_last_admin(session, target):
            flash(request, "This is the last admin. Make someone else an admin first.", "error")
            return _see_other()
        target.disabled = True
        devices = await revoke_user_sessions(session, target.id, "account_disabled")
        await mfa.forget_devices(session, target.id)
        paused: list[str] = []
        for mailbox in (await session.execute(select(MailboxRow).where(MailboxRow.user_id == target.id))).scalars():
            if mailbox.status == "active":
                mailbox.status = "paused"
                paused.append(mailbox.id)
        queries.audit(session, actor=user, action="user_disabled", target=target.id,
                      details={"email": target.login_email, "devices": devices, "paused": paused})
    flash(request, f"{target.login_email} is turned off. Their devices are signed out and their mailboxes paused.",
          "warn")
    return _see_other()


@router.post("/admin/users/{user_id}/enable", name="admin_user_enable")
async def admin_user_enable(request: Request, user_id: str, user: UserRow = Depends(admin_only)) -> Response:
    async with request.app.state.db.session() as session:
        target = await _target(session, user_id)
        if not target.disabled:
            return _see_other()
        target.disabled = False
        # Resume only the mailboxes turning the account off paused.
        last = (
            await session.execute(
                select(AuditLog)
                .where(AuditLog.action == "user_disabled", AuditLog.target == target.id)
                .order_by(AuditLog.at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        paused = set((last.details or {}).get("paused", [])) if last is not None else set()
        resumed: list[str] = []
        for mailbox in (await session.execute(select(MailboxRow).where(MailboxRow.user_id == target.id))).scalars():
            if mailbox.id in paused and mailbox.status == "paused":
                mailbox.status = "active"
                mailbox.last_error = None
                resumed.append(mailbox.id)
        queries.audit(session, actor=user, action="user_enabled", target=target.id,
                      details={"email": target.login_email, "resumed": resumed})
    flash(request, f"{target.login_email} is turned back on.")
    return _see_other()


@router.post("/admin/users/{user_id}/role", name="admin_user_role")
async def admin_user_role(
    request: Request, user_id: str, role: str = Form(""), user: UserRow = Depends(admin_only)
) -> Response:
    if role not in ASSIGNABLE_ROLES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Please pick Member, Analyst or Admin.")
    async with request.app.state.db.session() as session:
        target = await _target(session, user_id)
        if target.role == role:
            return _see_other()
        if target.id == user.id:
            flash(request, "You cannot change your own role. Ask another admin.", "error")
            return _see_other()
        if role != Role.ADMIN.value and await _is_last_admin(session, target):
            flash(request, "This is the last admin. Make someone else an admin first.", "error")
            return _see_other()
        previous = target.role
        target.role = role
        queries.audit(session, actor=user, action="role_changed", target=target.id,
                      details={"email": target.login_email, "from": previous, "to": role})
    flash(request, f"{target.login_email} is now {presenters.ROLE_NAMES[role]}.")
    return _see_other()

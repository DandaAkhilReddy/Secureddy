"""Account security settings: 2-step sign-in (TOTP) and a local password.

Enrolment is two-phase on purpose. The secret is generated and parked in the
session, and only once the client proves their authenticator produces the
right code do we encrypt and store it. Storing first would lock out anyone
whose app scan failed.
"""

from __future__ import annotations

from fastapi import Depends, Form, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse, Response

from reddysec.store.models import UserRow

from .. import queries
from ..auth import PASSWORD_MIN_LENGTH, current_user, hash_password, new_totp_secret, totp_uri, verify_totp
from ..security import flash
from ..templating import THEME_COOKIE, THEMES, render
from . import protected_router

router = protected_router()

SESSION_PENDING_TOTP = "totp_pending"


def _see_other() -> RedirectResponse:
    return RedirectResponse("/settings/security", status_code=status.HTTP_303_SEE_OTHER)


async def _attach(session: AsyncSession, user: UserRow) -> UserRow:
    """Bring the signed-in account (loaded by ``current_user`` in its own
    session) into the writing transaction so changes to it are flushed."""
    return await session.merge(user)


def _grouped(secret: str) -> str:
    """Base32 in groups of four is what people can actually type."""
    return " ".join(secret[i : i + 4] for i in range(0, len(secret), 4))


@router.get("/settings/security", name="settings_security")
async def security_page(request: Request, user: UserRow = Depends(current_user)) -> Response:
    pending = None
    if not user.totp_secret_enc:
        pending = request.session.get(SESSION_PENDING_TOTP)
        if not isinstance(pending, str) or not pending:
            pending = new_totp_secret()
            request.session[SESSION_PENDING_TOTP] = pending
    return render(
        request,
        "settings_security.html",
        {
            "totp_enabled": bool(user.totp_secret_enc),
            "has_password": bool(user.password_hash),
            "otpauth_uri": totp_uri(pending, user.login_email) if pending else "",
            "manual_key": _grouped(pending) if pending else "",
            "password_min_length": PASSWORD_MIN_LENGTH,
        },
    )


@router.post("/settings/security/totp/enable", name="totp_enable")
async def totp_enable(
    request: Request, code: str = Form(""), user: UserRow = Depends(current_user)
) -> Response:
    pending = request.session.get(SESSION_PENDING_TOTP)
    if not isinstance(pending, str) or not verify_totp(pending, code):
        flash(request, "That code did not match. Check the time on your phone and try again.", "error")
        return _see_other()
    cipher = request.app.state.cipher
    async with request.app.state.db.session() as session:
        row = await _attach(session, user)
        row.totp_secret_enc = cipher.encrypt(pending, aad=row.id)
        queries.audit(session, actor=row, action="totp_enabled")
    request.session.pop(SESSION_PENDING_TOTP, None)
    flash(
        request,
        "2-step sign-in is on. You will need your authenticator app each time you sign in with a password.",
    )
    return _see_other()


@router.post("/settings/security/totp/disable", name="totp_disable")
async def totp_disable(
    request: Request, code: str = Form(""), user: UserRow = Depends(current_user)
) -> Response:
    cipher = request.app.state.cipher
    async with request.app.state.db.session() as session:
        row = await _attach(session, user)
        if not row.totp_secret_enc:
            return _see_other()
        secret = cipher.decrypt(row.totp_secret_enc, aad=row.id)
        if not verify_totp(secret, code):
            flash(request, "That code did not match, so 2-step sign-in stays on.", "error")
            return _see_other()
        row.totp_secret_enc = None
        queries.audit(session, actor=row, action="totp_disabled")
    flash(request, "2-step sign-in is off.", "warn")
    return _see_other()


@router.post("/settings/security/password", name="password_set")
async def password_set(
    request: Request,
    password: str = Form(""),
    confirm: str = Form(""),
    user: UserRow = Depends(current_user),
) -> Response:
    if len(password) < PASSWORD_MIN_LENGTH:
        flash(request, f"Please choose a password of at least {PASSWORD_MIN_LENGTH} characters.", "error")
        return _see_other()
    if password != confirm:
        flash(request, "The two passwords did not match.", "error")
        return _see_other()
    async with request.app.state.db.session() as session:
        row = await _attach(session, user)
        row.password_hash = hash_password(password)
        queries.audit(session, actor=row, action="password_set")
    flash(request, "Your password is set. You can now sign in with your email and password.")
    return _see_other()


@router.post("/settings/theme", name="theme_set")
async def theme_set(request: Request, theme: str = Form("system"), user: UserRow = Depends(current_user)) -> Response:
    """Dark is the brand; "system" follows the phone or laptop. A plain cookie
    (not the session) so the choice survives signing out on this device."""
    choice = theme if theme in THEMES else "system"
    response = _see_other()
    response.set_cookie(
        THEME_COOKIE, choice, max_age=365 * 24 * 3600, path="/", samesite="lax",
        secure=request.app.state.settings.is_prod, httponly=True,
    )
    flash(request, {"system": "Appearance follows your device.", "dark": "Dark appearance is on.",
                    "light": "Light appearance is on."}[choice])
    return response

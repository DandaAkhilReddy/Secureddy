"""Settings: appearance, how accounts are shown, ways to sign in, app lock,
signed-in devices, installing on iPhone, two-step sign-in (an authenticator
app such as Microsoft Authenticator; see ``web.mfa``) and a local password.

Two-step setup is two-phase on purpose. The secret is generated and parked in
the flow cookie, and only once the person proves their app produces the right
code do we encrypt and store it. Storing first would lock out anyone whose
scan failed. The recovery codes are shown once, on the page that confirms it
is on, and stored only as hashes.
"""

from __future__ import annotations

from urllib.parse import quote

from fastapi import Depends, Form, HTTPException, Request, status
from markupsafe import Markup
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse, Response

from reddysec.store.models import MfaStateRow, UserIdentityRow, UserRow, UserSessionRow

from .. import applock, mfa, preferences, queries
from ..auth import (
    PASSWORD_MIN_LENGTH,
    PROVIDER_NAMES,
    current_user,
    end_session,
    hash_password,
)
from ..security import flash
from ..sessions import auth_of, list_sessions, revoke_session, revoke_user_sessions
from ..templating import THEME_COOKIE, THEME_COOKIE_MAX_AGE, THEMES, render
from . import protected_router

router = protected_router()

SESSION_PENDING_TOTP = mfa.SETUP_KEY


def _see_other(anchor: str = "") -> RedirectResponse:
    return RedirectResponse(f"/settings/security{anchor}", status_code=status.HTTP_303_SEE_OTHER)


async def _attach(session: AsyncSession, user: UserRow) -> UserRow:
    """Bring the signed-in account (loaded by ``current_user`` in its own
    session) into the writing transaction so changes to it are flushed."""
    return await session.merge(user)


_grouped = mfa.grouped


@router.get("/settings", name="settings")
async def settings_root(request: Request, user: UserRow = Depends(current_user)) -> Response:
    return _see_other()


@router.get("/settings/security", name="settings_security")
async def security_page(request: Request, user: UserRow = Depends(current_user)) -> Response:
    pending = None
    if not user.totp_secret_enc:
        pending = request.session.get(SESSION_PENDING_TOTP)
        if not isinstance(pending, str) or not pending:
            pending = mfa.new_secret()
            request.session[SESSION_PENDING_TOTP] = pending
    auth = auth_of(request)
    async with request.app.state.db.session() as session:
        identities = await queries.list_identities(session, user.id)
        devices = await list_sessions(session, user.id)
        lock = await applock.get_lock(session, user.id)
        passkeys = await applock.list_passkeys(session, user.id)
        prefs = await preferences.get_preferences(session, user.id)
        recovery_left = await mfa.recovery_codes_left(session, user.id) if user.totp_secret_enc else 0
        remembered = await mfa.remembered_devices(session, user.id) if user.totp_secret_enc else 0
    state = request.app.state
    enabled = {
        "google": state.oauth is not None,
        "microsoft": state.microsoft_oauth is not None,
        "yahoo": state.yahoo_oauth is not None,
    }
    linked = {i.provider for i in identities}
    if user.google_sub:
        linked.add("google")
    return render(
        request,
        "settings_security.html",
        {
            "totp_enabled": bool(user.totp_secret_enc),
            "has_password": bool(user.password_hash),
            "otpauth_uri": mfa.otpauth_uri(pending, user.login_email) if pending else "",
            "qr_svg": Markup(mfa.qr_svg(mfa.otpauth_uri(pending, user.login_email), label="QR code to scan with your "
                                        "authenticator app")) if pending else "",
            "manual_key": _grouped(pending) if pending else "",
            "manual_key_raw": pending or "",
            "recovery_left": recovery_left,
            "remembered_devices": remembered,
            "password_min_length": PASSWORD_MIN_LENGTH,
            "identities": identities,
            "sign_in_count": sign_in_count(user, identities),
            "providers": [(key, PROVIDER_NAMES[key]) for key in ("google", "microsoft", "yahoo") if enabled[key]],
            "linked_providers": linked,
            "devices": devices,
            "this_device": auth.session_id if auth else "",
            "lock": lock,
            "lock_timeout": applock.timeout_key(lock.timeout_s) if lock else "5m",
            "timeouts": applock.TIMEOUTS,
            "passkeys": passkeys,
            "inbox_view": prefs[preferences.INBOX_VIEW],
            "text_scams": prefs[preferences.TEXT_SCAMS] == "on",
        },
    )


def sign_in_count(user: UserRow, identities: list[UserIdentityRow]) -> int:
    """How many independent ways into this account exist (identities + password)."""
    return len(identities) + (1 if user.password_hash else 0)


def _recovery_page(request: Request, user: UserRow, codes: list[str], *, fresh_setup: bool) -> Response:
    text = mfa.recovery_text(codes, user.login_email)
    return render(
        request,
        "settings_recovery.html",
        {
            "codes": codes,
            "fresh_setup": fresh_setup,
            "download_href": "data:text/plain;charset=utf-8," + quote(text),
        },
        headers={"Cache-Control": "no-store, private"},
    )


@router.post("/settings/security/totp/enable", name="totp_enable")
async def totp_enable(
    request: Request, code: str = Form(""), user: UserRow = Depends(current_user)
) -> Response:
    pending = request.session.get(SESSION_PENDING_TOTP)
    step = mfa.matching_step(pending, code) if isinstance(pending, str) else None
    if step is None:
        flash(request, "That code did not match. Check the time on your phone is set automatically, then try "
                       "the newest code.", "error")
        return _see_other("#two-step")
    cipher = request.app.state.cipher
    codes = mfa.new_recovery_codes()
    async with request.app.state.db.session() as session:
        row = await _attach(session, user)
        row.totp_secret_enc = cipher.encrypt(pending, aad=row.id)
        await mfa.replace_recovery_codes(session, row.id, codes)
        state = await session.get(MfaStateRow, row.id)
        if state is None:
            session.add(MfaStateRow(user_id=row.id, last_step=step, failed_attempts=0))
        else:
            state.last_step, state.failed_attempts, state.locked_until = step, 0, None
        queries.audit(session, actor=row, action="totp_enabled")
    request.session.pop(SESSION_PENDING_TOTP, None)
    return _recovery_page(request, user, codes, fresh_setup=True)


async def _current_code_ok(request: Request, session: AsyncSession, row: UserRow, code: str) -> mfa.CheckResult:
    secret = request.app.state.cipher.decrypt(row.totp_secret_enc, aad=row.id)
    return await mfa.check_code(session, row, secret, code)


@router.post("/settings/security/totp/disable", name="totp_disable")
async def totp_disable(
    request: Request, code: str = Form(""), user: UserRow = Depends(current_user)
) -> Response:
    async with request.app.state.db.session() as session:
        row = await _attach(session, user)
        if not row.totp_secret_enc:
            return _see_other("#two-step")
        result = await _current_code_ok(request, session, row, code)
        if not result.ok:
            message = mfa.result_message(result)
    if not result.ok:
        flash(request, f"{message} Two-step sign-in stays on.", "error")
        return _see_other("#two-step")
    async with request.app.state.db.session() as session:
        row = await _attach(session, user)
        await mfa.turn_off(session, row)
        queries.audit(session, actor=row, action="totp_disabled")
    response = _see_other("#two-step")
    response.delete_cookie(mfa.TRUST_COOKIE, path="/")
    flash(request, "Two-step sign-in is off. You can remove Secureddy from your authenticator app.", "warn")
    return response


@router.post("/settings/security/totp/recovery", name="totp_recovery_codes")
async def totp_recovery_codes(
    request: Request, code: str = Form(""), user: UserRow = Depends(current_user)
) -> Response:
    """New recovery codes (the old ones stop working). Asks for a current code."""
    codes = mfa.new_recovery_codes()
    async with request.app.state.db.session() as session:
        row = await _attach(session, user)
        if not row.totp_secret_enc:
            return _see_other("#two-step")
        result = await _current_code_ok(request, session, row, code)
        if result.ok:
            await mfa.replace_recovery_codes(session, row.id, codes)
            queries.audit(session, actor=row, action="recovery_codes_renewed")
        else:
            message = mfa.result_message(result)
    if not result.ok:
        flash(request, message, "error")
        return _see_other("#two-step")
    return _recovery_page(request, user, codes, fresh_setup=False)


@router.post("/settings/security/totp/forget-devices", name="totp_forget_devices")
async def totp_forget_devices(request: Request, user: UserRow = Depends(current_user)) -> Response:
    async with request.app.state.db.session() as session:
        count = await mfa.forget_devices(session, user.id)
        queries.audit(session, actor=user, action="mfa_devices_forgotten", details={"devices": count})
    response = _see_other("#two-step")
    response.delete_cookie(mfa.TRUST_COOKIE, path="/")
    flash(request, "Every device will ask for a code at its next sign-in.")
    return response


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
    auth = auth_of(request)
    async with request.app.state.db.session() as session:
        row = await _attach(session, user)
        changed = bool(row.password_hash)
        row.password_hash = hash_password(password)
        others = await revoke_user_sessions(
            session, user.id, "password_changed", keep=auth.session_id if auth else None
        )
        queries.audit(session, actor=row, action="password_set", details={"signed_out_devices": others})
    tail = f" We signed out {others} other device{'s' if others != 1 else ''}." if others else ""
    if changed:
        flash(request, f"Your password is changed.{tail}")
    else:
        flash(request, f"Your password is set. You can now sign in with your email and password.{tail}")
    return _see_other()


@router.post("/settings/theme", name="theme_set")
async def theme_set(
    request: Request, theme: str = Form("system"), next: str = Form(""), user: UserRow = Depends(current_user)  # noqa: A002
) -> Response:
    """Dark is the brand; "system" follows the phone or laptop. Saved for the
    person (``user_preferences``, so every device and the installed app
    follow) and in the ``rs_theme`` cookie on this device, which the sign-in
    and lock pages read. Settings applies the choice at once in the browser
    too (app.js); this request makes it stick."""
    from ..security import safe_return_to

    choice = theme if theme in THEMES else "system"
    async with request.app.state.db.session() as session:
        await preferences.set_preference(session, user.id, preferences.THEME, choice)
    response = RedirectResponse(safe_return_to(next, "/settings/security#look"), status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        THEME_COOKIE, choice, max_age=THEME_COOKIE_MAX_AGE, path="/", samesite="lax",
        secure=request.app.state.settings.is_prod, httponly=True,
    )
    flash(request, {"system": "Appearance follows your device.", "dark": "Dark appearance is on.",
                    "light": "Light appearance is on."}[choice])
    return response


# --------------------------------------------------------------------------- show my accounts


@router.post("/settings/view", name="view_set")
async def view_set(
    request: Request, inbox_view: str = Form("together"), next: str = Form(""), user: UserRow = Depends(current_user)  # noqa: A002
) -> Response:
    from ..security import safe_return_to

    async with request.app.state.db.session() as session:
        ok = await preferences.set_preference(session, user.id, preferences.INBOX_VIEW, inbox_view)
    if not ok:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Please pick Together or Separately.")
    if not next:
        flash(request, "Your accounts are shown together." if inbox_view == "together" else
              "Each account is shown on its own.")
    return RedirectResponse(safe_return_to(next, "/settings/security#view"), status_code=status.HTTP_303_SEE_OTHER)


# --------------------------------------------------------------------------- text-only money scams


TEXT_SCAMS_HELP = (
    "Scammers sometimes send no links at all and just ask for money. Turn this on to also check those."
)


@router.post("/settings/text-scams", name="text_scams_set")
async def text_scams_set(request: Request, user: UserRow = Depends(current_user)) -> Response:
    """"Also watch text-only emails for money scams" (off by default: we only
    check email with something to click or open). Applies to new email. The
    form sends a hidden "off" and, when ticked, the checkbox's "on"."""
    form = await request.form()
    choice = "on" if "on" in form.getlist("text_scams") else "off"
    async with request.app.state.db.session() as session:
        await preferences.set_preference(session, user.id, preferences.TEXT_SCAMS, choice)
        queries.audit(session, actor=user, action="text_scams_" + choice)
    flash(request, "We now also check text-only emails for money scams." if choice == "on"
          else "We check only emails with links or files.")
    return _see_other("#scams")


# --------------------------------------------------------------------------- devices


@router.post("/settings/devices/{handle}/sign-out", name="device_sign_out")
async def device_sign_out(request: Request, handle: str, user: UserRow = Depends(current_user)) -> Response:
    auth = auth_of(request)
    async with request.app.state.db.session() as session:
        row = (
            await session.execute(
                select(UserSessionRow).where(UserSessionRow.handle == handle, UserSessionRow.user_id == user.id)
            )
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="We could not find that device.")
        this_device = auth is not None and row.id == auth.session_id
        await revoke_session(session, row, "signed_out_remotely")
        await mfa.forget_devices(session, user.id, session_id=row.id)
        queries.audit(session, actor=user, action="device_signed_out", details={"device": row.user_agent})
    if this_device:
        await end_session(request)
        flash(request, "You are signed out on this device.")
        return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    flash(request, f"Signed out {row.user_agent}.")
    return _see_other("#devices")


@router.post("/settings/devices/sign-out-everywhere", name="sign_out_everywhere")
async def sign_out_everywhere(request: Request, user: UserRow = Depends(current_user)) -> Response:
    async with request.app.state.db.session() as session:
        count = await revoke_user_sessions(session, user.id, "signed_out_everywhere")
        await mfa.forget_devices(session, user.id)
        queries.audit(session, actor=user, action="signed_out_everywhere", details={"devices": count})
    await end_session(request, "signed_out_everywhere")
    flash(request, "You are signed out on every device. Sign in again to continue.")
    return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)


# --------------------------------------------------------------------------- ways to sign in


@router.post("/settings/sign-in/{identity_id}/remove", name="identity_remove")
async def identity_remove(request: Request, identity_id: str, user: UserRow = Depends(current_user)) -> Response:
    """Remove a way to sign in, keeping at least one. Mailboxes stay."""
    async with request.app.state.db.session() as session:
        identities = await queries.list_identities(session, user.id)
        target = next((i for i in identities if i.id == identity_id), None)
        if target is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="We could not find that sign-in.")
        row = await _attach(session, user)
        if sign_in_count(row, identities) <= 1:
            flash(request, "This is your only way to sign in, so it stays. Add another one first.", "warn")
            return _see_other("#signin")
        await session.delete(await session.merge(target))
        if target.provider == "google" and row.google_sub == target.subject:
            row.google_sub = None  # otherwise the legacy column would link it straight back
        queries.audit(
            session, actor=row, action="identity_removed",
            details={"provider": target.provider, "email": target.email},
        )
    flash(request, f"You can no longer sign in with {PROVIDER_NAMES.get(target.provider, target.provider)} ({target.email}).")
    return _see_other("#signin")

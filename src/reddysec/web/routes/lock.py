"""The lock screen (``/lock``) and the app-lock and passkey settings.

The lock screen is reachable while locked (``web.sessions`` lets ``/lock*``
through); everything else redirects here or answers 423. It deliberately
shows almost nothing: the logo, a PIN pad or password field, a passkey
button, "Forgot PIN?" and "Sign out".
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, Form, HTTPException, Request, status
from sqlalchemy import delete
from starlette.responses import JSONResponse, RedirectResponse, Response

from reddysec.core.logging import get_logger
from reddysec.store.models import PasskeyRow, UserRow

from .. import applock, mfa, preferences, queries
from ..auth import current_user, end_session
from ..security import flash, safe_return_to
from ..sessions import auth_of
from ..templating import remember_theme, render, wants_json
from . import protected_router

log = get_logger(__name__)
router = protected_router()


def _see_other(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)


def _base_url(request: Request) -> str:
    return request.app.state.settings.base_url


async def _lock_context(request: Request) -> tuple[Any, UserRow | None, Any, list[PasskeyRow]]:
    auth = auth_of(request)
    if auth is None:
        return None, None, None, []
    async with request.app.state.db.session() as session:
        user = await queries.get_user(session, auth.user_id)
        lock = await applock.get_lock(session, auth.user_id)
        passkeys = await applock.list_passkeys(session, auth.user_id)
        theme = await preferences.get_preference(session, auth.user_id, preferences.THEME)
    if theme:
        remember_theme(request, theme)
    return auth, user, lock, passkeys


def _lock_page(request: Request, user: UserRow, lock: Any, passkeys: list[PasskeyRow], next_url: str, *,
               error: str = "", status_code: int = 200) -> Response:
    until = lock.locked_until if lock is not None else None
    if until is not None and until.tzinfo is None:
        until = until.replace(tzinfo=UTC)
    cooling = until is not None and until > datetime.now(UTC)
    return render(
        request,
        "lock.html",
        {
            "lock_user": user,
            "kind": lock.kind if lock is not None else "pin",
            "has_secret": bool(lock is not None and lock.secret_hash),
            "has_passkeys": bool(passkeys),
            "has_totp": bool(user.totp_secret_enc),
            "next_url": next_url,
            "error": error,
            "cooldown_minutes": max(1, int((until - datetime.now(UTC)).total_seconds() // 60) + 1) if cooling else 0,
        },
        status_code=status_code,
    )


@router.get("/lock", name="lock")
async def lock_page(request: Request, next: str | None = None) -> Response:  # noqa: A002
    auth, user, lock, passkeys = await _lock_context(request)
    target = safe_return_to(next)
    if auth is None or user is None:
        return _see_other("/login")
    if not auth.locked:
        return _see_other(target)
    return _lock_page(request, user, lock, passkeys, target)


@router.post("/lock", name="unlock")
async def unlock(
    request: Request, secret: str = Form(""), next: str = Form("/")  # noqa: A002
) -> Response:
    auth, user, lock, passkeys = await _lock_context(request)
    target = safe_return_to(next)
    if auth is None or user is None:
        return _see_other("/login")
    if not auth.locked:
        return _see_other(target)
    async with request.app.state.db.session() as session:
        result = await applock.try_unlock(session, auth.user_id, auth.session_id, secret.strip())
        if result.outcome in ("ok", "signed_out"):
            queries.audit(session, actor=user, action="app_unlocked" if result.outcome == "ok" else "app_lock_signed_out")
        lock = await applock.get_lock(session, auth.user_id)
    if result.outcome in ("ok", "not_locked"):
        return _see_other(target)
    if result.outcome == "signed_out":
        request.scope.pop("auth", None)
        request.scope["auth_clear_cookie"] = True
        request.session.clear()
        flash(request, "Too many wrong tries. For your safety we signed you out everywhere. Please sign in again.", "warn")
        return _see_other("/login")
    word = "PIN" if lock is not None and lock.kind == "pin" else "password"
    if result.outcome == "cooldown":
        message = f"Too many wrong tries. Please wait 15 minutes, or sign in again to reset your {word}."
    else:
        message = f"That {word} did not match. {result.left} {'try' if result.left == 1 else 'tries'} left before a pause."
    return _lock_page(request, user, lock, passkeys, target, error=message, status_code=401)


@router.post("/lock/totp", name="unlock_totp")
async def unlock_totp(request: Request, code: str = Form(""), next: str = Form("/")) -> Response:  # noqa: A002
    """Unlock with a code from the authenticator app (two-step sign-in), as
    well as the PIN, password or passkey. Same replay rule and the same
    5-in-15-minutes limit as signing in (``web.mfa``)."""
    auth, user, lock, passkeys = await _lock_context(request)
    target = safe_return_to(next)
    if auth is None or user is None:
        return _see_other("/login")
    if not auth.locked:
        return _see_other(target)
    if not user.totp_secret_enc:
        return _lock_page(request, user, lock, passkeys, target, error="Two-step sign-in is not on.", status_code=400)
    async with request.app.state.db.session() as session:
        secret = request.app.state.cipher.decrypt(user.totp_secret_enc, aad=user.id)
        result = await mfa.check_code(session, user, secret, code, allow_recovery=False)
        if result.ok:
            await applock.mark_unlocked(session, auth.session_id, datetime.now(UTC))
            row = await applock.get_lock(session, auth.user_id)
            if row is not None:
                row.failed_attempts = 0
                row.locked_until = None
            queries.audit(session, actor=user, action="app_unlocked", details={"method": "authenticator"})
    if result.ok:
        return _see_other(target)
    return _lock_page(request, user, lock, passkeys, target, error=mfa.result_message(result),
                      status_code=429 if result.outcome == "limited" else 401)


@router.post("/lock/forgot", name="lock_forgot")
async def lock_forgot(request: Request, next: str = Form("/")) -> Response:  # noqa: A002
    """"Forgot PIN": sign this device out; signing in again unlocks it."""
    target = safe_return_to(next)
    await end_session(request, "forgot_pin")
    flash(request, "Sign in again to open Secureddy. You can change your PIN in Settings afterwards.")
    return _see_other(f"/login?next={target}" if target != "/" else "/login")


@router.post("/lock/now", name="lock_now")
async def lock_now(request: Request, user: UserRow = Depends(current_user)) -> Response:
    auth = auth_of(request)
    async with request.app.state.db.session() as session:
        lock = await applock.get_lock(session, user.id)
        if lock is None or auth is None:
            flash(request, "Turn on the app lock in Settings first.", "warn")
            return _see_other("/settings/security#lock")
        await applock.lock_now(session, auth.session_id)
    return _see_other("/lock")


@router.post("/lock/passkey/options", name="lock_passkey_options")
async def lock_passkey_options(request: Request) -> Response:
    auth, user, _lock, passkeys = await _lock_context(request)
    if auth is None or user is None or not passkeys:
        return JSONResponse({"error": "no_passkeys"}, status_code=400)
    options, challenge = applock.authentication_options(_base_url(request), passkeys)
    applock.remember_challenge(request.session, challenge, "unlock")
    return Response(options, media_type="application/json", headers={"Cache-Control": "no-store"})


@router.post("/lock/passkey", name="lock_passkey_verify")
async def lock_passkey_verify(request: Request, credential: str = Form(...), next: str = Form("/")) -> Response:  # noqa: A002
    auth, user, _lock, passkeys = await _lock_context(request)
    if auth is None or user is None:
        return JSONResponse({"error": "sign_in_required"}, status_code=401)
    challenge = applock.take_challenge(request.session, "unlock")
    try:
        cred_id = applock.credential_id_of(credential)
    except (ValueError, AttributeError):
        cred_id = ""
    matches = [p for p in passkeys if p.credential_id == cred_id]
    passkey = matches[0] if matches else None
    if challenge is None or passkey is None:
        return JSONResponse({"error": "That passkey is not set up for Secureddy."}, status_code=400)
    try:
        sign_count = applock.verify_authentication(_base_url(request), credential, challenge, passkey)
    except Exception as exc:  # noqa: BLE001 - any verification problem is a refusal
        log.info("passkey_unlock_refused", error=type(exc).__name__)
        return JSONResponse({"error": "Your passkey did not work. Try again or use your PIN."}, status_code=400)
    async with request.app.state.db.session() as session:
        row = await session.get(PasskeyRow, passkey.id)
        if row is not None:
            row.sign_count = sign_count
            row.last_used_at = datetime.now(UTC)
        await applock.mark_unlocked(session, auth.session_id, datetime.now(UTC))
        lock = await applock.get_lock(session, auth.user_id)
        if lock is not None:
            lock.failed_attempts = 0
            lock.locked_until = None
        queries.audit(session, actor=user, action="app_unlocked", details={"method": "passkey"})
    return JSONResponse({"ok": True, "next": safe_return_to(next)})


# --------------------------------------------------------------------------- settings


SETTINGS = "/settings/security#lock"


def _done(request: Request, text: str, kind: str = "ok") -> Response:
    if wants_json(request):
        return JSONResponse({"ok": kind == "ok", "message": text}, status_code=200 if kind == "ok" else 400)
    flash(request, text, kind)
    return _see_other(SETTINGS)


async def _current_ok(session: Any, user: UserRow, current: str) -> bool:
    """Changing or removing a lock asks for the current PIN or password, so a
    phone left unlocked cannot have its lock switched off."""
    lock = await applock.get_lock(session, user.id)
    if lock is None or not lock.secret_hash:
        return True
    return applock.verify_secret(lock.secret_hash, current.strip())


@router.post("/settings/lock", name="lock_set")
async def lock_set(
    request: Request,
    kind: str = Form("pin"),
    secret: str = Form(""),
    confirm: str = Form(""),
    current: str = Form(""),
    timeout: str = Form("5m"),
    user: UserRow = Depends(current_user),
) -> Response:
    if timeout not in applock.TIMEOUT_SECONDS:
        timeout = "5m"
    auth = auth_of(request)
    async with request.app.state.db.session() as session:
        if not await _current_ok(session, user, current):
            return _done(request, "Your current PIN or password did not match, so nothing changed.", "error")
        if kind == "passkey":
            if not await applock.list_passkeys(session, user.id):
                return _done(request, "Add a passkey first, then you can lock with it alone.", "error")
            secret_value = None
        else:
            problem = applock.validate_secret(kind, secret.strip(), confirm.strip())
            if problem:
                return _done(request, problem, "error")
            secret_value = secret.strip()
        others = await applock.set_lock(
            session, user, kind=kind, secret=secret_value, timeout_s=applock.TIMEOUT_SECONDS[timeout],
            keep_session=auth.session_id if auth else None,
        )
        queries.audit(session, actor=user, action="app_lock_set", details={"kind": kind, "timeout": timeout})
    tail = f" We signed out {others} other device{'s' if others != 1 else ''}." if others else ""
    return _done(request, f"App lock is on.{tail}")


@router.post("/settings/lock/timeout", name="lock_timeout")
async def lock_timeout(request: Request, timeout: str = Form("5m"), user: UserRow = Depends(current_user)) -> Response:
    if timeout not in applock.TIMEOUT_SECONDS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Please pick one of the options.")
    async with request.app.state.db.session() as session:
        lock = await applock.get_lock(session, user.id)
        if lock is None:
            return _done(request, "Turn on the app lock first.", "error")
        lock.timeout_s = applock.TIMEOUT_SECONDS[timeout]
        queries.audit(session, actor=user, action="app_lock_timeout", details={"timeout": timeout})
    return _done(request, "Saved. " + dict((k, label) for k, _s, label in applock.TIMEOUTS)[timeout] + ", Secureddy locks.")


@router.post("/settings/lock/remove", name="lock_remove")
async def lock_remove(request: Request, current: str = Form(""), user: UserRow = Depends(current_user)) -> Response:
    auth = auth_of(request)
    async with request.app.state.db.session() as session:
        if not await _current_ok(session, user, current):
            return _done(request, "Your current PIN or password did not match, so the lock stays on.", "error")
        await applock.remove_lock(session, user, keep_session=auth.session_id if auth else None)
        queries.audit(session, actor=user, action="app_lock_removed")
    return _done(request, "App lock is off.", "warn")


@router.post("/settings/passkeys/options", name="passkey_options")
async def passkey_options(request: Request, user: UserRow = Depends(current_user)) -> Response:
    async with request.app.state.db.session() as session:
        existing = await applock.list_passkeys(session, user.id)
    options, challenge = applock.registration_options(_base_url(request), user, existing)
    applock.remember_challenge(request.session, challenge, "register")
    return Response(options, media_type="application/json", headers={"Cache-Control": "no-store"})


@router.post("/settings/passkeys", name="passkey_add")
async def passkey_add(
    request: Request, credential: str = Form(...), name: str = Form(""), user: UserRow = Depends(current_user)
) -> Response:
    challenge = applock.take_challenge(request.session, "register")
    if challenge is None:
        return JSONResponse({"error": "That took too long. Please try again."}, status_code=400)
    try:
        cred_id, public_key, sign_count = applock.verify_registration(_base_url(request), credential, challenge)
    except Exception as exc:  # noqa: BLE001
        log.info("passkey_register_refused", error=type(exc).__name__)
        return JSONResponse({"error": "We could not add that passkey. Please try again."}, status_code=400)
    async with request.app.state.db.session() as session:
        if any(p.credential_id == cred_id for p in await applock.list_passkeys(session, user.id)):
            return JSONResponse({"error": "That passkey is already added."}, status_code=400)
        label = name or _guess_name(request)
        await applock.add_passkey(
            session, user, credential_id=cred_id, public_key=public_key, sign_count=sign_count, name=label
        )
        queries.audit(session, actor=user, action="passkey_added")
    flash(request, "Passkey added. You can unlock Secureddy with it.")
    return JSONResponse({"ok": True, "next": SETTINGS})


def _guess_name(request: Request) -> str:
    from ..sessions import device_name

    return f"Passkey on {device_name(request.headers.get('user-agent')).split(' on ')[-1]}"


@router.post("/settings/passkeys/{passkey_id}/remove", name="passkey_remove")
async def passkey_remove(request: Request, passkey_id: str, user: UserRow = Depends(current_user)) -> Response:
    async with request.app.state.db.session() as session:
        result = await session.execute(
            delete(PasskeyRow).where(PasskeyRow.id == passkey_id, PasskeyRow.user_id == user.id)
        )
        if not result.rowcount:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="We could not find that passkey.")
        lock = await applock.get_lock(session, user.id)
        if lock is not None and lock.kind == "passkey" and not await applock.list_passkeys(session, user.id):
            await session.delete(lock)  # nothing left that could unlock it
        queries.audit(session, actor=user, action="passkey_removed")
    return _done(request, "Passkey removed.")


"""Sign-in and authorisation.

Three ways in, one session format:

* **Google, Microsoft or Yahoo** (the normal path). The OAuth dance is
  delegated to an :class:`OAuthProvider`; we only keep the state and PKCE
  verifier in the session, verify the returned identity, and connect the Gmail
  or Outlook mailbox with the tokens we were handed (Yahoo signs in only; its
  mail is connected with an app password on the next step). Each identity is
  recorded in ``user_identities``. A sign-in is matched to an existing
  account by email only when the provider verified the email (see
  ``queries.resolve_identity``); "Connect another mailbox" links by the
  signed-in session, never by email.
* **Email and password** for clients without a Google account, with optional
  TOTP as a second step.
* **Developer sign-in**, which exists only when ``dev_login_enabled`` is set
  and the environment is not production.

Authorisation is a pair of dependencies: :func:`current_user` (any signed-in
account) and :func:`require_role` (staff areas). Visibility of *data* is
decided in :mod:`reddysec.web.queries`, not here, so every route reads
through the same rules.
"""

from __future__ import annotations

import inspect
import secrets
import time
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any, Protocol, runtime_checkable
from urllib.parse import quote

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from starlette.responses import RedirectResponse, Response

from reddysec.core.logging import get_logger
from reddysec.models import Role
from reddysec.store import people
from reddysec.store.models import AppLockRow, UserRow, UserSessionRow

from . import mfa, preferences, queries
from .security import (
    client_ip,
    csrf_protect,
    current_user_id,
    flash,
    login_session,
    logout_session,
    safe_return_to,
    tokens_match,
)
from .sessions import AuthContext, auth_of, create_session, device_name, revoke_session
from .templating import remember_theme, render

log = get_logger(__name__)

TOTP_ISSUER = "Secureddy"
PASSWORD_MIN_LENGTH = 12


# --------------------------------------------------------------------------
# Contracts implemented elsewhere
# --------------------------------------------------------------------------


class AuthStartLike(Protocol):
    """What ``OAuthProvider.begin`` returns (``reddysec.mail.oauth_google.AuthStart``)."""

    url: str
    state: str
    code_verifier: str


class TokenSetLike(Protocol):
    """What ``OAuthProvider.finish`` returns (``reddysec.mail.oauth_google.TokenSet``)."""

    access_token: str
    refresh_token: str | None
    expires_at: datetime | None
    id_claims: dict[str, Any]
    scopes: list[str]


@runtime_checkable
class OAuthProvider(Protocol):
    """The two calls the web app makes. Implemented by ``GoogleOAuth``,
    ``MicrosoftOAuth`` and ``YahooOAuth`` (``reddysec.mail``); faked in tests.
    ``begin`` also accepts ``link=<account id>`` for "Connect another mailbox",
    and providers may offer ``link_of(state)`` to read it back from the
    signed state."""

    def begin(self, return_to: str = "/") -> AuthStartLike: ...

    async def finish(self, state: str, code: str, code_verifier: str) -> TokenSetLike: ...


class LoginRequired(Exception):
    """Raised by :func:`current_user`; the app-level handler turns it into a
    redirect to the sign-in page (HTML) or a 401 (JSON)."""

    def __init__(self, next_url: str = "/") -> None:
        super().__init__("sign in required")
        self.next_url = next_url


# --------------------------------------------------------------------------
# Passwords and TOTP
# --------------------------------------------------------------------------

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    if not password_hash or not password:
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


# Verified against when the email is unknown so a missing account costs the
# same wall time as a wrong password. Enumeration via timing is cheap to stop.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(24))


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, account: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name=TOTP_ISSUER)


def verify_totp(secret: str, code: str | None) -> bool:
    if not secret or not code:
        return False
    digits = "".join(ch for ch in code if ch.isdigit())
    if len(digits) != 6:
        return False
    return pyotp.TOTP(secret).verify(digits, valid_window=1)


# --------------------------------------------------------------------------
# Sessions (see web.sessions)
# --------------------------------------------------------------------------


async def start_session(request: Request, user_id: str, *, method: str) -> None:
    """Sign ``user_id`` in on this device: a new ``user_sessions`` row and
    ``rs_sid`` cookie, a rotated flow cookie (new CSRF token), and the device's
    previous session, if any, ended. A full sign-in also clears wrong-PIN
    counts: it is the "Forgot PIN" path."""
    settings = request.app.state.settings
    db = request.app.state.db
    previous = auth_of(request)
    if previous is not None:
        async with db.session() as session:
            row = await session.get(UserSessionRow, previous.session_id)
            if row is not None:
                await revoke_session(session, row, "replaced")
    token, row = await create_session(
        db,
        user_id,
        user_agent=request.headers.get("user-agent", ""),
        ip=client_ip(request.scope),
        method=method,
        idle_days=settings.session_idle_days,
        absolute_days=settings.session_absolute_days,
    )
    async with db.session() as session:
        lock = await session.get(AppLockRow, user_id)
        if lock is not None and (lock.failed_attempts or lock.locked_until):
            lock.failed_attempts = 0
            lock.locked_until = None
        await _bootstrap_admin(session, settings, user_id)
    login_session(request)
    max_age = int((row.expires_at - row.created_at).total_seconds())
    request.scope["auth_set_cookie"] = (token, max_age)
    request.scope["auth"] = AuthContext(session_id=row.id, handle=row.handle, user_id=user_id)


async def _bootstrap_admin(session: Any, settings: Any, user_id: str) -> None:
    """First run: while nobody is an admin, the account with the bootstrap
    admin email (``RS_BOOTSTRAP_ADMIN_EMAIL``) becomes one at sign-in. Only an
    account whose email was verified qualifies (see ``store.people``)."""
    policy = people.SignupPolicy.from_settings(settings)
    if not policy.bootstrap_admin_email:
        return
    user = await session.get(UserRow, user_id)
    if user is None or people.normalize_email(user.login_email) != policy.bootstrap_admin_email:
        return
    trusted = await queries.account_email_is_trusted(session, user)
    if await people.maybe_bootstrap_admin(session, policy, user, trusted=trusted):
        queries.audit(session, actor=None, action="admin_bootstrapped", target=user.id,
                      details={"email": user.login_email})
        log.info("auth.admin_bootstrapped", user_id=user.id)


def signup_policy(request: Request) -> people.SignupPolicy:
    return people.SignupPolicy.from_settings(request.app.state.settings)


INVITE_ONLY_TITLE = "Secureddy is invite-only right now"


def _signup_refused(request: Request, refused: people.SignupRefused) -> Response:
    """The calm page for a sign-in that would open a new account we cannot open."""
    email = refused.email
    message = f"Ask the person who invited you to add {email}."
    if refused.reason == "full":
        message = (f"Every place is taken at the moment. Ask the person who invited you to make room, "
                   f"then add {email}.")
    log.info("auth.signup_refused", reason=refused.reason)
    return render(
        request,
        "error.html",
        {"status_code": 403, "title": INVITE_ONLY_TITLE, "message": message, "cta_href": "/login",
         "cta_label": "Back to sign in"},
        status_code=status.HTTP_403_FORBIDDEN,
    )


async def end_session(request: Request, reason: str = "signed_out") -> None:
    """Sign this device out: revoke its session row and clear both cookies."""
    auth = auth_of(request)
    if auth is not None:
        async with request.app.state.db.session() as session:
            row = await session.get(UserSessionRow, auth.session_id)
            if row is not None:
                await revoke_session(session, row, reason)
    request.scope.pop("auth", None)
    request.scope["auth_clear_cookie"] = True
    logout_session(request)


# --------------------------------------------------------------------------
# Dependencies
# --------------------------------------------------------------------------


def _next_url(request: Request) -> str:
    path = request.url.path
    return f"{path}?{request.url.query}" if request.url.query else path


async def current_user(request: Request) -> UserRow:
    """The signed-in account, loaded fresh on every request so a disabled
    account is locked out at once rather than when its cookie expires."""
    uid = current_user_id(request)
    if uid:
        async with request.app.state.db.session() as session:
            user = await queries.get_user(session, uid)
            theme = await preferences.get_preference(session, uid, preferences.THEME) if user is not None else ""
        if user is not None and not user.disabled:
            request.state.user = user
            if theme:
                remember_theme(request, theme)
            return user
        await end_session(request, "account_closed")
    raise LoginRequired(next_url=_next_url(request))


def require_role(*roles: str | Role) -> Callable[..., Awaitable[UserRow]]:
    allowed = {r.value if isinstance(r, Role) else str(r) for r in roles}

    async def dependency(user: UserRow = Depends(current_user)) -> UserRow:
        if user.role not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="This area is for Secureddy staff.")
        return user

    return dependency


async def get_principal_id(request: Request) -> str:
    """For ``chamber.readingroom_web.make_room_router(get_principal_id=...)``:
    the Reading Room keys its sessions by the signed-in account."""
    user = await current_user(request)
    return user.id


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

router = APIRouter(dependencies=[Depends(csrf_protect)])

GENERIC_LOGIN_ERROR = "That email, password or code did not match. Please try again."


def _redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)


def _login_page(
    request: Request,
    *,
    next_url: str,
    error: str | None = None,
    email: str = "",
    status_code: int = 200,
) -> Response:
    return render(
        request,
        "login.html",
        {"next_url": next_url, "error": error, "email": email},
        status_code=status_code,
    )


@router.get("/login", name="login")
async def login_page(request: Request, next: str | None = None) -> Response:
    if current_user_id(request):
        return _redirect(safe_return_to(next))
    return _login_page(request, next_url=safe_return_to(next))


PROVIDER_NAMES = {"google": "Google", "microsoft": "Microsoft", "yahoo": "Yahoo"}
PERSONAL_MICROSOFT_TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad"
ACCOUNT_EXISTS_TITLE = "Already have an account?"
ACCOUNT_EXISTS_MESSAGE = (
    "Sign in first, then connect this mailbox. An account with this email address already exists, and "
    "{provider} did not confirm the address, so we will not open that account for this sign-in. Sign in the "
    "way you did before, then use Connect another mailbox on the Mailboxes page."
)


def _oauth_for(request: Request, provider: str) -> Any:
    state = request.app.state
    return {
        "google": getattr(state, "oauth", None),
        "microsoft": getattr(state, "microsoft_oauth", None),
        "yahoo": getattr(state, "yahoo_oauth", None),
    }.get(provider)


def _not_set_up(provider: str) -> HTTPException:
    return HTTPException(
        status.HTTP_404_NOT_FOUND, detail=f"{PROVIDER_NAMES[provider]} sign-in is not set up on this server."
    )


PURPOSES = ("mailbox", "signin")


def _begin_oauth(
    request: Request,
    provider: str,
    return_to: str,
    *,
    link: str | None = None,
    purpose: str = "mailbox",
    login_hint: str | None = None,
) -> Response:
    """Start a sign-in (``link`` None) or a link flow while signed in (``link``
    = the signed-in account's id): "Add an account" / "Reconnect" (purpose
    ``mailbox``) or "Ways to sign in" (purpose ``signin``). State and PKCE
    verifier stay in the signed flow cookie; ``link`` is kept there *and* in
    the provider's signed ``state`` and both are checked against the
    signed-in session at the callback."""
    oauth = _oauth_for(request, provider)
    if oauth is None:
        raise _not_set_up(provider)
    kwargs: dict[str, Any] = {"return_to": return_to}
    if link:
        kwargs["link"] = link
    if login_hint and "login_hint" in inspect.signature(oauth.begin).parameters:
        kwargs["login_hint"] = login_hint
    start = oauth.begin(**kwargs)
    pending: dict[str, Any] = {
        "provider": provider,
        "state": start.state,
        "verifier": start.code_verifier,
        "return_to": return_to,
        "at": int(time.time()),
    }
    if link:
        pending["link"] = link
        pending["purpose"] = purpose if purpose in PURPOSES else "mailbox"
    request.session["oauth"] = pending
    return _redirect(start.url)


@router.get("/auth/google/start", name="google_start")
async def google_start(request: Request, next: str | None = None) -> Response:
    return _begin_oauth(request, "google", safe_return_to(next))


@router.get("/auth/microsoft/start", name="microsoft_start")
async def microsoft_start(request: Request, next: str | None = None) -> Response:
    return _begin_oauth(request, "microsoft", safe_return_to(next))


@router.get("/auth/yahoo/start", name="yahoo_start")
async def yahoo_start(request: Request, next: str | None = None) -> Response:
    return _begin_oauth(request, "yahoo", safe_return_to(next))


@router.post("/auth/{provider}/link", name="oauth_link")
async def oauth_link(
    request: Request,
    provider: str,
    next: str = Form(""),
    purpose: str = Form("mailbox"),
    login_hint: str = Form(""),
) -> Response:
    """"Add an account" / "Reconnect" / "Add a way to sign in" with Google,
    Microsoft or Yahoo while signed in. A POST (CSRF-protected) so another
    site cannot start it for the client. Linking is only ever to the account
    that is signed in on this device, never by email."""
    if provider not in PROVIDER_NAMES:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    user = await current_user(request)
    default = "/settings/security" if purpose == "signin" else "/mailboxes"
    hint = login_hint.strip().lower()[:254] or None
    return _begin_oauth(
        request, provider, safe_return_to(next, default), link=user.id, purpose=purpose, login_hint=hint
    )


def _token_payload(token: TokenSetLike, *, email: str, sub: str) -> dict[str, Any]:
    expires = token.expires_at
    return {
        "access_token": token.access_token,
        "refresh_token": token.refresh_token,
        "expires_at": expires.isoformat() if isinstance(expires, datetime) else expires,
        "scopes": list(token.scopes or []),
        "email": email,
        "sub": sub,
    }


class _Callback:
    """What a callback learned before touching the database."""

    def __init__(self, token: TokenSetLike, pending: dict[str, Any], link: str | None) -> None:
        self.token = token
        self.pending = pending
        self.link = link
        self.claims: dict[str, Any] = dict(token.id_claims or {})

    @property
    def signin_only(self) -> bool:
        """"Add a way to sign in": link the identity; touch a mailbox only if
        one for this address is already protected (fresh tokens for it)."""
        return bool(self.link) and self.pending.get("purpose") == "signin"

    @property
    def return_to(self) -> str:
        return safe_return_to(str(self.pending.get("return_to", "/")))


async def _finish_oauth(
    request: Request, provider: str, state: str | None, code: str | None, error: str | None
) -> _Callback | Response:
    """Shared callback checks: a pending flow for this provider in the session,
    a matching state, a signed-in session that matches a link flow, and the
    provider's own code redemption. Any failure ends at the sign-in page."""
    name = PROVIDER_NAMES[provider]
    oauth = _oauth_for(request, provider)
    pending = request.session.pop("oauth", None)
    failed = f"{name} sign-in did not complete. Please try again."
    if oauth is None or error or not state or not code or not isinstance(pending, dict):
        flash(request, failed, "error")
        return _redirect("/login")
    if pending.get("provider", "google") != provider or not tokens_match(str(pending.get("state", "")), state):
        # A mismatched state is either a stale tab or a forged callback; both
        # end the same way, with nothing stored.
        flash(request, "That sign-in link was not valid. Please start again.", "error")
        return _redirect("/login")
    link = pending.get("link")
    link = str(link) if link else None
    if link is not None:
        link_of = getattr(oauth, "link_of", None)
        try:
            state_link = link_of(state) if callable(link_of) else link
        except Exception:
            state_link = None
        if current_user_id(request) != link or state_link != link:
            flash(request, "Please sign in again, then connect the mailbox.", "error")
            return _redirect("/login")
    try:
        token = await oauth.finish(state, code, str(pending.get("verifier", "")))
    except Exception:
        # Any provider failure (network, revoked code, clock skew) is something
        # the client can simply retry; it must never surface as a 500.
        log.warning("oauth_finish_failed", provider=provider)
        flash(request, failed, "error")
        return _redirect("/mailboxes" if link else "/login")
    return _Callback(token, pending, link)


def _link_action(result: _Callback) -> str:
    if result.signin_only:
        return "identity_linked"
    return "mailbox_linked" if result.link else "login"


async def _has_mailbox(session: Any, user: UserRow, address: str) -> bool:
    mailbox = await queries.find_mailbox_by_address(session, user.id, address)
    return mailbox is not None and mailbox.status != "disconnected"


def _closed_account(request: Request) -> Response:
    return render(
        request,
        "error.html",
        {"status_code": 403, "title": "This account is closed", "message": "Please contact your concierge."},
        status_code=status.HTTP_403_FORBIDDEN,
    )


def _identity_problem(request: Request, provider: str, reason: str) -> Response:
    name = PROVIDER_NAMES[provider]
    if reason == "other_account":
        return render(
            request,
            "error.html",
            {
                "status_code": 409,
                "title": f"This {name} account is already connected",
                "message": f"It belongs to a different Secureddy account. Sign in with {name} to use that account.",
                "cta_href": "/mailboxes",
                "cta_label": "Back to Mailboxes",
            },
            status_code=status.HTTP_409_CONFLICT,
        )
    if reason == "no_email":
        return render(
            request,
            "error.html",
            {
                "status_code": 400,
                "title": "We could not read your email address",
                "message": f"{name} did not tell us which email address this account uses. Please try another way to sign in.",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return render(
        request,
        "error.html",
        {
            "status_code": 409,
            "title": ACCOUNT_EXISTS_TITLE,
            "message": ACCOUNT_EXISTS_MESSAGE.format(provider=name),
            "cta_href": "/login",
            "cta_label": "Sign in first",
        },
        status_code=status.HTTP_409_CONFLICT,
    )


@router.get("/auth/google/callback", name="google_callback")
async def google_callback(
    request: Request, state: str | None = None, code: str | None = None, error: str | None = None
) -> Response:
    result = await _finish_oauth(request, "google", state, code, error)
    if not isinstance(result, _Callback):
        return result
    claims = result.claims
    email = str(claims.get("email") or "")
    sub = str(claims.get("sub") or "")
    if not email or not sub or claims.get("email_verified") is not True:
        return render(
            request,
            "error.html",
            {
                "status_code": 403,
                "title": "We could not confirm your email address",
                "message": "Google has not verified this address, so we cannot use it to sign you in.",
            },
            status_code=status.HTTP_403_FORBIDDEN,
        )

    created = False
    async with request.app.state.db.session() as session:
        try:
            if result.link:
                user = await queries.get_user(session, result.link)
                if user is None:
                    raise queries.IdentityConflict("other_account")
                await queries.link_identity(
                    session, user, provider="google", subject=sub, email=email, email_verified=True
                )
            else:
                user, created = await queries.upsert_google_user(
                    session, sub=sub, email=email, name=claims.get("name"), signup=signup_policy(request)
                )
        except queries.IdentityConflict as exc:
            problem: str | None = exc.reason
        except people.SignupRefused as refused:
            return _signup_refused(request, refused)
        else:
            problem = None
        if problem is None:
            if user.disabled:
                return _closed_account(request)
            payload = _token_payload(result.token, email=email, sub=sub)
            if not result.signin_only or await _has_mailbox(session, user, email):
                await queries.connect_gmail_mailbox(session, request.app.state.cipher, user, email, payload)
            queries.audit(
                session, actor=user, action=_link_action(result), details={"method": "google"}
            )
            user_id = user.id
    if problem is not None:
        return _identity_problem(request, "google", problem)

    if result.signin_only:
        flash(request, f"You can now sign in with Google ({email}).")
        return _redirect(result.return_to)
    if result.link:
        flash(request, f"Gmail {email} is connected. We start checking new email within a minute.")
        return _redirect(result.return_to)
    welcome = "Welcome. Your Gmail is connected and we start checking new email within a minute." if created else ""
    return await finish_sign_in(request, user_id, method="google", next_url=result.return_to, welcome=welcome)


@router.get("/auth/microsoft/callback", name="microsoft_callback")
async def microsoft_callback(
    request: Request, state: str | None = None, code: str | None = None, error: str | None = None
) -> Response:
    result = await _finish_oauth(request, "microsoft", state, code, error)
    if not isinstance(result, _Callback):
        return result
    claims = result.claims
    email = str(claims.get("email") or "").strip().lower()
    oid = str(claims.get("oid") or claims.get("sub") or "")
    tenant = str(claims.get("tid") or "")
    verified = claims.get("email_verified") is True
    if not oid or not email:
        return _identity_problem(request, "microsoft", "no_email")

    created = False
    async with request.app.state.db.session() as session:
        try:
            if result.link:
                user = await queries.get_user(session, result.link)
                if user is None:
                    raise queries.IdentityConflict("other_account")
                await queries.link_identity(
                    session, user, provider="microsoft", subject=oid, email=email, email_verified=verified,
                    tenant=tenant,
                )
            else:
                user, created = await queries.resolve_identity(
                    session, provider="microsoft", subject=oid, email=email, email_verified=verified,
                    name=claims.get("name"), tenant=tenant, personal_tenant=PERSONAL_MICROSOFT_TENANT,
                    signup=signup_policy(request),
                )
        except queries.IdentityConflict as exc:
            problem: str | None = exc.reason
        except people.SignupRefused as refused:
            return _signup_refused(request, refused)
        else:
            problem = None
        if problem is None:
            if user.disabled:
                return _closed_account(request)
            payload = {**_token_payload(result.token, email=email, sub=oid), "tid": tenant}
            if not result.signin_only or await _has_mailbox(session, user, email):
                await queries.connect_microsoft_mailbox(session, request.app.state.cipher, user, email, payload)
            queries.audit(
                session, actor=user, action=_link_action(result),
                details={"method": "microsoft", "personal": tenant == PERSONAL_MICROSOFT_TENANT},
            )
            user_id = user.id
    if problem is not None:
        return _identity_problem(request, "microsoft", problem)

    if result.signin_only:
        flash(request, f"You can now sign in with Microsoft ({email}).")
        return _redirect(result.return_to)
    message = f"Your Outlook mailbox {email} is connected. We start checking new email within a minute."
    if result.link:
        flash(request, message)
        return _redirect(result.return_to)
    return await finish_sign_in(
        request, user_id, method="microsoft", next_url=result.return_to, welcome=f"Welcome. {message}" if created else ""
    )


@router.get("/auth/yahoo/callback", name="yahoo_callback")
async def yahoo_callback(
    request: Request, state: str | None = None, code: str | None = None, error: str | None = None
) -> Response:
    """Yahoo sign-in identifies the person only (see mail.oauth_yahoo); the
    mailbox itself is connected on the next step with an app password."""
    result = await _finish_oauth(request, "yahoo", state, code, error)
    if not isinstance(result, _Callback):
        return result
    claims = result.claims
    email = str(claims.get("email") or "").strip().lower()
    sub = str(claims.get("sub") or "")
    verified = claims.get("email_verified") is True
    if not sub or not email:
        return _identity_problem(request, "yahoo", "no_email")

    async with request.app.state.db.session() as session:
        try:
            if result.link:
                user = await queries.get_user(session, result.link)
                if user is None:
                    raise queries.IdentityConflict("other_account")
                await queries.link_identity(
                    session, user, provider="yahoo", subject=sub, email=email, email_verified=verified
                )
            else:
                user, _created = await queries.resolve_identity(
                    session, provider="yahoo", subject=sub, email=email, email_verified=verified,
                    name=claims.get("name"), signup=signup_policy(request),
                )
        except queries.IdentityConflict as exc:
            problem: str | None = exc.reason
        except people.SignupRefused as refused:
            return _signup_refused(request, refused)
        else:
            problem = None
        if problem is None:
            if user.disabled:
                return _closed_account(request)
            queries.audit(
                session, actor=user, action="identity_linked" if result.link else "login", details={"method": "yahoo"}
            )
            user_id = user.id
    if problem is not None:
        return _identity_problem(request, "yahoo", problem)

    if result.signin_only:
        flash(request, f"You can now sign in with Yahoo ({email}).")
        return _redirect(result.return_to)
    target = f"/mailboxes/connect-yahoo?address={quote(email)}"
    if not result.link:
        return await finish_sign_in(request, user_id, method="yahoo", next_url=target)
    return _redirect(target)


@router.post("/auth/login", name="password_login")
async def password_login(
    request: Request,
    email: str = Form(""),
    password: str = Form(""),
    code: str = Form(""),
    next: str = Form("/"),
) -> Response:
    """Email and password. With two-step sign-in on, the authenticator code
    comes next on ``/auth/mfa`` (or in the same form, when a password manager
    fills both)."""
    next_url = safe_return_to(next)
    async with request.app.state.db.session() as session:
        user = await queries.get_user_by_email(session, email) if email and password else None
        ok = verify_password(user.password_hash if user else _DUMMY_HASH, password)
        if not ok or user is None or user.disabled:
            return _login_page(request, next_url=next_url, error=GENERIC_LOGIN_ERROR, email=email, status_code=401)
        queries.audit(session, actor=user, action="login", details={"method": "password"})
        user_id = user.id
    return await finish_sign_in(request, user_id, method="password", next_url=next_url, code=code)


# --------------------------------------------------------------------------
# Two-step sign-in (web.mfa)
# --------------------------------------------------------------------------


async def finish_sign_in(
    request: Request, user_id: str, *, method: str, next_url: str, welcome: str = "", code: str = ""
) -> Response:
    """The last step of every sign-in. Without two-step sign-in, or on a
    device remembered for 30 days, the session starts now. Otherwise nothing
    is signed in yet: the person goes to ``/auth/mfa`` for their code."""
    cipher = request.app.state.cipher
    async with request.app.state.db.session() as session:
        user = await session.get(UserRow, user_id)
        needs = user is not None and bool(user.totp_secret_enc)
        trusted = needs and await mfa.device_is_trusted(session, user_id, request.cookies.get(mfa.TRUST_COOKIE))
        result = None
        if needs and not trusted and code.strip():
            assert user is not None
            secret = cipher.decrypt(user.totp_secret_enc, aad=user.id)
            result = await mfa.check_code(session, user, secret, code, allow_recovery=False)
    if needs and not trusted and not (result is not None and result.ok):
        mfa.remember_pending(request.session, user_id, method, next_url)
        if welcome:
            request.session[mfa.SESSION_KEY]["w"] = welcome[:300]
        if result is not None:
            flash(request, mfa.result_message(result), "error")
        return _redirect("/auth/mfa")
    suffix = "+trusted" if trusted else ("+2fa" if needs else "")
    await start_session(request, user_id, method=method + suffix)
    if welcome:
        flash(request, welcome)
    return _redirect(next_url)


def _mfa_page(request: Request, pending: dict[str, Any], user: UserRow, *, error: str = "", status_code: int = 200
              ) -> Response:
    return render(
        request,
        "mfa.html",
        {
            "mfa_user": user,
            "method": PROVIDER_NAMES.get(str(pending.get("m", "")), "your password"),
            "error": error,
            "remember_days": mfa.REMEMBER_DAYS,
        },
        status_code=status_code,
    )


async def _pending_user(request: Request) -> tuple[dict[str, Any] | None, UserRow | None]:
    pending = mfa.pending_of(request.session)
    if pending is None:
        return None, None
    async with request.app.state.db.session() as session:
        user = await queries.get_user(session, str(pending["uid"]))
    if user is None or user.disabled or not user.totp_secret_enc:
        request.session.pop(mfa.SESSION_KEY, None)
        return None, None
    return pending, user


@router.get("/auth/mfa", name="mfa_challenge")
async def mfa_challenge(request: Request) -> Response:
    pending, user = await _pending_user(request)
    if pending is None or user is None:
        flash(request, "Please sign in again.", "warn")
        return _redirect("/login")
    return _mfa_page(request, pending, user)


@router.post("/auth/mfa", name="mfa_verify")
async def mfa_verify(request: Request, code: str = Form(""), remember: str = Form("")) -> Response:
    pending, user = await _pending_user(request)
    if pending is None or user is None:
        flash(request, "That took too long. Please sign in again.", "warn")
        return _redirect("/login")
    cipher = request.app.state.cipher
    async with request.app.state.db.session() as session:
        secret = cipher.decrypt(user.totp_secret_enc, aad=user.id)
        result = await mfa.check_code(session, user, secret, code)
        if result.ok:
            queries.audit(session, actor=user, action="mfa_passed",
                          details={"method": str(pending.get("m", "")), "with": result.outcome})
        else:
            queries.audit(session, actor=user, action="mfa_failed", details={"outcome": result.outcome})
    if not result.ok:
        what = "code"
        return _mfa_page(request, pending, user, error=mfa.result_message(result, what=what),
                         status_code=429 if result.outcome == "limited" else 401)
    welcome = str(pending.get("w", ""))
    next_url = safe_return_to(str(pending.get("next", "/")))
    await start_session(request, user.id, method=f"{pending.get('m', '')}+2fa")
    response = _redirect(next_url)
    if remember == "1":
        auth = auth_of(request)
        async with request.app.state.db.session() as session:
            token = await mfa.trust_device(
                session, user.id, session_id=auth.session_id if auth else "",
                user_agent=device_name(request.headers.get("user-agent")),
            )
        response.set_cookie(
            mfa.TRUST_COOKIE, token, max_age=mfa.REMEMBER_DAYS * 86400, path="/", samesite="lax",
            secure=request.app.state.settings.is_prod, httponly=True,
        )
    if welcome:
        flash(request, welcome)
    if result.outcome == "recovery":
        left = result.recovery_left
        flash(
            request,
            f"You used a recovery code. {left} left. " + (
                "Make new ones in Settings soon." if left <= 3 else "Each one works once."),
            "warn" if left <= 3 else "ok",
        )
    return response


@router.post("/auth/mfa/cancel", name="mfa_cancel")
async def mfa_cancel(request: Request) -> Response:
    request.session.pop(mfa.SESSION_KEY, None)
    return _redirect("/login")


@router.post("/auth/logout", name="logout")
async def logout(request: Request) -> Response:
    uid = current_user_id(request)
    if uid:
        async with request.app.state.db.session() as session:
            user = await queries.get_user(session, uid)
            if user is not None:
                queries.audit(session, actor=user, action="logout")
    await end_session(request)
    flash(request, "You are signed out.")
    return _redirect("/login")


def _dev_login_enabled(request: Request) -> None:
    if not request.app.state.dev_login_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND)


@router.get("/auth/dev-login", name="dev_login_page")
async def dev_login_page(request: Request, next: str | None = None) -> Response:
    _dev_login_enabled(request)
    return _login_page(request, next_url=safe_return_to(next))


@router.post("/auth/dev-login", name="dev_login")
async def dev_login(
    request: Request,
    email: str = Form(...),
    name: str = Form(""),
    role: str = Form(Role.PRINCIPAL.value),
    next: str = Form("/"),
) -> Response:
    """Password-less sign-in for local development. Creates the account on
    first use; the role is accepted so staff screens can be exercised. Not
    limited by invites or ``max_users`` (``store.people``): it exists only
    when ``dev_login_enabled`` is set outside production."""
    _dev_login_enabled(request)
    if role not in {r.value for r in Role}:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Unknown role.")
    if "@" not in email:
        return _login_page(
            request,
            next_url=safe_return_to(next),
            error="Please enter an email address.",
            email=email,
            status_code=400,
        )
    async with request.app.state.db.session() as session:
        user, _created = await queries.get_or_create_user(
            session, email=email, display_name=name or None, role=role
        )
        queries.audit(session, actor=user, action="login", details={"method": "dev"})
        user_id = user.id
    return await finish_sign_in(request, user_id, method="dev", next_url=safe_return_to(next))

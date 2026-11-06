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
from reddysec.store.models import UserRow

from . import queries
from .security import (
    csrf_protect,
    current_user_id,
    flash,
    login_session,
    logout_session,
    safe_return_to,
    tokens_match,
)
from .templating import render

log = get_logger(__name__)

TOTP_ISSUER = "Secureddy"
TOTP_LOGIN_WINDOW_S = 300  # how long a verified password waits for its code
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
        if user is not None and not user.disabled:
            request.state.user = user
            return user
        logout_session(request)
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
    needs_code: bool = False,
    status_code: int = 200,
) -> Response:
    return render(
        request,
        "login.html",
        {"next_url": next_url, "error": error, "email": email, "needs_code": needs_code},
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


def _begin_oauth(request: Request, provider: str, return_to: str, *, link: str | None = None) -> Response:
    """Start a sign-in (``link`` None) or a "Connect another mailbox" flow
    (``link`` = the signed-in account's id). State and PKCE verifier stay in
    the signed session cookie; ``link`` is kept there *and* in the provider's
    signed ``state`` and both are checked against the signed-in session at
    the callback."""
    oauth = _oauth_for(request, provider)
    if oauth is None:
        raise _not_set_up(provider)
    start = oauth.begin(return_to=return_to, link=link) if link else oauth.begin(return_to=return_to)
    pending: dict[str, Any] = {
        "provider": provider,
        "state": start.state,
        "verifier": start.code_verifier,
        "return_to": return_to,
        "at": int(time.time()),
    }
    if link:
        pending["link"] = link
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
async def oauth_link(request: Request, provider: str, next: str = Form("/mailboxes")) -> Response:
    """"Connect another mailbox" with Google / Microsoft / Yahoo while signed in.
    A POST (CSRF-protected) so another site cannot start it for the client."""
    if provider not in PROVIDER_NAMES:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    user = await current_user(request)
    return _begin_oauth(request, provider, safe_return_to(next, "/mailboxes"), link=user.id)


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
                    session, sub=sub, email=email, name=claims.get("name")
                )
        except queries.IdentityConflict as exc:
            problem: str | None = exc.reason
        else:
            problem = None
        if problem is None:
            if user.disabled:
                return _closed_account(request)
            await queries.connect_gmail_mailbox(
                session, request.app.state.cipher, user, email, _token_payload(result.token, email=email, sub=sub)
            )
            queries.audit(
                session, actor=user, action="mailbox_linked" if result.link else "login", details={"method": "google"}
            )
            user_id = user.id
    if problem is not None:
        return _identity_problem(request, "google", problem)

    if result.link:
        flash(request, f"Gmail {email} is connected. We start checking new email within a minute.")
        return _redirect(result.return_to)
    login_session(request, user_id)
    if created:
        flash(request, "Welcome. Your Gmail is connected and we start checking new email within a minute.")
    return _redirect(result.return_to)


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
                )
        except queries.IdentityConflict as exc:
            problem: str | None = exc.reason
        else:
            problem = None
        if problem is None:
            if user.disabled:
                return _closed_account(request)
            payload = {**_token_payload(result.token, email=email, sub=oid), "tid": tenant}
            await queries.connect_microsoft_mailbox(session, request.app.state.cipher, user, email, payload)
            queries.audit(
                session, actor=user, action="mailbox_linked" if result.link else "login",
                details={"method": "microsoft", "personal": tenant == PERSONAL_MICROSOFT_TENANT},
            )
            user_id = user.id
    if problem is not None:
        return _identity_problem(request, "microsoft", problem)

    message = f"Your Outlook mailbox {email} is connected. We start checking new email within a minute."
    if result.link:
        flash(request, message)
        return _redirect(result.return_to)
    login_session(request, user_id)
    if created:
        flash(request, f"Welcome. {message}")
    return _redirect(result.return_to)


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
                    name=claims.get("name"),
                )
        except queries.IdentityConflict as exc:
            problem: str | None = exc.reason
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

    if not result.link:
        login_session(request, user_id)
    return _redirect(f"/mailboxes/connect-yahoo?address={quote(email)}")


@router.post("/auth/login", name="password_login")
async def password_login(
    request: Request,
    email: str = Form(""),
    password: str = Form(""),
    code: str = Form(""),
    next: str = Form("/"),
) -> Response:
    next_url = safe_return_to(next)
    marker = request.session.get("totp_login")
    db = request.app.state.db
    cipher = request.app.state.cipher

    async with db.session() as session:
        if password:
            user = await queries.get_user_by_email(session, email) if email else None
            ok = verify_password(user.password_hash if user else _DUMMY_HASH, password)
            if not ok or user is None or user.disabled:
                return _login_page(
                    request, next_url=next_url, error=GENERIC_LOGIN_ERROR, email=email, status_code=401
                )
            if user.totp_secret_enc:
                # Remember that the password step passed, so a wrong or missing
                # code can be retried with the code alone for a few minutes.
                request.session["totp_login"] = {
                    "uid": user.id,
                    "exp": int(time.time()) + TOTP_LOGIN_WINDOW_S,
                }
                if not code:
                    return _login_page(request, next_url=next_url, email=user.login_email, needs_code=True)
        elif code and isinstance(marker, dict) and int(marker.get("exp", 0)) > time.time():
            # Second step: the password was verified moments ago (see marker).
            user = await queries.get_user(session, str(marker.get("uid", "")))
            if user is None or user.disabled or not user.totp_secret_enc:
                return _login_page(request, next_url=next_url, error=GENERIC_LOGIN_ERROR, status_code=401)
        else:
            return _login_page(
                request, next_url=next_url, error=GENERIC_LOGIN_ERROR, email=email, status_code=401
            )

        if user.totp_secret_enc:
            secret = cipher.decrypt(user.totp_secret_enc, aad=user.id)
            if not verify_totp(secret, code):
                return _login_page(
                    request,
                    next_url=next_url,
                    error=GENERIC_LOGIN_ERROR,
                    email=user.login_email,
                    needs_code=True,
                    status_code=401,
                )
        queries.audit(session, actor=user, action="login", details={"method": "password"})
        user_id = user.id

    login_session(request, user_id)
    return _redirect(next_url)


@router.post("/auth/logout", name="logout")
async def logout(request: Request) -> Response:
    uid = current_user_id(request)
    if uid:
        async with request.app.state.db.session() as session:
            user = await queries.get_user(session, uid)
            if user is not None:
                queries.audit(session, actor=user, action="logout")
    logout_session(request)
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
    first use; the role is accepted so staff screens can be exercised."""
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
    login_session(request, user_id)
    return _redirect(safe_return_to(next))

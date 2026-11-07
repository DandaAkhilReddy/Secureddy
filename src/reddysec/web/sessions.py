"""Server-side sign-in sessions ("stay signed in until I sign out") and the
server half of the app lock.

Why server-side: a signed cookie cannot be taken back. Here the browser holds
only a random 256-bit token in ``rs_sid`` (HttpOnly, SameSite=Lax, Secure in
production); the database keeps its SHA-256 in ``user_sessions``. Signing out
a device, "sign out everywhere", a PIN or password change, or ten wrong PINs
revoke rows, and the next request from that device is signed out.

Lifetimes: a session slides forward with use (``session_idle_days``, 90 by
default), renewed at most once an hour, and ends ``session_absolute_days``
(365) after sign-in whatever happens. The cookie's ``Max-Age`` follows, so an
installed iPhone app stays signed in across launches.

The flow cookie ``rs_session`` (``security.SessionMiddleware``) still carries
the CSRF token, flash messages and in-flight OAuth state. It grants nothing:
who you are comes only from ``rs_sid``.

App lock (``web.applock``): whether a session is locked is decided here, on
every request, from ``user_sessions.unlocked_at`` / ``last_active_at`` and
the person's ``app_locks`` row. A locked session reaches only the lock
screen: pages redirect to ``/lock``, JSON and fetch calls get ``423 Locked``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

from sqlalchemy import select, update
from starlette.datastructures import MutableHeaders
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse, RedirectResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from reddysec.core.ids import new_id
from reddysec.core.logging import get_logger
from reddysec.store.models import AppLockRow, UserSessionRow

log = get_logger(__name__)

AUTH_COOKIE = "rs_sid"
THEME_COOKIE = "rs_theme"  # the device's copy of the person's appearance choice (see web.templating)
THEME_MAX_AGE = 365 * 24 * 3600
TOKEN_BYTES = 32  # 256 bits
RENEW_EVERY_S = 3600  # sliding renewal at most once an hour
ACTIVITY_EVERY_S = 15  # how often "last active" is written while the app lock is on
SCOPE_KEY = "auth"

# Reachable while locked: the lock screen itself, signing out, the app shell.
LOCK_EXEMPT_PREFIXES = (
    "/lock",
    "/static/",
    "/auth/logout",
    "/sw.js",
    "/manifest.webmanifest",
    "/offline",
    "/healthz",
    "/readyz",
    "/favicon.ico",
    "/apple-touch-icon",
)
# Never looked up at all: no session work for static files and probes.
SKIP_PREFIXES = ("/static/", "/healthz", "/readyz", "/sw.js", "/manifest.webmanifest", "/favicon.ico")

Clock = Callable[[], float]


def utcnow() -> datetime:
    return datetime.now(UTC)


def aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_session_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


# --------------------------------------------------------------------------- device names

_BROWSERS = (
    ("Edg/", "Edge"),
    ("EdgiOS", "Edge"),
    ("CriOS", "Chrome"),
    ("FxiOS", "Firefox"),
    ("Firefox/", "Firefox"),
    ("OPR/", "Opera"),
    ("Chrome/", "Chrome"),
    ("Safari/", "Safari"),
)
_SYSTEMS = (
    ("iPhone", "iPhone"),
    ("iPad", "iPad"),
    ("Android", "Android"),
    ("Windows", "Windows"),
    ("Macintosh", "Mac"),
    ("CrOS", "Chromebook"),
    ("Linux", "Linux"),
)


def device_name(user_agent: str | None) -> str:
    """"Safari on iPhone" from a User-Agent; the raw string is never stored."""
    ua = user_agent or ""
    browser = next((name for marker, name in _BROWSERS if marker in ua), "")
    system = next((name for marker, name in _SYSTEMS if marker in ua), "")
    if browser and system:
        return f"{browser} on {system}"
    return browser or system or "Unknown device"


def ip_prefix(ip: str | None) -> str:
    """A network, not an address: IPv4 /24, IPv6 /48. Enough to recognise
    "home" or "office" in the device list without keeping exact addresses."""
    try:
        address = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return ""
    bits = 24 if address.version == 4 else 48
    return str(ipaddress.ip_network(f"{address}/{bits}", strict=False))


# --------------------------------------------------------------------------- the per-request view


@dataclass
class AuthContext:
    """What ``rs_sid`` proved for this request."""

    session_id: str
    handle: str
    user_id: str
    locked: bool = False
    lock_enabled: bool = False

    @property
    def id(self) -> str:
        return self.session_id


def auth_of(scope_or_request: Any) -> AuthContext | None:
    scope = scope_or_request.scope if hasattr(scope_or_request, "scope") else scope_or_request
    value = scope.get(SCOPE_KEY)
    return value if isinstance(value, AuthContext) else None


# --------------------------------------------------------------------------- store


async def create_session(
    db: Any,
    user_id: str,
    *,
    user_agent: str = "",
    ip: str = "",
    method: str = "",
    idle_days: int = 90,
    absolute_days: int = 365,
    now: datetime | None = None,
) -> tuple[str, UserSessionRow]:
    """A new signed-in device. Returns the raw token (for the cookie, never
    stored) and the row. A fresh full sign-in counts as unlocked."""
    now = now or utcnow()
    token = new_session_token()
    absolute = now + timedelta(days=absolute_days)
    row = UserSessionRow(
        id=hash_token(token),
        handle=new_id("dev"),
        user_id=user_id,
        created_at=now,
        last_seen_at=now,
        expires_at=min(now + timedelta(days=idle_days), absolute),
        absolute_expires_at=absolute,
        user_agent=device_name(user_agent)[:120],
        ip_prefix=ip_prefix(ip)[:64],
        auth_method=(method or "")[:20],
        unlocked_at=now,
        last_active_at=now,
    )
    async with db.session() as session:
        session.add(row)
    return token, row


def session_is_live(row: UserSessionRow, now: datetime) -> bool:
    if row.revoked_at is not None:
        return False
    expires = aware(row.expires_at)
    absolute = aware(row.absolute_expires_at)
    return bool(expires and absolute and now < expires and now < absolute)


async def find_session(session: Any, token: str, now: datetime) -> tuple[UserSessionRow, AppLockRow | None] | None:
    if not token or len(token) > 200:
        return None
    row = (
        await session.execute(
            select(UserSessionRow, AppLockRow)
            .outerjoin(AppLockRow, AppLockRow.user_id == UserSessionRow.user_id)
            .where(UserSessionRow.id == hash_token(token))
        )
    ).first()
    if row is None or not session_is_live(row[0], now):
        return None
    return row[0], row[1]


async def list_sessions(session: Any, user_id: str, *, now: datetime | None = None) -> list[UserSessionRow]:
    now = now or utcnow()
    rows = (
        await session.execute(
            select(UserSessionRow)
            .where(UserSessionRow.user_id == user_id, UserSessionRow.revoked_at.is_(None))
            .order_by(UserSessionRow.last_seen_at.desc())
        )
    ).scalars()
    return [r for r in rows if session_is_live(r, now)]


async def revoke_session(session: Any, row: UserSessionRow, reason: str, *, now: datetime | None = None) -> None:
    if row.revoked_at is None:
        row.revoked_at = now or utcnow()
        row.revoked_reason = reason[:30]


async def revoke_user_sessions(
    session: Any, user_id: str, reason: str, *, keep: str | None = None, now: datetime | None = None
) -> int:
    """Sign a person out of every device (except ``keep``, a session id).
    Returns how many sessions ended."""
    stmt = (
        update(UserSessionRow)
        .where(UserSessionRow.user_id == user_id, UserSessionRow.revoked_at.is_(None))
        .values(revoked_at=now or utcnow(), revoked_reason=reason[:30])
    )
    if keep:
        stmt = stmt.where(UserSessionRow.id != keep)
    result = await session.execute(stmt)
    return int(result.rowcount or 0)


# --------------------------------------------------------------------------- lock state


def lock_state(row: UserSessionRow, lock: AppLockRow | None, now: datetime) -> tuple[bool, bool]:
    """(lock enabled, locked now) for one session."""
    if lock is None:
        return False, False
    unlocked = aware(row.unlocked_at)
    active = aware(row.last_active_at) or unlocked
    if unlocked is None or active is None:
        return True, True
    idle = (now - active).total_seconds()
    return True, idle > max(0, int(lock.timeout_s or 0))


def is_lock_exempt(path: str) -> bool:
    return path.startswith(LOCK_EXEMPT_PREFIXES)


def wants_json_scope(scope: Scope) -> bool:
    path = str(scope.get("path", ""))
    if path.startswith(("/api/", "/hooks/")):
        return True
    headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
    accept = headers.get("accept", "")
    if "text/event-stream" in accept:
        return True
    return "application/json" in accept and "text/html" not in accept


def _cookie(name: str, value: str, *, max_age: int, secure: bool) -> str:
    parts = [f"{name}={value}", "Path=/", f"Max-Age={max(0, max_age)}", "HttpOnly", "SameSite=Lax"]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


class AuthSessionMiddleware:
    """Resolves ``rs_sid`` to :class:`AuthContext` (``scope["auth"]``), slides
    the session forward, enforces the app lock, and writes the cookie when a
    route signed someone in (``scope["auth_set_cookie"]``) or out
    (``scope["auth_clear_cookie"]``)."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        secure: bool = False,
        idle_days: int = 90,
        absolute_days: int = 365,
        cookie_name: str = AUTH_COOKIE,
        clock: Clock = time.time,
    ) -> None:
        self.app = app
        self.secure = secure
        self.idle = timedelta(days=idle_days)
        self.absolute_days = absolute_days
        self.cookie_name = cookie_name
        self.clock = clock

    def now(self) -> datetime:
        return datetime.fromtimestamp(self.clock(), UTC)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        path = str(scope.get("path", ""))
        if path.startswith(SKIP_PREFIXES):
            await self.app(scope, receive, send)
            return
        connection = HTTPConnection(scope)
        token = connection.cookies.get(self.cookie_name)
        renew_max_age: int | None = None
        clear = False
        if token:
            db = scope["app"].state.db
            now = self.now()
            async with db.session() as session:
                found = await find_session(session, token, now)
                if found is None:
                    clear = True
                else:
                    row, lock = found
                    enabled, locked = lock_state(row, lock, now)
                    changes: dict[str, Any] = {}
                    if (now - (aware(row.last_seen_at) or now)).total_seconds() >= RENEW_EVERY_S:
                        expires = min(now + self.idle, aware(row.absolute_expires_at) or now)
                        changes.update(last_seen_at=now, expires_at=expires)
                        renew_max_age = int((expires - now).total_seconds())
                    if enabled and locked and row.unlocked_at is not None:
                        changes["unlocked_at"] = None  # stays locked until a PIN or passkey
                    elif enabled and not locked and not is_lock_exempt(path):
                        last = aware(row.last_active_at) or now
                        if (now - last).total_seconds() >= ACTIVITY_EVERY_S:
                            changes["last_active_at"] = now
                    for key, value in changes.items():
                        setattr(row, key, value)
                    scope[SCOPE_KEY] = AuthContext(
                        session_id=row.id, handle=row.handle, user_id=row.user_id,
                        locked=locked, lock_enabled=enabled,
                    )
        auth = scope.get(SCOPE_KEY)
        if isinstance(auth, AuthContext) and auth.locked and not is_lock_exempt(path):
            if scope["type"] == "websocket":
                scope.pop(SCOPE_KEY, None)  # a locked device gets no live connections
            else:
                await self._locked_response(scope, receive, send)
                return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                new = scope.get("auth_set_cookie")
                if new:
                    value, max_age = new
                    headers.append("set-cookie", _cookie(self.cookie_name, value, max_age=max_age, secure=self.secure))
                elif scope.get("auth_clear_cookie") or clear:
                    headers.append("set-cookie", _cookie(self.cookie_name, "", max_age=0, secure=self.secure))
                elif renew_max_age is not None and token:
                    headers.append(
                        "set-cookie", _cookie(self.cookie_name, token, max_age=renew_max_age, secure=self.secure)
                    )
                theme = scope.get("theme_cookie")
                if theme and not any(
                    v.startswith(f"{THEME_COOKIE}=") for k, v in headers.items() if k.lower() == "set-cookie"
                ):
                    headers.append("set-cookie", _cookie(THEME_COOKIE, theme, max_age=THEME_MAX_AGE, secure=self.secure))
            await send(message)

        await self.app(scope, receive, send_wrapper)

    async def _locked_response(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = str(scope.get("path", ""))
        if wants_json_scope(scope):
            response: Any = JSONResponse(
                {"error": "locked", "message": "Secureddy is locked. Unlock it to continue.", "unlock": "/lock"},
                status_code=423,
            )
        else:
            target = "/lock"
            method = scope.get("method", "GET")
            query = scope.get("query_string", b"").decode("latin-1")
            if method == "GET" and path not in ("/", ""):
                full = f"{path}?{query}" if query else path
                target = f"/lock?next={quote(full, safe='/?=&')}"
            response = RedirectResponse(target, status_code=303)
        await response(scope, receive, send)


__all__ = [
    "AUTH_COOKIE",
    "AuthContext",
    "AuthSessionMiddleware",
    "auth_of",
    "create_session",
    "device_name",
    "find_session",
    "hash_token",
    "ip_prefix",
    "list_sessions",
    "lock_state",
    "revoke_session",
    "revoke_user_sessions",
]

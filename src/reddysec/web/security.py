"""Browser-facing security primitives: sessions, CSRF, headers, rate limits.

Everything here is deliberately small and dependency-free so it can be unit
tested with a fake clock and reasoned about line by line. The threat model is
a client on a consumer laptop: a stolen cookie must expire, a malicious page
must not be able to submit our forms, and a brute-force attempt against the
sign-in page must stall.

Sessions are *signed* cookies (itsdangerous), not encrypted ones. The payload
holds only identifiers and short-lived flow state (an OAuth state token, a
pending TOTP secret the user is about to confirm, flash messages); nothing in
it is secret from the user whose browser holds it.
"""

from __future__ import annotations

import copy
import hmac
import secrets
import time
from collections.abc import Callable, MutableMapping
from typing import Any

from fastapi import HTTPException, Request, status
from itsdangerous import BadSignature, TimestampSigner, URLSafeTimedSerializer
from starlette.datastructures import MutableHeaders
from starlette.requests import HTTPConnection
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

SESSION_COOKIE = "rs_session"
SESSION_MAX_AGE_S = 12 * 60 * 60
CSRF_FORM_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

Clock = Callable[[], float]


# --------------------------------------------------------------------------
# Session cookie codec
# --------------------------------------------------------------------------


def _signer_with_clock(clock: Clock) -> type[TimestampSigner]:
    """itsdangerous reads ``time.time()`` directly; wrapping it lets tests
    expire a cookie without sleeping for twelve hours."""

    class _ClockedSigner(TimestampSigner):
        def get_timestamp(self) -> int:
            return int(clock())

    return _ClockedSigner


class SessionCodec:
    """Serialises the session dict to a signed, timestamped cookie value.

    Two independent lifetimes apply. The signature timestamp is refreshed
    whenever the cookie is rewritten (any change to the session), so
    ``max_age`` alone would let an active session live forever. The ``iat``
    field is set once at sign-in and never rewritten, which gives an absolute
    12-hour lifetime regardless of activity.
    """

    def __init__(
        self, secret_key: str, *, max_age: int = SESSION_MAX_AGE_S, clock: Clock = time.time
    ) -> None:
        if not secret_key:
            raise ValueError("secret_key must not be empty")
        self.max_age = max_age
        self._clock = clock
        self._serializer = URLSafeTimedSerializer(
            secret_key, salt="reddysec.web.session", signer=_signer_with_clock(clock)
        )

    def encode(self, data: MutableMapping[str, Any]) -> str:
        return self._serializer.dumps(dict(data))

    def decode(self, value: str | None) -> dict[str, Any] | None:
        """Return the session dict, or ``None`` for anything we should not trust:
        missing, tampered, expired, or structurally wrong."""
        if not value:
            return None
        try:
            data = self._serializer.loads(value, max_age=self.max_age)
        except BadSignature:
            return None
        if not isinstance(data, dict):
            return None
        issued = data.get("iat")
        if isinstance(issued, int | float) and self._clock() - issued > self.max_age:
            return None
        return data


class SessionMiddleware:
    """Loads ``scope["session"]`` from the cookie and writes it back only when
    the handler changed it. Writing on every response would reset the
    signature timestamp constantly and spam Set-Cookie headers; writing only
    on change keeps the cookie quiet and the lifetime meaningful."""

    def __init__(
        self,
        app: ASGIApp,
        codec: SessionCodec,
        *,
        cookie_name: str = SESSION_COOKIE,
        secure: bool = False,
    ) -> None:
        self.app = app
        self.codec = codec
        self.cookie_name = cookie_name
        self.secure = secure

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        connection = HTTPConnection(scope)
        raw_cookie = connection.cookies.get(self.cookie_name)
        session = self.codec.decode(raw_cookie) or {}
        scope["session"] = session
        before = copy.deepcopy(session)
        had_cookie = raw_cookie is not None

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                current = scope["session"]
                if current != before:
                    headers = MutableHeaders(scope=message)
                    if current:
                        headers.append("set-cookie", self._cookie_header(self.codec.encode(current)))
                    elif had_cookie:
                        headers.append("set-cookie", self._cookie_header("", max_age=0))
            await send(message)

        await self.app(scope, receive, send_wrapper)

    def _cookie_header(self, value: str, *, max_age: int | None = None) -> str:
        age = self.codec.max_age if max_age is None else max_age
        parts = [f"{self.cookie_name}={value}", "Path=/", f"Max-Age={age}", "HttpOnly", "SameSite=Lax"]
        if self.secure:
            parts.append("Secure")
        return "; ".join(parts)


# --------------------------------------------------------------------------
# Session helpers used by routes
# --------------------------------------------------------------------------


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def login_session(request: Request, user_id: str, *, now: float | None = None) -> None:
    """Rotate the session on sign-in. A fresh dict (new CSRF token, new id, new
    ``iat``) means a cookie captured before sign-in is worthless afterwards."""
    request.session.clear()
    request.session.update(
        {
            "uid": user_id,
            "csrf": new_token(),
            "sid": new_token(16),
            "iat": int(now if now is not None else time.time()),
        }
    )


def logout_session(request: Request) -> None:
    request.session.clear()


def current_user_id(request: Request) -> str | None:
    uid = request.session.get("uid")
    return uid if isinstance(uid, str) and uid else None


def flash(request: Request, text: str, kind: str = "ok") -> None:
    """Queue a one-time message for the next rendered page. ``kind`` is one of
    ``ok``, ``warn`` or ``error`` and only affects styling."""
    flashes = list(request.session.get("flash", []))
    flashes.append({"kind": kind, "text": text})
    request.session["flash"] = flashes[-5:]  # a cookie has to stay small


def pop_flashes(request: Request) -> list[dict[str, str]]:
    if "session" not in request.scope:
        return []
    flashes = request.session.pop("flash", [])
    return [f for f in flashes if isinstance(f, dict) and "text" in f]


# --------------------------------------------------------------------------
# CSRF
# --------------------------------------------------------------------------


def csrf_token(request: Request) -> str:
    """The per-session CSRF token, created on first use so even the anonymous
    sign-in form is protected (login CSRF is a real attack)."""
    token = request.session.get("csrf")
    if not isinstance(token, str) or not token:
        token = new_token()
        request.session["csrf"] = token
    return token


def tokens_match(expected: str | None, presented: str | None) -> bool:
    if not expected or not presented:
        return False
    return hmac.compare_digest(expected.encode(), presented.encode())


async def csrf_protect(request: Request) -> None:
    """FastAPI dependency attached to every router. Safe methods pass; state
    changing requests must present the session token, in the form body for
    HTML pages and in the ``X-CSRF-Token`` header for ``/api`` JSON calls."""
    if request.method in SAFE_METHODS:
        return
    expected = request.session.get("csrf") if "session" in request.scope else None
    if request.url.path.startswith("/api/"):
        presented = request.headers.get(CSRF_HEADER)
    else:
        form = await request.form()
        value = form.get(CSRF_FORM_FIELD)
        presented = value if isinstance(value, str) else None
    if not tokens_match(expected, presented):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="This form has expired. Please go back, refresh the page and try again.",
        )


# --------------------------------------------------------------------------
# Security headers
# --------------------------------------------------------------------------

# style-src allows inline styles for one reason: the Reading Room page sizes its
# streamed canvas with element styles. Our own templates never use style
# attributes (signal bars use width classes) so this can tighten the moment the
# room moves to a stylesheet. Inline *scripts* stay forbidden everywhere.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "img-src 'self' data: blob:; "
    "style-src 'self' 'unsafe-inline'; "
    "script-src 'self'; "
    "connect-src 'self' ws: wss:; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "base-uri 'self'; "
    "object-src 'none'"
)

SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "clipboard-read=(), clipboard-write=(), camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}
HSTS_HEADER = "max-age=31536000; includeSubDomains"
STATIC_PREFIX = "/static/"


class SecurityHeadersMiddleware:
    """Adds the hardening headers to every HTTP response, including errors.
    HSTS is sent only in production because it would pin a developer's
    ``localhost`` to HTTPS for a year."""

    def __init__(self, app: ASGIApp, *, hsts: bool = False) -> None:
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path", ""))

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers.setdefault(name, value)
                # Pages and JSON may be someone's mail: no browser or proxy keeps
                # them. Static files revalidate. Routes that set their own value
                # (artifacts, the manifest, the service worker) keep it.
                headers.setdefault("Cache-Control", "no-cache" if path.startswith(STATIC_PREFIX) else "no-store")
                if self.hsts:
                    headers.setdefault("Strict-Transport-Security", HSTS_HEADER)
            await send(message)

        await self.app(scope, receive, send_wrapper)


# --------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------


class RateLimiter:
    """Token bucket per key, in memory.

    Good enough for a single web process in front of a handful of clients;
    a multi-instance deployment should put the same logic in the ingress.
    Buckets refill continuously, so a burst of ``rate`` attempts is allowed and
    then one more every ``per / rate`` seconds.
    """

    def __init__(
        self, rate: int = 20, per: float = 60.0, *, clock: Clock = time.monotonic, max_keys: int = 10_000
    ):
        if rate <= 0 or per <= 0:
            raise ValueError("rate and per must be positive")
        self.rate = rate
        self.per = per
        self._clock = clock
        self._max_keys = max_keys
        self._buckets: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_refill)

    def allow(self, key: str) -> bool:
        now = self._clock()
        tokens, last = self._buckets.get(key, (float(self.rate), now))
        tokens = min(float(self.rate), tokens + (now - last) * (self.rate / self.per))
        if tokens >= 1.0:
            self._buckets[key] = (tokens - 1.0, now)
            allowed = True
        else:
            self._buckets[key] = (tokens, now)
            allowed = False
        if len(self._buckets) > self._max_keys:
            self._prune(now)
        return allowed

    def retry_after(self, key: str) -> int:
        """Whole seconds until ``key`` gets its next token; 0 when allowed now."""
        tokens, last = self._buckets.get(key, (float(self.rate), self._clock()))
        tokens = min(float(self.rate), tokens + (self._clock() - last) * (self.rate / self.per))
        if tokens >= 1.0:
            return 0
        return max(1, int((1.0 - tokens) * (self.per / self.rate) + 0.999))

    def _prune(self, now: float) -> None:
        """Drop buckets that have fully refilled; they are indistinguishable from
        absent ones, so forgetting them loses nothing."""
        for key, (tokens, last) in list(self._buckets.items()):
            if tokens + (now - last) * (self.rate / self.per) >= self.rate:
                del self._buckets[key]


def client_ip(scope: Scope) -> str:
    """The peer address as the ASGI server reports it. Behind a proxy run
    uvicorn with ``--proxy-headers`` so this is the real client, not the proxy."""
    client = scope.get("client")
    return client[0] if client else "unknown"


class RateLimitMiddleware:
    """Applies a :class:`RateLimiter` to requests whose path starts with one of
    ``prefixes`` (the sign-in endpoints). Rejections are plain text 429s with a
    ``Retry-After`` header; no template rendering on the hot path."""

    def __init__(
        self, app: ASGIApp, limiter: RateLimiter, *, prefixes: tuple[str, ...] = ("/auth/",)
    ) -> None:
        self.app = app
        self.limiter = limiter
        self.prefixes = prefixes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["path"].startswith(self.prefixes):
            key = client_ip(scope)
            if not self.limiter.allow(key):
                response = PlainTextResponse(
                    "Too many attempts. Please wait a minute and try again.",
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    headers={"Retry-After": str(self.limiter.retry_after(key))},
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


# --------------------------------------------------------------------------
# Redirect safety
# --------------------------------------------------------------------------


def safe_return_to(value: str | None, default: str = "/") -> str:
    """Only same-origin absolute paths are honoured. ``//evil.example`` and
    ``https://...`` would turn the sign-in flow into an open redirect."""
    if not value or not isinstance(value, str):
        return default
    if not value.startswith("/") or value.startswith("//") or "\\" in value:
        return default
    if any(ord(ch) < 32 for ch in value):
        return default
    return value


__all__ = [
    "CONTENT_SECURITY_POLICY",
    "CSRF_FORM_FIELD",
    "CSRF_HEADER",
    "SECURITY_HEADERS",
    "SESSION_COOKIE",
    "SESSION_MAX_AGE_S",
    "RateLimitMiddleware",
    "RateLimiter",
    "SecurityHeadersMiddleware",
    "SessionCodec",
    "SessionMiddleware",
    "client_ip",
    "csrf_protect",
    "csrf_token",
    "current_user_id",
    "flash",
    "login_session",
    "logout_session",
    "new_token",
    "pop_flashes",
    "safe_return_to",
    "tokens_match",
]

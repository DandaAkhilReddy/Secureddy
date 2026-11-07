"""Application factory.

``create_app`` wires settings, the database, the OAuth provider, the Reading
Room router and the Gmail push handler together. Everything external is a
parameter with a sensible default so the functional tests can run the whole
app offline with fakes, and the integrator can swap pieces without editing
this module.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.staticfiles import StaticFiles

from reddysec.assistant.agent import Assistant
from reddysec.assistant.llm import ChatModel, chat_model_from_settings
from reddysec.config import Settings, get_settings
from reddysec.core.artifacts import ArtifactStore, artifact_store_from_settings
from reddysec.core.crypto import TokenCipher
from reddysec.core.logging import get_logger
from reddysec.store.db import Database, get_database

from . import auth
from .auth import LoginRequired, OAuthProvider
from .routes import (
    api,
    assistant,
    audit,
    concierge,
    dashboard,
    hooks,
    lock,
    mailboxes,
    mailread,
    messages,
    notifications,
    pwa,
)
from .routes import settings as settings_routes
from .security import (
    RateLimiter,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    SessionCodec,
    SessionMiddleware,
)
from .sessions import AuthSessionMiddleware
from .templating import build_templates, package_path, render, wants_json

log = get_logger(__name__)

GmailPushHandler = Callable[[str, str], Awaitable[None]]
# (host, port, username, password) -> None; raises AuthExpired / ConnectorError.
ImapTester = Callable[[str, int, str, str], Awaitable[None]]

ERROR_TITLES = {
    400: "That request was not valid",
    403: "You cannot do that here",
    404: "We could not find that page",
    405: "That action is not allowed here",
    429: "Too many attempts",
    500: "Something went wrong on our side",
}


def create_app(
    settings: Settings | None = None,
    *,
    db: Database | None = None,
    oauth: OAuthProvider | None = None,
    room_router: APIRouter | None = None,
    on_gmail_push: GmailPushHandler | None = None,
    pubsub_token: str | None = None,
    artifact_store: ArtifactStore | None = None,
    enable_reading_room: bool = False,
    chat_model: ChatModel | None = None,
    microsoft_oauth: OAuthProvider | None = None,
    yahoo_oauth: OAuthProvider | None = None,
    imap_tester: ImapTester | None = None,
    connector_factory: Callable[[Any], Awaitable[Any]] | None = None,
    http_client: Any | None = None,
) -> FastAPI:
    """Build the FastAPI application.

    :param settings: configuration; defaults to the process environment.
    :param db: database handle; defaults to the shared ``get_database()``.
    :param oauth: Google sign-in provider. ``None`` builds the real
        ``GoogleOAuth`` from settings when a client id is configured, and
        otherwise hides the Google button.
    :param room_router: the Reading Room router from
        ``chamber.readingroom_web.make_room_router``; ``None`` disables the
        "Open in Reading Room" button with an explanation.
    :param on_gmail_push: coroutine ``(email_address, history_id)`` called for
        each Pub/Sub push; ``None`` acknowledges pushes without acting.
    :param pubsub_token: shared secret the push subscription must present as
        ``?token=``; ``None`` rejects every push.
    :param artifact_store: where screenshots and safe copies live; defaults to
        ``LocalArtifactStore(settings.artifacts_dir)``.
    :param enable_reading_room: build the real Reading Room (Chromium-backed)
        inside this process and mount it with the web tier's auth, CSRF and
        audit wiring. Ignored when ``room_router`` is given. The CLI turns this
        on; tests pass their own router or leave the room off.
    :param connector_factory: ``async (MailboxRow) -> MailboxConnector`` used to
        read an email live, search inside emails, archive / mark read / delete
        and revoke a mailbox's grant. ``None`` builds the real connectors from
        settings on first use (``mail.factory``).
    :param http_client: the ``httpx.AsyncClient`` for "Load images" (the image
        proxy); ``None`` creates one owned by the app. Tests pass a client on
        an ``httpx.MockTransport``.
    """
    settings = settings or get_settings()
    database = db or get_database()
    owns_database = db is None
    if oauth is None:
        oauth = default_oauth(settings)
    if microsoft_oauth is None:
        microsoft_oauth = default_microsoft_oauth(settings)
    if yahoo_oauth is None:
        yahoo_oauth = default_yahoo_oauth(settings)
    store = artifact_store or artifact_store_from_settings(settings)

    import httpx

    owned_http = None
    if chat_model is None and settings.effective_assistant_provider not in ("", "none"):
        owned_http = httpx.AsyncClient()
        chat_model = chat_model_from_settings(settings, owned_http)
    owned_proxy_http = None
    if http_client is None:
        owned_proxy_http = http_client = httpx.AsyncClient(follow_redirects=False, timeout=10.0)

    room_bundle = None
    if room_router is None and enable_reading_room:
        from .room import build_reading_room  # lazy: imports the chamber (Playwright)

        room_bundle = build_reading_room(settings, store, database)
        room_router = room_bundle.router

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if settings.env in ("dev", "test"):
            # Production uses migrations; dev and test start from an empty file.
            await database.create_all()
        try:
            if room_bundle is not None:
                async with room_bundle.lifespan():
                    yield
            else:
                yield
        finally:
            if owned_http is not None:
                await owned_http.aclose()
            if owned_proxy_http is not None:
                await owned_proxy_http.aclose()
            if owns_database:
                await database.dispose()

    app = FastAPI(
        title="Secureddy",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.env != "prod" else None,
    )

    app.state.settings = settings
    app.state.db = database
    app.state.oauth = oauth
    app.state.microsoft_oauth = microsoft_oauth
    app.state.yahoo_oauth = yahoo_oauth
    app.state.imap_tester = imap_tester or test_imap_login
    app.state.cipher = TokenCipher.from_settings(
        settings.token_kek.get_secret_value(),
        settings.secret_key.get_secret_value(),
        settings.token_kek_previous.get_secret_value(),
    )
    app.state.templates = build_templates()
    app.state.artifact_store = store
    app.state.room_manager = room_bundle.manager if room_bundle is not None else None
    app.state.on_gmail_push = on_gmail_push
    app.state.pubsub_token = pubsub_token
    app.state.room_enabled = room_router is not None
    app.state.dev_login_enabled = bool(settings.dev_login_enabled) and not settings.is_prod
    app.state.rate_limiter = RateLimiter(rate=20, per=60.0)
    app.state.assistant = Assistant(
        chat_model,
        max_turns=max(1, settings.assistant_max_turns),
        daily_limit=max(0, settings.assistant_daily_message_limit),
    )
    app.state.assistant_provider = settings.effective_assistant_provider
    app.state.http = http_client
    app.state.connector_factory = connector_factory or _default_connector_factory(settings, database)

    # Middleware order: the last one added runs first. Security headers must
    # wrap everything so even a 429 from the rate limiter carries them. The
    # sign-in session (rs_sid) is resolved inside the flow cookie.
    app.add_middleware(
        AuthSessionMiddleware,
        secure=settings.is_prod,
        idle_days=max(1, settings.session_idle_days),
        absolute_days=max(1, settings.session_absolute_days),
    )
    app.add_middleware(
        SessionMiddleware,
        codec=SessionCodec(settings.secret_key.get_secret_value(), max_age=max(1, settings.session_idle_days) * 86400),
        secure=settings.is_prod,
    )
    app.add_middleware(RateLimitMiddleware, limiter=app.state.rate_limiter, prefixes=("/auth/",))
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.is_prod)

    app.mount("/static", StaticFiles(directory=str(package_path("static"))), name="static")

    for router in (
        auth.router,
        dashboard.router,
        messages.router,
        mailread.router,
        assistant.router,
        lock.router,
        mailboxes.router,
        audit.router,
        concierge.router,
        notifications.router,
        settings_routes.router,
        hooks.router,
        api.router,
        pwa.router,
    ):
        app.include_router(router)
    if room_router is not None:
        app.include_router(room_router)

    _register_health(app)
    _register_error_handlers(app)
    return app


def _default_connector_factory(settings: Settings, database: Database) -> Callable[[Any], Awaitable[Any]]:
    """Real connectors, built lazily: importing the mail stack is not free."""
    holder: dict[str, Any] = {}

    async def factory(mailbox: Any) -> Any:
        if "f" not in holder:
            from reddysec.mail.factory import connector_factory_from_settings

            holder["f"] = connector_factory_from_settings(settings, database)
        return await holder["f"](mailbox)

    return factory


def default_oauth(settings: Settings) -> OAuthProvider | None:
    """The production Google provider, built only when ``RS_GOOGLE_CLIENT_ID``
    and ``RS_GOOGLE_CLIENT_SECRET`` are set, so ``reddysec web`` works from a
    filled-in ``.env`` and tests never touch the real module."""
    client_secret = settings.google_client_secret.get_secret_value()
    if not settings.google_client_id or not client_secret:
        return None
    from reddysec.mail.oauth_google import GoogleOAuth  # lazy: not needed without Google

    return GoogleOAuth(
        settings.google_client_id,
        client_secret,
        settings.google_redirect_uri,
        state_signer_secret=settings.secret_key.get_secret_value(),
    )


def default_microsoft_oauth(settings: Settings) -> OAuthProvider | None:
    """Built only when ``RS_MICROSOFT_CLIENT_ID`` and ``RS_MICROSOFT_CLIENT_CERT``
    are set. A certificate that cannot be read hides the button and logs an
    error rather than stopping the whole site."""
    if not settings.microsoft_enabled:
        return None
    from reddysec.mail.factory import make_microsoft_oauth  # lazy: pulls in the Graph connector

    try:
        return make_microsoft_oauth(settings)
    except ValueError as exc:
        log.error("microsoft_oauth_misconfigured", error=str(exc))
        return None


def default_yahoo_oauth(settings: Settings) -> OAuthProvider | None:
    if not settings.yahoo_enabled:
        return None
    from reddysec.mail.factory import make_yahoo_oauth

    return make_yahoo_oauth(settings)


async def test_imap_login(host: str, port: int, username: str, password: str) -> None:
    """The real "Test connection": an IMAP login through ``ImapConnector``."""
    from reddysec.mail.imap import ImapConnector, ImapCredentials
    from reddysec.models import Provider

    connector = ImapConnector(
        "test-connection",
        username,
        Provider.GENERIC_IMAP,
        ImapCredentials(username=username, password=password, host=host, port=port),
    )
    await connector.check_login()


test_imap_login.__test__ = False  # type: ignore[attr-defined]  # not a pytest test


def _register_health(app: FastAPI) -> None:
    @app.get("/healthz", include_in_schema=False)
    async def healthz(request: Request) -> JSONResponse:
        try:
            async with request.app.state.db.session() as session:
                await session.execute(text("SELECT 1"))
        except Exception:
            log.exception("healthz_db_failed")
            return JSONResponse(
                {"status": "degraded", "db": "error"}, status_code=status.HTTP_503_SERVICE_UNAVAILABLE
            )
        return JSONResponse({"status": "ok", "db": "ok"})

    @app.get("/readyz", include_in_schema=False)
    async def readyz(request: Request) -> JSONResponse:
        checks: dict[str, Any] = {"templates": "ok", "db": "ok"}
        try:
            request.app.state.templates.env.get_template("base.html")
        except Exception:
            checks["templates"] = "error"
        try:
            async with request.app.state.db.session() as session:
                await session.execute(text("SELECT 1"))
        except Exception:
            checks["db"] = "error"
        ready = all(v == "ok" for v in checks.values())
        return JSONResponse(
            {"status": "ready" if ready else "not_ready", **checks},
            status_code=status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE,
        )


def _error_response(request: Request, status_code: int, message: str) -> Response:
    if wants_json(request):
        return JSONResponse({"error": message, "status": status_code}, status_code=status_code)
    request.state.keep_flashes = True
    try:
        return render(
            request,
            "error.html",
            {
                "status_code": status_code,
                "title": ERROR_TITLES.get(status_code, "Something went wrong"),
                "message": message,
            },
            status_code=status_code,
        )
    except Exception:
        # The error page itself must never be the thing that fails.
        log.exception("error_page_render_failed")
        return Response(message, status_code=status_code, media_type="text/plain")


def _register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(LoginRequired)
    async def login_required(request: Request, exc: LoginRequired) -> Response:
        if wants_json(request):
            return JSONResponse({"error": "sign_in_required"}, status_code=status.HTTP_401_UNAUTHORIZED)
        target = "/login"
        if exc.next_url and exc.next_url != "/":
            target = f"/login?next={quote(exc.next_url, safe='/?=&')}"
        return RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
        detail = (
            exc.detail
            if isinstance(exc.detail, str) and exc.detail
            else ERROR_TITLES.get(exc.status_code, "")
        )
        response = _error_response(request, exc.status_code, detail or "Something went wrong.")
        if exc.headers:
            response.headers.update(exc.headers)
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> Response:
        if wants_json(request):
            return JSONResponse(
                {"error": "invalid_request", "detail": jsonable_encoder(exc.errors())}, status_code=422
            )
        return _error_response(
            request, 400, "Something in that form was missing or not valid. Please go back and try again."
        )

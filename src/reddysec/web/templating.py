"""Jinja environment and the ``render`` helper every page uses.

``StrictUndefined`` is on purpose: a typo in a template raises during the
functional tests instead of printing an empty string on a client's report.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from fastapi import Request
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from starlette.responses import HTMLResponse
from starlette.templating import Jinja2Templates

from reddysec import __version__
from reddysec.models.accounts import MAILBOX_RETRYING_ERRORS

from . import presenters
from .queries import is_staff
from .security import csrf_token, pop_flashes

NAV_ITEMS: tuple[tuple[str, str], ...] = (
    ("/", "Home"),
    ("/messages", "Email"),
    ("/assistant", "Ask Secureddy"),
    ("/mailboxes", "Mailboxes"),
    ("/audit", "Audit"),
)
STAFF_NAV_ITEMS: tuple[tuple[str, str], ...] = (("/concierge", "Concierge"),)
SETTINGS_NAV_ITEM: tuple[str, str] = ("/settings/security", "Settings")
NAV_ICONS = {
    "/": "home", "/messages": "mail", "/assistant": "chat", "/mailboxes": "inbox", "/audit": "list",
    "/concierge": "users", "/settings/security": "settings",
}


# Phones get a bottom tab bar with the four places people go most.
TAB_ITEMS: tuple[tuple[str, str, str], ...] = (
    ("/", "Home", "home"),
    ("/messages", "Email", "mail"),
    ("/assistant", "Ask", "chat"),
    ("/mailboxes", "Mailboxes", "inbox"),
)
THEME_COOKIE = "rs_theme"
THEMES = ("system", "dark", "light")


def theme_of(request: Request) -> str:
    value = request.cookies.get(THEME_COOKIE, "system")
    return value if value in THEMES else "system"


def package_path(name: str) -> Path:
    """``templates`` and ``static`` ship inside the package so the app works
    from a wheel, not only from a checkout."""
    return Path(str(resources.files("reddysec.web").joinpath(name)))


@lru_cache(maxsize=1)
def asset_version() -> str:
    """A short hash of the shipped static files: added to asset URLs as
    ``?v=`` and to the service worker's cache name, so a deploy that changes
    the stylesheet or scripts is picked up at once."""
    digest = hashlib.sha256()
    static = package_path("static")
    for path in sorted(static.rglob("*")):
        if path.is_file():
            digest.update(path.relative_to(static).as_posix().encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()[:10]


def _context_processor(request: Request) -> dict[str, Any]:
    """Values every template needs. ``user`` is whatever ``current_user`` left on
    ``request.state`` (``None`` on anonymous pages such as sign-in)."""
    state = request.app.state
    user = getattr(request.state, "user", None)
    nav = list(NAV_ITEMS)
    if user is not None and is_staff(user):
        nav.extend(STAFF_NAV_ITEMS)
    nav.append(SETTINGS_NAV_ITEM)
    # Error pages leave queued flashes alone so the message the client was
    # meant to see survives until the next real page.
    keep_flashes = bool(getattr(request.state, "keep_flashes", False))
    return {
        "user": user,
        "csrf_token": csrf_token(request) if "session" in request.scope else "",
        "flashes": [] if keep_flashes else pop_flashes(request),
        "nav_items": nav,
        "current_path": request.url.path,
        "room_enabled": bool(getattr(state, "room_enabled", False)),
        "google_login_enabled": getattr(state, "oauth", None) is not None,
        "microsoft_login_enabled": getattr(state, "microsoft_oauth", None) is not None,
        "yahoo_login_enabled": getattr(state, "yahoo_oauth", None) is not None,
        "tab_items": TAB_ITEMS,
        "theme": theme_of(request),
        "asset_version": asset_version(),
        "dev_login_enabled": bool(getattr(state, "dev_login_enabled", False)),
        "app_version": __version__,
    }


def build_templates() -> Jinja2Templates:
    env = Environment(
        loader=FileSystemLoader(str(package_path("templates"))),
        autoescape=select_autoescape(["html", "xml"]),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["dt"] = presenters.format_dt
    env.filters["ago"] = presenters.humanize_ago
    env.filters["ago_short"] = presenters.ago_short
    env.filters["short_date"] = presenters.short_date
    env.filters["provider"] = presenters.provider_label
    env.filters["lane"] = presenters.lane_short
    env.filters["action_phrase"] = presenters.action_phrase
    env.globals["SAFE_REASONS"] = presenters.SAFE_REASON_CHOICES
    env.globals["FAKE_REASONS"] = presenters.FAKE_REASON_CHOICES
    env.globals["NOT_FAKE_REASONS"] = presenters.NOT_FAKE_REASON_CHOICES
    env.globals["NAV_ICONS"] = NAV_ICONS
    env.globals["RETRYING_ERRORS"] = MAILBOX_RETRYING_ERRORS
    env.globals["PROVIDER_LOGOS"] = {
        "gmail": "google", "microsoft": "microsoft", "outlook": "microsoft", "yahoo": "yahoo",
    }
    return Jinja2Templates(env=env, context_processors=[_context_processor])


def render(
    request: Request, name: str, context: dict[str, Any] | None = None, *, status_code: int = 200
) -> HTMLResponse:
    templates: Jinja2Templates = request.app.state.templates
    return templates.TemplateResponse(request, name, context or {}, status_code=status_code)


def wants_json(request: Request) -> bool:
    """API callers get JSON errors; browsers get a page. The path decides, with
    the Accept header as a fallback for fetch() calls to HTML routes."""
    if request.url.path.startswith("/api/") or request.url.path.startswith("/hooks/"):
        return True
    accept = request.headers.get("accept", "")
    return "application/json" in accept and "text/html" not in accept

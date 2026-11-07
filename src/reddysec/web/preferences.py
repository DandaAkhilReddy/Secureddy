"""Per-person choices kept on the server (``user_preferences``).

* ``inbox_view``: ``together`` (one merged list with a small account chip on
  each row) or ``separate`` (a section per mailbox with its own counts).
* ``selected_mailbox``: the inbox picked in the "All inboxes · ..." switch on
  Home and Email; empty means all. The assistant reads it too, so "show me the
  most suspicious emails" answers for the inbox the person is looking at.
* ``period``: the window on Home and Email: ``today``, ``7d`` (default),
  ``1m`` or ``1y``.
* ``theme``: ``system`` (follow the device), ``dark`` or ``light``. Pages
  read it on every signed-in request; the ``rs_theme`` cookie is the fallback
  for pages without a signed-in person (sign-in, lock screen).

Only the keys and values listed here can be stored.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from reddysec.core.ids import new_id
from reddysec.store.models import MailboxRow, UserPreferenceRow

INBOX_VIEW = "inbox_view"
SELECTED_MAILBOX = "selected_mailbox"
PERIOD = "period"
THEME = "theme"
VIEWS = ("together", "separate")
PERIODS = ("today", "7d", "1m", "1y")
THEMES = ("system", "dark", "light")
DEFAULTS: dict[str, str] = {INBOX_VIEW: "together", SELECTED_MAILBOX: "", PERIOD: "7d", THEME: ""}
TZ_COOKIE = "rs_tz"
MAX_VALUE = 200


def _valid(key: str, value: str) -> bool:
    if key == INBOX_VIEW:
        return value in VIEWS
    if key == SELECTED_MAILBOX:
        return len(value) <= 40 and (value == "" or value.replace("_", "").isalnum())
    if key == PERIOD:
        return value in PERIODS
    if key == THEME:
        return value in THEMES
    return False


async def get_preference(session: AsyncSession, user_id: str, key: str) -> str:
    row = (
        await session.execute(
            select(UserPreferenceRow.value).where(UserPreferenceRow.user_id == user_id, UserPreferenceRow.key == key)
        )
    ).scalar_one_or_none()
    return row if row is not None and _valid(key, row) else DEFAULTS.get(key, "")


def resolve_period(requested: str | None, stored: str, days: int | None = None) -> tuple[str, bool]:
    """``?period=`` wins (older links send ``?days=``), else the stored choice.
    Returns (period, changed)."""
    from .queries import DAYS_TO_PERIOD

    if requested not in PERIODS and days is not None:
        requested = DAYS_TO_PERIOD.get(days)
    if requested in PERIODS:
        return str(requested), requested != stored
    return (stored if stored in PERIODS else "7d"), False


def client_tz(request: Any) -> Any:
    """The browser's time zone (``rs_tz``, set by app.js), else UTC. Only
    names the zone database knows are accepted."""
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    name = (request.cookies.get(TZ_COOKIE) or "").strip()
    if not name or len(name) > 64 or ".." in name or name.startswith("/"):
        return UTC
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return UTC


async def get_preferences(session: AsyncSession, user_id: str) -> dict[str, str]:
    rows = (await session.execute(select(UserPreferenceRow).where(UserPreferenceRow.user_id == user_id))).scalars()
    prefs = dict(DEFAULTS)
    for row in rows:
        if row.key in DEFAULTS and _valid(row.key, row.value):
            prefs[row.key] = row.value
    return prefs


async def set_preference(session: AsyncSession, user_id: str, key: str, value: str) -> bool:
    """Store one choice; returns False (and stores nothing) for an unknown key
    or a value outside its set."""
    value = (value or "")[:MAX_VALUE]
    if key not in DEFAULTS or not _valid(key, value):
        return False
    row = (
        await session.execute(
            select(UserPreferenceRow).where(UserPreferenceRow.user_id == user_id, UserPreferenceRow.key == key)
        )
    ).scalar_one_or_none()
    now = datetime.now(UTC)
    if row is None:
        session.add(UserPreferenceRow(id=new_id("prf"), user_id=user_id, key=key, value=value, updated_at=now))
    elif row.value != value:
        row.value = value
        row.updated_at = now
    return True


def resolve_selection(requested: str | None, stored: str, mailboxes: list[MailboxRow]) -> tuple[str | None, bool]:
    """The mailbox to show: ``?mailbox=`` wins (``all`` or empty string means
    every inbox), else the stored choice. A mailbox the person cannot see
    falls back to all. Returns (mailbox id or None for all, changed)."""
    ids = {m.id for m in mailboxes}
    if requested is not None:
        chosen = None if requested in ("", "all") else requested
        if chosen is not None and chosen not in ids:
            chosen = None
        return chosen, (chosen or "") != stored
    return (stored if stored in ids else None), False


def switcher(mailboxes: list[MailboxRow], selected: str | None, base: str, extra: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Items for the "All inboxes · a@x · b@y" segmented control."""
    from urllib.parse import urlencode

    params = {k: v for k, v in (extra or {}).items() if v not in (None, "")}

    def href(value: str) -> str:
        return f"{base}?{urlencode({**params, 'mailbox': value})}"

    items = [{"id": "all", "label": "All inboxes", "href": href("all"), "current": selected is None, "provider": ""}]
    for m in mailboxes:
        if m.status == "disconnected":
            continue
        items.append(
            {"id": m.id, "label": m.address, "href": href(m.id), "current": selected == m.id, "provider": m.provider}
        )
    return items


__all__ = [
    "DEFAULTS",
    "INBOX_VIEW",
    "PERIOD",
    "PERIODS",
    "THEME",
    "THEMES",
    "client_tz",
    "get_preference",
    "resolve_period",
    "SELECTED_MAILBOX",
    "VIEWS",
    "get_preferences",
    "resolve_selection",
    "set_preference",
    "switcher",
]

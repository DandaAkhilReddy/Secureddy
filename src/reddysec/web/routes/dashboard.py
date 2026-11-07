"""The home page: one true sentence about the chosen period, then the detail.

The period (Today · 7 days · 1 month · 1 year) applies to everything on the
page: the two cards and their sparklines, the sentence, the recent list and
the account cards. It is kept in ``user_preferences`` and shared with Email.
"""

from __future__ import annotations

from datetime import timedelta

from fastapi import Depends, Query, Request
from starlette.responses import Response

from reddysec.store.models import UserRow

from .. import preferences, presenters, queries
from ..auth import current_user
from ..templating import render
from . import protected_router
from .assistant import suggestions_for

router = protected_router()


@router.get("/", name="dashboard")
async def dashboard(
    request: Request,
    mailbox: str | None = Query(default=None, max_length=40),
    period: str | None = Query(default=None, max_length=10),
    user: UserRow = Depends(current_user),
) -> Response:
    now = queries.utcnow()
    async with request.app.state.db.session() as session:
        mailboxes = await queries.list_mailboxes(session, user)
        prefs = await preferences.get_preferences(session, user.id)
        selected, changed = preferences.resolve_selection(mailbox, prefs[preferences.SELECTED_MAILBOX], mailboxes)
        if changed:
            await preferences.set_preference(session, user.id, preferences.SELECTED_MAILBOX, selected or "")
        period_key, period_changed = preferences.resolve_period(period, prefs[preferences.PERIOD])
        if period_changed:
            await preferences.set_preference(session, user.id, preferences.PERIOD, period_key)
        window = queries.period_window(period_key, now=now, tz=preferences.client_tz(request))
        counts, series = await queries.period_stats(session, user, window, mailbox_id=selected)
        recent = await queries.list_messages(session, user, limit=15, mailbox_id=selected, since=window.since)
        notifications = await queries.list_notifications(
            session, user, limit=5, since=now - timedelta(days=7)
        )
        weeks = await queries.mailbox_week_counts(session, user, since=window.since)
        suggestions = await suggestions_for(session, user, selected)

    active = [m for m in mailboxes if m.status != "disconnected"]
    when = presenters.PERIOD_PHRASES[period_key]
    return render(
        request,
        "dashboard.html",
        {
            "first_name": presenters.first_name(user),
            "sentence": presenters.weekly_sentence(counts, has_mailboxes=bool(active), period=period_key),
            "counts": counts,
            "stat_cards": presenters.stat_cards(counts, series, mailbox=selected, period=period_key),
            "hero": presenters.hero(counts, has_mailboxes=bool(active)),
            "period": period_key,
            "period_label": window.label,
            "period_when": when,
            "periods": presenters.period_items(period_key, "/", {"mailbox": selected}),
            "suggestions": suggestions,
            "switcher": preferences.switcher(mailboxes, selected, "/", {"period": period_key}),
            "selected": selected,
            "view": prefs[preferences.INBOX_VIEW],
            "weeks": weeks,
            "assistant_enabled": request.app.state.assistant.enabled,
            "mailboxes": [
                {"row": m, "status": presenters.account_status(m).chip, "mode": presenters.mode_chip(m),
                 "week": weeks.get(m.id, queries.MailboxWeek())}
                for m in mailboxes if m.status != "disconnected"
            ],
            "recent": presenters.list_rows(recent),
            "see_all_href": "/messages?" + "&".join(
                f"{k}={v}" for k, v in (("period", period_key), ("mailbox", selected)) if v
            ),
            "notifications": notifications,
            "show_empty_state": not active,
            "hold_minutes": request.app.state.settings.hold_dead_man_minutes,
        },
    )

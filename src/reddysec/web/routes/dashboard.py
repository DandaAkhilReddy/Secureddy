"""The home page: one true sentence about the week, then the detail."""

from __future__ import annotations

from datetime import timedelta

from fastapi import Depends, Request
from starlette.responses import Response

from reddysec.store.models import UserRow

from .. import presenters, queries
from ..auth import current_user
from ..templating import render
from . import protected_router

router = protected_router()


@router.get("/", name="dashboard")
async def dashboard(request: Request, user: UserRow = Depends(current_user)) -> Response:
    now = queries.utcnow()
    async with request.app.state.db.session() as session:
        mailboxes = await queries.list_mailboxes(session, user)
        counts = await queries.weekly_counts(session, user, now=now)
        recent = await queries.list_messages(session, user, limit=15)
        notifications = await queries.list_notifications(
            session, user, limit=5, since=now - timedelta(days=7)
        )

    active = [m for m in mailboxes if m.status != "disconnected"]
    return render(
        request,
        "dashboard.html",
        {
            "first_name": presenters.first_name(user),
            "sentence": presenters.weekly_sentence(counts, has_mailboxes=bool(active)),
            "counts": counts,
            "mailboxes": [
                {"row": m, "status": presenters.mailbox_status_chip(m), "mode": presenters.mode_chip(m)}
                for m in mailboxes
            ],
            "recent": presenters.list_rows(recent),
            "notifications": notifications,
            "show_empty_state": not active,
            "hold_minutes": request.app.state.settings.hold_dead_man_minutes,
        },
    )

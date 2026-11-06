"""Notifications we raised for the client (dashboard channel and copies of
what was emailed). Read-only: the schema has no read flag and the audit log
already records every action the client takes from here."""

from __future__ import annotations

from fastapi import Depends, Request
from starlette.responses import Response

from reddysec.store.models import UserRow

from .. import presenters, queries
from ..auth import current_user
from ..templating import render
from . import protected_router

router = protected_router()


@router.get("/notifications", name="notifications")
async def notifications_page(request: Request, user: UserRow = Depends(current_user)) -> Response:
    async with request.app.state.db.session() as session:
        rows = await queries.list_notifications(session, user, limit=100)
    return render(
        request,
        "notifications.html",
        {"notifications": [{"row": n, "chip": presenters.level_chip(n.level)} for n in rows]},
    )

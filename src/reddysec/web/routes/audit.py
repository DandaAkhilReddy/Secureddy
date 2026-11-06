"""The client's glass-box log: who did what, to which mailbox, when."""

from __future__ import annotations

from fastapi import Depends, Query, Request
from starlette.responses import Response

from reddysec.store.models import UserRow

from .. import presenters, queries
from ..auth import current_user
from ..templating import render
from . import protected_router

router = protected_router()

PER_PAGE = 50


@router.get("/audit", name="audit")
async def audit_page(
    request: Request, page: int = Query(default=1, ge=1, le=10_000), user: UserRow = Depends(current_user)
) -> Response:
    async with request.app.state.db.session() as session:
        entries, total = await queries.list_audit(session, user, page=page, per_page=PER_PAGE)
    pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    return render(
        request,
        "audit.html",
        {
            "entries": [
                {
                    "row": e,
                    "actor": presenters.actor_label(e, user),
                    "action": presenters.action_phrase(e.action),
                    "detail": presenters.detail_phrase(e),
                }
                for e in entries
            ],
            "page": page,
            "pages": pages,
            "total": total,
        },
    )

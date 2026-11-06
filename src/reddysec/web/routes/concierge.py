"""Staff queue: messages the engine or a client flagged for a human."""

from __future__ import annotations

from fastapi import Depends, Form, HTTPException, Request, status
from starlette.responses import RedirectResponse, Response

from reddysec.models import Role
from reddysec.store.models import UserRow

from .. import presenters, queries
from ..auth import require_role
from ..security import flash
from ..templating import render
from . import protected_router

router = protected_router()

staff_only = require_role(Role.CONCIERGE, Role.ADMIN)
OVERRIDE_LEVELS = ("safe", "suspicious", "malicious")


def _see_other(url: str = "/concierge") -> RedirectResponse:
    return RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)


@router.get("/concierge", name="concierge")
async def concierge_page(request: Request, user: UserRow = Depends(staff_only)) -> Response:
    async with request.app.state.db.session() as session:
        queue = await queries.concierge_queue(session)
        reasons = await queries.latest_reasons(session, [m.id for m, _, _ in queue])
    return render(
        request,
        "concierge.html",
        {
            "queue": [
                {
                    "message": m,
                    "mailbox": mb,
                    "owner": owner,
                    "chip": presenters.verdict_chip(m),
                    "summary": presenters.message_summary(m),
                    "request_note": ((m.verdict or {}).get("review_request") or {}).get("note", ""),
                    "client_reason": presenters.decision_note(
                        reasons.get(m.id), presenters.client_decision(m)
                    ).replace("You marked", "Client marked", 1),
                }
                for m, mb, owner in queue
            ],
            "levels": [(code, presenters.level_chip(code).label) for code in OVERRIDE_LEVELS],
        },
    )


@router.post("/concierge/{message_id}/reviewed", name="concierge_reviewed")
async def concierge_reviewed(
    request: Request, message_id: str, note: str = Form(""), user: UserRow = Depends(staff_only)
) -> Response:
    async with request.app.state.db.session() as session:
        found = await queries.get_message(session, user, message_id)
        if found is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="We could not find that email.")
        message, mailbox = found
        await queries.mark_reviewed(session, user, message, mailbox, note.strip())
    flash(request, "Marked as reviewed.")
    return _see_other()


@router.post("/concierge/{message_id}/override", name="concierge_override")
async def concierge_override(
    request: Request,
    message_id: str,
    level: str = Form(...),
    note: str = Form(""),
    user: UserRow = Depends(staff_only),
) -> Response:
    if level not in OVERRIDE_LEVELS:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail="Level must be safe, suspicious or malicious."
        )
    async with request.app.state.db.session() as session:
        found = await queries.get_message(session, user, message_id)
        if found is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="We could not find that email.")
        message, mailbox = found
        await queries.override_verdict(session, user, message, mailbox, level, note.strip())
    flash(request, f"Verdict changed to {presenters.level_chip(level).label}. The client has been told.")
    return _see_other()

"""Message list, the report page, client actions, and artifact serving.

Design rule for the report: a link from a scanned email is text, never an
anchor. The only way to open it is the Reading Room form, which runs the page
on our servers and streams pixels back.
"""

from __future__ import annotations

import mimetypes
import re
from urllib.parse import quote

from fastapi import Depends, Form, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse, Response

from reddysec.store.models import MailboxRow, MessageRow, UserRow

from .. import presenters, queries
from ..auth import current_user
from ..security import flash
from ..templating import render
from . import protected_router

router = protected_router()

LEVEL_FILTERS = ("safe", "suspicious", "malicious", "unknown")
_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


def _see_other(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)


async def _get_or_404(session: AsyncSession, user: UserRow, message_id: str) -> tuple[MessageRow, MailboxRow]:
    """Message + mailbox, or a 404 that does not reveal whether the id exists."""
    found = await queries.get_message(session, user, message_id)
    if found is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="We could not find that email report.")
    return found


@router.get("/messages", name="messages")
async def message_list(
    request: Request,
    user: UserRow = Depends(current_user),
    level: str | None = Query(default=None),
    mailbox: str | None = Query(default=None),
    quarantined: str | None = Query(default=None),
) -> Response:
    level_filter = level if level in LEVEL_FILTERS else None
    async with request.app.state.db.session() as session:
        mailboxes = await queries.list_mailboxes(session, user)
        mailbox_filter = mailbox if any(m.id == mailbox for m in mailboxes) else None
        rows = await queries.list_messages(
            session,
            user,
            limit=100,
            mailbox_id=mailbox_filter,
            level=level_filter,
            quarantined=True if quarantined == "1" else None,
        )
    return render(
        request,
        "messages.html",
        {
            "rows": presenters.list_rows(rows),
            "mailboxes": mailboxes,
            "level": level_filter,
            "mailbox": mailbox_filter,
            "quarantined": quarantined == "1",
            "levels": [(code, presenters.level_chip(code).label) for code in LEVEL_FILTERS],
        },
    )


@router.get("/messages/{message_id}", name="message_report")
async def message_report(
    request: Request, message_id: str, user: UserRow = Depends(current_user)
) -> Response:
    async with request.app.state.db.session() as session:
        message, mailbox = await _get_or_404(session, user, message_id)

    def artifact_url(ref: str) -> str:
        return f"/artifacts/{quote(ref, safe='/:')}?m={quote(message.id)}"

    def download_url(ref: str) -> str:
        return artifact_url(ref) + "&download=1"

    report = presenters.build_report(message, artifact_url=artifact_url, download_url=download_url)
    return render(
        request,
        "message.html",
        {
            "message": message,
            "mailbox": mailbox,
            "report": report,
            "is_staff": queries.is_staff(user),
        },
    )


@router.post("/messages/{message_id}/release", name="message_release")
async def message_release(
    request: Request, message_id: str, user: UserRow = Depends(current_user)
) -> Response:
    async with request.app.state.db.session() as session:
        message, mailbox = await _get_or_404(session, user, message_id)
        changed = await queries.request_restore(session, user, message, mailbox)
    if changed:
        flash(
            request,
            "We are moving this email back to your inbox. It will appear within a minute. Please treat it with care.",
            "warn",
        )
    else:
        flash(request, "This email is not in Quarantine, so there is nothing to release.", "warn")
    return _see_other(f"/messages/{message_id}")


@router.post("/messages/{message_id}/review", name="message_review")
async def message_review(
    request: Request, message_id: str, note: str = Form(""), user: UserRow = Depends(current_user)
) -> Response:
    async with request.app.state.db.session() as session:
        message, mailbox = await _get_or_404(session, user, message_id)
        await queries.request_review(session, user, message, mailbox, note.strip())
    flash(request, "Our concierge will look at this email and get back to you.")
    return _see_other(f"/messages/{message_id}")


@router.post("/messages/{message_id}/feedback", name="message_feedback")
async def message_feedback(
    request: Request, message_id: str, verdict: str = Form(...), user: UserRow = Depends(current_user)
) -> Response:
    if verdict not in ("fine", "bad"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Feedback must be 'fine' or 'bad'.")
    async with request.app.state.db.session() as session:
        message, mailbox = await _get_or_404(session, user, message_id)
        await queries.record_feedback(session, user, message, mailbox, verdict)
    flash(request, "Thank you. This helps us tune your protection.")
    return _see_other(f"/messages/{message_id}")


def _ref_is_well_formed(ref: str) -> bool:
    """Mirror of ``LocalArtifactStore._rel``: a scheme, a relative path, no
    parent segments. Checked before the store sees it so a hostile ref written
    into a verdict can never touch the filesystem."""
    scheme, sep, rel = ref.partition(":")
    if not sep or not scheme.isalnum() or not rel or rel.startswith("/"):
        return False
    return ".." not in rel.split("/")


def _download_name(ref: str) -> str:
    base = ref.rsplit("/", 1)[-1]
    base = _SAFE_FILENAME.sub("-", base).strip("-") or "safe-copy"
    return f"safe-copy-{base}"


@router.get("/artifacts/{ref:path}", name="artifact")
async def artifact(
    request: Request,
    ref: str,
    m: str = Query(..., description="The message this artifact belongs to"),
    download: str | None = Query(default=None),
    user: UserRow = Depends(current_user),
) -> Response:
    """Serve a screenshot or sanitized copy. Authorisation is by message: the
    caller must be allowed to read message ``m`` and ``ref`` must appear in
    that message's verdict. Nothing else is ever read from the store."""
    async with request.app.state.db.session() as session:
        message, _ = await _get_or_404(session, user, m)
    if not _ref_is_well_formed(ref) or ref not in presenters.artifact_refs(message.verdict):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="We could not find that file.")
    store = request.app.state.artifact_store
    try:
        data = store.get(ref)
    except (ValueError, OSError) as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="We could not find that file.") from exc
    media_type = mimetypes.guess_type(ref)[0] or "application/octet-stream"
    headers = {"Cache-Control": "private, max-age=300"}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{_download_name(ref)}"'
    return Response(content=data, media_type=media_type, headers=headers)

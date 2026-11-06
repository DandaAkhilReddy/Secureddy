"""Message list, the report page, client actions, and artifact serving.

Design rule for the report: a link from a scanned email is text, never an
anchor. The only way to open it is the Reading Room form, which runs the page
on our servers and streams pixels back.
"""

from __future__ import annotations

import mimetypes
import re
from datetime import timedelta
from urllib.parse import quote, urlencode

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
DAY_FILTERS = (1, 7, 30)
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
    filter: str | None = Query(default=None),  # noqa: A002 - the public query parameter name
    days: int | None = Query(default=None),
    page: int = Query(default=1),
) -> Response:
    """Filter tabs (All, Checked, Suspicious, Quarantine), 50 per page.
    ``?filter=quarantined`` and the older ``?quarantined=1`` both mean the
    Quarantine tab; ``?days=7`` limits to the period the dashboard counts."""
    level_filter = level if level in LEVEL_FILTERS else None
    only_quarantined = filter == "quarantined" or quarantined == "1"
    tab = "quarantined" if only_quarantined else (level_filter or "all")
    days_filter = days if days in DAY_FILTERS else None
    since = queries.utcnow() - timedelta(days=days_filter) if days_filter else None
    page = max(1, page)
    async with request.app.state.db.session() as session:
        mailboxes = await queries.list_mailboxes(session, user)
        mailbox_filter = mailbox if any(m.id == mailbox for m in mailboxes) else None
        filters = {
            "mailbox_id": mailbox_filter,
            "level": level_filter,
            "quarantined": True if only_quarantined else None,
            "since": since,
        }
        total = await queries.count_messages(session, user, **filters)
        rows = await queries.list_messages(
            session, user, limit=queries.PAGE_SIZE, offset=(page - 1) * queries.PAGE_SIZE, **filters
        )
    pages = max(1, -(-total // queries.PAGE_SIZE))

    def page_href(n: int) -> str:
        params: dict[str, str | int] = {}
        if level_filter:
            params["level"] = level_filter
        if only_quarantined:
            params["filter"] = "quarantined"
        if days_filter:
            params["days"] = days_filter
        if mailbox_filter:
            params["mailbox"] = mailbox_filter
        params["page"] = n
        return "/messages?" + urlencode(params)

    empty_title, empty_text = presenters.EMPTY_STATES.get(tab, presenters.EMPTY_STATES["all"])
    return render(
        request,
        "messages.html",
        {
            "rows": presenters.list_rows(rows),
            "mailboxes": mailboxes,
            "level": level_filter,
            "mailbox": mailbox_filter,
            "quarantined": only_quarantined,
            "levels": [(code, presenters.level_chip(code).label) for code in LEVEL_FILTERS],
            "tabs": presenters.message_tabs(tab, days=days_filter, mailbox=mailbox_filter),
            "tab": tab,
            "days": days_filter,
            "all_days_href": next(
                (t.href for t in presenters.message_tabs(tab, days=None, mailbox=mailbox_filter) if t.current),
                "/messages",
            ),
            "total": total,
            "page": page,
            "pages": pages,
            "prev_href": page_href(page - 1) if page > 1 else None,
            "next_href": page_href(page + 1) if page < pages else None,
            "empty_title": empty_title,
            "empty_text": empty_text,
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


@router.post("/messages/{message_id}/safe", name="message_safe")
async def message_safe(request: Request, message_id: str, user: UserRow = Depends(current_user)) -> Response:
    """"This is safe - I know this sender"."""
    return await _sender_decision(request, message_id, user, "safe")


@router.post("/messages/{message_id}/fake", name="message_fake")
async def message_fake(request: Request, message_id: str, user: UserRow = Depends(current_user)) -> Response:
    """"This is fake"."""
    return await _sender_decision(request, message_id, user, "fake")


async def _sender_decision(request: Request, message_id: str, user: UserRow, decision: str) -> Response:
    async with request.app.state.db.session() as session:
        message, mailbox = await _get_or_404(session, user, message_id)
        try:
            result = await queries.record_sender_decision(session, user, message, mailbox, decision)
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, detail="We cannot tell who sent this email, so there is no sender to remember."
            ) from exc
        sender = message.from_address
    # "info" flashes stay until dismissed: this one explains what will change.
    flash(request, presenters.decision_flash(result, sender=sender), "info")
    return _see_other(f"/messages/{message_id}")


@router.post("/messages/{message_id}/recheck", name="message_recheck")
async def message_recheck(request: Request, message_id: str, user: UserRow = Depends(current_user)) -> Response:
    """"Check again": re-analyse with today's rules and the client's choices."""
    async with request.app.state.db.session() as session:
        message, mailbox = await _get_or_404(session, user, message_id)
        queued = await queries.request_rescore(session, user, message, mailbox)
    if queued:
        flash(request, "We are checking this email again with our latest rules. Refresh this page in a minute.")
    else:
        flash(request, "This email is already being checked. Refresh this page in a minute.", "warn")
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

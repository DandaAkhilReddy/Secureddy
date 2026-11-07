"""Message list, the report page, client actions, and artifact serving.

Design rule for the report: a link from a scanned email is text, never an
anchor. The only way to open it is the Reading Room form, which runs the page
on our servers and streams pixels back.
"""

from __future__ import annotations

import mimetypes
import re
from urllib.parse import quote, urlencode

from fastapi import Depends, Form, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse, Response

from reddysec.store.models import MailboxRow, MessageRow, UserRow

from .. import mailview, preferences, presenters, queries, search
from ..auth import current_user
from ..security import flash, safe_return_to
from ..templating import render
from . import protected_router
from .mailread import PROVIDER_APP

router = protected_router()

TABS = ("all", "checked", "suspicious")
# Older links: ?level=safe|suspicious are the tabs; ?level=malicious,
# ?filter=quarantined and ?quarantined=1 were the Quarantine tab, which is now
# part of Suspicious (and redirect there). ?level=unknown stays a quiet filter.
LEVEL_TO_TAB = {"safe": "checked", "suspicious": "suspicious"}
ALL_DATES = "all"
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
    tab: str | None = Query(default=None, max_length=20),
    period: str | None = Query(default=None, max_length=10),
    level: str | None = Query(default=None),
    mailbox: str | None = Query(default=None, max_length=40),
    quarantined: str | None = Query(default=None),
    filter: str | None = Query(default=None),  # noqa: A002 - the public query parameter name
    days: int | None = Query(default=None),
    page: int = Query(default=1),
    q: str = Query(default="", max_length=200),
    inside: str | None = Query(default=None),
) -> Response:
    """Tabs (All, Checked, Suspicious), the period (Today, 7 days, 1 month,
    1 year, or all dates), 50 per page, the "All inboxes · ..." switch, and
    search. Suspicious includes the email we moved out of the inbox; each of
    those rows says so. ``?q=`` searches our records and, with ``?inside=1``,
    the mailboxes themselves."""
    if filter == "quarantined" or quarantined == "1" or level == "malicious":
        params: dict[str, str | int] = {"tab": "suspicious"}
        legacy_period = period or (queries.DAYS_TO_PERIOD.get(days) if days else None)
        if legacy_period:
            params["period"] = legacy_period
        if mailbox:
            params["mailbox"] = mailbox
        return RedirectResponse("/messages?" + urlencode(params), status_code=status.HTTP_303_SEE_OTHER)
    tab_key = tab if tab in TABS else LEVEL_TO_TAB.get(level or "", "all")
    level_filter = "unknown" if level == "unknown" and tab_key == "all" else None
    verdict = tab_key if tab_key != "all" else None
    page = max(1, page)
    query = " ".join(q.split())
    search_inside = bool(query) and inside == "1"
    async with request.app.state.db.session() as session:
        mailboxes = await queries.list_mailboxes(session, user)
        prefs = await preferences.get_preferences(session, user.id)
        mailbox_filter, changed = preferences.resolve_selection(mailbox, prefs[preferences.SELECTED_MAILBOX], mailboxes)
        if changed:
            await preferences.set_preference(session, user.id, preferences.SELECTED_MAILBOX, mailbox_filter or "")
        all_dates = period == ALL_DATES
        period_key = prefs[preferences.PERIOD]
        if not all_dates:
            period_key, period_changed = preferences.resolve_period(period, prefs[preferences.PERIOD], days)
            if period_changed:
                await preferences.set_preference(session, user.id, preferences.PERIOD, period_key)
        window = queries.period_window(period_key, tz=preferences.client_tz(request))
        since = None if all_dates else window.since
        view = prefs[preferences.INBOX_VIEW]
        filters = {
            "mailbox_id": mailbox_filter,
            "level": level_filter,
            "verdict": verdict,
            "since": since,
        }
        sections: list[dict] = []
        if query:
            rows, total = await search.search_records(
                session, user, query, mailbox_id=mailbox_filter,
                limit=queries.PAGE_SIZE, offset=(page - 1) * queries.PAGE_SIZE,
            )
        else:
            total = await queries.count_messages(session, user, **filters)
            rows = await queries.list_messages(
                session, user, limit=queries.PAGE_SIZE, offset=(page - 1) * queries.PAGE_SIZE, **filters
            )
            if view == "separate" and mailbox_filter is None and len(mailboxes) > 1:
                for m in mailboxes:
                    if m.status == "disconnected":
                        continue
                    scoped = {**filters, "mailbox_id": m.id}
                    sections.append({
                        "mailbox": m,
                        "total": await queries.count_messages(session, user, **scoped),
                        "rows": presenters.list_rows(
                            await queries.list_messages(session, user, limit=SECTION_SIZE, **scoped)
                        ),
                        "href": _href(tab_key, ALL_DATES if all_dates else period_key, m.id, 1, level_filter),
                    })
    live = None
    if search_inside:
        chosen = [m for m in mailboxes if mailbox_filter is None or m.id == mailbox_filter]
        live = await search.search_live(request, user, chosen, query)
    pages = max(1, -(-total // queries.PAGE_SIZE))
    shown_period = ALL_DATES if all_dates else period_key

    def page_href(n: int) -> str:
        if query:
            params: dict[str, str | int] = {"q": query, "page": n}
            if search_inside:
                params["inside"] = "1"
            return "/messages?" + urlencode(params)
        return _href(tab_key, shown_period, mailbox_filter, n, level_filter)

    empty_title, empty_text = presenters.EMPTY_STATES.get(level_filter or tab_key, presenters.EMPTY_STATES["all"])
    if query:
        empty_title = "Nothing found"
        empty_text = (
            "No checked email matches all of those words. Try fewer words"
            + ("." if search_inside else ', or tick "Search inside emails".')
        )
    tab_param = tab_key if tab_key != "all" else None
    switch_extra = {"tab": tab_param, "level": level_filter, "period": shown_period,
                    "q": query or None, "inside": "1" if search_inside else None}
    return render(
        request,
        "messages.html",
        {
            "rows": presenters.list_rows(rows),
            "sections": sections,
            "mailboxes": mailboxes,
            "switcher": preferences.switcher(mailboxes, mailbox_filter, "/messages", switch_extra),
            "view": view,
            "level": level_filter,
            "mailbox": mailbox_filter,
            "tabs": presenters.message_tabs(tab_key, period=shown_period, mailbox=mailbox_filter),
            "tab": tab_key,
            "periods": presenters.period_items(
                "" if all_dates else period_key, "/messages", {"tab": tab_param, "mailbox": mailbox_filter}
            ),
            "all_dates": all_dates,
            "period_when": presenters.PERIOD_PHRASES[period_key],
            "all_dates_href": _href(tab_key, ALL_DATES, mailbox_filter, 1, level_filter),
            "total": total,
            "page": page,
            "pages": pages,
            "prev_href": page_href(page - 1) if page > 1 else None,
            "next_href": page_href(page + 1) if page < pages else None,
            "empty_title": empty_title,
            "empty_text": empty_text,
            "q": query,
            "inside": search_inside,
            "live": live,
            "highlight": search.highlight,
            "multi": len([m for m in mailboxes if m.status != "disconnected"]) > 1,
        },
    )


SECTION_SIZE = 10


def _href(tab: str, period: str | None, mailbox: str | None, page: int, level: str | None = None) -> str:
    params: dict[str, str | int] = {}
    if tab and tab != "all":
        params["tab"] = tab
    if level:
        params["level"] = level
    if period:
        params["period"] = period
    if mailbox:
        params["mailbox"] = mailbox
    params["page"] = page
    return "/messages?" + urlencode(params)


@router.post("/messages/check-now", name="message_check_now")
async def message_check_now(
    request: Request, token: str = Form(...), next: str = Form("/messages"), user: UserRow = Depends(current_user)  # noqa: A002
) -> Response:
    """"Check now" on a search result we had not seen: queue it for the worker
    (fetched, analysed and labelled like any re-check)."""
    secret = request.app.state.settings.secret_key.get_secret_value()
    data = search.read_check(secret, token, user.id)
    if data is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That search result has expired. Please search again.")
    async with request.app.state.db.session() as session:
        mailbox = await queries.get_mailbox(session, user, str(data["b"]), manage=True)
        if mailbox is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="We could not find that mailbox.")
        message = await queries.queue_unchecked_message(session, user, mailbox, data)
    flash(request, "We are checking that email now. Its report appears in a minute.")
    return _see_other(safe_return_to(next, f"/messages/{message.id}"))


@router.get("/messages/{message_id}", name="message_report")
async def message_report(
    request: Request,
    message_id: str,
    tab: str = Query(default="report"),
    images: int = Query(default=0),
    user: UserRow = Depends(current_user),
) -> Response:
    async with request.app.state.db.session() as session:
        message, mailbox = await _get_or_404(session, user, message_id)

    def artifact_url(ref: str) -> str:
        return f"/artifacts/{quote(ref, safe='/:')}?m={quote(message.id)}"

    def download_url(ref: str) -> str:
        return artifact_url(ref) + "&download=1"

    report = presenters.build_report(message, artifact_url=artifact_url, download_url=download_url)
    async with request.app.state.db.session() as session:
        reasons = await queries.latest_reasons(session, [message.id])
    secret = request.app.state.settings.secret_key.get_secret_value()
    own_mail = mailbox.user_id in queries.visible_owner_ids(user)
    can_read = own_mail and mailbox.status in ("active", "paused", "error")
    return render(
        request,
        "message.html",
        {
            "message": message,
            "mailbox": mailbox,
            "report": report,
            "is_staff": queries.is_staff(user),
            "decision_note": presenters.decision_note(reasons.get(message.id), report.client_decision),
            "flagged": bool(message.quarantined or (message.level or "unknown") != "safe"),
            "safe_reasons": presenters.SAFE_REASON_CHOICES,
            "fake_reasons": presenters.FAKE_REASON_CHOICES,
            "assistant_enabled": request.app.state.assistant.enabled,
            "tab": "read" if tab == "read" and can_read else "report",
            "can_read": can_read,
            "images": bool(images),
            "go": {u.url: mailview.go_href(secret, message.id, u.url) for u in report.urls},
            "advice_copy": presenters.LINK_ADVICE_COPY,
            "links_summary": presenters.link_summary(message),
            "provider_app": PROVIDER_APP.get(mailbox.provider, "your mail app"),
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
async def message_safe(
    request: Request,
    message_id: str,
    reason_code: str = Form(""),
    reason_text: str = Form(""),
    next: str = Form(""),  # noqa: A002 - the public form field name
    user: UserRow = Depends(current_user),
) -> Response:
    """"Not suspicious? Mark as safe", with an optional reason."""
    return await _sender_decision(request, message_id, user, "safe", reason_code, reason_text, next)


@router.post("/messages/{message_id}/fake", name="message_fake")
async def message_fake(
    request: Request,
    message_id: str,
    reason_code: str = Form(""),
    reason_text: str = Form(""),
    next: str = Form(""),  # noqa: A002 - the public form field name
    user: UserRow = Depends(current_user),
) -> Response:
    """"This is fake", with an optional reason."""
    return await _sender_decision(request, message_id, user, "fake", reason_code, reason_text, next)


async def _sender_decision(
    request: Request, message_id: str, user: UserRow, decision: str, reason_code: str, reason_text: str, next_url: str
) -> Response:
    try:
        code, text = queries.clean_reason(decision, reason_code, reason_text)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Please pick one of the reasons offered.") from exc
    async with request.app.state.db.session() as session:
        message, mailbox = await _get_or_404(session, user, message_id)
        try:
            result = await queries.record_sender_decision(
                session, user, message, mailbox, decision, reason_code=code, reason_text=text
            )
        except ValueError as exc:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, detail="We cannot tell who sent this email, so there is no sender to remember."
            ) from exc
        sender = message.from_address
    # "info" flashes stay until dismissed: this one explains what will change.
    flash(request, presenters.decision_flash(result, sender=sender), "info")
    return _see_other(safe_return_to(next_url, f"/messages/{message_id}"))


@router.post("/messages/{message_id}/recheck", name="message_recheck")
async def message_recheck(
    request: Request,
    message_id: str,
    next: str = Form(""),  # noqa: A002 - the public form field name
    user: UserRow = Depends(current_user),
) -> Response:
    """"Check again": re-analyse with today's rules and the client's choices."""
    async with request.app.state.db.session() as session:
        message, mailbox = await _get_or_404(session, user, message_id)
        queued = await queries.request_rescore(session, user, message, mailbox)
    if queued:
        flash(request, "We are checking this email again with our latest rules. Refresh this page in a minute.")
    else:
        flash(request, "This email is already being checked. Refresh this page in a minute.", "warn")
    return _see_other(safe_return_to(next, f"/messages/{message_id}"))


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

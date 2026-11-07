"""Reading and tidying mail inside Secureddy.

* ``GET /messages/{id}/body``: the email itself, fetched live from Gmail,
  Outlook or Yahoo, sanitised (``web.mailview``) and returned with
  ``Cache-Control: no-store`` and its own strict CSP. The report page shows it
  in a sandboxed iframe. Nothing is stored.
* ``GET /messages/{id}/image``: "Load images", one remote image through our
  server (signed URL, private addresses refused, size-limited).
* ``GET /go``: the warning page every link in a rendered email goes through.
  The target is signed, so ``/go`` is not an open redirect.
* ``GET /messages/{id}/attachments/{n}``: the original file, live from the
  provider, only when our verdict for it is "safe"; otherwise the person gets
  the safe copy from the report.
* ``POST /messages/{id}/archive|read|unread|trash`` and
  ``GET /messages/{id}/open``: basic mail actions through the connector, and
  "Reply in Gmail / Outlook / Yahoo" (we never send mail).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from fastapi import Depends, Form, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import HTMLResponse, RedirectResponse, Response

from reddysec.core.logging import get_logger
from reddysec.mail.base import AuthExpired, ConnectorError
from reddysec.store.models import MailboxRow, MessageRow, UserRow

from .. import mailview, presenters, queries
from ..auth import current_user
from ..security import flash, safe_return_to
from ..templating import render
from . import protected_router

log = get_logger(__name__)
router = protected_router()

NO_STORE = "no-store, private"
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._ -]+")
PROVIDER_APP = {"gmail": "Gmail", "microsoft": "Outlook", "outlook": "Outlook", "yahoo": "Yahoo Mail",
                "icloud": "iCloud Mail"}


def _see_other(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)


def _secret(request: Request) -> str:
    return request.app.state.settings.secret_key.get_secret_value()


def _origin(request: Request) -> str:
    base = str(request.base_url).rstrip("/")
    parts = urlsplit(base)
    return f"{parts.scheme}://{parts.netloc}"


async def _message_or_404(session: AsyncSession, user: UserRow, message_id: str) -> tuple[MessageRow, MailboxRow]:
    found = await queries.get_message(session, user, message_id)
    if found is None or found[1].user_id not in queries.visible_owner_ids(user):
        # Staff may read reports, never the mail itself.
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="We could not find that email.")
    return found


async def connector_for(request: Request, mailbox: MailboxRow) -> Any:
    """A live connector for ``mailbox``. Raises ``AuthExpired`` (reconnect) or
    ``ConnectorError`` (try again)."""
    if mailbox.status == "disconnected":
        raise AuthExpired("mailbox is disconnected")
    return await request.app.state.connector_factory(mailbox)


async def close_connector(connector: Any) -> None:
    closer = getattr(connector, "aclose", None)
    if callable(closer):
        try:
            await closer()
        except Exception:  # noqa: BLE001 - closing is best effort
            pass


def _problem_doc(text: str) -> str:
    return mailview.body_document(f'<p style="color:#555">{text}</p>')


def _body_response(request: Request, html: str, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(
        html,
        status_code=status_code,
        headers={
            "Cache-Control": NO_STORE,
            "Content-Security-Policy": mailview.body_csp(_origin(request)),
            "X-Frame-Options": "SAMEORIGIN",
            "Referrer-Policy": "no-referrer",
            "Cross-Origin-Resource-Policy": "same-origin",
        },
    )


async def fetch_raw_live(request: Request, mailbox: MailboxRow, message: MessageRow) -> bytes:
    connector = await connector_for(request, mailbox)
    try:
        return await connector.fetch_raw(message.provider_message_id)
    finally:
        await close_connector(connector)


@router.get("/messages/{message_id}/body", name="message_body")
async def message_body(
    request: Request, message_id: str, images: int = Query(default=0), user: UserRow = Depends(current_user)
) -> Response:
    async with request.app.state.db.session() as session:
        message, mailbox = await _message_or_404(session, user, message_id)
    try:
        raw = await fetch_raw_live(request, mailbox, message)
    except AuthExpired:
        return _body_response(request, _problem_doc(
            "We could not open this email: the mailbox needs to be reconnected on the Accounts page."), 409)
    except ConnectorError:
        return _body_response(request, _problem_doc(
            "We could not reach your mail provider just now, or the email was moved or deleted. Please try again."),
            502)
    try:
        body = mailview.parse_message(raw)
    except Exception:  # noqa: BLE001 - a malformed email must not become a 500
        log.warning("mailread.parse_failed", message_id=message.id)
        return _body_response(request, _problem_doc("We could not display this email."), 422)
    secret = _secret(request)
    if body.html:
        result = mailview.sanitize_html(
            body.html, secret=secret, message_id=message.id, load_images=bool(images),
            inline_images=body.inline_images,
        )
        fragment = result.html
    elif body.text:
        fragment = mailview.text_to_html(body.text, secret=secret, message_id=message.id)
    else:
        fragment = '<p style="color:#555">This email has no text.</p>'
    return _body_response(request, mailview.body_document(fragment))


@router.get("/messages/{message_id}/image", name="message_image")
async def message_image(
    request: Request, message_id: str, u: str = Query(..., max_length=4000), s: str = Query(..., max_length=64),
    user: UserRow = Depends(current_user),
) -> Response:
    async with request.app.state.db.session() as session:
        await _message_or_404(session, user, message_id)
    if not mailview.verify_link(_secret(request), message_id, u, s, purpose="img"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="We could not find that image.")
    settings = request.app.state.settings
    try:
        ctype, data = await mailview.fetch_image(
            request.app.state.http, u, max_bytes=settings.image_proxy_max_bytes,
            resolver=getattr(request.app.state, "image_resolver", None),
        )
    except mailview.ImageRefused:
        return Response(status_code=404, headers={"Cache-Control": NO_STORE})
    return Response(
        data, media_type=ctype,
        headers={"Cache-Control": NO_STORE, "Content-Security-Policy": "default-src 'none'; sandbox",
                 "X-Content-Type-Options": "nosniff", "Cross-Origin-Resource-Policy": "same-origin"},
    )


@router.get("/go", name="go")
async def go(
    request: Request,
    u: str = Query(..., max_length=4000),
    m: str = Query(..., max_length=60),
    s: str = Query(..., max_length=64),
    user: UserRow = Depends(current_user),
) -> Response:
    """The page between a click in an email and the web. It tells the person
    what we know about the link and offers only what is safe."""
    if not mailview.verify_link(_secret(request), m, u, s):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="That link is not valid. Please open it from the email again.")
    async with request.app.state.db.session() as session:
        message, _mailbox = await _message_or_404(session, user, m)
    view, _index = presenters.find_link(message, u)
    if view is None:
        # Not one of the links we analysed: be careful, the Reading Room only.
        advice, reason, downloads = "open_in_reading_room", "We have not checked this exact link.", ""
        chip = presenters.level_chip("unknown")
    else:
        advice, reason, downloads, chip = view.advice, view.advice_reason, view.downloads, view.chip
    copy = presenters.LINK_ADVICE_COPY[advice]
    parts = urlsplit(u)
    return render(
        request,
        "go.html",
        {
            "url": u,
            "host": (parts.hostname or "").lower(),
            "scheme_ok": parts.scheme in ("http", "https"),
            "message": message,
            "advice": advice,
            "copy": copy,
            "reason": reason,
            "downloads": downloads,
            "link_chip": chip,
            "final_url": view.final_url if view else None,
            "checked": view is not None,
        },
    )


@router.get("/messages/{message_id}/attachments/{index}", name="message_attachment")
async def message_attachment(
    request: Request, message_id: str, index: int, user: UserRow = Depends(current_user)
) -> Response:
    """The original of attachment ``index`` (its place in our report), only
    when our verdict for it is "safe". Anything else: the safe copy."""
    async with request.app.state.db.session() as session:
        message, mailbox = await _message_or_404(session, user, message_id)
    wanted = attachment_name(message, index)
    if wanted is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="We could not find that file.")
    if attachment_level(message, wanted) != "safe":
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="We only hand out the original of a file we checked and found safe. Use the safe copy on the report.",
        )
    try:
        raw = await fetch_raw_live(request, mailbox, message)
    except (AuthExpired, ConnectorError) as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail="We could not reach your mail provider just now.") from exc
    found = mailview.attachment_by_name(raw, wanted)
    if found is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="We could not find that file in the email any more.")
    filename, _ctype, data = found
    if attachment_level(message, filename) != "safe":
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="We only hand out the original of a file we checked and found safe. Use the safe copy on the report.",
        )
    safe_name = _SAFE_NAME.sub("-", filename).strip("-. ") or "attachment"
    async with request.app.state.db.session() as session:
        queries.audit(
            session, actor=user, action="attachment_downloaded", mailbox_id=mailbox.id, target=message.id,
            details={"filename": safe_name[:100]},
        )
    return Response(
        data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}"',
            "Cache-Control": NO_STORE,
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox",
        },
    )


def attachment_name(message: MessageRow, index: int) -> str | None:
    raw = message.verdict if isinstance(message.verdict, dict) else {}
    items = [a for a in raw.get("attachments") or [] if isinstance(a, dict)]
    if not 0 <= index < len(items):
        return None
    return str(items[index].get("filename", ""))


def attachment_level(message: MessageRow, filename: str) -> str:
    """Our verdict for the attachment called ``filename`` ("" if unchecked)."""
    raw = message.verdict if isinstance(message.verdict, dict) else {}
    for item in raw.get("attachments") or []:
        if isinstance(item, dict) and str(item.get("filename", "")) == filename:
            return str(item.get("level", ""))
    return ""


# --------------------------------------------------------------------------- actions


ACTIONS = {
    "archive": ("archive", "Archived in {app}.", "message_archived"),
    "read": ("set_read", "Marked as read.", "message_marked_read"),
    "unread": ("set_read", "Marked as unread.", "message_marked_unread"),
    "trash": ("trash", "Moved to the Trash in {app}. You can restore it there for a while.", "message_trashed"),
}


async def _message_action(request: Request, message_id: str, action: str, next_url: str, user: UserRow) -> Response:
    method, done, audit_action = ACTIONS[action]
    back = safe_return_to(next_url, f"/messages/{message_id}")
    async with request.app.state.db.session() as session:
        message, mailbox = await _message_or_404(session, user, message_id)
    app = PROVIDER_APP.get(mailbox.provider, "your mailbox")
    try:
        connector = await connector_for(request, mailbox)
        try:
            call = getattr(connector, method)
            if method == "set_read":
                await call(message.provider_message_id, action == "read")
            else:
                await call(message.provider_message_id)
        finally:
            await close_connector(connector)
    except AuthExpired:
        flash(request, "This mailbox needs to be reconnected first. Open Accounts and choose Reconnect.", "warn")
        return _see_other(back)
    except (ConnectorError, AttributeError):
        flash(request, f"We could not reach {app} just now. Nothing changed. Please try again.", "warn")
        return _see_other(back)
    async with request.app.state.db.session() as session:
        queries.audit(session, actor=user, action=audit_action, mailbox_id=mailbox.id, target=message.id)
    flash(request, done.format(app=app))
    return _see_other(back)


@router.post("/messages/{message_id}/archive", name="message_archive")
async def message_archive(
    request: Request, message_id: str, next: str = Form(""), user: UserRow = Depends(current_user)  # noqa: A002
) -> Response:
    return await _message_action(request, message_id, "archive", next, user)


@router.post("/messages/{message_id}/read", name="message_read")
async def message_read(
    request: Request, message_id: str, next: str = Form(""), user: UserRow = Depends(current_user)  # noqa: A002
) -> Response:
    return await _message_action(request, message_id, "read", next, user)


@router.post("/messages/{message_id}/unread", name="message_unread")
async def message_unread(
    request: Request, message_id: str, next: str = Form(""), user: UserRow = Depends(current_user)  # noqa: A002
) -> Response:
    return await _message_action(request, message_id, "unread", next, user)


@router.post("/messages/{message_id}/trash", name="message_trash")
async def message_trash(
    request: Request, message_id: str, next: str = Form(""), user: UserRow = Depends(current_user)  # noqa: A002
) -> Response:
    return await _message_action(request, message_id, "trash", next, user)


@router.get("/messages/{message_id}/open", name="message_open_in_provider")
async def message_open_in_provider(request: Request, message_id: str, user: UserRow = Depends(current_user)) -> Response:
    """"Reply in Gmail / Outlook / Yahoo": a deep link to the message in the
    provider's own web app. We never send mail."""
    async with request.app.state.db.session() as session:
        message, mailbox = await _message_or_404(session, user, message_id)
    try:
        connector = await connector_for(request, mailbox)
        try:
            link = await connector.web_link(message.provider_message_id)
        finally:
            await close_connector(connector)
    except (AuthExpired, ConnectorError, AttributeError):
        link = ""
    if not link.startswith("https://"):
        flash(request, "We could not open this email in your mail app just now.", "warn")
        return _see_other(f"/messages/{message_id}")
    return RedirectResponse(link, status_code=status.HTTP_303_SEE_OTHER)

"""Mailbox onboarding and protection settings.

Only the owner may change a mailbox. A helper account (family, assistant) can
read the mail it protects but a wrong click on their side must not switch the
principal's protection off, so every mutation uses ``manage=True`` and answers
404 rather than 403 to avoid confirming the mailbox exists.
"""

from __future__ import annotations

from fastapi import Depends, Form, HTTPException, Request, status
from starlette.responses import RedirectResponse, Response

from reddysec.store.models import UserRow

from .. import presenters, queries
from ..auth import current_user
from ..security import flash
from ..templating import render
from . import protected_router

router = protected_router()

MODES = ("scan", "hold")


def _see_other(url: str = "/mailboxes") -> RedirectResponse:
    return RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)


async def _owned_or_404(session, user: UserRow, mailbox_id: str):
    mailbox = await queries.get_mailbox(session, user, mailbox_id, manage=True)
    if mailbox is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="We could not find that mailbox.")
    return mailbox


@router.get("/mailboxes", name="mailboxes")
async def mailboxes_page(request: Request, user: UserRow = Depends(current_user)) -> Response:
    async with request.app.state.db.session() as session:
        mailboxes = await queries.list_mailboxes(session, user)
    settings = request.app.state.settings
    return render(
        request,
        "mailboxes.html",
        {
            "mailboxes": [
                {
                    "row": m,
                    "status": presenters.mailbox_status_chip(m),
                    "mode": presenters.mode_chip(m),
                    "owned": m.user_id == user.id,
                }
                for m in mailboxes
            ],
            "hold_minutes": settings.hold_dead_man_minutes,
            "hold_timeout_s": settings.hold_timeout_s,
        },
    )


def _add_imap_page(
    request: Request, *, error: str | None = None, form: dict | None = None, status_code: int = 200
) -> Response:
    return render(
        request,
        "mailbox_add_imap.html",
        {"providers": list(presenters.IMAP_PROVIDERS.values()), "error": error, "form": form or {}},
        status_code=status_code,
    )


@router.get("/mailboxes/add-imap", name="add_imap")
async def add_imap_page(request: Request, user: UserRow = Depends(current_user)) -> Response:
    return _add_imap_page(request, form={"provider": "yahoo", "port": "993"})


@router.post("/mailboxes/add-imap", name="add_imap_submit")
async def add_imap_submit(
    request: Request,
    provider: str = Form(...),
    address: str = Form(""),
    app_password: str = Form(""),
    host: str = Form(""),
    port: str = Form("993"),
    user: UserRow = Depends(current_user),
) -> Response:
    form = {"provider": provider, "address": address, "host": host, "port": port}
    spec = presenters.IMAP_PROVIDERS.get(provider)
    if spec is None:
        return _add_imap_page(request, error="Please choose a mail provider.", form=form, status_code=400)
    address = address.strip().lower()
    if "@" not in address or " " in address:
        return _add_imap_page(
            request, error="Please enter the full email address.", form=form, status_code=400
        )
    if not app_password.strip():
        return _add_imap_page(request, error="Please paste the app password.", form=form, status_code=400)
    imap_host = spec.host or host.strip().lower()
    if not imap_host or " " in imap_host or "/" in imap_host:
        return _add_imap_page(request, error="Please enter the IMAP server name.", form=form, status_code=400)
    try:
        imap_port = int(port) if spec.host == "" else spec.port
    except ValueError:
        imap_port = 0
    if not 1 <= imap_port <= 65535:
        return _add_imap_page(
            request, error="The port must be a number between 1 and 65535.", form=form, status_code=400
        )

    async with request.app.state.db.session() as session:
        existing = await queries.list_mailboxes(session, user)
        if any(m.address == address and m.status != "disconnected" for m in existing):
            return _add_imap_page(
                request, error="That mailbox is already connected.", form=form, status_code=400
            )
        await queries.add_imap_mailbox(
            session,
            request.app.state.cipher,
            user,
            provider=provider,
            address=address,
            host=imap_host,
            port=imap_port,
            password=app_password.strip(),
        )
    flash(request, f"{spec.label} is connected. We start checking new email within a minute.")
    return _see_other()


@router.post("/mailboxes/{mailbox_id}/mode", name="mailbox_mode")
async def mailbox_mode(
    request: Request, mailbox_id: str, mode: str = Form(...), user: UserRow = Depends(current_user)
) -> Response:
    if mode not in MODES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Mode must be scan or hold.")
    async with request.app.state.db.session() as session:
        mailbox = await _owned_or_404(session, user, mailbox_id)
        if mailbox.mode != mode:
            await queries.set_mailbox_mode(session, user, mailbox, mode)
            changed = True
        else:
            changed = False
    if changed and mode == "hold":
        flash(request, "Hold mode is on. New email waits for its check before it reaches your inbox.")
    elif changed:
        flash(request, "Scan mode is on. Email arrives as usual and is labelled within seconds.")
    return _see_other()


@router.post("/mailboxes/{mailbox_id}/pause", name="mailbox_pause")
async def mailbox_pause(request: Request, mailbox_id: str, user: UserRow = Depends(current_user)) -> Response:
    async with request.app.state.db.session() as session:
        mailbox = await _owned_or_404(session, user, mailbox_id)
        if mailbox.status == "active":
            await queries.set_mailbox_status(session, user, mailbox, "paused", "mailbox_paused")
    flash(request, "Protection is paused for this mailbox. New email is not being checked.", "warn")
    return _see_other()


@router.post("/mailboxes/{mailbox_id}/resume", name="mailbox_resume")
async def mailbox_resume(
    request: Request, mailbox_id: str, user: UserRow = Depends(current_user)
) -> Response:
    async with request.app.state.db.session() as session:
        mailbox = await _owned_or_404(session, user, mailbox_id)
        if mailbox.status in ("paused", "error"):
            await queries.set_mailbox_status(session, user, mailbox, "active", "mailbox_resumed")
    flash(request, "Protection is back on for this mailbox.")
    return _see_other()


@router.post("/mailboxes/{mailbox_id}/disconnect", name="mailbox_disconnect")
async def mailbox_disconnect(
    request: Request, mailbox_id: str, user: UserRow = Depends(current_user)
) -> Response:
    async with request.app.state.db.session() as session:
        mailbox = await _owned_or_404(session, user, mailbox_id)
        if mailbox.status != "disconnected":
            await queries.disconnect_mailbox(session, user, mailbox)
    flash(request, "The mailbox is disconnected and its password or token has been deleted from our systems.")
    return _see_other()

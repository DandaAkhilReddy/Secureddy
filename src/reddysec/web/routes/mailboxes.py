"""Mailbox onboarding and protection settings.

Only the owner may change a mailbox. A helper account (family, assistant) can
read the mail it protects but a wrong click on their side must not switch the
principal's protection off, so every mutation uses ``manage=True`` and answers
404 rather than 403 to avoid confirming the mailbox exists.
"""

from __future__ import annotations

from fastapi import Depends, Form, HTTPException, Request, status
from starlette.responses import RedirectResponse, Response

from reddysec.mail.base import AuthExpired, ConnectorError
from reddysec.store.models import UserRow

from .. import presenters, queries
from ..auth import current_user
from ..security import flash
from ..templating import render
from . import protected_router

router = protected_router()

MODES = ("scan", "hold")
MAX_ADDRESS = 254  # the longest a real email address can be (RFC 5321 path limit)


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
        entries = await queries.list_sender_feedback(session, [m.id for m in mailboxes])
        reasons, stats = await queries.sender_entry_context(session, entries)
    settings = request.app.state.settings
    by_mailbox: dict[str, list] = {}
    for entry in sorted(entries, key=lambda e: (e.decision != "trusted", e.value)):
        by_mailbox.setdefault(entry.mailbox_id, []).append(
            presenters.sender_entry(
                entry,
                reason=reasons.get(entry.id),
                stats=stats.get((entry.mailbox_id, entry.scope, entry.value.lower())),
            )
        )
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
                    "senders": by_mailbox.get(m.id, []),
                }
                for m in mailboxes
            ],
            "hold_minutes": settings.hold_dead_man_minutes,
            "hold_timeout_s": settings.hold_timeout_s,
        },
    )


def _add_imap_page(
    request: Request,
    *,
    error: str | None = None,
    form: dict | None = None,
    status_code: int = 200,
    suggest_microsoft: bool = False,
) -> Response:
    return render(
        request,
        "mailbox_add_imap.html",
        {
            "providers": list(presenters.IMAP_PROVIDERS.values()),
            "error": error,
            "form": form or {},
            "suggest_microsoft": suggest_microsoft,
            "provider_domains": presenters.PROVIDER_DOMAINS,
        },
        status_code=status_code,
    )


@router.get("/mailboxes/add-imap", name="add_imap")
async def add_imap_page(
    request: Request, address: str = "", provider: str = "", user: UserRow = Depends(current_user)
) -> Response:
    detected = presenters.detect_provider(address)
    chosen = provider if provider in presenters.IMAP_PROVIDERS else detected or "yahoo"
    if chosen == "outlook" and detected == "outlook" and request.app.state.microsoft_oauth is not None:
        return _add_imap_page(request, form={"provider": "outlook", "address": address, "port": "993"},
                              suggest_microsoft=True)
    return _add_imap_page(request, form={"provider": chosen, "address": address.strip().lower(), "port": "993"})


@router.post("/mailboxes/add-imap", name="add_imap_submit")
async def add_imap_submit(
    request: Request,
    provider: str = Form(...),
    address: str = Form(""),
    app_password: str = Form(""),
    host: str = Form(""),
    port: str = Form("993"),
    use_imap: str = Form(""),
    user: UserRow = Depends(current_user),
) -> Response:
    form = {"provider": provider, "address": address, "host": host, "port": port}
    spec = presenters.IMAP_PROVIDERS.get(provider)
    if spec is None:
        return _add_imap_page(request, error="Please choose a mail provider.", form=form, status_code=400)
    address = address.strip().lower()
    if "@" not in address or " " in address or len(address) > MAX_ADDRESS:
        return _add_imap_page(
            request, error="Please enter the full email address.", form=form, status_code=400
        )
    # The address tells us the provider better than the dropdown does.
    detected = presenters.detect_provider(address)
    if detected == "outlook" and request.app.state.microsoft_oauth is not None and not use_imap:
        return _add_imap_page(request, form={**form, "provider": "outlook"}, suggest_microsoft=True)
    if detected in ("yahoo", "icloud") and provider != "imap" and provider != detected:
        provider = detected
        spec = presenters.IMAP_PROVIDERS[detected]
        form["provider"] = detected
    if not app_password.strip():
        return _add_imap_page(request, error="Please paste the app password.", form=form, status_code=400)
    imap_host = spec.host or host.strip().lower()
    if provider == "yahoo" and address.endswith("@aol.com"):
        imap_host = presenters.AOL_IMAP_HOST  # AOL runs on Yahoo's platform with its own IMAP name
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
        existing = await queries.find_mailbox_by_address(session, user.id, address)
        if queries.mailbox_is_connected(existing):
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


# ---------------------------------------------------------------- Yahoo Mail

YAHOO_BAD_PASSWORD = (
    "Yahoo did not accept that app password. Copy it again from Yahoo (16 letters) and paste it here. "
    "Your normal Yahoo password will not work here."
)
YAHOO_UNREACHABLE = "We could not reach Yahoo Mail just now. Please try again in a minute."


def _connect_yahoo_page(
    request: Request, *, address: str = "", error: str | None = None, status_code: int = 200
) -> Response:
    spec = presenters.IMAP_PROVIDERS["yahoo"]
    return render(
        request,
        "mailbox_connect_yahoo.html",
        {"address": address, "error": error, "host": spec.host, "port": spec.port},
        status_code=status_code,
    )


@router.get("/mailboxes/connect-yahoo", name="connect_yahoo")
async def connect_yahoo_page(request: Request, address: str = "", user: UserRow = Depends(current_user)) -> Response:
    """The step after "Sign in with Yahoo" (or the Yahoo tile): three steps to
    create an app password, one field to paste it, and a real test."""
    if not address and presenters.detect_provider(user.login_email) == "yahoo":
        address = user.login_email
    return _connect_yahoo_page(request, address=address.strip().lower())


@router.post("/mailboxes/connect-yahoo", name="connect_yahoo_submit")
async def connect_yahoo_submit(
    request: Request,
    address: str = Form(""),
    app_password: str = Form(""),
    user: UserRow = Depends(current_user),
) -> Response:
    address = address.strip().lower()
    # Yahoo shows the password in groups of four; people paste it with spaces.
    password = "".join(app_password.split())
    if "@" not in address or " " in address or len(address) > MAX_ADDRESS:
        return _connect_yahoo_page(request, address=address, error="Please enter your full Yahoo email address.",
                                   status_code=400)
    if not password:
        return _connect_yahoo_page(request, address=address, error="Please paste the app password.", status_code=400)
    spec = presenters.IMAP_PROVIDERS["yahoo"]
    host = presenters.AOL_IMAP_HOST if address.endswith("@aol.com") else spec.host
    try:
        await request.app.state.imap_tester(host, spec.port, address, password)
    except AuthExpired:
        return _connect_yahoo_page(request, address=address, error=YAHOO_BAD_PASSWORD, status_code=400)
    except (ConnectorError, OSError):
        return _connect_yahoo_page(request, address=address, error=YAHOO_UNREACHABLE, status_code=502)
    async with request.app.state.db.session() as session:
        existing = await queries.find_mailbox_by_address(session, user.id, address)
        if queries.mailbox_is_connected(existing):
            return _connect_yahoo_page(request, address=address, error="That mailbox is already connected.",
                                       status_code=400)
        await queries.add_imap_mailbox(
            session, request.app.state.cipher, user, provider="yahoo", address=address, host=host,
            port=spec.port, password=password,
        )
    flash(request, "Connected. Yahoo accepted the app password, and we start checking new email within a minute.")
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


@router.post("/mailboxes/{mailbox_id}/senders/{entry_id}/remove", name="sender_feedback_remove")
async def sender_feedback_remove(
    request: Request, mailbox_id: str, entry_id: str, user: UserRow = Depends(current_user)
) -> Response:
    """Forget one "This is safe" / "This is fake" choice."""
    async with request.app.state.db.session() as session:
        mailbox = await _owned_or_404(session, user, mailbox_id)
        entry = await queries.remove_sender_feedback(session, user, mailbox, entry_id)
    if entry is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="We could not find that sender.")
    flash(request, f"Removed {entry.value}. New email from it will be checked like any other.")
    return _see_other()


@router.post("/mailboxes/{mailbox_id}/recheck", name="mailbox_recheck")
async def mailbox_recheck(request: Request, mailbox_id: str, user: UserRow = Depends(current_user)) -> Response:
    """Check the last 7 days: re-check what we already checked with today's
    rules and the client's choices, and ask the worker to fetch and check the
    mail from those days we have never seen (a brand-new mailbox has none)."""
    async with request.app.state.db.session() as session:
        mailbox = await _owned_or_404(session, user, mailbox_id)
        if mailbox.status in ("paused", "disconnected"):
            message = RECHECK_PAUSED if mailbox.status == "paused" else RECHECK_NOT_CONNECTED
        else:  # active, or in error: the request waits until the worker gets back in
            await queries.request_recheck_recent(session, user, mailbox)
            await queries.request_recent_backfill(session, user, mailbox)
            message = None
    if message:
        flash(request, message, "warn")
    else:
        flash(request, RECHECK_STARTED)
    return _see_other()


RECHECK_STARTED = "We're checking your email from the last 7 days. Results appear here within a few minutes."
RECHECK_PAUSED = "Protection is paused for this mailbox. Resume protection first, then check your recent email."
RECHECK_NOT_CONNECTED = "This mailbox is disconnected. Connect it again first, then check your recent email."

""""Ask Secureddy": the chat page, sending a question, and proposal cards.

The page is server-rendered and works without JavaScript (forms post and
redirect back). ``static/assistant.js`` upgrades it: the question is posted
with ``fetch`` (still a CSRF form body) and the reply comes back as JSON,
which the script turns into DOM nodes with ``textContent``, never HTML.

Proposal cards carry ordinary forms to the existing, CSRF-protected
``/messages/{id}/safe|fake|recheck`` routes with ``next`` pointing back here.
The model cannot submit them; only the person can.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import timedelta
from typing import Any

from fastapi import Depends, Form, HTTPException, Query, Request, status
from sqlalchemy import or_, select
from starlette.responses import JSONResponse, RedirectResponse, Response, StreamingResponse

from reddysec.assistant import store
from reddysec.assistant.agent import MAX_QUESTION_CHARS, AgentResult, Assistant, RateLimited
from reddysec.assistant.tools import ToolBox
from reddysec.core.logging import get_logger
from reddysec.store.models import (
    AssistantConversationRow,
    AssistantMessageRow,
    MailboxRow,
    MessageRow,
    UserRow,
)

from .. import mailview, preferences, presenters, queries
from ..auth import current_user
from ..security import flash
from ..templating import render, wants_json
from . import protected_router

log = get_logger(__name__)
router = protected_router()

SUGGESTIONS = (
    "Show me the most suspicious emails",
    "What's suspicious this week?",
    "Did you move anything out of my inbox?",
)
GENERIC_BRANDS = frozenset({"gmail", "yahoo", "outlook", "hotmail", "icloud", "live", "mail", "googlemail", "aol",
                            "me", "msn", "proton", "protonmail"})


async def suggestions_for(session: Any, user: UserRow, mailbox_id: str | None = None) -> tuple[str, ...]:
    """Questions that fit this person's own mail: what needs a look, the
    company they hear from most, their accounts."""
    now = queries.utcnow()
    where: list[Any] = [MailboxRow.user_id.in_(queries.visible_owner_ids(user))]
    if mailbox_id:
        where.append(MessageRow.mailbox_id == mailbox_id)
    flagged = await session.execute(
        select(MessageRow.id)
        .join(MailboxRow, MailboxRow.id == MessageRow.mailbox_id)
        .where(*where, MessageRow.received_at >= now - timedelta(days=7),
               or_(MessageRow.level.in_(("suspicious", "malicious")), MessageRow.quarantined.is_(True)))
    )
    n = len(flagged.all())
    senders = await session.execute(
        select(MessageRow.from_address)
        .join(MailboxRow, MailboxRow.id == MessageRow.mailbox_id)
        .where(*where, MessageRow.received_at >= now - timedelta(days=30))
        .limit(500)
    )
    brands: Counter[str] = Counter()
    for (address,) in senders.all():
        domain = (address or "").rsplit("@", 1)[-1].lower()
        parts = [p for p in domain.split(".") if p]
        label = parts[-2] if len(parts) >= 2 else ""
        if label and label not in GENERIC_BRANDS and label.isalpha():
            brands[label] += 1
    out: list[str] = []
    if n:
        out.append(f"{n} email{'s' if n != 1 else ''} need{'s' if n == 1 else ''} a look. Show {'it' if n == 1 else 'them'}")
    else:
        out.append("Show me the most suspicious emails")
    if brands:
        out.append(f"Search my {brands.most_common(1)[0][0].title()} emails")
    boxes = [m for m in await queries.list_mailboxes(session, user) if m.status != "disconnected"]
    if len(boxes) > 1 and not mailbox_id:
        out.append("Which account gets the most suspicious mail?")
    out.append("Did you move anything out of my inbox?")
    return tuple(out[:4])
ABOUT_SUGGESTIONS = ("Why was this email flagged?", "Is it safe to open the links?", "What should I do with it?")
NOT_FOUND = "We could not find that conversation."

PROPOSAL_COPY: dict[str, dict[str, str]] = {
    "mark_safe": {"title": "Mark this email as safe?", "yes": "Yes, mark as safe", "path": "safe", "tone": "ok",
                  "done": "Marked as safe."},
    "mark_fake": {"title": "Mark this email as fake?", "yes": "Yes, mark as fake", "path": "fake", "tone": "bad",
                  "done": "Marked as fake."},
    "recheck": {"title": "Check this email again?", "yes": "Yes, check again", "path": "recheck", "tone": "accent",
                "done": "Being checked again."},
}


def _see_other(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)


def _assistant(request: Request) -> Assistant:
    return request.app.state.assistant


def proposal_view(
    proposal: dict[str, Any], *, conversation_id: str, reply_id: str, index: int, message: Any | None
) -> dict[str, Any]:
    """Everything a proposal card shows. The state is read live from the
    message so a card reflects what the person actually did."""
    kind = str(proposal.get("kind", ""))
    copy = PROPOSAL_COPY.get(kind, PROPOSAL_COPY["recheck"])
    status_ = str(proposal.get("status", "open"))
    if message is None:
        status_ = "gone"
    else:
        decision = presenters.client_decision(message)
        if (kind == "mark_safe" and decision == "safe") or (kind == "mark_fake" and decision == "fake"):
            status_ = "done"
        elif kind == "recheck" and message.state == "rescore_requested":
            status_ = "done"
    message_id = str(proposal.get("message_id", ""))
    return {
        "kind": kind,
        "title": copy["title"],
        "yes": copy["yes"],
        "tone": copy["tone"],
        "action": f"/messages/{message_id}/{copy['path']}",
        "report": f"/messages/{message_id}",
        "decline_action": f"/assistant/{conversation_id}/proposals/decline",
        "next": f"/assistant/{conversation_id}#{reply_id}",
        "reply_id": reply_id,
        "index": index,
        "sender": str(proposal.get("sender", "")),
        "address": str(proposal.get("address", "")),
        "subject": str(proposal.get("subject", "")),
        "reason": str(proposal.get("reason", "")),
        "status": status_,
        "status_text": {"done": copy["done"], "declined": "You said no. Nothing changed.",
                        "gone": "This email is no longer available."}.get(status_, ""),
        "send_reason": kind != "recheck",
    }


async def _bubbles(session: Any, user: UserRow, conversation: AssistantConversationRow,
                   rows: list[AssistantMessageRow]) -> list[dict[str, Any]]:
    tools = ToolBox(session, user)
    cache: dict[str, Any] = {}

    async def lookup(message_id: str) -> Any | None:
        if message_id not in cache:
            found = await tools.visible_message(message_id)
            cache[message_id] = found[0] if found else None
        return cache[message_id]

    out: list[dict[str, Any]] = []
    for row in rows:
        content = row.content or {}
        if row.role == "user":
            out.append({"id": row.id, "role": "user", "text": str(content.get("text", "")),
                        "about_label": str(content.get("about_label") or ""), "at": row.created_at,
                        "read_email": bool(content.get("read_email")),
                        "blocks": [], "failed": False, "proposals": [], "cards": []})
        elif row.role == "assistant" and not content.get("tool_calls"):
            cards = []
            for i, p in enumerate(content.get("proposals") or []):
                message = await lookup(str(p.get("message_id", "")))
                cards.append(proposal_view(p, conversation_id=conversation.id, reply_id=row.id, index=i, message=message))
            text = str(content.get("text", ""))
            out.append({"id": row.id, "role": "assistant", "text": text, "blocks": presenters.chat_blocks(text),
                        "failed": bool(content.get("failed")), "proposals": cards, "at": row.created_at,
                        "cards": [c for c in content.get("cards") or [] if isinstance(c, dict)]})
    return out


async def _page(request: Request, user: UserRow, conversation_id: str | None, about: str | None) -> Response:
    assistant = _assistant(request)
    async with request.app.state.db.session() as session:
        conversations = await store.list_conversations(session, user)
        conversation = None
        bubbles: list[dict[str, Any]] = []
        if conversation_id is not None:
            conversation = await store.get_conversation(session, user, conversation_id)
            if conversation is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, detail=NOT_FOUND)
            bubbles = await _bubbles(session, user, conversation, await store.list_messages(session, conversation))
        about_message = None
        if about:
            found = await ToolBox(session, user).visible_message(about)
            if found is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, detail="We could not find that email report.")
            about_message = found[0]
        used_today = await store.questions_today(session, user)
        prefs = await preferences.get_preferences(session, user.id)
        mailboxes = await queries.list_mailboxes(session, user)
        selected, _changed = preferences.resolve_selection(None, prefs[preferences.SELECTED_MAILBOX], mailboxes)
        suggestions = ABOUT_SUGGESTIONS if about_message is not None else await suggestions_for(session, user, selected)
    return render(
        request,
        "assistant.html",
        {
            "enabled": assistant.enabled,
            "provider_name": PROVIDER_NAMES.get(getattr(request.app.state, "assistant_provider", ""), ""),
            "conversations": conversations,
            "conversation": conversation,
            "bubbles": bubbles,
            "about": about_message,
            "suggestions": suggestions,
            "max_chars": MAX_QUESTION_CHARS,
            "limit_reached": used_today >= assistant.daily_limit,
            "scope_label": next((m.address for m in mailboxes if m.id == selected), "All inboxes"),
            "is_admin": queries.is_staff(user),
        },
    )


PROVIDER_NAMES = {"anthropic": "Claude", "azure_foundry": "Azure AI Foundry", "azure_openai": "Azure OpenAI"}


@router.get("/assistant", name="assistant")
async def assistant_page(
    request: Request, about: str | None = Query(default=None, max_length=60), user: UserRow = Depends(current_user)
) -> Response:
    return await _page(request, user, None, about)


@router.get("/assistant/{conversation_id}", name="assistant_conversation")
async def assistant_conversation(
    request: Request, conversation_id: str, user: UserRow = Depends(current_user)
) -> Response:
    return await _page(request, user, conversation_id, None)


@router.post("/assistant/new", name="assistant_new")
async def assistant_new(request: Request, user: UserRow = Depends(current_user)) -> Response:
    async with request.app.state.db.session() as session:
        conversation = await store.create_conversation(session, user)
    return _see_other(f"/assistant/{conversation.id}")


def _error(request: Request, message: str, code: int, back: str) -> Response:
    if wants_json(request):
        return JSONResponse({"error": message}, status_code=code)
    flash(request, message, "warn")
    return _see_other(back)


async def _prepare(
    request: Request, user: UserRow, message: str, conversation_id: str
) -> tuple[str, AssistantConversationRow | None, str | None, Response | None]:
    """(question, conversation, selected mailbox, early response)."""
    question = message.strip()
    back = f"/assistant/{conversation_id}" if conversation_id else "/assistant"
    if not question:
        return question, None, None, _error(request, "Please type a question first.", status.HTTP_400_BAD_REQUEST, back)
    if len(question) > MAX_QUESTION_CHARS:
        return question, None, None, _error(
            request, f"Please keep your question under {MAX_QUESTION_CHARS} characters.", status.HTTP_400_BAD_REQUEST, back
        )
    async with request.app.state.db.session() as session:
        if conversation_id:
            conversation = await store.get_conversation(session, user, conversation_id)
            if conversation is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, detail=NOT_FOUND)
        else:
            conversation = await store.create_conversation(session, user, store.title_from(question))
        prefs = await preferences.get_preferences(session, user.id)
        mailboxes = await queries.list_mailboxes(session, user)
        selected, _ = preferences.resolve_selection(None, prefs[preferences.SELECTED_MAILBOX], mailboxes)
    return question, conversation, selected, None


def email_reader(request: Request):
    """Reads one email's plain text live from the provider, for "Let the
    assistant read this email" only."""
    from .mailread import fetch_raw_live

    limit = max(500, int(request.app.state.settings.assistant_read_email_max_chars))

    async def read(message: MessageRow, mailbox: MailboxRow) -> str:
        raw = await fetch_raw_live(request, mailbox, message)
        return mailview.plain_text(raw, limit)

    return read


@router.post("/assistant/send", name="assistant_send")
async def assistant_send(
    request: Request,
    message: str = Form(""),
    conversation_id: str = Form(""),
    about: str = Form(""),
    read_email: str = Form(""),
    user: UserRow = Depends(current_user),
) -> Response:
    question, conversation, selected, early = await _prepare(request, user, message, conversation_id)
    if early is not None:
        return early
    assert conversation is not None
    about_id = about.strip() or None
    try:
        result = await _assistant(request).ask(
            request.app.state.db, user, conversation, question, about=about_id, mailbox_id=selected,
            read_email=email_reader(request) if about_id and read_email == about_id else None,
        )
    except RateLimited:
        return _error(request, LIMIT_TEXT, status.HTTP_429_TOO_MANY_REQUESTS, f"/assistant/{conversation.id}")
    url = f"/assistant/{conversation.id}"
    if not wants_json(request):
        return _see_other(f"{url}#{result.reply_id}")
    return JSONResponse(await _reply_json(request, user, conversation, result))


async def _reply_json(
    request: Request, user: UserRow, conversation: AssistantConversationRow, result: AgentResult
) -> dict[str, Any]:
    async with request.app.state.db.session() as session:
        tools = ToolBox(session, user)
        proposals = []
        for i, p in enumerate(result.proposals):
            found = await tools.visible_message(p["message_id"])
            proposals.append(proposal_view(p, conversation_id=conversation.id, reply_id=result.reply_id, index=i,
                                           message=found[0] if found else None))
    return {
        "conversation_id": conversation.id,
        "conversation_url": f"/assistant/{conversation.id}",
        "title": conversation.title,
        "reply": {"id": result.reply_id, "text": result.text, "failed": result.failed, "proposals": proposals,
                  "cards": result.cards},
    }


def _sse(event: str, data: dict[str, Any]) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False, separators=(',', ':'))}\n\n".encode()


@router.post("/assistant/stream", name="assistant_stream")
async def assistant_stream(
    request: Request,
    message: str = Form(""),
    conversation_id: str = Form(""),
    about: str = Form(""),
    read_email: str = Form(""),
    user: UserRow = Depends(current_user),
) -> Response:
    """The same as ``/assistant/send``, as Server-Sent Events: ``status``,
    ``delta`` (text as it is written), ``draft_done``, ``cards``, then
    ``done`` with the stored reply (or ``error``). Closing the connection
    (the Stop button) stops the work."""
    question, conversation, selected, early = await _prepare(request, user, message, conversation_id)
    if early is not None:
        return early
    assert conversation is not None
    about_id = about.strip() or None
    assistant = _assistant(request)
    db = request.app.state.db
    # The daily limit is checked before the stream starts so it can be a 429.
    async with db.session() as session:
        if await store.questions_today(session, user) >= assistant.daily_limit:
            return _error(request, LIMIT_TEXT, status.HTTP_429_TOO_MANY_REQUESTS, f"/assistant/{conversation.id}")
    reader = email_reader(request) if about_id and read_email == about_id else None

    async def events():
        yield _sse("start", {"conversation_id": conversation.id, "conversation_url": f"/assistant/{conversation.id}",
                             "title": conversation.title})
        try:
            async for event in assistant.events(
                db, user, conversation, question, about=about_id, mailbox_id=selected, read_email=reader
            ):
                kind = event["type"]
                if kind == "done":
                    yield _sse("done", await _reply_json(request, user, conversation, event["result"]))
                else:
                    yield _sse(kind, {k: v for k, v in event.items() if k != "type"})
        except RateLimited:
            yield _sse("error", {"text": LIMIT_TEXT})
        except Exception:  # noqa: BLE001 - the stream must end with a message, not a broken connection
            log.exception("assistant_stream_failed")
            yield _sse("error", {"text": "Sorry, something went wrong. Please try again."})

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


LIMIT_TEXT = (
    "You have asked a lot of questions today. The assistant will be back tomorrow; your email is still checked as usual."
)


@router.post("/assistant/{conversation_id}/proposals/decline", name="assistant_decline")
async def assistant_decline(
    request: Request,
    conversation_id: str,
    reply_id: str = Form(...),
    index: int = Form(...),
    user: UserRow = Depends(current_user),
) -> Response:
    """"No" on a proposal card: remember it so the card stays answered."""
    async with request.app.state.db.session() as session:
        conversation = await store.get_conversation(session, user, conversation_id)
        if conversation is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail=NOT_FOUND)
        row = await session.get(AssistantMessageRow, reply_id)
        if row is None or row.conversation_id != conversation.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail=NOT_FOUND)
        changed = await store.set_proposal_status(session, row, index, "declined")
    if wants_json(request):
        return JSONResponse({"ok": changed})
    if changed:
        flash(request, "Okay. Nothing was changed.")
    return _see_other(f"/assistant/{conversation_id}#{reply_id}")

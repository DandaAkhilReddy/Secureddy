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

from typing import Any

from fastapi import Depends, Form, HTTPException, Query, Request, status
from starlette.responses import JSONResponse, RedirectResponse, Response

from reddysec.assistant import store
from reddysec.assistant.agent import MAX_QUESTION_CHARS, Assistant, RateLimited
from reddysec.assistant.tools import ToolBox
from reddysec.store.models import AssistantConversationRow, AssistantMessageRow, UserRow

from .. import presenters
from ..auth import current_user
from ..security import flash
from ..templating import render, wants_json
from . import protected_router

router = protected_router()

SUGGESTIONS = (
    "What's suspicious this week?",
    "Why was my Walmart email flagged?",
    "Is anything in Quarantine I should look at?",
)
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
                        "blocks": [], "failed": False, "proposals": []})
        elif row.role == "assistant" and not content.get("tool_calls"):
            cards = []
            for i, p in enumerate(content.get("proposals") or []):
                message = await lookup(str(p.get("message_id", "")))
                cards.append(proposal_view(p, conversation_id=conversation.id, reply_id=row.id, index=i, message=message))
            text = str(content.get("text", ""))
            out.append({"id": row.id, "role": "assistant", "text": text, "blocks": presenters.chat_blocks(text),
                        "failed": bool(content.get("failed")), "proposals": cards, "at": row.created_at})
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
    return render(
        request,
        "assistant.html",
        {
            "enabled": assistant.enabled,
            "conversations": conversations,
            "conversation": conversation,
            "bubbles": bubbles,
            "about": about_message,
            "suggestions": ABOUT_SUGGESTIONS if about_message is not None else SUGGESTIONS,
            "max_chars": MAX_QUESTION_CHARS,
            "limit_reached": used_today >= assistant.daily_limit,
        },
    )


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


@router.post("/assistant/send", name="assistant_send")
async def assistant_send(
    request: Request,
    message: str = Form(""),
    conversation_id: str = Form(""),
    about: str = Form(""),
    user: UserRow = Depends(current_user),
) -> Response:
    question = message.strip()
    back = f"/assistant/{conversation_id}" if conversation_id else "/assistant"
    if not question:
        return _error(request, "Please type a question first.", status.HTTP_400_BAD_REQUEST, back)
    if len(question) > MAX_QUESTION_CHARS:
        return _error(request, f"Please keep your question under {MAX_QUESTION_CHARS} characters.",
                      status.HTTP_400_BAD_REQUEST, back)
    async with request.app.state.db.session() as session:
        if conversation_id:
            conversation = await store.get_conversation(session, user, conversation_id)
            if conversation is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, detail=NOT_FOUND)
        else:
            conversation = await store.create_conversation(session, user, store.title_from(question))
    try:
        result = await _assistant(request).ask(
            request.app.state.db, user, conversation, question, about=about.strip() or None
        )
    except RateLimited:
        return _error(
            request,
            "You have asked a lot of questions today. The assistant will be back tomorrow; your email is still checked as usual.",
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"/assistant/{conversation.id}",
        )
    url = f"/assistant/{conversation.id}"
    if not wants_json(request):
        return _see_other(f"{url}#{result.reply_id}")
    async with request.app.state.db.session() as session:
        tools = ToolBox(session, user)
        cards = []
        for i, p in enumerate(result.proposals):
            found = await tools.visible_message(p["message_id"])
            cards.append(proposal_view(p, conversation_id=conversation.id, reply_id=result.reply_id, index=i,
                                       message=found[0] if found else None))
    return JSONResponse(
        {
            "conversation_id": conversation.id,
            "conversation_url": url,
            "title": conversation.title,
            "reply": {"id": result.reply_id, "text": result.text, "failed": result.failed, "proposals": cards},
        }
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

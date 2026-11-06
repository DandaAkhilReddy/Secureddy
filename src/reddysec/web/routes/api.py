"""Small JSON API for a future mobile app. Same session cookie, same
visibility rules; mutations (none yet) would need the ``X-CSRF-Token`` header."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import Depends, Query, Request

from reddysec.store.models import MailboxRow, MessageRow, UserRow

from .. import presenters, queries
from ..auth import current_user
from . import protected_router

router = protected_router(prefix="/api")


def _iso(value: datetime | None) -> str | None:
    return presenters.as_utc(value).isoformat() if value is not None else None


def mailbox_json(mailbox: MailboxRow) -> dict[str, Any]:
    return {
        "id": mailbox.id,
        "provider": mailbox.provider,
        "address": mailbox.address,
        "mode": mailbox.mode,
        "status": mailbox.status,
        "last_sync_at": _iso(mailbox.last_sync_at),
    }


def message_json(message: MessageRow, mailbox: MailboxRow) -> dict[str, Any]:
    chip = presenters.verdict_chip(message)
    return {
        "id": message.id,
        "mailbox_id": mailbox.id,
        "mailbox_address": mailbox.address,
        "from_address": message.from_address,
        "from_name": message.from_name,
        "subject": message.subject,
        "received_at": _iso(message.received_at),
        "state": message.state,
        "level": message.level,
        "score": message.score,
        "lane": message.lane,
        "quarantined": bool(message.quarantined),
        "verdict_label": chip.label,
        "summary": presenters.message_summary(message),
        "url_count": message.url_count,
        "attachment_count": message.attachment_count,
    }


@router.get("/me", name="api_me")
async def api_me(request: Request, user: UserRow = Depends(current_user)) -> dict[str, Any]:
    async with request.app.state.db.session() as session:
        mailboxes = await queries.list_mailboxes(session, user)
    return {
        "id": user.id,
        "display_name": user.display_name,
        "login_email": user.login_email,
        "role": user.role,
        "mailboxes": [mailbox_json(m) for m in mailboxes],
    }


@router.get("/messages", name="api_messages")
async def api_messages(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    mailbox_id: str | None = Query(default=None),
    level: str | None = Query(default=None),
    user: UserRow = Depends(current_user),
) -> dict[str, Any]:
    async with request.app.state.db.session() as session:
        rows = await queries.list_messages(session, user, limit=limit, mailbox_id=mailbox_id, level=level)
    return {"items": [message_json(m, mb) for m, mb in rows], "limit": limit}

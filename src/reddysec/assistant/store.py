"""Persistence for "Ask Secureddy" conversations.

A conversation belongs to exactly one user and nobody else can read it, not
even staff: the questions are the client's own words about their own mail.
The audit log records *that* a question was asked (``assistant_question``),
never what it said.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from reddysec.core.ids import new_id
from reddysec.store.models import AssistantConversationRow, AssistantMessageRow, UserRow, utcnow

CONTEXT_TURNS = 20  # user questions (with their replies) replayed to the model
MAX_TITLE = 80
DEFAULT_TITLE = "New conversation"


def title_from(text: str) -> str:
    words = " ".join(text.split())
    if len(words) <= MAX_TITLE:
        return words or DEFAULT_TITLE
    return words[: MAX_TITLE - 1].rsplit(" ", 1)[0] + "…"


async def create_conversation(session: AsyncSession, user: UserRow, title: str = DEFAULT_TITLE) -> AssistantConversationRow:
    now = utcnow()
    row = AssistantConversationRow(
        id=new_id("cnv"), user_id=user.id, title=title[:200] or DEFAULT_TITLE, created_at=now, updated_at=now
    )
    session.add(row)
    await session.flush()
    return row


async def get_conversation(session: AsyncSession, user: UserRow, conversation_id: str) -> AssistantConversationRow | None:
    """``None`` unless ``user`` owns it; callers turn that into a 404."""
    row = await session.get(AssistantConversationRow, conversation_id)
    return row if row is not None and row.user_id == user.id else None


async def list_conversations(session: AsyncSession, user: UserRow, *, limit: int = 30) -> list[AssistantConversationRow]:
    stmt = (
        select(AssistantConversationRow)
        .where(AssistantConversationRow.user_id == user.id)
        .order_by(AssistantConversationRow.updated_at.desc(), AssistantConversationRow.id.desc())
        .limit(limit)
    )
    return list((await session.execute(stmt)).scalars())


async def add_message(
    session: AsyncSession, conversation: AssistantConversationRow, role: str, content: dict[str, Any]
) -> AssistantMessageRow:
    if role not in ("user", "assistant", "tool"):
        raise ValueError(f"unknown role {role!r}")
    last = (
        await session.execute(
            select(func.max(AssistantMessageRow.seq)).where(AssistantMessageRow.conversation_id == conversation.id)
        )
    ).scalar_one()
    now = utcnow()
    row = AssistantMessageRow(
        id=new_id("amsg"), conversation_id=conversation.id, seq=(last or 0) + 1, role=role,
        content=dict(content), created_at=now,
    )
    session.add(row)
    conversation.updated_at = now
    await session.flush()
    return row


async def list_messages(session: AsyncSession, conversation: AssistantConversationRow) -> list[AssistantMessageRow]:
    stmt = (
        select(AssistantMessageRow)
        .where(AssistantMessageRow.conversation_id == conversation.id)
        .order_by(AssistantMessageRow.seq)
    )
    return list((await session.execute(stmt)).scalars())


def context_window(rows: list[AssistantMessageRow], turns: int = CONTEXT_TURNS) -> list[dict[str, Any]]:
    """The last ``turns`` questions and the final answers to them, in the
    neutral chat format. Earlier tool rounds are not replayed: the model can
    call the tools again, and old tool output would only cost tokens."""
    user_idx = [i for i, r in enumerate(rows) if r.role == "user"]
    start = user_idx[-turns] if len(user_idx) > turns else 0
    out: list[dict[str, Any]] = []
    for r in rows[start:]:
        content = r.content or {}
        if r.role == "user":
            out.append({"role": "user", "text": str(content.get("model_text") or content.get("text", ""))})
        elif r.role == "assistant" and not content.get("tool_calls") and content.get("text"):
            out.append({"role": "assistant", "text": str(content["text"])})
    return out


async def questions_today(session: AsyncSession, user: UserRow, *, now: datetime | None = None) -> int:
    """How many questions ``user`` asked since 00:00 UTC (the daily limit)."""
    now = now or utcnow()
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    stmt = (
        select(func.count(AssistantMessageRow.id))
        .join(AssistantConversationRow, AssistantConversationRow.id == AssistantMessageRow.conversation_id)
        .where(
            AssistantConversationRow.user_id == user.id,
            AssistantMessageRow.role == "user",
            AssistantMessageRow.created_at >= start,
            AssistantMessageRow.created_at < start + timedelta(days=1),
        )
    )
    return int((await session.execute(stmt)).scalar_one())


async def set_proposal_status(
    session: AsyncSession, row: AssistantMessageRow, index: int, status: str
) -> bool:
    """Record that the client declined (or accepted) proposal ``index`` of an
    assistant reply, so the card stays answered after a reload."""
    content = dict(row.content or {})
    proposals = [dict(p) for p in content.get("proposals") or []]
    if row.role != "assistant" or not 0 <= index < len(proposals):
        return False
    proposals[index]["status"] = status
    content["proposals"] = proposals
    row.content = content  # reassign: JSON columns only notice new objects
    await session.flush()
    return True

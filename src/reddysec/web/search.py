"""Searching your email from inside Secureddy.

Two sources, merged on one page:

1. **Our records** (always): sender name and address, subject, the account it
   arrived in, our verdict ("suspicious", "quarantine", "safe" ...) and the
   reasons we gave. Every word must match somewhere.
2. **Inside your emails** (only when the person ticks "Search inside
   emails"): a live search at Gmail (``q=``), Microsoft Graph (``$search``) or
   IMAP (``SEARCH TEXT``) for the selected accounts. Results we have already
   checked show their verdict; the rest are marked "Not checked yet" with a
   "Check now" button. Live results are never stored; "Check now" carries a
   signed token so only what the provider returned can be queued.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from markupsafe import Markup, escape
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from reddysec.core.logging import get_logger
from reddysec.mail.base import AuthExpired, ConnectorError, SearchHit
from reddysec.store.models import MailboxRow, MessageRow, UserRow

from . import presenters, queries

log = get_logger(__name__)

MAX_TERMS = 6
MAX_SCAN = 2000
LIVE_LIMIT = 15
CHECK_TOKEN_TTL_S = 3600

LEVEL_WORDS: dict[str, tuple[str, Any]] = {
    "suspicious": ("level", "suspicious"),
    "quarantine": ("quarantined", True),
    "quarantined": ("quarantined", True),
    "dangerous": ("level", "malicious"),
    "malicious": ("level", "malicious"),
    "fake": ("level", "malicious"),
    "safe": ("level", "safe"),
    "checked": ("level", "safe"),
}


def terms_of(query: str) -> list[str]:
    words = re.findall(r"[^\s\"']+", (query or "").lower())
    return [w[:80] for w in words][:MAX_TERMS]


def _verdict_text(message: MessageRow) -> str:
    """What a person might search for in our verdict: the summary, the
    reasons we show, and the engine's own signal titles."""
    verdict = presenters.parse_verdict(message.verdict)
    parts = [presenters.list_reason(message)]
    if verdict is not None:
        parts.append(verdict.summary)
        parts.extend(s.title for s in verdict.signals)
    return " ".join(p for p in parts if p).lower()


def _matches(message: MessageRow, mailbox: MailboxRow, term: str) -> bool:
    if term in LEVEL_WORDS:
        attr, value = LEVEL_WORDS[term]
        return bool(getattr(message, attr) == value)
    haystack = " ".join(
        (message.from_address or "", message.from_name or "", message.subject or "", mailbox.address or "")
    ).lower()
    return term in haystack or term in _verdict_text(message)


async def search_records(
    session: AsyncSession,
    user: UserRow,
    query: str,
    *,
    mailbox_id: str | None = None,
    limit: int = queries.PAGE_SIZE,
    offset: int = 0,
) -> tuple[list[tuple[MessageRow, MailboxRow]], int]:
    """Messages matching every word of ``query`` in the visible mailboxes (or
    one), newest first, with the total count."""
    terms = terms_of(query)
    if not terms:
        return [], 0
    where: list[Any] = [MailboxRow.user_id.in_(queries.visible_owner_ids(user))]
    if mailbox_id:
        where.append(MessageRow.mailbox_id == mailbox_id)
    for term in terms:
        if term in LEVEL_WORDS:
            attr, value = LEVEL_WORDS[term]
            column = getattr(MessageRow, attr)
            where.append(column.is_(True) if value is True else column == value)
            continue
        where.append(
            or_(
                func.lower(MessageRow.from_address).contains(term, autoescape=True),
                func.lower(func.coalesce(MessageRow.from_name, "")).contains(term, autoescape=True),
                func.lower(MessageRow.subject).contains(term, autoescape=True),
                func.lower(MailboxRow.address).contains(term, autoescape=True),
                func.lower(cast(MessageRow.verdict, String)).contains(term, autoescape=True),
            )
        )
    stmt = (
        select(MessageRow, MailboxRow)
        .join(MailboxRow, MailboxRow.id == MessageRow.mailbox_id)
        .where(*where)
        .order_by(MessageRow.received_at.desc(), MessageRow.id)
        .limit(MAX_SCAN)
    )
    rows = [(r[0], r[1]) for r in (await session.execute(stmt)).all()]
    # The verdict JSON also contains field names; keep only real matches.
    matched = [(m, mb) for m, mb in rows if all(_matches(m, mb, t) for t in terms)]
    return matched[offset : offset + limit], len(matched)


def highlight(text: str | None, query: str) -> Markup:
    """``text`` with the searched words wrapped in ``<mark>``; always escaped."""
    value = text or ""
    words = sorted({t for t in terms_of(query) if t not in LEVEL_WORDS and len(t) >= 2}, key=len, reverse=True)
    if not words or not value:
        return Markup(escape(value))
    pattern = re.compile("|".join(re.escape(w) for w in words), re.I)
    out: list[str] = []
    last = 0
    for match in pattern.finditer(value):
        out.append(str(escape(value[last : match.start()])))
        out.append(f"<mark>{escape(match.group(0))}</mark>")
        last = match.end()
    out.append(str(escape(value[last:])))
    return Markup("".join(out))


# --------------------------------------------------------------------------- live search


def _check_key(secret: str) -> bytes:
    return hashlib.sha256(f"reddysec.web.check-now\x00{secret}".encode()).digest()


def sign_check(secret: str, user_id: str, mailbox_id: str, hit: SearchHit, *, now: float | None = None) -> str:
    """A token for "Check now" that names exactly one message the provider
    returned to this person, valid for an hour."""
    payload = {
        "u": user_id,
        "b": mailbox_id,
        "p": hit.provider_message_id,
        "f": hit.from_address[:320],
        "n": hit.from_name[:300],
        "s": hit.subject[:1000],
        "r": hit.received_at.isoformat() if hit.received_at else "",
        "e": int((now or datetime.now(UTC).timestamp()) + CHECK_TOKEN_TTL_S),
    }
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    mac = hmac.new(_check_key(secret), body.encode(), hashlib.sha256).digest()[:16]
    return f"{body}.{base64.urlsafe_b64encode(mac).decode().rstrip('=')}"


def read_check(secret: str, token: str, user_id: str, *, now: float | None = None) -> dict[str, Any] | None:
    try:
        body, mac = token.split(".", 1)
        expected = base64.urlsafe_b64encode(
            hmac.new(_check_key(secret), body.encode(), hashlib.sha256).digest()[:16]
        ).decode().rstrip("=")
        if not hmac.compare_digest(expected, mac):
            return None
        data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict) or data.get("u") != user_id:
        return None
    if int(data.get("e", 0)) < (now or datetime.now(UTC).timestamp()):
        return None
    return data


@dataclass
class LiveResult:
    mailbox: MailboxRow
    hit: SearchHit
    message: MessageRow | None = None
    check_token: str = ""


@dataclass
class LiveSearch:
    results: list[LiveResult] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)  # one plain sentence per account that failed


async def search_live(
    request: Any,
    user: UserRow,
    mailboxes: list[MailboxRow],
    query: str,
    *,
    limit: int = LIVE_LIMIT,
) -> LiveSearch:
    """Ask each selected provider, at the same time, with a time limit."""
    settings = request.app.state.settings
    factory = request.app.state.connector_factory
    out = LiveSearch()
    live = [m for m in mailboxes if m.status in ("active", "error")]

    async def one(mailbox: MailboxRow) -> tuple[MailboxRow, list[SearchHit] | str]:
        try:
            connector = await factory(mailbox)
            try:
                hits = await asyncio.wait_for(connector.search(query, limit), timeout=settings.live_search_timeout_s)
            finally:
                closer = getattr(connector, "aclose", None)
                if callable(closer):
                    await closer()
            return mailbox, list(hits)
        except AuthExpired:
            return mailbox, f"{mailbox.address} needs to be reconnected before we can search it."
        except (ConnectorError, TimeoutError, AttributeError, OSError) as exc:
            log.info("live_search_failed", mailbox_id=mailbox.id, error=type(exc).__name__)
            return mailbox, f"We could not search {mailbox.address} just now."

    answers = await asyncio.gather(*(one(m) for m in live))
    secret = settings.secret_key.get_secret_value()
    async with request.app.state.db.session() as session:
        for mailbox, hits in answers:
            if isinstance(hits, str):
                out.problems.append(hits)
                continue
            ids = [h.provider_message_id for h in hits]
            known: dict[str, MessageRow] = {}
            if ids:
                rows = await session.execute(
                    select(MessageRow).where(
                        MessageRow.mailbox_id == mailbox.id, MessageRow.provider_message_id.in_(ids)
                    )
                )
                known = {r.provider_message_id: r for r in rows.scalars()}
            for hit in hits:
                message = known.get(hit.provider_message_id)
                token = "" if message is not None else sign_check(secret, user.id, mailbox.id, hit)
                out.results.append(LiveResult(mailbox, hit, message, token))
    epoch = datetime.min.replace(tzinfo=UTC)
    out.results.sort(key=lambda r: presenters.as_utc(r.hit.received_at) if r.hit.received_at else epoch, reverse=True)
    return out


__all__ = [
    "LEVEL_WORDS",
    "LiveResult",
    "LiveSearch",
    "highlight",
    "read_check",
    "search_live",
    "search_records",
    "sign_check",
    "terms_of",
]

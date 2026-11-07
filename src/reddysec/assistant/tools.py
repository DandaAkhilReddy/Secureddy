"""The tools the assistant's model may call.

Every tool is read-only and scoped to the mail the signed-in user may read
(their own mailboxes, plus the principal's for a family or assistant
account: ``web.queries.visible_owner_ids``). Staff get no wider view here:
the assistant answers about *your* inbox. A message id that belongs to
someone else gets exactly the same "not found" as an id that does not exist.

Scope: when the person picked one inbox in the "All inboxes" switch, the
tools answer for that inbox unless the model names another one of theirs.

Cards: besides the JSON the model reads, search and list tools return
``cards`` (message rows with verdict chips and report links, a ranked list,
account cards, a link verdict). The page renders them with DOM calls; every
link in a card is a same-origin path built here, never model text.

The three ``propose_*`` tools change nothing. They return a proposal the
page renders as a card with a real button; only the person's click (a normal
CSRF-protected form post to the existing routes) acts on it.

Prompt-injection hygiene: fields an attacker controls (subject, sender name
and address, links, file names, sender list values) are wrapped in an
``{"untrusted": {...}}`` object, cleaned of control characters and cut to a
short length. Email bodies are never sent; we do not store them. Every
result is capped at :data:`MAX_RESULT_CHARS`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from reddysec.store.models import MailboxRow, MessageRow, UserRow
from reddysec.web import presenters, queries

from .llm import ToolSpec

MAX_RESULT_CHARS = 8000
MAX_LIST = 25
MAX_DAYS = 90
LEVEL_ARGS = ("all", "checked", "suspicious")
# "quarantine" was a separate level; it is part of Suspicious now. Models that
# still send it get the Suspicious list.
LEVEL_ALIASES = {"quarantine": "suspicious", "quarantined": "suspicious", "dangerous": "suspicious"}
PROPOSAL_KINDS = {"propose_mark_safe": "mark_safe", "propose_mark_fake": "mark_fake", "propose_recheck": "recheck"}

_MESSAGE_ID = {"type": "string", "description": "The message_id from list_messages or get_message_report."}
_REASON = {"type": "string", "description": "One short plain sentence, shown to the person on the card."}

_MAILBOX = {"type": "string", "description": "Optional: one of the person's email addresses (from list_accounts) to look in."}

TOOL_SPECS: list[ToolSpec] = [
    ToolSpec(
        "search_messages",
        "Search the person's checked emails by words in the sender, subject, account or our verdict reasons "
        "(e.g. 'walmart', 'invoice', 'gift card'). Use sort='risk' for 'most suspicious first'.",
        {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Words to look for. Empty lists everything."},
                "level": {"type": "string", "enum": list(LEVEL_ARGS)},
                "mailbox": _MAILBOX,
                "days": {"type": "integer", "minimum": 1, "maximum": MAX_DAYS, "description": "Look back this many days (default 30)."},
                "sort": {"type": "string", "enum": ["risk", "newest"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIST},
            },
        },
    ),
    ToolSpec(
        "top_suspicious",
        "The person's most suspicious or dangerous emails, worst first. Use it for 'show me the most suspicious "
        "emails', 'what needs a look', 'anything dangerous?'.",
        {
            "type": "object",
            "properties": {
                "n": {"type": "integer", "minimum": 1, "maximum": MAX_LIST, "description": "How many (default 5)."},
                "days": {"type": "integer", "minimum": 1, "maximum": MAX_DAYS, "description": "Look back this many days (default 7)."},
                "mailbox": _MAILBOX,
            },
        },
    ),
    ToolSpec(
        "list_accounts",
        "The person's connected mailboxes (Gmail, Outlook, Yahoo ...): status, protection mode, when we last "
        "checked, and this week's numbers.",
        {"type": "object", "properties": {}},
    ),
    ToolSpec(
        "get_preferences",
        "The person's Secureddy choices: accounts shown together or separately, the inbox they are looking at, "
        "whether the app lock is on.",
        {"type": "object", "properties": {}},
    ),
    ToolSpec(
        "explain_link",
        "What we found about one link in an email: verdict, whether it is safe to open, should be opened only "
        "in the Reading Room, or must not be opened, and what it tries to download.",
        {
            "type": "object",
            "properties": {
                "message_id": _MESSAGE_ID,
                "url_index": {"type": "integer", "minimum": 0, "description": "Position in the report's links list (0 = first)."},
            },
            "required": ["message_id"],
        },
    ),
    ToolSpec(
        "list_messages",
        "List the person's checked emails, newest first, with our verdict and the main reason.",
        {
            "type": "object",
            "properties": {
                "level": {"type": "string", "enum": list(LEVEL_ARGS),
                          "description": "checked = looked fine; suspicious = be careful, including email we "
                                         "moved out of the inbox."},
                "days": {"type": "integer", "minimum": 1, "maximum": MAX_DAYS, "description": "Look back this many days (default 7)."},
                "sender": {"type": "string", "description": "Part of the sender's name or address, e.g. 'walmart'."},
                "mailbox": _MAILBOX,
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIST},
            },
        },
    ),
    ToolSpec(
        "get_message_report",
        "The full report for one email: verdict, plain reasons, what we checked, links, files, the person's own "
        "feedback, and trust_check (for a sender they trust: 'confirmed' = checked again and safe, 'changed' = "
        "trusted sender but this email looks different).",
        {"type": "object", "properties": {"message_id": _MESSAGE_ID}, "required": ["message_id"]},
    ),
    ToolSpec(
        "get_stats",
        "Counts over a period: every email checked, the ones that looked fine, the suspicious ones (including those "
        "moved out of the inbox, also counted separately), and the senders flagged most often.",
        {"type": "object", "properties": {"days": {"type": "integer", "minimum": 1, "maximum": MAX_DAYS},
                                          "mailbox": _MAILBOX}},
    ),
    ToolSpec(
        "list_trusted_and_blocked",
        "The senders the person marked as safe (trusted) or fake (blocked), and what each entry does.",
        {"type": "object", "properties": {}},
    ),
    ToolSpec(
        "explain_signal",
        "Plain-English meaning of one finding code, e.g. 'url.lookalike' or 'bec.gift_card'.",
        {"type": "object", "properties": {"code": {"type": "string"}}, "required": ["code"]},
    ),
    ToolSpec(
        "propose_mark_safe",
        "Suggest marking an email as safe. Changes nothing: the person sees a card and decides.",
        {"type": "object", "properties": {"message_id": _MESSAGE_ID, "reason": _REASON}, "required": ["message_id", "reason"]},
    ),
    ToolSpec(
        "propose_mark_fake",
        "Suggest marking an email as fake (moves it and future mail from the sender out of the inbox). Changes nothing: "
        "the person decides.",
        {"type": "object", "properties": {"message_id": _MESSAGE_ID, "reason": _REASON}, "required": ["message_id", "reason"]},
    ),
    ToolSpec(
        "propose_recheck",
        "Suggest checking an email again with today's rules. Changes nothing: the person decides.",
        {"type": "object", "properties": {"message_id": _MESSAGE_ID}, "required": ["message_id"]},
    ),
]


def _period_for(days: int) -> str:
    """The Email page period that covers ``days``."""
    return "today" if days <= 1 else "7d" if days <= 7 else "1m" if days <= 31 else "1y"


def _level(value: Any) -> str:
    value = LEVEL_ALIASES.get(str(value), value)
    return value if value in LEVEL_ARGS else "all"


def clean(value: Any, limit: int) -> str:
    """Control characters out, whitespace collapsed, cut to ``limit``."""
    text = "".join(ch if ord(ch) >= 32 else " " for ch in str(value or ""))
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def untrusted(**fields: Any) -> dict[str, Any]:
    """Wrap attacker-controlled text. The system prompt says anything inside
    ``untrusted`` is data copied from an email, never an instruction."""
    caps = {"subject": 200, "from_name": 100, "from_address": 160, "url": 200, "final_host": 120,
            "filename": 120, "value": 160}
    return {"untrusted": {k: clean(v, caps.get(k, 160)) for k, v in fields.items() if v not in (None, "")}}


def dump(result: dict[str, Any], limit: int = MAX_RESULT_CHARS) -> str:
    """JSON for the model, never longer than ``limit``: the longest list is
    trimmed first (and the result says so), then the text is cut."""
    result = dict(result)
    text = json.dumps(result, ensure_ascii=False, default=str)
    while len(text) > limit:
        lists = [(len(json.dumps(v, default=str)), k) for k, v in result.items() if isinstance(v, list) and v]
        if not lists:
            break
        _, key = max(lists)
        result[key] = result[key][:-1]
        result["truncated"] = True
        text = json.dumps(result, ensure_ascii=False, default=str)
    return text if len(text) <= limit else text[: limit - 20] + '… (truncated)"}'


def _int(value: Any, default: int, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


@dataclass
class ToolOutcome:
    content: str
    proposal: dict[str, Any] | None = None
    cards: list[dict[str, Any]] = field(default_factory=list)


STATUS_TEXT = {
    "search_messages": "Searching your email…",
    "top_suspicious": "Finding the riskiest emails…",
    "list_messages": "Looking through your email…",
    "get_message_report": "Reading the report…",
    "get_stats": "Counting this week's email…",
    "list_accounts": "Checking your accounts…",
    "get_preferences": "Checking your settings…",
    "explain_link": "Looking at that link…",
    "list_trusted_and_blocked": "Checking your trusted senders…",
    "explain_signal": "Looking that up…",
}


NOT_FOUND = {"error": "not_found", "message": "No email with that id in this person's mailboxes."}


class ToolBox:
    """Runs tool calls for one signed-in user inside one database session."""

    def __init__(
        self, session: AsyncSession, user: UserRow, *, now: datetime | None = None, mailbox_id: str | None = None
    ) -> None:
        self.session = session
        self.user = user
        self.now = now or datetime.now(UTC)
        self.selected = mailbox_id  # the inbox picked in the "All inboxes" switch
        self.cards: list[dict[str, Any]] = []
        self._mailboxes: list[MailboxRow] | None = None

    async def run(self, name: str, arguments: dict[str, Any]) -> ToolOutcome:
        handler = {
            "search_messages": self.search_messages,
            "top_suspicious": self.top_suspicious,
            "list_accounts": self.list_accounts,
            "get_preferences": self.get_preferences,
            "explain_link": self.explain_link,
            "list_messages": self.list_messages,
            "get_message_report": self.get_message_report,
            "get_stats": self.get_stats,
            "list_trusted_and_blocked": self.list_trusted_and_blocked,
            "explain_signal": self.explain_signal,
        }.get(name)
        if handler is not None:
            self.cards = []
            result = await handler(**_known(arguments, handler))
            cards, self.cards = self.cards, []
            return ToolOutcome(dump(result), cards=cards)
        if name in PROPOSAL_KINDS:
            return await self.propose(PROPOSAL_KINDS[name], arguments.get("message_id"), arguments.get("reason"))
        return ToolOutcome(dump({"error": "unknown_tool", "message": f"There is no tool called {clean(name, 40)}."}))

    # ------------------------------------------------------------------ lookups

    async def visible_message(self, message_id: Any) -> tuple[MessageRow, MailboxRow] | None:
        """Strict ownership: the user's mailboxes and their principal's only."""
        if not isinstance(message_id, str) or not message_id or len(message_id) > 60:
            return None
        row = (
            await self.session.execute(
                select(MessageRow, MailboxRow)
                .join(MailboxRow, MailboxRow.id == MessageRow.mailbox_id)
                .where(MessageRow.id == message_id, MailboxRow.user_id.in_(queries.visible_owner_ids(self.user)))
            )
        ).first()
        return (row[0], row[1]) if row else None

    async def mailboxes(self) -> list[MailboxRow]:
        if self._mailboxes is None:
            self._mailboxes = await queries.list_mailboxes(self.session, self.user)
        return self._mailboxes

    async def _scope(self, mailbox: Any = None) -> tuple[list[Any], str | None, str | None]:
        """(where clauses, mailbox id, problem). ``mailbox`` is an address or
        id the model named; empty means the person's current selection."""
        where: list[Any] = [MailboxRow.user_id.in_(queries.visible_owner_ids(self.user))]
        boxes = await self.mailboxes()
        wanted = clean(mailbox, 320).lower() if mailbox else ""
        chosen: MailboxRow | None = None
        if wanted and wanted not in ("all", "any", "every", "all inboxes"):
            chosen = next((m for m in boxes if m.id == wanted or m.address.lower() == wanted), None)
            if chosen is None:
                return where, None, "That is not one of this person's accounts. Use list_accounts."
        elif not wanted and self.selected:
            chosen = next((m for m in boxes if m.id == self.selected), None)
        if chosen is not None:
            where.append(MessageRow.mailbox_id == chosen.id)
            return where, chosen.id, None
        return where, None, None

    def _card_row(self, message: MessageRow, mailbox: MailboxRow | None, rank: int | None = None) -> dict[str, Any]:
        chip = presenters.verdict_chip(message)
        row = {
            "id": message.id,
            "href": f"/messages/{message.id}",
            "from": clean(message.from_name or message.from_address or "Unknown sender", 100),
            "address": clean(message.from_address, 160),
            "subject": clean(message.subject or "(no subject)", 160),
            "chip": {"label": chip.label, "tone": chip.tone},
            "moved": bool(presenters.moved_chip(message)),
            "reason": clean(presenters.list_reason(message), 160),
            "when": presenters.ago_short(message.received_at, self.now),
            "account": clean(mailbox.address, 160) if mailbox is not None else "",
            "provider": mailbox.provider if mailbox is not None else "",
        }
        if rank is not None:
            row["rank"] = rank
        return row

    def _add_card(self, kind: str, title: str, rows: list[dict[str, Any]], more: str = "") -> None:
        self.cards.append({"kind": kind, "title": title, "rows": rows, "more_href": more})

    def _summary_row(self, message: MessageRow, reason: str = "") -> dict[str, Any]:
        return {
            "message_id": message.id,
            "received": presenters.as_utc(message.received_at).isoformat(timespec="minutes"),
            "received_ago": presenters.humanize_ago(message.received_at, self.now),
            "verdict": presenters.verdict_chip(message).label,
            "moved_out_of_inbox": bool(presenters.moved_chip(message)),
            "reason": reason or presenters.list_reason(message),
            "trusted_sender_check": presenters.trust_outcome(message) or None,
            "email": untrusted(from_name=message.from_name, from_address=message.from_address, subject=message.subject),
        }

    async def list_messages(
        self, level: Any = "all", days: Any = 7, sender: Any = "", limit: Any = 10, mailbox: Any = None
    ) -> dict[str, Any]:
        level = _level(level)
        days_n = _int(days, 7, 1, MAX_DAYS)
        limit_n = _int(limit, 10, 1, MAX_LIST)
        where, _mailbox_id, problem = await self._scope(mailbox)
        if problem:
            return {"error": "unknown_mailbox", "message": problem}
        where.append(MessageRow.received_at >= self.now - timedelta(days=days_n))
        if level == "checked":
            where.append(queries.checked_clause())
        elif level == "suspicious":
            where.append(queries.flagged_clause())
        needle = clean(sender, 100).lower()
        if needle:
            where.append(
                or_(
                    func.lower(MessageRow.from_address).contains(needle, autoescape=True),
                    func.lower(func.coalesce(MessageRow.from_name, "")).contains(needle, autoescape=True),
                )
            )
        stmt = (
            select(MessageRow, MailboxRow)
            .join(MailboxRow, MailboxRow.id == MessageRow.mailbox_id)
            .where(*where)
            .order_by(MessageRow.received_at.desc(), MessageRow.id)
            .limit(limit_n)
        )
        pairs = [(r[0], r[1]) for r in (await self.session.execute(stmt)).all()]
        if pairs:
            self._add_card("messages", f"{len(pairs)} email{'s' if len(pairs) != 1 else ''}",
                           [self._card_row(m, mb) for m, mb in pairs])
        return {
            "filter": {"level": level, "days": days_n, "sender": needle or None},
            "count": len(pairs),
            "messages": [self._summary_row(m) for m, _mb in pairs],
        }

    # ------------------------------------------------------------------ new tools

    def _risk_order(self) -> list[Any]:
        rank = case(
            (MessageRow.quarantined.is_(True), 3),
            (MessageRow.level == "malicious", 3),
            (MessageRow.level == "suspicious", 2),
            (MessageRow.level == "unknown", 1),
            else_=0,
        )
        return [rank.desc(), func.coalesce(MessageRow.score, 0).desc(), MessageRow.received_at.desc(), MessageRow.id]

    async def search_messages(
        self, query: Any = "", level: Any = "all", mailbox: Any = None, days: Any = 30, sort: Any = "newest",
        limit: Any = 10,
    ) -> dict[str, Any]:
        from reddysec.web import search

        level = _level(level)
        days_n = _int(days, 30, 1, MAX_DAYS)
        limit_n = _int(limit, 10, 1, MAX_LIST)
        where, mailbox_id, problem = await self._scope(mailbox)
        if problem:
            return {"error": "unknown_mailbox", "message": problem}
        text = clean(query, 200)
        where.append(MessageRow.received_at >= self.now - timedelta(days=days_n))
        if level == "checked":
            where.append(queries.checked_clause())
        elif level == "suspicious":
            where.append(queries.flagged_clause())
        order = self._risk_order() if sort == "risk" else [MessageRow.received_at.desc(), MessageRow.id]
        stmt = (
            select(MessageRow, MailboxRow)
            .join(MailboxRow, MailboxRow.id == MessageRow.mailbox_id)
            .where(*where)
            .order_by(*order)
            .limit(search.MAX_SCAN)
        )
        pairs = [(r[0], r[1]) for r in (await self.session.execute(stmt)).all()]
        terms = search.terms_of(text)
        if terms:
            pairs = [(m, mb) for m, mb in pairs if all(search._matches(m, mb, t) for t in terms)]
        total = len(pairs)
        pairs = pairs[:limit_n]
        if pairs:
            title = f"{total} email{'s' if total != 1 else ''}" + (f" matching \u201c{text}\u201d" if text else "")
            more = "/messages?" + _urlencode({"q": text, "mailbox": mailbox_id or ""}) if text else ""
            self._add_card("ranked" if sort == "risk" else "messages", title,
                           [self._card_row(m, mb, i + 1 if sort == "risk" else None) for i, (m, mb) in enumerate(pairs)],
                           more)
        return {
            "filter": {"query": text or None, "level": level, "days": days_n, "sort": "risk" if sort == "risk" else "newest"},
            "total_matches": total,
            "count": len(pairs),
            "messages": [self._summary_row(m) for m, _mb in pairs],
        }

    async def top_suspicious(self, n: Any = 5, days: Any = 7, mailbox: Any = None) -> dict[str, Any]:
        n_ = _int(n, 5, 1, MAX_LIST)
        days_n = _int(days, 7, 1, MAX_DAYS)
        where, _mailbox_id, problem = await self._scope(mailbox)
        if problem:
            return {"error": "unknown_mailbox", "message": problem}
        where += [
            MessageRow.received_at >= self.now - timedelta(days=days_n),
            or_(MessageRow.level.in_(("suspicious", "malicious")), MessageRow.quarantined.is_(True)),
        ]
        stmt = (
            select(MessageRow, MailboxRow)
            .join(MailboxRow, MailboxRow.id == MessageRow.mailbox_id)
            .where(*where)
            .order_by(*self._risk_order())
            .limit(n_)
        )
        pairs = [(r[0], r[1]) for r in (await self.session.execute(stmt)).all()]
        if pairs:
            self._add_card("ranked", f"Most suspicious, last {days_n} day{'s' if days_n != 1 else ''}",
                           [self._card_row(m, mb, i + 1) for i, (m, mb) in enumerate(pairs)],
                           f"/messages?tab=suspicious&period={_period_for(days_n)}")
        return {
            "days": days_n,
            "count": len(pairs),
            "note": None if pairs else "Nothing suspicious or dangerous in this period.",
            "messages": [{**self._summary_row(m), "score_out_of_100": m.score} for m, _mb in pairs],
        }

    async def list_accounts(self) -> dict[str, Any]:
        boxes = await self.mailboxes()
        weeks = await queries.mailbox_week_counts(self.session, self.user, now=self.now)
        rows = []
        out = []
        for m in boxes:
            status = presenters.account_status(m)
            week = weeks.get(m.id, queries.MailboxWeek())
            out.append({
                "address": m.address,
                "provider": presenters.provider_label(m.provider),
                "status": status.chip.label,
                "problem": status.problem or None,
                "mode": "Hold" if m.mode == "hold" else "Scan",
                "last_checked": presenters.humanize_ago(m.last_sync_at, self.now) if m.last_sync_at else None,
                "this_week": {"checked": week.checked, "flagged": week.flagged},
                "selected": m.id == self.selected,
            })
            if m.status != "disconnected":
                rows.append({
                    "address": m.address, "provider": m.provider, "href": f"/messages?mailbox={m.id}",
                    "chip": {"label": status.chip.label, "tone": status.chip.tone},
                    "checked": week.checked, "flagged": week.flagged,
                })
        if rows:
            self.cards.append({"kind": "accounts", "title": "Your accounts", "rows": rows, "more_href": "/mailboxes"})
        return {"accounts": out, "count": len(out)}

    async def get_preferences(self) -> dict[str, Any]:
        from reddysec.store.models import AppLockRow
        from reddysec.web import preferences

        prefs = await preferences.get_preferences(self.session, self.user.id)
        boxes = await self.mailboxes()
        selected = next((m.address for m in boxes if m.id == self.selected), None)
        lock = await self.session.get(AppLockRow, self.user.id)
        return {
            "accounts_shown": "together" if prefs[preferences.INBOX_VIEW] == "together" else "separately",
            "looking_at": selected or "all inboxes",
            "app_lock": "on" if lock is not None else "off",
            "where_to_change": "Settings",
        }

    async def explain_link(self, message_id: Any = None, url_index: Any = 0) -> dict[str, Any]:
        found = await self.visible_message(message_id)
        if found is None:
            return NOT_FOUND
        message, _mailbox = found
        report = presenters.build_report(message, artifact_url=lambda ref: "", download_url=lambda ref: "")
        if not report.urls:
            return {"error": "no_links", "message": "We found no links in this email."}
        index = _int(url_index, 0, 0, len(report.urls) - 1)
        link = report.urls[index]
        copy = presenters.LINK_ADVICE_COPY[link.advice]
        host = urlsplit(link.final_url or link.url).hostname or ""
        self.cards.append({
            "kind": "link", "title": copy["title"], "rows": [], "more_href": "",
            "href": f"/messages/{message.id}#links", "url": clean(link.url, 200), "host": clean(host, 120),
            "chip": {"label": link.chip.label, "tone": link.chip.tone}, "advice": link.advice,
            "text": copy["text"], "reason": clean(link.advice_reason, 300), "downloads": clean(link.downloads, 300),
        })
        return {
            "message_id": message.id,
            "link_number": index,
            "links_in_email": len(report.urls),
            "verdict": link.chip.label,
            "advice": link.advice,
            "advice_in_words": copy["title"],
            "why": link.advice_reason or None,
            "downloads": link.downloads or None,
            "opened_in_sandbox": link.detonated,
            "link": untrusted(url=link.url, final_host=host),
        }

    async def get_message_report(self, message_id: Any = None) -> dict[str, Any]:
        found = await self.visible_message(message_id)
        if found is None:
            return NOT_FOUND
        message, mailbox = found
        report = presenters.build_report(message, artifact_url=lambda ref: "", download_url=lambda ref: "")
        reasons = await queries.latest_reasons(self.session, [message.id])
        feedback = None
        decision = report.client_decision
        if decision:
            given = reasons.get(message.id)
            feedback = {
                "decision": "marked safe" if decision == "safe" else "marked fake",
                "reason": presenters.reason_sentence(given) if given else "",
            }
        result: dict[str, Any] = {
            "message_id": message.id,
            "verdict": report.chip.label,
            "headline": report.headline,
            "score_out_of_100": report.score,
            "summary": report.summary,
            "status_note": report.note,
            "received": presenters.as_utc(message.received_at).isoformat(timespec="minutes"),
            "mailbox": mailbox.address,
            "email": untrusted(from_name=message.from_name, from_address=message.from_address, subject=message.subject),
            "sender_verified_by_google": report.verified_domain or None,
            "trust_check": _trust_check(message),
            "reasons": [{"title": r.title, "meaning": r.meaning, "what_to_do": r.todo, "severity": r.tone}
                        for r in report.reasons[:10]],
            "good_signs": [{"title": g.title, "meaning": g.meaning} for g in report.good_signs[:6]],
            "what_we_checked": [c.label for c in report.checks],
            "links": [
                {
                    "verdict": u.chip.label,
                    "opened_in_sandbox": u.detonated,
                    **untrusted(url=u.url, final_host=urlsplit(u.final_url or u.url).hostname or ""),
                }
                for u in report.urls[:10]
            ],
            "attachments": [{"verdict": a.chip.label, **untrusted(filename=a.filename)} for a in report.attachments[:10]],
            "persons_feedback": feedback,
            "possible_actions": {
                "mark_safe": report.can_mark_safe,
                "mark_fake": report.can_mark_fake,
                "recheck": report.can_recheck,
            },
        }
        return result

    async def get_stats(self, days: Any = 7, mailbox: Any = None) -> dict[str, Any]:
        days_n = _int(days, 7, 1, MAX_DAYS)
        since = self.now - timedelta(days=days_n)
        where, mailbox_id, problem = await self._scope(mailbox)
        if problem:
            return {"error": "unknown_mailbox", "message": problem}
        count = queries.count_messages
        checked = await count(self.session, self.user, verdict="checked", since=since, mailbox_id=mailbox_id)
        suspicious = await count(self.session, self.user, verdict="suspicious", since=since, mailbox_id=mailbox_id)
        quarantined = await count(self.session, self.user, quarantined=True, since=since, mailbox_id=mailbox_id)
        total = await count(self.session, self.user, since=since, mailbox_id=mailbox_id)
        flagged = (
            await self.session.execute(
                select(MessageRow.from_address, func.count(MessageRow.id))
                .join(MailboxRow, MailboxRow.id == MessageRow.mailbox_id)
                .where(
                    *where,
                    MessageRow.received_at >= since,
                    or_(MessageRow.level.in_(("suspicious", "malicious")), MessageRow.quarantined.is_(True)),
                )
                .group_by(MessageRow.from_address)
                .order_by(func.count(MessageRow.id).desc(), MessageRow.from_address)
                .limit(5)
            )
        ).all()
        return {
            "days": days_n,
            "inbox": next((m.address for m in await self.mailboxes() if m.id == mailbox_id), "all inboxes"),
            "total_seen": total,
            "checked_and_fine": checked,
            "suspicious": suspicious,
            "moved_out_of_inbox": quarantined,
            "top_flagged_senders": [{"emails": n, **untrusted(from_address=addr)} for addr, n in flagged],
        }

    async def list_trusted_and_blocked(self) -> dict[str, Any]:
        mailboxes = await queries.list_mailboxes(self.session, self.user)
        entries = await queries.list_sender_feedback(self.session, [m.id for m in mailboxes])
        return {
            "entries": [
                {
                    "decision": "trusted" if e.decision == "trusted" else "blocked",
                    "kind": e.scope,
                    "what_it_does": presenters.sender_entry(e).label,
                    **untrusted(value=e.value),
                }
                for e in entries[:50]
            ]
        }

    async def explain_signal(self, code: Any = "") -> dict[str, Any]:
        code = clean(code, 60)
        if not presenters.known_signal_code(code):
            return {"error": "unknown_code", "message": "We have no explanation for that code."}
        copy = presenters.signal_copy(SimpleNamespace(code=code, evidence={}, title="", detail=""))
        return {
            "code": code,
            "good_sign": code in presenters.GOOD_SIGN_COPY,
            "title": copy.title,
            "meaning": copy.meaning,
            "what_to_do": copy.todo,
        }

    # ------------------------------------------------------------------ proposals

    async def propose(self, kind: str, message_id: Any, reason: Any) -> ToolOutcome:
        found = await self.visible_message(message_id)
        if found is None:
            return ToolOutcome(dump(NOT_FOUND))
        message, _ = found
        report = presenters.build_report(message, artifact_url=lambda ref: "", download_url=lambda ref: "")
        allowed = {"mark_safe": report.can_mark_safe, "mark_fake": report.can_mark_fake,
                   "recheck": report.can_recheck}[kind]
        if not allowed:
            return ToolOutcome(dump({
                "proposal": "not_shown",
                "message": "That action is not available for this email right now (already done, or it is still being checked).",
            }))
        proposal = {
            "kind": kind,
            "message_id": message.id,
            "reason": clean(reason, 300),
            "sender": clean(message.from_name or message.from_address or "Unknown sender", 100),
            "address": clean(message.from_address, 160),
            "subject": clean(message.subject or "(no subject)", 160),
            "status": "open",
        }
        return ToolOutcome(
            dump({
                "proposal": "shown",
                "message": "A card with a button is now shown to the person. Nothing has changed; they decide.",
            }),
            proposal,
        )


def _trust_check(message: MessageRow) -> dict[str, Any] | None:
    """What the re-check of a trusted sender found: "confirmed" (checked again,
    safe) or "changed" (the sender is trusted but this email looks different)."""
    raw = message.verdict if isinstance(message.verdict, dict) else {}
    check = raw.get("trust_check")
    if not isinstance(check, dict):
        return None
    return {
        "trusted_by_client": bool(check.get("trusted_by_client")),
        "outcome": check.get("outcome"),
        **untrusted(reason=check.get("reason") or "", sender=check.get("value") or ""),
    }


def _urlencode(params: dict[str, Any]) -> str:
    from urllib.parse import urlencode

    return urlencode({k: v for k, v in params.items() if v})


def _known(arguments: dict[str, Any], handler: Any) -> dict[str, Any]:
    """Drop arguments the handler does not take, so a model that invents a
    parameter gets a normal answer instead of a crash."""
    import inspect

    params = inspect.signature(handler).parameters
    return {k: v for k, v in (arguments or {}).items() if k in params}

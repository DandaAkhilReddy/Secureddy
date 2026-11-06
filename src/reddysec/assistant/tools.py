"""The tools the assistant's model may call.

Every tool is read-only and scoped to the mail the signed-in user may read
(their own mailboxes, plus the principal's for a family or assistant
account: ``web.queries.visible_owner_ids``). Staff get no wider view here:
the assistant answers about *your* inbox. A message id that belongs to
someone else gets exactly the same "not found" as an id that does not exist.

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
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from reddysec.store.models import MailboxRow, MessageRow, UserRow
from reddysec.web import presenters, queries

from .llm import ToolSpec

MAX_RESULT_CHARS = 8000
MAX_LIST = 25
MAX_DAYS = 90
LEVEL_ARGS = ("all", "checked", "suspicious", "quarantine")
PROPOSAL_KINDS = {"propose_mark_safe": "mark_safe", "propose_mark_fake": "mark_fake", "propose_recheck": "recheck"}

_MESSAGE_ID = {"type": "string", "description": "The message_id from list_messages or get_message_report."}
_REASON = {"type": "string", "description": "One short plain sentence, shown to the person on the card."}

TOOL_SPECS: list[ToolSpec] = [
    ToolSpec(
        "list_messages",
        "List the person's checked emails, newest first, with our verdict and the main reason.",
        {
            "type": "object",
            "properties": {
                "level": {"type": "string", "enum": list(LEVEL_ARGS),
                          "description": "checked = looked fine; suspicious; quarantine = held back as dangerous."},
                "days": {"type": "integer", "minimum": 1, "maximum": MAX_DAYS, "description": "Look back this many days (default 7)."},
                "sender": {"type": "string", "description": "Part of the sender's name or address, e.g. 'walmart'."},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIST},
            },
        },
    ),
    ToolSpec(
        "get_message_report",
        "The full report for one email: verdict, plain reasons, what we checked, links, files and the person's own feedback.",
        {"type": "object", "properties": {"message_id": _MESSAGE_ID}, "required": ["message_id"]},
    ),
    ToolSpec(
        "get_stats",
        "Counts of checked, suspicious and quarantined email over a period, and the senders flagged most often.",
        {"type": "object", "properties": {"days": {"type": "integer", "minimum": 1, "maximum": MAX_DAYS}}},
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
        "Suggest marking an email as fake (moves it and future mail from the sender to Quarantine). Changes nothing: the person decides.",
        {"type": "object", "properties": {"message_id": _MESSAGE_ID, "reason": _REASON}, "required": ["message_id", "reason"]},
    ),
    ToolSpec(
        "propose_recheck",
        "Suggest checking an email again with today's rules. Changes nothing: the person decides.",
        {"type": "object", "properties": {"message_id": _MESSAGE_ID}, "required": ["message_id"]},
    ),
]


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


NOT_FOUND = {"error": "not_found", "message": "No email with that id in this person's mailboxes."}


class ToolBox:
    """Runs tool calls for one signed-in user inside one database session."""

    def __init__(self, session: AsyncSession, user: UserRow, *, now: datetime | None = None) -> None:
        self.session = session
        self.user = user
        self.now = now or datetime.now(UTC)

    async def run(self, name: str, arguments: dict[str, Any]) -> ToolOutcome:
        handler = {
            "list_messages": self.list_messages,
            "get_message_report": self.get_message_report,
            "get_stats": self.get_stats,
            "list_trusted_and_blocked": self.list_trusted_and_blocked,
            "explain_signal": self.explain_signal,
        }.get(name)
        if handler is not None:
            return ToolOutcome(dump(await handler(**_known(arguments, handler))))
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

    def _summary_row(self, message: MessageRow, reason: str = "") -> dict[str, Any]:
        return {
            "message_id": message.id,
            "received": presenters.as_utc(message.received_at).isoformat(timespec="minutes"),
            "received_ago": presenters.humanize_ago(message.received_at, self.now),
            "verdict": presenters.verdict_chip(message).label,
            "reason": reason or presenters.list_reason(message),
            "email": untrusted(from_name=message.from_name, from_address=message.from_address, subject=message.subject),
        }

    async def list_messages(self, level: Any = "all", days: Any = 7, sender: Any = "", limit: Any = 10) -> dict[str, Any]:
        level = level if level in LEVEL_ARGS else "all"
        days_n = _int(days, 7, 1, MAX_DAYS)
        limit_n = _int(limit, 10, 1, MAX_LIST)
        where = [
            MailboxRow.user_id.in_(queries.visible_owner_ids(self.user)),
            MessageRow.received_at >= self.now - timedelta(days=days_n),
        ]
        if level == "checked":
            where += [MessageRow.level == "safe", MessageRow.quarantined.is_(False)]
        elif level == "suspicious":
            where.append(MessageRow.level == "suspicious")
        elif level == "quarantine":
            where.append(MessageRow.quarantined.is_(True))
        needle = clean(sender, 100).lower()
        if needle:
            where.append(
                or_(
                    func.lower(MessageRow.from_address).contains(needle, autoescape=True),
                    func.lower(func.coalesce(MessageRow.from_name, "")).contains(needle, autoescape=True),
                )
            )
        stmt = (
            select(MessageRow)
            .join(MailboxRow, MailboxRow.id == MessageRow.mailbox_id)
            .where(*where)
            .order_by(MessageRow.received_at.desc(), MessageRow.id)
            .limit(limit_n)
        )
        rows = list((await self.session.execute(stmt)).scalars())
        return {
            "filter": {"level": level, "days": days_n, "sender": needle or None},
            "count": len(rows),
            "messages": [self._summary_row(m) for m in rows],
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

    async def get_stats(self, days: Any = 7) -> dict[str, Any]:
        days_n = _int(days, 7, 1, MAX_DAYS)
        since = self.now - timedelta(days=days_n)
        count = queries.count_messages
        checked = await count(self.session, self.user, level="safe", since=since)
        suspicious = await count(self.session, self.user, level="suspicious", since=since)
        quarantined = await count(self.session, self.user, quarantined=True, since=since)
        total = await count(self.session, self.user, since=since)
        flagged = (
            await self.session.execute(
                select(MessageRow.from_address, func.count(MessageRow.id))
                .join(MailboxRow, MailboxRow.id == MessageRow.mailbox_id)
                .where(
                    MailboxRow.user_id.in_(queries.visible_owner_ids(self.user)),
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
            "total_seen": total,
            "checked_and_fine": checked,
            "suspicious": suspicious,
            "in_quarantine": quarantined,
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
        if code not in presenters.SIGNAL_COPY and code not in presenters.GOOD_SIGN_COPY:
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


def _known(arguments: dict[str, Any], handler: Any) -> dict[str, Any]:
    """Drop arguments the handler does not take, so a model that invents a
    parameter gets a normal answer instead of a crash."""
    import inspect

    params = inspect.signature(handler).parameters
    return {k: v for k, v in (arguments or {}).items() if k in params}

"""Turns database rows into what the client reads.

All English the client sees about a verdict, a mailbox or an audit entry is
composed here, in Python, so it can be unit tested without rendering a
template. The reader is a non-technical person or their assistant: no codes,
no jargon, no hedging. Templates receive small frozen view objects and only
lay them out.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from reddysec.models import Role, Verdict
from reddysec.store.models import AuditLog, FeedbackReasonRow, MailboxRow, MessageRow, UserRow

from .queries import (
    FAKE_REASONS,
    IN_FLIGHT_STATES,
    PENDING_REQUEST_STATES,
    SAFE_REASONS,
    STATE_RESTORE_REQUESTED,
    STATE_REVIEWED,
    DailyCounts,
    SenderDecision,
    WeeklyCounts,
    reason_label,
    verified_sender_domain,
)


@dataclass(frozen=True)
class Chip:
    """A short status word with a visual tone: ``ok``, ``warn``, ``bad``,
    ``grey`` or ``accent``."""

    label: str
    tone: str


LEVEL_CHIPS: dict[str, Chip] = {
    "safe": Chip("Checked", "ok"),
    "suspicious": Chip("Suspicious", "warn"),
    "malicious": Chip("Quarantine", "bad"),
    "unknown": Chip("Could not check", "grey"),
}
CHECKING = Chip("Checking", "grey")


def verdict_chip(message: MessageRow) -> Chip:
    """The one word that answers "is this email safe?"."""
    if message.state in ("pending", "analyzing"):
        return CHECKING
    if message.state == "failed" and message.level is None:
        return LEVEL_CHIPS["unknown"]
    if message.quarantined and message.state != STATE_RESTORE_REQUESTED:
        return LEVEL_CHIPS["malicious"]
    return LEVEL_CHIPS.get(message.level or "unknown", LEVEL_CHIPS["unknown"])


def level_chip(level: str | None) -> Chip:
    return LEVEL_CHIPS.get(level or "unknown", LEVEL_CHIPS["unknown"])


MAILBOX_STATUS_CHIPS: dict[str, Chip] = {
    "active": Chip("Protected", "ok"),
    "paused": Chip("Paused", "grey"),
    "error": Chip("Needs attention", "warn"),
    "disconnected": Chip("Disconnected", "grey"),
}


def mailbox_status_chip(mailbox: MailboxRow) -> Chip:
    if mailbox.status == "active" and not mailbox.labels:
        return Chip("Setting up", "accent")
    return MAILBOX_STATUS_CHIPS.get(mailbox.status, Chip(mailbox.status.title(), "grey"))


def mode_chip(mailbox: MailboxRow) -> Chip:
    return Chip("Hold", "accent") if mailbox.mode == "hold" else Chip("Scan", "grey")


PROVIDER_LABELS = {
    "gmail": "Gmail",
    "yahoo": "Yahoo Mail",
    "icloud": "iCloud Mail",
    "outlook": "Outlook.com",
    "imap": "Other mailbox",
}


def provider_label(provider: str) -> str:
    return PROVIDER_LABELS.get(provider, provider.title())


LANE_LABELS = {
    "release_fast": "No links or files, so only the basic checks were needed",
    "trusted": "A sender you know, with a clean record",
    "detonate": "Opened in our sandbox before you saw it",
    "block": "Blocked on sight from the evidence alone",
}


def lane_label(lane: str | None) -> str:
    return LANE_LABELS.get(lane or "", "")


LANE_SHORT = {
    "release_fast": "Quick check",
    "trusted": "Known sender",
    "detonate": "Sandboxed",
    "block": "Blocked",
}


def lane_short(lane: str | None) -> str:
    """Two-word version for table columns."""
    return LANE_SHORT.get(lane or "", "")


STATE_NOTES = {
    STATE_RESTORE_REQUESTED: "You asked for this email back. It returns to your inbox within a minute.",
    "quarantine_requested": "You marked this email as fake. We are moving it to Quarantine now.",
    "relabel_safe_requested": "You marked this email as safe. Its label changes to Checked within a minute.",
    "rescore_requested": "We are checking this email again with our latest rules. Refresh in a minute.",
    STATE_REVIEWED: "One of our analysts has looked at this email.",
    "released_by_deadman": "Delivered without a full check because our service paused. We never hold mail hostage.",
    "failed": "We could not finish checking this email. Treat it with care or ask the concierge.",
}


def state_note(message: MessageRow) -> str:
    return STATE_NOTES.get(message.state, "")


# --------------------------------------------------------------------------
# People and time
# --------------------------------------------------------------------------


def first_name(user: UserRow) -> str:
    name = (user.display_name or "").strip()
    if not name:
        return user.login_email.split("@", 1)[0]
    return name.split()[0]


def as_utc(value: datetime) -> datetime:
    """SQLite hands back naive datetimes even for timezone-aware columns; every
    value we store is UTC, so treating naive as UTC is exact, not a guess."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def format_dt(value: datetime | None) -> str:
    if value is None:
        return ""
    value = as_utc(value)
    return f"{value.day} {value:%b %Y, %H:%M} UTC"


def humanize_ago(value: datetime | None, now: datetime | None = None) -> str:
    if value is None:
        return ""
    value = as_utc(value)
    delta = (now or datetime.now(UTC)) - value
    seconds = int(delta.total_seconds())
    if seconds < 0:
        return format_dt(value)
    if seconds < 60:
        return "just now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    days = hours // 24
    if days < 7:
        return f"{days} day{'s' if days != 1 else ''} ago"
    return format_dt(value)


def ago_short(value: datetime | None, now: datetime | None = None) -> str:
    """Compact relative time for dense lists: "just now", "5 min ago", "2 h ago", "3 d ago"."""
    if value is None:
        return ""
    value = as_utc(value)
    seconds = int(((now or datetime.now(UTC)) - value).total_seconds())
    if seconds < 0:
        return short_date(value)
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60} min ago"
    if seconds < 86400:
        return f"{seconds // 3600} h ago"
    if seconds < 7 * 86400:
        return f"{seconds // 86400} d ago"
    return short_date(value)


def short_date(value: datetime | None) -> str:
    """"6 Nov" (same year) or "6 Nov 2025"."""
    if value is None:
        return ""
    value = as_utc(value)
    if value.year == datetime.now(UTC).year:
        return f"{value.day} {value:%b}"
    return f"{value.day} {value:%b %Y}"


def initials(name: str | None, address: str | None = None) -> str:
    """Two letters for the sender avatar: "Walmart.com" -> "W", "Ana Ruiz" -> "AR"."""
    words = [w for w in (name or "").replace(".", " ").replace("_", " ").split() if w[:1].isalnum()]
    if len(words) >= 2:
        return (words[0][0] + words[1][0]).upper()
    if words:
        return words[0][0].upper()
    local = (address or "").split("@", 1)[0]
    return (local[:1] or "?").upper()


AVATAR_TONES = 6


def avatar_tone(seed: str | None) -> str:
    """A stable, quiet colour class per sender so the list is easy to scan."""
    total = sum(ord(ch) for ch in (seed or "").lower())
    return f"av-{total % AVATAR_TONES}"


# --------------------------------------------------------------------------
# Dashboard copy
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Hero:
    """The big line at the top of the dashboard."""

    title: str
    tone: str  # ok | warn | bad | grey


def hero(counts: WeeklyCounts, *, has_mailboxes: bool) -> Hero:
    if not has_mailboxes:
        return Hero("Let's get your inbox protected", "grey")
    need = counts.suspicious + counts.quarantined
    if counts.quarantined and need:
        return Hero(f"{_n(need, 'email')} need{'s' if need == 1 else ''} a look", "bad")
    if need:
        return Hero(f"{_n(need, 'email')} need{'s' if need == 1 else ''} a look", "warn")
    return Hero("Your inbox is safe", "ok")


@dataclass(frozen=True)
class Sparkline:
    """A tiny server-rendered line chart. Coordinates are SVG user units in a
    ``0 0 width height`` view box; ``label`` is the text alternative."""

    points: str
    area: str
    last_x: str
    last_y: str
    label: str
    width: int
    height: int


def sparkline(values: tuple[int, ...] | list[int], days: tuple[datetime, ...] = (), *,
              width: int = 112, height: int = 32, pad: int = 3) -> Sparkline:
    vals = list(values) or [0]
    top = max(vals) or 1
    step = (width - 2 * pad) / max(1, len(vals) - 1)
    coords = [(pad + i * step, height - pad - (v / top) * (height - 2 * pad)) for i, v in enumerate(vals)]
    pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in coords)
    area = f"M{coords[0][0]:.1f},{height - pad} L" + " L".join(f"{x:.1f},{y:.1f}" for x, y in coords)
    area += f" L{coords[-1][0]:.1f},{height - pad} Z"
    if days and len(days) == len(vals):
        detail = ", ".join(f"{d:%a} {v}" for d, v in zip(days, vals, strict=True))
    else:
        detail = ", ".join(str(v) for v in vals)
    return Sparkline(pts, area, f"{coords[-1][0]:.1f}", f"{coords[-1][1]:.1f}",
                     f"Last {len(vals)} days: {detail}", width, height)


def _n(count: int, noun: str) -> str:
    return f"{count} {noun}{'' if count == 1 else 's'}"


def weekly_sentence(counts: WeeklyCounts, *, has_mailboxes: bool) -> str:
    """The first sentence on the dashboard. It must be true, short, and calm."""
    if not has_mailboxes:
        return "Connect a mailbox and we start checking your email within a minute."
    if counts.checked == 0:
        return "We have not seen any new email this week. Everything is quiet."
    parts = [f"We checked {_n(counts.checked, 'email')} this week."]
    if counts.quarantined:
        verb = "was" if counts.quarantined == 1 else "were"
        where = "is" if counts.quarantined == 1 else "are"
        parts.append(f"{counts.quarantined} {verb} dangerous and {where} in Quarantine.")
    if counts.suspicious:
        pronoun = "it" if counts.suspicious == 1 else "them"
        parts.append(f"{counts.suspicious} looked suspicious, so we marked {pronoun} for care.")
    if not counts.quarantined and not counts.suspicious:
        parts.append("Nothing dangerous was found.")
    return " ".join(parts)


@dataclass(frozen=True)
class StatCard:
    """A clickable number on the dashboard."""

    label: str
    count: int
    hint: str
    href: str
    tone: str  # ok | warn | bad
    aria: str
    spark: Sparkline | None = None


def stat_cards(counts: WeeklyCounts, daily: DailyCounts | None = None) -> list[StatCard]:
    """The three numbers on the home page. Each one opens the matching list.
    The lists show the same 7 days the numbers count; ``daily`` adds a
    sparkline of those days."""

    def hint(n: int) -> str:
        return "Tap to see why" if n else "Nothing here this week"

    def spark(values: tuple[int, ...] | None) -> Sparkline | None:
        return sparkline(values, daily.days) if daily is not None and values is not None else None

    return [
        StatCard("Checked", counts.safe, "Looked fine. Tap to see them" if counts.safe else hint(0),
                 "/messages?level=safe&days=7", "ok", f"{_n(counts.safe, 'email')} checked and fine this week",
                 spark(daily.safe if daily else None)),
        StatCard("Suspicious", counts.suspicious, hint(counts.suspicious),
                 "/messages?level=suspicious&days=7", "warn",
                 f"{counts.suspicious} suspicious this week. See which emails and why",
                 spark(daily.suspicious if daily else None)),
        StatCard("In Quarantine", counts.quarantined, hint(counts.quarantined),
                 "/messages?filter=quarantined&days=7", "bad",
                 f"{counts.quarantined} in Quarantine this week. See which emails and why",
                 spark(daily.quarantined if daily else None)),
    ]


@dataclass(frozen=True)
class SenderEntryView:
    id: str
    mailbox_id: str
    value: str
    trusted: bool
    label: str  # one plain line saying what the entry does


def sender_entry(entry: Any) -> SenderEntryView:
    trusted = entry.decision == "trusted"
    if trusted and entry.scope == "domain":
        label = f"Email that Google confirms is from {entry.value} is marked Checked."
    elif trusted and entry.authenticated:
        label = "Trusted when Google confirms it is really them. Links are still opened in our sandbox."
    elif trusted:
        label = "Trusted a little. It was not verified by Google, so we still check its links."
    elif entry.scope == "domain" or entry.authenticated:
        label = "Goes straight to Quarantine."
    else:
        label = "Goes to Quarantine unless Google confirms it is really them."
    return SenderEntryView(entry.id, entry.mailbox_id, entry.value, trusted, label)


@dataclass(frozen=True)
class Tab:
    key: str
    label: str
    href: str
    current: bool


MESSAGE_TABS: tuple[tuple[str, str], ...] = (
    ("all", "All"),
    ("safe", "Checked"),
    ("suspicious", "Suspicious"),
    ("quarantined", "Quarantine"),
)

EMPTY_STATES: dict[str, tuple[str, str]] = {
    "all": ("Nothing to show", "No email matches these filters yet."),
    "safe": ("Nothing to show", "No email was marked Checked in this period."),
    "suspicious": ("Nothing suspicious", "No email looked suspicious in this period. Nothing to do."),
    "quarantined": ("Quarantine is empty", "We did not need to hold back any email in this period."),
    "malicious": ("Nothing to show", "No dangerous email in this period."),
    "unknown": ("Nothing to show", "We finished checking every email in this period."),
}


def message_tabs(current: str, *, days: int | None, mailbox: str | None) -> list[Tab]:
    tabs = []
    for key, label in MESSAGE_TABS:
        params = []
        if key in ("safe", "suspicious"):
            params.append(f"level={key}")
        elif key == "quarantined":
            params.append("filter=quarantined")
        if days:
            params.append(f"days={days}")
        if mailbox:
            params.append(f"mailbox={mailbox}")
        href = "/messages" + ("?" + "&".join(params) if params else "")
        tabs.append(Tab(key, label, href, key == current))
    return tabs


# --------------------------------------------------------------------------
# Audit copy
# --------------------------------------------------------------------------

ACTION_PHRASES = {
    "login": "Signed in",
    "logout": "Signed out",
    "mailbox_connected": "Connected a mailbox",
    "mailbox_disconnected": "Disconnected a mailbox",
    "mailbox_paused": "Paused protection",
    "mailbox_resumed": "Resumed protection",
    "mode_changed": "Changed the protection mode",
    "restore_requested": "Asked for an email to be released to the inbox",
    "review_requested": "Asked the concierge to review an email",
    "client_feedback": "Gave feedback on a verdict",
    "concierge_reviewed": "Analyst reviewed an email",
    "verdict_override": "Analyst changed a verdict",
    "totp_enabled": "Turned on 2-step sign-in",
    "totp_disabled": "Turned off 2-step sign-in",
    "password_set": "Set a sign-in password",
    "sender_trusted": "Marked a sender as safe",
    "sender_blocked": "Marked a sender as fake",
    "sender_feedback_removed": "Removed a trusted or blocked sender",
    "rescore_requested": "Asked us to check an email again",
    "recheck_requested": "Asked us to re-check recent email",
    "rescore": "Checked an email again",
    "rescore_failed": "Could not check an email again",
    "client_quarantine": "Moved an email to Quarantine for you",
    "client_mark_safe": "Marked an email Checked for you",
    "assistant_question": "Asked Secureddy a question",
}


def action_phrase(action: str) -> str:
    return ACTION_PHRASES.get(action, action.replace("_", " ").capitalize())


ROLE_LABELS = {
    Role.PRINCIPAL.value: "Account owner",
    Role.FAMILY.value: "Family member",
    Role.ASSISTANT.value: "Your assistant",
    Role.CONCIERGE.value: "Secureddy analyst",
    Role.ADMIN.value: "Secureddy staff",
    "system": "Secureddy (automatic)",
}


def actor_label(entry: AuditLog, viewer: UserRow) -> str:
    if entry.actor_id and entry.actor_id == viewer.id:
        return "You"
    return ROLE_LABELS.get(entry.actor_role, entry.actor_role.replace("_", " ").title())


def detail_phrase(entry: AuditLog) -> str:
    """One quiet line of context under an audit row; never raw JSON."""
    d = entry.details or {}
    if entry.action == "mode_changed":
        return f"{str(d.get('from', '')).title()} to {str(d.get('to', '')).title()}".strip()
    if entry.action == "verdict_override":
        return f"{level_chip(d.get('from')).label} to {level_chip(d.get('to')).label}"
    if entry.action in ("review_requested", "concierge_reviewed") and d.get("note"):
        return str(d["note"])
    if entry.action == "client_feedback":
        return "Marked as fine" if d.get("feedback") == "fine" else "Marked as bad"
    if entry.action in ("sender_trusted", "sender_blocked") and d.get("value"):
        decision = "safe" if entry.action == "sender_trusted" else "fake"
        why = _reason_words(decision, str(d.get("reason_code") or ""), str(d.get("reason") or ""))
        return f"{d['value']} · {why}" if why else str(d["value"])
    if entry.action == "sender_feedback_removed" and d.get("value"):
        return str(d["value"])
    if entry.action == "sender_feedback_removed":
        return str(entry.target or "")
    if entry.action == "rescore" and d.get("to"):
        return f"{level_chip(d.get('from')).label} to {level_chip(d.get('to')).label}"
    if entry.action == "recheck_requested":
        return f"{_n(int(d.get('count', 0)), 'email')} from the last {d.get('days', 7)} days"
    if entry.action == "login" and d.get("method"):
        return {"google": "With Google", "password": "With a password", "dev": "Developer sign-in"}.get(
            str(d["method"]), ""
        )
    if entry.action == "mailbox_connected" and d.get("provider"):
        return provider_label(str(d["provider"]))
    return ""


# --------------------------------------------------------------------------
# The report
# --------------------------------------------------------------------------


def bar_class(weight: int) -> str:
    """Width class for the quiet evidence bar, in steps of ten. Classes instead
    of a style attribute keep our templates free of inline CSS."""
    clamped = max(0, min(100, abs(int(weight))))
    step = min(100, int((clamped + 5) // 10) * 10)  # round half up, not banker's rounding
    if weight != 0 and step == 0:
        step = 10  # any evidence at all gets a visible sliver
    return f"bar-w{step}"


@dataclass(frozen=True)
class SignalView:
    title: str
    detail: str
    weight: int
    bar: str
    trust: bool  # negative weights express trust, drawn in the calm colour


@dataclass(frozen=True)
class UrlView:
    url: str
    final_url: str | None
    chip: Chip
    screenshot_url: str | None
    detonated: bool
    signals: tuple[SignalView, ...]


@dataclass(frozen=True)
class AttachmentView:
    filename: str
    chip: Chip
    safe_copy_url: str | None
    signals: tuple[SignalView, ...]


@dataclass(frozen=True)
class ReasonCard:
    """One finding, in three plain lines."""

    title: str
    meaning: str
    todo: str
    tone: str  # bad | warn | info
    weight: int


@dataclass(frozen=True)
class GoodSign:
    title: str
    meaning: str


@dataclass(frozen=True)
class CheckItem:
    """A line of the "What we checked" list. ``ok``: True (passed), False
    (failed) or None (could not tell / nothing to check)."""

    ok: bool | None
    label: str


@dataclass(frozen=True)
class ReportView:
    chip: Chip
    summary: str
    lane: str
    score: int | None
    signals: tuple[SignalView, ...]
    urls: tuple[UrlView, ...]
    attachments: tuple[AttachmentView, ...]
    needs_human_review: bool
    analyzed_at: datetime | None
    engine_version: str
    override_note: str
    verdict_available: bool
    note: str
    can_release: bool
    artifact_refs: frozenset[str] = field(default_factory=frozenset)
    headline: str = ""
    reasons: tuple[ReasonCard, ...] = ()
    good_signs: tuple[GoodSign, ...] = ()
    checks: tuple[CheckItem, ...] = ()
    verified_domain: str = ""
    client_decision: str = ""
    can_mark_safe: bool = False
    can_mark_fake: bool = False
    can_recheck: bool = False
    previous_level: str = ""


ArtifactUrl = Callable[[str], str]


def _signals(items: list[Any]) -> tuple[SignalView, ...]:
    out = []
    for s in sorted(items, key=lambda s: -s.weight):
        out.append(SignalView(s.title, s.detail, s.weight, bar_class(s.weight), s.weight < 0))
    return tuple(out)


def parse_verdict(raw: dict[str, Any] | None) -> Verdict | None:
    """The verdict JSON is written by another process; a schema drift must
    degrade to "still checking", never to a 500 on the client's report."""
    if not raw:
        return None
    try:
        return Verdict.model_validate(raw)
    except ValidationError:
        return None


def artifact_refs(raw: dict[str, Any] | None) -> frozenset[str]:
    """Every artifact reference a message's verdict points at. The artifact
    route only serves refs in this set, so a message id doubles as the
    capability to view its screenshots and safe copies."""
    refs: set[str] = set()
    verdict = parse_verdict(raw)
    if verdict is None:
        return frozenset()
    for u in verdict.urls:
        if u.screenshot_ref:
            refs.add(u.screenshot_ref)
    for a in verdict.attachments:
        if a.safe_copy_ref:
            refs.add(a.safe_copy_ref)
    return frozenset(refs)


HEADLINES = {
    "checking": "We are still checking this email.",
    "quarantine": "This email is dangerous. We moved it to Quarantine.",
    "malicious": "This email is dangerous.",
    "suspicious": "Be careful with this email.",
    "safe": "This email looks safe.",
    "unknown": "We could not finish checking this email.",
}


def headline(message: MessageRow) -> str:
    """The big sentence at the top of the report."""
    if message.state in IN_FLIGHT_STATES:
        return HEADLINES["checking"]
    decision = client_decision(message)
    if decision == "safe" and message.level == "safe":
        return "You marked this email as safe."
    if decision == "fake":
        return "You marked this email as fake. It is in Quarantine." if message.quarantined else (
            "You marked this email as fake."
        )
    if message.quarantined and message.state != STATE_RESTORE_REQUESTED:
        return HEADLINES["quarantine"]
    return HEADLINES.get(message.level or "unknown", HEADLINES["unknown"])


def client_decision(message: MessageRow) -> str:
    raw = message.verdict if isinstance(message.verdict, dict) else {}
    d = raw.get("client_decision")
    return str(d.get("decision", "")) if isinstance(d, dict) else ""


def _tone(weight: int) -> str:
    if weight >= 60:
        return "bad"
    if weight >= 30:
        return "warn"
    return "info"


def _strongest_by_code(signals: list[Any]) -> list[Any]:
    best: dict[str, Any] = {}
    for s in signals:
        if s.code not in best or abs(s.weight) > abs(best[s.code].weight):
            best[s.code] = s
    return list(best.values())


def reason_cards(verdict: Verdict, *, sender: str, verified_domain: str) -> tuple[ReasonCard, ...]:
    """"Why we think this": every finding that counted, strongest first, once per kind."""
    items = [s for s in _all_verdict_signals(verdict) if s.weight > 0 and s.code not in GOOD_SIGN_CODES]
    cards = []
    for s in sorted(_strongest_by_code(items), key=lambda s: -s.weight):
        copy = signal_copy(s, sender=sender, verified_domain=verified_domain)
        cards.append(ReasonCard(copy.title, copy.meaning, copy.todo, _tone(s.weight), s.weight))
    return tuple(cards)


def good_signs(verdict: Verdict, *, sender: str, verified_domain: str) -> tuple[GoodSign, ...]:
    items = [
        s for s in _all_verdict_signals(verdict)
        if s.code in GOOD_SIGN_CODES or (s.weight < 0 and s.code not in SIGNAL_COPY)
    ]
    signs = []
    for s in _strongest_by_code(items):
        if s.code == "history.client_trusted" and s.weight == 0:
            continue  # trust was withheld because of a serious finding
        copy = signal_copy(s, sender=sender, verified_domain=verified_domain)
        signs.append(GoodSign(copy.title, copy.meaning))
    return tuple(signs)


def _all_verdict_signals(verdict: Verdict) -> list[Any]:
    """Message-level signals already include every link's and file's signals."""
    return list(verdict.signals)


def checks(verdict: Verdict, verified_domain: str) -> tuple[CheckItem, ...]:
    """"What we checked", as a short list of facts."""
    codes = {s.code for s in verdict.signals}
    items: list[CheckItem] = []
    if verified_domain:
        items.append(CheckItem(True, f"Google confirmed this really came from {verified_domain}."))
    elif codes & {"auth.dmarc_fail", "auth.dkim_fail", "auth.spf_fail"}:
        items.append(CheckItem(False, "Google could not confirm who sent this. It may be forged."))
    else:
        items.append(CheckItem(None, "Google could not confirm who sent this."))
    total = len(verdict.urls)
    opened = sum(1 for u in verdict.urls if u.detonated)
    if total == 0:
        items.append(CheckItem(None, "This email has no links."))
    elif opened:
        items.append(CheckItem(True, f"We opened {opened} of its {_n(total, 'link')} in our sandbox first."))
    else:
        items.append(CheckItem(True, f"We checked its {_n(total, 'link')} without opening them."))
    files = len(verdict.attachments)
    if files:
        items.append(CheckItem(True, f"We checked {_n(files, 'attached file')}."))
    else:
        items.append(CheckItem(None, "No files are attached."))
    return tuple(items)


def build_report(message: MessageRow, *, artifact_url: ArtifactUrl, download_url: ArtifactUrl) -> ReportView:
    """``artifact_url`` serves a screenshot inline; ``download_url`` serves a
    sanitized attachment copy as a download. Both are closures over the
    message id so the artifact route can check the reference belongs to it."""
    verdict = parse_verdict(message.verdict)
    chip = verdict_chip(message)
    busy = message.state in IN_FLIGHT_STATES or message.state in PENDING_REQUEST_STATES
    can_release = bool(message.quarantined) and message.state != STATE_RESTORE_REQUESTED
    decision = client_decision(message)
    if verdict is None:
        summary = (
            "We are still checking this email. Links and files are being opened in our sandbox first."
            if message.state in ("pending", "analyzing")
            else "We could not produce a full report for this email. Treat it with care or ask the concierge."
        )
        return ReportView(
            chip=chip,
            summary=summary,
            lane=lane_label(message.lane),
            score=message.score,
            signals=(),
            urls=(),
            attachments=(),
            needs_human_review=False,
            analyzed_at=message.analyzed_at,
            engine_version="",
            override_note="",
            verdict_available=False,
            note=state_note(message),
            can_release=can_release,
            headline=headline(message),
            client_decision=decision,
            can_recheck=not busy and message.state not in ("pending", "analyzing"),
        )

    urls = tuple(
        UrlView(
            url=u.url,
            final_url=u.final_url if u.final_url and u.final_url != u.url else None,
            chip=level_chip(u.level.value),
            screenshot_url=artifact_url(u.screenshot_ref) if u.screenshot_ref else None,
            detonated=u.detonated,
            signals=_signals(u.signals),
        )
        for u in verdict.urls
    )
    attachments = tuple(
        AttachmentView(
            filename=a.filename,
            chip=level_chip(a.level.value),
            safe_copy_url=download_url(a.safe_copy_ref) if a.safe_copy_ref else None,
            signals=_signals(a.signals),
        )
        for a in verdict.attachments
    )
    raw = message.verdict or {}
    override = raw.get("override") if isinstance(raw.get("override"), dict) else None
    previous = raw.get("previous") if isinstance(raw.get("previous"), dict) else None
    verified = verified_sender_domain(message)
    sender = (message.from_address or "").lower()
    return ReportView(
        chip=chip,
        summary=verdict.summary,
        lane=lane_label(verdict.lane.value),
        score=verdict.score,
        signals=_signals(verdict.signals),
        urls=urls,
        attachments=attachments,
        needs_human_review=verdict.needs_human_review,
        analyzed_at=verdict.analyzed_at,
        engine_version=verdict.engine_version,
        override_note=str(override.get("note", "")) if override else "",
        verdict_available=True,
        note=state_note(message),
        can_release=can_release,
        artifact_refs=artifact_refs(message.verdict),
        headline=headline(message),
        reasons=reason_cards(verdict, sender=sender, verified_domain=verified),
        good_signs=good_signs(verdict, sender=sender, verified_domain=verified),
        checks=checks(verdict, verified),
        verified_domain=verified,
        client_decision=decision,
        can_mark_safe=not busy and not (decision == "safe" and message.level == "safe"),
        can_mark_fake=not busy and decision != "fake",
        can_recheck=not busy,
        previous_level=str(previous.get("level", "")) if previous else "",
    )


def list_reason(message: MessageRow) -> str:
    """One plain line under each row of the message list: the main reason."""
    if message.state in IN_FLIGHT_STATES:
        return "Still checking."
    verdict = parse_verdict(message.verdict)
    if verdict is None:
        return state_note(message) or ""
    sender = (message.from_address or "").lower()
    verified = verified_sender_domain(message)
    decision = client_decision(message)
    if decision == "safe" and message.level == "safe":
        return "You marked this sender as safe."
    if decision == "fake":
        return "You marked this as fake."
    if message.level == "safe" and not message.quarantined:
        return f"Google confirmed it came from {verified}." if verified else "Nothing wrong found."
    positives = [s for s in verdict.signals if s.weight > 0 and s.code not in GOOD_SIGN_CODES]
    if not positives:
        return "We could not finish checking it." if message.level == "unknown" else "Several small warning signs."
    top = max(positives, key=lambda s: s.weight)
    return short_reason(top, sender=sender, verified_domain=verified) + "."


# --------------------------------------------------------------------------
# Reasons the client gave ("Not suspicious?" / "This is fake")
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ReasonChoice:
    code: str
    label: str


SAFE_REASON_CHOICES = tuple(ReasonChoice(k, v) for k, v in SAFE_REASONS.items())
FAKE_REASON_CHOICES = tuple(ReasonChoice(k, v) for k, v in FAKE_REASONS.items())


def _reason_words(decision: str, code: str, text: str) -> str:
    label = reason_label(decision, code) if code != "other" else ""
    if label and text:
        return f"{label}. {text}"
    return text or label


def reason_sentence(row: FeedbackReasonRow) -> str:
    """The client's reason in one line: "I ordered this / expected it" plus
    their own words, if any. Rendered escaped by the templates."""
    return _reason_words(row.decision, row.reason_code or "", row.reason_text or "")


def decision_note(row: FeedbackReasonRow | None, decision: str) -> str:
    """"You marked this safe on 6 Nov: I ordered this / expected it." for the report."""
    if row is None or row.decision != decision:
        return ""
    words = reason_sentence(row)
    what = "safe" if decision == "safe" else "fake"
    when = short_date(row.created_at)
    if not words:
        return f"You marked this {what} on {when}."
    return f"You marked this {what} on {when}: {words.rstrip('.')}."


def decision_flash(result: SenderDecision, *, sender: str) -> str:
    """What the client reads right after "This is safe" / "This is fake"."""
    what = result.value
    if result.decision == "trusted":
        if result.scope == "domain":
            future = (
                f"From now on, emails that Google confirms are from {what} will be marked Checked. "
                "We will still warn you if one carries a dangerous link or file."
            )
        elif result.authenticated and result.shared_platform:
            domain = what.rsplit("@", 1)[-1]
            future = (
                f"Many people send email from {domain}, so we will trust only {what}, and only when Google "
                "confirms it is really them. We will still open their links in our sandbox."
            )
        elif result.authenticated:
            future = f"We'll trust messages from {what} when Google confirms they are really from them."
        else:
            future = (
                "We'll trust messages from this address. Because it wasn't verified by Google, "
                "we'll still check its links."
            )
    else:
        if result.scope == "domain":
            future = f"From now on, email from {what} goes straight to Quarantine."
        elif result.authenticated:
            future = f"From now on, email from {what} goes straight to Quarantine."
        else:
            future = (
                f"From now on, email that claims to be from {what} but is not confirmed by Google goes "
                "straight to Quarantine."
            )
    now = {
        "restore": " We are moving this email back to your inbox and marking it Checked.",
        "relabel": " We are changing this email's label to Checked.",
        "quarantine": " We are moving this email to Quarantine now.",
        "none": "",
    }[result.message_action]
    return future + now


def message_summary(message: MessageRow) -> str:
    """Short summary for tables and the JSON API."""
    raw = message.verdict or {}
    summary = raw.get("summary") if isinstance(raw, dict) else None
    if isinstance(summary, str) and summary:
        return summary
    return "Still checking." if message.state in ("pending", "analyzing") else ""


@dataclass(frozen=True)
class MessageListRow:
    message: MessageRow
    mailbox: MailboxRow
    chip: Chip
    summary: str
    reason: str = ""
    initials: str = ""
    avatar: str = "av-0"
    can_mark_safe: bool = False
    can_mark_fake: bool = False


def row_actions(message: MessageRow) -> tuple[bool, bool]:
    """(can say "Not suspicious?", can say "This is fake") for a list row.
    Offered on every message that is not plainly Checked, unless the worker
    is busy with it or the client already said the same thing."""
    busy = message.state in IN_FLIGHT_STATES or message.state in PENDING_REQUEST_STATES
    if busy or not (message.from_address or "").strip():
        return False, False
    decision = client_decision(message)
    flagged = message.quarantined or (message.level or "unknown") != "safe"
    # A quarantined email is already held back; "This is fake" stays on its report.
    return (flagged and decision != "safe"), (flagged and decision != "fake" and not message.quarantined)


def list_rows(pairs: list[tuple[MessageRow, MailboxRow]]) -> list[MessageListRow]:
    rows = []
    for m, mb in pairs:
        safe, fake = row_actions(m)
        rows.append(
            MessageListRow(
                m, mb, verdict_chip(m), message_summary(m), list_reason(m),
                initials(m.from_name, m.from_address), avatar_tone(m.from_address or m.from_name), safe, fake,
            )
        )
    return rows


@dataclass(frozen=True)
class ImapProvider:
    """A consumer IMAP provider and the plain-English steps to get an app
    password. ``host`` is empty for the generic entry, which asks the user."""

    key: str
    label: str
    host: str
    port: int
    steps: tuple[str, ...]


IMAP_PROVIDERS: dict[str, ImapProvider] = {
    "yahoo": ImapProvider(
        "yahoo",
        "Yahoo Mail",
        "imap.mail.yahoo.com",
        993,
        (
            "Sign in to Yahoo and open Account Security (login.yahoo.com/account/security).",
            "Choose Generate app password, then Other app. Name it Secureddy.",
            "Copy the 16-character password Yahoo shows you and paste it below. Your normal Yahoo password is not shared with us and does not change.",
        ),
    ),
    "icloud": ImapProvider(
        "icloud",
        "iCloud Mail",
        "imap.mail.me.com",
        993,
        (
            "Sign in at account.apple.com with your Apple Account.",
            "Open Sign-In and Security, then App-Specific Passwords, and choose Generate. Label it Secureddy.",
            "Copy the password Apple shows you and paste it below. Two-factor authentication must be on for your Apple Account.",
        ),
    ),
    "outlook": ImapProvider(
        "outlook",
        "Outlook.com",
        "outlook.office365.com",
        993,
        (
            "Sign in at account.microsoft.com/security and open Advanced security options.",
            "Under App passwords choose Create a new app password. Two-step verification must be on.",
            "Copy the password and paste it below. In Outlook.com settings, make sure Sync email allows IMAP.",
        ),
    ),
    "imap": ImapProvider(
        "imap",
        "Other mailbox",
        "",
        993,
        (
            "Ask your email provider for their IMAP server name and port (usually 993).",
            "If they offer app passwords, create one named Secureddy and use it here. Otherwise your normal password works, but an app password is safer.",
        ),
    ),
}


# --------------------------------------------------------------------------
# Plain-English copy for every signal the engine emits
# --------------------------------------------------------------------------
#
# Three short lines per finding, written for someone who is not technical:
#   title   what we saw, in a few words
#   meaning what that means for them, one sentence
#   todo    what to do about it, one sentence ("" for good signs)
# Placeholders are filled from the signal's evidence: {brand} {host} {domain}
# {filename} {shown} {days} {sender} {value}. Missing values read naturally.


@dataclass(frozen=True)
class SignalCopy:
    title: str
    meaning: str
    todo: str = ""


_DONT_CLICK = "Do not click its links or open its files. If you need to, use the Reading Room."
_CALL = "Before you act, call the person on a number you already have, not one from this email."
_IGNORE_OK = "On its own this is minor; we mention it so you know we looked."

SIGNAL_COPY: dict[str, SignalCopy] = {
    # ---- links (static)
    "url.known_bad": SignalCopy(
        "A link goes to a known dangerous website",
        "Security services already list {host} as used in attacks.",
        "Do not open this link. Delete the email or leave it in Quarantine.",
    ),
    "url.lookalike": SignalCopy(
        "A link goes to a fake copy of {domain}",
        "{host} is spelled to look like {domain}, but it is a different website.",
        "Do not sign in there. Go to {domain} by typing it yourself.",
    ),
    "url.display_mismatch": SignalCopy(
        "A link does not go where its text says",
        "The text shows {shown}, but clicking it opens {host}.",
        "Hover over links before you click, or use the Reading Room.",
    ),
    "url.ip_literal": SignalCopy(
        "A link points to a bare server number",
        "Real companies use website names. A raw number like {host} often means a hacked or throwaway server.",
        _DONT_CLICK,
    ),
    "url.dangerous_scheme": SignalCopy(
        "A link carries hidden code",
        "Instead of pointing to a website, the link would run code in your browser.",
        _DONT_CLICK,
    ),
    "url.punycode": SignalCopy(
        "A link uses look-alike letters",
        "The address {host} uses foreign letters that can look like normal ones.",
        "Do not trust what the address seems to say. Use the Reading Room.",
    ),
    "url.shortener": SignalCopy(
        "A link is shortened",
        "Short links hide where they really go until you click.",
        "We opened it for you; see where it lands below.",
    ),
    "url.new_domain": SignalCopy(
        "A link goes to a brand-new website",
        "{host} was registered only {days} days ago. Scam sites are often days old.",
        _DONT_CLICK,
    ),
    "url.young_domain": SignalCopy(
        "A link goes to a fairly new website",
        "{host} is only a few months old.",
        "Be a little careful with it.",
    ),
    "url.opaque_token_unknown_host": SignalCopy(
        "A link carries a long tracking code",
        "Common in newsletters. It can also be a one-time link that tells the sender you clicked.",
        _IGNORE_OK,
    ),
    "url.suspicious_tld": SignalCopy(
        "A link uses an unusual web address ending",
        "Endings like this are cheap and popular with scam sites.",
        "Be careful with this link.",
    ),
    "url.many_subdomains": SignalCopy(
        "A link has a long, confusing address",
        "Long chains of names can hide the real website at the end.",
        "Look at the last part of the address, or use the Reading Room.",
    ),
    "url.credential_words": SignalCopy(
        "A link talks about signing in or verifying",
        "The address mentions log-in or verification words on a website we do not recognise.",
        "Never type a password on a page you reached from an email.",
    ),
    "url.insecure_http": SignalCopy(
        "A link is not encrypted",
        "The page at {host} does not use a secure connection.",
        "Do not type anything private there.",
    ),
    "url.sender_own_domain": SignalCopy(
        "The links stay on your contact's own website",
        "They go to {host}, the same website as someone you write to.",
    ),
    # ---- links (what the sandbox saw)
    "dynamic.credential_phish": SignalCopy(
        "A link opens a fake {brand} sign-in page",
        "The page looks like {brand} but lives on {host}. It is built to steal passwords.",
        "Do not sign in. If you already did, change that password now and tell us.",
    ),
    "dynamic.password_unknown_host": SignalCopy(
        "A link asks for a password on an unfamiliar website",
        "The page at {host} has a password box, and we do not know this website.",
        "Never type a password on a page you reached from an email.",
    ),
    "dynamic.dangerous_download": SignalCopy(
        "A link downloads a program",
        "Opening it starts a download of {filename}, which can install harmful software.",
        "Do not open the link or the file.",
    ),
    "dynamic.unexpected_download": SignalCopy(
        "A link starts a download",
        "Opening it downloads {filename} without asking.",
        "Only open the file if you expected it, and use the safe copy if we made one.",
    ),
    "dynamic.new_domain": SignalCopy(
        "A link ends on a brand-new website",
        "After its redirects, the link lands on a website registered {days} days ago.",
        _DONT_CLICK,
    ),
    "dynamic.young_domain": SignalCopy(
        "A link ends on a fairly new website",
        "The page it lands on is only a few months old.",
        "Be a little careful with it.",
    ),
    "dynamic.redirect_chain": SignalCopy(
        "A link bounces through several websites",
        "It jumps across several addresses before it lands. Newsletters do this to count clicks; scams do it to hide.",
        "See where it finally lands in the list of links below.",
    ),
    "dynamic.redirect_offsite": SignalCopy(
        "A link lands on a different website",
        "It starts at one address and ends at {host}.",
        "Check that {host} is a website you expect.",
    ),
    "dynamic.client_redirect": SignalCopy(
        "A page forwards you on automatically",
        "The page sends visitors somewhere else right away.",
        _IGNORE_OK,
    ),
    "dynamic.hidden_from_automation": SignalCopy(
        "A page hid itself from our check",
        "It showed a robot test or a blank page to our sandbox. Big shops do this; so do scam pages.",
        "If you must open it, use the Reading Room.",
    ),
    "dynamic.external_form_action": SignalCopy(
        "A form sends your answers to another website",
        "Anything you type on that page goes to a different company's server.",
        "Do not type anything private there.",
    ),
    "dynamic.obfuscated_js": SignalCopy(
        "A page runs disguised code",
        "The page's code is scrambled so it is hard to read.",
        "Use the Reading Room if you need to see it.",
    ),
    "dynamic.qr_on_page": SignalCopy(
        "A page shows a QR code",
        "Scanning it with your phone takes you somewhere we did not check.",
        "Do not scan QR codes from emails you were not expecting.",
    ),
    "dynamic.hidden_text": SignalCopy(
        "A page hides much of its text",
        "Hidden text is a trick to fool filters.",
        _IGNORE_OK,
    ),
    "dynamic.many_third_parties": SignalCopy(
        "A page loads from many other websites",
        "Normal for big shopping and news sites.",
        _IGNORE_OK,
    ),
    "dynamic.unavailable": SignalCopy(
        "We could not finish opening a link",
        "The website was slow or refused our sandbox, so we could not see the page.",
        "If you must open it, use the Reading Room.",
    ),
    "dynamic.blocked": SignalCopy(
        "We did not open one link",
        "It pointed somewhere our sandbox never visits, such as a private network address.",
        "",
    ),
    "dynamic.file_network_activity": SignalCopy(
        "An attached file contacts the internet",
        "Opening {filename} reached out to another server. Normal documents do not.",
        "Do not open the file. Use the safe copy if we made one.",
    ),
    # ---- the sender
    "sender.display_brand_impersonation": SignalCopy(
        "The sender pretends to be {brand}",
        "The name says {brand}, but the email came from {from_domain}.",
        "Do not reply or click. Contact {brand} through its own app or website.",
    ),
    "sender.display_contact_impersonation": SignalCopy(
        "Someone is using your contact's name",
        "The name matches a person you know, but the address is different.",
        _CALL,
    ),
    "sender.display_contains_other_address": SignalCopy(
        "The sender's name shows a different email address",
        "The name field shows an address, but the email really came from {sender}.",
        "Trust the real address, not the name.",
    ),
    "sender.domain_lookalike": SignalCopy(
        "The sender's address copies {domain}",
        "It came from a website name made to look like {domain}.",
        "Do not reply or click. Contact the company through its own website.",
    ),
    "sender.freemail_company_name": SignalCopy(
        "A company name on a personal email account",
        "Companies write from their own website address, not from a free email account.",
        _CALL,
    ),
    "sender.reply_to_mismatch": SignalCopy(
        "Replies would go to someone else",
        "If you press Reply, your answer goes to a different address than the sender's.",
        "Check who you are replying to before you send anything.",
    ),
    "sender.return_path_mismatch": SignalCopy(
        "The email was sent through another company's system",
        "Common for newsletters; also used to hide the real sender.",
        _IGNORE_OK,
    ),
    "sender.first_seen": SignalCopy(
        "First email from this sender",
        "You have not received email from {sender} before.",
        _IGNORE_OK,
    ),
    "sender.missing_from": SignalCopy(
        "The email has no real sender address",
        "We cannot tell who sent it.",
        "Treat it with care.",
    ),
    "auth.dmarc_fail": SignalCopy(
        "Google could not confirm the sender",
        "The sender's own email system says this message should not exist. It may be forged.",
        "Do not trust who it claims to be from.",
    ),
    "auth.dkim_fail": SignalCopy(
        "The email's signature does not check out",
        "Its digital signature is broken, so it may have been changed on the way.",
        "Be careful with it.",
    ),
    "auth.spf_fail": SignalCopy(
        "Sent from a server the sender does not use",
        "The sender's domain does not allow this server to send its email.",
        "Be careful with it.",
    ),
    "auth.spf_softfail": SignalCopy(
        "Sent from an unusual server",
        "The sender's domain does not fully vouch for this server.",
        _IGNORE_OK,
    ),
    "auth.dmarc_none": SignalCopy(
        "The sender's domain is not protected against forgery",
        "Anyone could send email that looks like it comes from {from_domain}.",
        _IGNORE_OK,
    ),
    "auth.dkim_none": SignalCopy("The email has no digital signature", "Small senders often skip this.", _IGNORE_OK),
    "auth.spf_none": SignalCopy("The sender's domain lists no mail servers", "Small senders often skip this.", _IGNORE_OK),
    "auth.missing": SignalCopy(
        "We could not check who sent this", "Your mail provider recorded no sender checks for it.", _IGNORE_OK
    ),
    "subject.urgency": SignalCopy(
        "The subject pushes you to act fast",
        "Pressure to hurry is how scams stop people from thinking.",
        "Take your time. A real company will wait.",
    ),
    "header.date_skew": SignalCopy("The email's date looks wrong", "It is dated far from when it arrived.", _IGNORE_OK),
    # ---- wording (fraud patterns)
    "bec.payment_change": SignalCopy(
        "Asks you to send money to new bank details",
        "Changing where money goes is how wire fraud works.",
        _CALL,
    ),
    "bec.wire_request": SignalCopy(
        "Talks about sending money",
        "Requests to move money deserve a phone call.",
        _CALL,
    ),
    "bec.gift_card": SignalCopy(
        "Asks you to buy gift cards and send the codes",
        "No real boss, company, government office or friend asks for gift-card codes by email.",
        "Do not buy anything. Call the person on a number you already have.",
    ),
    "bec.urgency_secrecy": SignalCopy(
        "Asks for speed and secrecy",
        "Scammers ask for both so you have no time to check with anyone.",
        _CALL,
    ),
    "bec.secrecy": SignalCopy(
        "Asks you to keep it secret",
        "Real requests rarely need to be hidden from the people around you.",
        "Talk to someone you trust before you act.",
    ),
    "bec.executive_opener": SignalCopy(
        "Reads like a 'quick favour' from a boss",
        "This is how many scams begin; the real ask comes in the next email.",
        _CALL,
    ),
    "bec.payroll_change": SignalCopy(
        "Asks about pay, direct deposit or tax forms",
        "Payroll scams start with exactly this kind of request.",
        _CALL,
    ),
    "bec.channel_switch": SignalCopy(
        "Asks to move to WhatsApp, text or a personal address",
        "Moving off email removes the record and our protection.",
        "Stay on email, or call a number you already have.",
    ),
    "bec.invoice_first_time": SignalCopy(
        "An invoice from someone new",
        "This sender has never written to you before and is asking for payment.",
        "Check the invoice with the company by phone before paying.",
    ),
    "bec.from_lookalike_contact": SignalCopy(
        "The sender copies your contact's address",
        "It came from a website name made to look like {domain}, which you write to.",
        _CALL,
    ),
    "bec.signature_domain_mismatch": SignalCopy(
        "The signature names a different company",
        "The signature mentions another company than the address it came from.",
        "Check that the sender is who they say they are.",
    ),
    "bec.llm_assessment": SignalCopy(
        "Reads like a scam",
        "Our reviewer read the whole email and it looks like a trick.",
        _CALL,
    ),
    # ---- attachments
    "attachment.known_bad": SignalCopy(
        "An attached file is known malware", "{filename} matches a file seen in earlier attacks.", "Do not open it."
    ),
    "attachment.dangerous_type": SignalCopy(
        "An attached file is a program", "{filename} is a program, not a document.", "Do not open it."
    ),
    "attachment.executable_content": SignalCopy(
        "An attached file is secretly a program", "{filename} looks like a document but is a program.", "Do not open it."
    ),
    "attachment.double_extension": SignalCopy(
        "An attached file hides its real type", "{filename} uses a fake ending to look harmless.", "Do not open it."
    ),
    "attachment.filename_trick": SignalCopy(
        "An attached file name is a trick", "{filename} uses hidden characters to fake its type.", "Do not open it."
    ),
    "attachment.type_mismatch": SignalCopy(
        "An attached file is not what its name says",
        "{filename} is a different kind of file than its name claims.",
        "Open only the safe copy, if we made one.",
    ),
    "attachment.macros": SignalCopy(
        "An attached document contains hidden code",
        "{filename} has macros that run when you allow editing.",
        "Do not open it, and never click 'Enable content'.",
    ),
    "attachment.xlm_macros": SignalCopy(
        "An attached spreadsheet contains hidden code", "{filename} has old-style macros.", "Do not open it."
    ),
    "attachment.vba_stomping": SignalCopy(
        "An attached document hides its code", "{filename} contains code disguised to fool scanners.", "Do not open it."
    ),
    "attachment.remote_template": SignalCopy(
        "An attached document downloads more content",
        "{filename} fetches something from the internet when opened.",
        "Do not open it.",
    ),
    "attachment.dde": SignalCopy(
        "An attached document can start other programs", "{filename} launches a program when opened.", "Do not open it."
    ),
    "attachment.external_reference": SignalCopy(
        "An attached document links to outside content",
        "{filename} loads something from the internet when opened.",
        "Open only the safe copy, if we made one.",
    ),
    "attachment.embedded_object": SignalCopy(
        "An attached document carries a hidden file", "{filename} has another file tucked inside.", "Do not open it."
    ),
    "attachment.rtf_object": SignalCopy(
        "An attached document carries a hidden object", "{filename} uses a trick seen in attacks.", "Do not open it."
    ),
    "attachment.excel_external_links": SignalCopy(
        "An attached spreadsheet links to outside files", "{filename} reaches out to other files or websites.", "Be careful."
    ),
    "attachment.office_encrypted": SignalCopy(
        "An attached document is locked",
        "{filename} is password-protected, so we could not look inside.",
        "Only open it if you expected it and know the sender.",
    ),
    "attachment.pdf_javascript": SignalCopy(
        "An attached PDF runs code", "{filename} contains script that runs when opened.", "Open only the safe copy."
    ),
    "attachment.pdf_launch": SignalCopy(
        "An attached PDF tries to start a program", "{filename} tries to launch something when opened.", "Do not open it."
    ),
    "attachment.pdf_auto_actions": SignalCopy(
        "An attached PDF acts on its own", "{filename} does things automatically when opened.", "Open only the safe copy."
    ),
    "attachment.pdf_embedded_file": SignalCopy(
        "An attached PDF carries another file", "{filename} has a file hidden inside.", "Open only the safe copy."
    ),
    "attachment.pdf_form_submit": SignalCopy(
        "An attached PDF sends what you type",
        "{filename} has a form that sends your answers to the internet.",
        "Do not type anything into it.",
    ),
    "attachment.pdf_remote_content": SignalCopy(
        "An attached PDF loads outside content", "{filename} fetches content when opened.", "Open only the safe copy."
    ),
    "attachment.pdf_external_links": SignalCopy(
        "An attached PDF contains links", "{filename} links to websites.", "Treat its links like links in an email."
    ),
    "attachment.pdf_encrypted": SignalCopy(
        "An attached PDF is locked", "{filename} is password-protected, so we could not look inside.", "Be careful."
    ),
    "attachment.pdf_image_only": SignalCopy(
        "An attached PDF is just a picture",
        "Scam PDFs are often one big image with a link, which hides the words from filters.",
        "Do not follow links inside it.",
    ),
    "attachment.archive_password_in_body": SignalCopy(
        "A locked zip with the password in the email",
        "{filename} is locked so scanners cannot look inside, and the email gives you the key.",
        "Do not open it.",
    ),
    "attachment.archive_dangerous_entry": SignalCopy(
        "A zip file contains a program", "{filename} has a program inside.", "Do not open it."
    ),
    "attachment.archive_encrypted": SignalCopy(
        "An attached zip is locked", "{filename} is password-protected, so we could not look inside.", "Be careful."
    ),
    "attachment.archive_nested_deep": SignalCopy(
        "A zip inside a zip inside a zip", "{filename} is packed many times over to hide its contents.", "Do not open it."
    ),
    "attachment.archive_opaque": SignalCopy(
        "We could not look inside an attached archive", "{filename} could not be unpacked.", "Be careful."
    ),
    "attachment.zip_bomb": SignalCopy(
        "An attached zip is built to crash computers", "{filename} unpacks to an enormous size.", "Do not open it."
    ),
    "attachment.disk_image": SignalCopy(
        "An attached file is a disk image", "{filename} is a common wrapper for harmful programs.", "Do not open it."
    ),
    "attachment.html_smuggling": SignalCopy(
        "An attached web page builds a file in your browser",
        "{filename} secretly assembles a download when opened.",
        "Do not open it.",
    ),
    "attachment.html_credential_form": SignalCopy(
        "An attached file is a sign-in page", "{filename} asks for a password. Real companies never send these.", "Do not open it."
    ),
    "attachment.html_redirect": SignalCopy(
        "An attached web page sends you elsewhere", "{filename} forwards you to a website when opened.", "Do not open it."
    ),
    "attachment.html_obfuscated_script": SignalCopy(
        "An attached web page runs disguised code", "{filename} contains scrambled script.", "Do not open it."
    ),
    "attachment.html_attachment": SignalCopy(
        "An attached web page", "{filename} opens in your browser.", "Be careful with it."
    ),
    "attachment.svg_script": SignalCopy(
        "An attached image runs code", "{filename} is an image file with script inside.", "Do not open it."
    ),
    "attachment.svg_external": SignalCopy(
        "An attached image loads outside content", "{filename} fetches content from the internet.", "Be careful."
    ),
    "attachment.empty": SignalCopy("An attached file is empty", "{filename} has nothing in it.", _IGNORE_OK),
    "attachment.oversized": SignalCopy(
        "An attached file was too big to check", "{filename} is larger than we open.", "Be careful with it."
    ),
    # ---- the client's own choices and history
    "policy.blocked_sender": SignalCopy(
        "This sender is on your block list", "You asked us to stop mail from this sender.", ""
    ),
    "history.client_blocked": SignalCopy(
        "You marked this sender as fake", "You told us mail from {value} is fake.", ""
    ),
    "engine.timeout": SignalCopy(
        "We ran out of time checking this email", "Our check did not finish in time.", "Treat it with care or ask the concierge."
    ),
    "engine.error": SignalCopy(
        "Our check hit a problem", "We could not finish checking this email.", "Treat it with care or ask the concierge."
    ),
}

# Good signs: shown in green. {domain} is the verified sender domain.
GOOD_SIGN_COPY: dict[str, SignalCopy] = {
    "auth.dmarc_pass_aligned": SignalCopy(
        "Google confirmed this really came from {domain}",
        "The sender's own email system vouches for it, so it is not a forgery.",
    ),
    "sender.authenticated_bulk": SignalCopy(
        "A mailing list verified as {domain}",
        "Words that are normal in newsletters and receipts, like 'gift card' or 'today only', did not count against it.",
    ),
    "sender.known_contact": SignalCopy(
        "Someone you write to", "You have emailed this person before, and they write to you often."
    ),
    "sender.frequent_sender": SignalCopy("A sender you hear from often", "You have received mail from them before."),
    "history.client_trusted": SignalCopy("You told us you trust this sender", "You marked {value} as safe."),
    "url.sender_own_domain": SignalCopy(
        "The links stay on your contact's own website", "They go to the same website as someone you write to."
    ),
}
GOOD_SIGN_CODES = frozenset(GOOD_SIGN_COPY)


class _Blank(dict):
    def __missing__(self, key: str) -> str:
        return ""


def _evidence_values(signal: Any, *, sender: str = "", verified_domain: str = "") -> _Blank:
    ev = dict(getattr(signal, "evidence", None) or {})
    host = str(ev.get("final_host") or ev.get("host") or "")
    if not host and ev.get("url"):
        from urllib.parse import urlsplit

        host = urlsplit(str(ev["url"])).hostname or ""
    brand = ev.get("brand") or ev.get("impersonates")
    values = _Blank(
        host=host or "an unfamiliar website",
        brand=_brand_name(str(brand)) if brand else "a well-known company",
        domain=str(ev.get("target_domain") or ev.get("domain") or verified_domain or host or "the real website"),
        filename=str(ev.get("filename") or "the file")[:60],
        shown=str(ev.get("shown_domain") or ev.get("shown") or "one address")[:60],
        days=str(ev.get("age_days", "a few")),
        sender=sender or "this sender",
        from_domain=str(ev.get("from_domain") or (sender.rsplit("@", 1)[-1] if "@" in sender else "another address")),
        value=str(ev.get("value") or sender or "this sender"),
    )
    return values


def _brand_name(brand: str) -> str:
    from reddysec.analysis.scoring import brand_display_name

    return brand_display_name(brand)


def signal_copy(signal: Any, *, sender: str = "", verified_domain: str = "") -> SignalCopy:
    """Friendly copy for one signal. Unknown codes fall back to the engine's
    own title and detail (always plain English) so nothing is ever blank."""
    code = getattr(signal, "code", "")
    values = _evidence_values(signal, sender=sender, verified_domain=verified_domain)
    template = GOOD_SIGN_COPY.get(code) or SIGNAL_COPY.get(code)
    if code == "url.display_mismatch" and (getattr(signal, "evidence", {}) or {}).get("impersonates"):
        template = SignalCopy(
            "A link pretends to go to {shown}",
            "The text shows {shown}, but the link really opens {host}.",
            "Do not sign in there. Go to {shown} by typing it yourself.",
        )
    if template is None:
        return SignalCopy(getattr(signal, "title", "") or "Something looked unusual", getattr(signal, "detail", "") or "")
    return SignalCopy(
        template.title.format_map(values), template.meaning.format_map(values), template.todo.format_map(values)
    )


def short_reason(signal: Any, *, sender: str = "", verified_domain: str = "") -> str:
    """The one-line reason used in message lists."""
    return signal_copy(signal, sender=sender, verified_domain=verified_domain).title


# --------------------------------------------------------------------------
# Assistant replies: a tiny, safe subset of markdown
# --------------------------------------------------------------------------

_LIST_ITEM = re.compile(r"^\s*(?:[-*•]|\d{1,2}[.)])\s+(.*)$")


def _segments(line: str) -> list[dict[str, Any]]:
    """Split ``**bold**`` runs out of one line. Unmatched markers stay text."""
    parts = line.split("**")
    if len(parts) % 2 == 0:  # an odd number of markers: show them literally
        return [{"b": False, "t": line}]
    return [{"b": i % 2 == 1, "t": part} for i, part in enumerate(parts) if part]


def chat_blocks(text: str) -> list[dict[str, Any]]:
    """Paragraphs (with line breaks), bullet or numbered lists, and bold.
    Templates render the result with autoescaping; nothing here is HTML.
    ``static/assistant.js`` applies the same rules with DOM calls."""
    blocks: list[dict[str, Any]] = []
    for chunk in [c for c in text.replace("\r\n", "\n").split("\n\n") if c.strip()]:
        current: dict[str, Any] | None = None
        for raw in chunk.split("\n"):
            if not raw.strip():
                continue
            item = _LIST_ITEM.match(raw)
            if item:
                ordered = raw.strip()[0].isdigit()
                kind = "ol" if ordered else "ul"
                if current is None or current["type"] != kind:
                    current = {"type": kind, "items": []}
                    blocks.append(current)
                current["items"].append(_segments(item.group(1).strip()))
            else:
                line = raw.strip().lstrip("#").strip()
                if current is None or current["type"] != "p":
                    current = {"type": "p", "lines": []}
                    blocks.append(current)
                current["lines"].append(_segments(line))
    return blocks

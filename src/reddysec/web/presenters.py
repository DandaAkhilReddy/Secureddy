"""Turns database rows into what the client reads.

All English the client sees about a verdict, a mailbox or an audit entry is
composed here, in Python, so it can be unit tested without rendering a
template. The reader is a non-technical person or their assistant: no codes,
no jargon, no hedging. Templates receive small frozen view objects and only
lay them out.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from reddysec.models import Role, Verdict
from reddysec.store.models import AuditLog, MailboxRow, MessageRow, UserRow

from .queries import STATE_RESTORE_REQUESTED, STATE_REVIEWED, WeeklyCounts


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


# --------------------------------------------------------------------------
# Dashboard copy
# --------------------------------------------------------------------------


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


def build_report(message: MessageRow, *, artifact_url: ArtifactUrl, download_url: ArtifactUrl) -> ReportView:
    """``artifact_url`` serves a screenshot inline; ``download_url`` serves a
    sanitized attachment copy as a download. Both are closures over the
    message id so the artifact route can check the reference belongs to it."""
    verdict = parse_verdict(message.verdict)
    chip = verdict_chip(message)
    can_release = bool(message.quarantined) and message.state != STATE_RESTORE_REQUESTED
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
    )


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


def list_rows(pairs: list[tuple[MessageRow, MailboxRow]]) -> list[MessageListRow]:
    return [MessageListRow(m, mb, verdict_chip(m), message_summary(m)) for m, mb in pairs]


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

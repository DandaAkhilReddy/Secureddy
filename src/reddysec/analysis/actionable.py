"""Which emails we check: only the ones with something to click or open.

Secureddy exists to open links and files before the client does. An email
with nothing to click and nothing to open has nothing for the sandbox to do,
so the worker ignores it completely: no stored row, no mailbox label, no
count, no notification (the owner's rule: "pure-text emails, don't even
count them").

An email is **actionable** when it has at least one of:

* a link a person could click: an ``http``/``https`` link in the HTML (anchors,
  image maps, form actions and button ``formaction``), a bare URL in the text,
  a QR code in an image or a PDF, or a link inside an attachment. A
  ``javascript:`` or ``data:`` link counts too: it is clickable and it is
  never innocent;
* a real attached file (not an inline picture, not the machinery of a signed
  email or a bounce);
* a calendar invite *with a link* (the link is what counts; an invite with no
  link is just text).

Not actionable: plain text; ``mailto:``/``tel:``/``sms:`` links (they are not
pages, the URL extractor drops them); ``cid:`` references; tracking pixels and
other ``<img src>`` (fetched by the mail client, never clicked); and an
unsubscribe-only footer. A newsletter with real content links *is*
actionable: only the unsubscribe links themselves are set aside.

Careful with "unsubscribe": an attacker could dress the only link of a lure as
"Unsubscribe". A link is set aside as an unsubscribe link only when the
sender's own List-Unsubscribe header names it, or when its words or path say
unsubscribe/preferences *and* it points at the sender's own domain or a
well-known mailing service, on mail that carries a List-Unsubscribe header or
comes from that domain. Anything else is checked like any other link.

Text-only money scams. Business email compromise needs no link at all ("are
you at your desk? I need gift cards"). When the person turns on "Also watch
text-only emails for money scams" (off by default, as the owner asked), the
worker runs :func:`text_scam_signals` on text-only mail: the cheap, offline
wire-fraud / gift-card / payroll / callback heuristics, after the client's own
sender trust. Only mail that trips one of them is checked and shown; clean
text-only mail is still ignored.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import unquote

from reddysec.models import (
    Attachment,
    ClientFeedback,
    ExtractedUrl,
    ParsedMessage,
    SenderHistory,
    Signal,
    SignalStage,
)

from .intel import is_popular, is_tracking_domain
from .urls import registrable_domain

# Words in a link's visible text that make it an unsubscribe/preferences link.
_UNSUBSCRIBE_TEXT_RE = re.compile(
    r"\b(?:unsubscribe|un-subscribe|opt[ -]?out|manage (?:your )?(?:email |e-mail |mail |communication |subscription )?"
    r"(?:preferences|subscriptions?|settings)|(?:update|change|edit) (?:your )?(?:email |e-mail |subscription )?"
    r"preferences|(?:email|e-mail|subscription|communication|notification) (?:preferences|settings)|"
    r"stop (?:receiving|these|getting)|no longer (?:wish|want) to receive)\b",
    re.IGNORECASE,
)
# The same idea in a URL's path or query.
_UNSUBSCRIBE_URL_MARKERS = (
    "unsubscribe", "unsub", "optout", "opt-out", "opt_out", "manage-preferences", "manage_preferences",
    "managepreferences", "email-preferences", "email_preferences", "emailpreferences", "subscription-center",
    "subscription_center", "preference-center", "preference_center", "preferencecenter", "/preferences",
)
# Parts that are not files a person opens: S/MIME and PGP signatures on a
# signed plain-text email, and the machinery of bounces and read receipts.
NOT_A_FILE_TYPES = frozenset(
    {
        "application/pkcs7-signature",
        "application/x-pkcs7-signature",
        "application/pgp-signature",
        "message/delivery-status",
        "message/disposition-notification",
        "message/feedback-report",
        "text/rfc822-headers",
    }
)
_NOT_A_FILE_EXTENSIONS = frozenset({"p7s"})
_CALENDAR_EXTENSIONS = frozenset({"ics", "ical", "ifb", "icalendar", "vcs"})
# Text-only money scams. A finding that is about money (or about handing an
# account over) is enough on its own; the softer tells (a "quick favour"
# opener, secrecy, moving to WhatsApp, a borrowed signature) only count
# together, the way a CEO-fraud opener reads. An out-of-office reply ("I am
# out of the office") alone is not a scam.
TEXT_SCAM_MIN_WEIGHT = 20
MONEY_SCAM_CODES = frozenset(
    {
        "bec.payment_change",
        "bec.wire_request",
        "bec.gift_card",
        "bec.payroll_change",
        "bec.callback_scam",
        "bec.device_code_lure",
        "bec.invoice_first_time",
        "bec.from_lookalike_contact",
    }
)
TEXT_SCAM_COMBINED_WEIGHT = 50


@dataclass(frozen=True)
class Actionability:
    """Why an email is (or is not) worth checking. ``links`` are the clickable
    links that count; ``files`` the attachments that count."""

    links: tuple[ExtractedUrl, ...] = ()
    files: tuple[Attachment, ...] = ()
    unsubscribe_links: int = 0

    @property
    def actionable(self) -> bool:
        return bool(self.links or self.files)

    @property
    def reason(self) -> str:
        """A short label for logs: ``links``, ``files``, ``links+files`` or ``text_only``."""
        if self.links and self.files:
            return "links+files"
        if self.links:
            return "links"
        return "files" if self.files else "text_only"


def _scheme(url: ExtractedUrl) -> str:
    return url.normalized.split(":", 1)[0].lower()


def _in_list_unsubscribe(url: ExtractedUrl, parsed: ParsedMessage) -> bool:
    header = parsed.headers.get("list-unsubscribe", "")
    if not header:
        return False
    targets = {m.strip() for m in re.findall(r"<([^>]+)>", header)} or {header.strip()}
    candidates = {url.raw.strip(), url.normalized, unquote(url.raw.strip())}
    return bool(targets & candidates)


def _looks_like_unsubscribe(url: ExtractedUrl) -> bool:
    if url.display_text and _UNSUBSCRIBE_TEXT_RE.search(url.display_text):
        return True
    low = unquote(url.normalized).lower()
    after_host = low.split("://", 1)[-1].partition("/")[2]
    return any(marker.strip("/") in after_host for marker in _UNSUBSCRIBE_URL_MARKERS)


def is_unsubscribe_link(url: ExtractedUrl, parsed: ParsedMessage) -> bool:
    """An unsubscribe or "manage preferences" link we can safely set aside.

    The List-Unsubscribe header vouches for its own links. Otherwise the link
    must read as unsubscribe *and* point at the sender's domain or a
    well-known mailing service (an attacker's look-alike "Unsubscribe" link to
    a fresh domain is checked like any other link)."""
    if _scheme(url) not in ("http", "https") or not url.host:
        return False
    if _in_list_unsubscribe(url, parsed):
        return True
    if not _looks_like_unsubscribe(url):
        return False
    if url.is_ip_literal or url.display_mismatch:
        return False
    link_rd = url.registrable_domain
    sender_rd = registrable_domain(parsed.from_domain) if parsed.from_domain else ""
    if link_rd and sender_rd and link_rd == sender_rd:
        return True
    return parsed.has_list_unsubscribe and bool(link_rd) and (is_tracking_domain(link_rd) or is_popular(link_rd))


def clickable_links(parsed: ParsedMessage) -> tuple[list[ExtractedUrl], int]:
    """(links a person could click that are worth checking, unsubscribe links set aside)."""
    links: list[ExtractedUrl] = []
    unsubscribe = 0
    for url in parsed.urls:
        scheme = _scheme(url)
        if scheme in ("javascript", "data"):
            links.append(url)
            continue
        if scheme not in ("http", "https") or not url.host:
            continue
        if is_unsubscribe_link(url, parsed):
            unsubscribe += 1
            continue
        links.append(url)
    return links, unsubscribe


def _is_calendar(att: Attachment) -> bool:
    ctype = (att.content_type or "").lower()
    return ctype in ("text/calendar", "application/ics") or att.declared_extension.lower() in _CALENDAR_EXTENSIONS


def openable_files(attachments: Iterable[Attachment]) -> list[Attachment]:
    """Real attached files a person could open. Inline pictures, calendar
    invites (their links count instead), signatures of signed email and
    bounce/receipt reports are not files."""
    out: list[Attachment] = []
    for att in attachments:
        if att.is_inline:
            continue
        ctype = (att.content_type or "").lower()
        if ctype in NOT_A_FILE_TYPES or att.declared_extension.lower() in _NOT_A_FILE_EXTENSIONS:
            continue
        if _is_calendar(att):
            continue
        out.append(att)
    return out


def assess(parsed: ParsedMessage) -> Actionability:
    """Decide once, from the parsed message, whether it is worth checking."""
    links, unsubscribe = clickable_links(parsed)
    return Actionability(links=tuple(links), files=tuple(openable_files(parsed.attachments)),
                         unsubscribe_links=unsubscribe)


def is_actionable(parsed: ParsedMessage) -> bool:
    return assess(parsed).actionable


def text_scam_signals(
    parsed: ParsedMessage,
    history: SenderHistory | None = None,
    *,
    contact_domains: tuple[str, ...] = (),
    feedback: ClientFeedback | None = None,
) -> list[Signal]:
    """The money-scam findings of a text-only email, or ``[]``.

    Runs only the offline wire-fraud, gift-card, payroll and callback-scam
    heuristics (``analysis.bec``), then the client's own sender trust: mail
    from a sender the client trusts is never flagged here, and the rest is
    softened exactly as the full pipeline would. A money finding
    (:data:`MONEY_SCAM_CODES`) counts alone; softer tells only together
    (:data:`TEXT_SCAM_COMBINED_WEIGHT`). Never raises.
    """
    from .bec import bec_signals  # lazy: keeps the worker import light
    from .headers import sender_signals
    from .trust import assess_sender, soften_static

    try:
        sender = sender_signals(parsed, history, contact_domains)
        trust = assess_sender(parsed, contact_domains=contact_domains, feedback=feedback, sender_signals=sender)
        if trust.client_trust is not None:
            return []
        signals = soften_static(bec_signals(parsed, history, contact_domains), trust)
    except Exception:  # noqa: BLE001 - a heuristic bug must never stop the worker
        return []
    bec = [s for s in signals if s.stage is SignalStage.BEC and s.weight > 0]
    if any(s.code in MONEY_SCAM_CODES and s.weight >= TEXT_SCAM_MIN_WEIGHT for s in bec):
        return bec
    if sum(s.weight for s in bec) >= TEXT_SCAM_COMBINED_WEIGHT:
        return bec
    return []


def has_bec_signal(verdict: dict | None) -> bool:
    """Whether a stored verdict (``MessageRow.verdict``) carries any BEC finding."""
    if not isinstance(verdict, dict):
        return False
    for signal in verdict.get("signals") or []:
        if isinstance(signal, dict) and str(signal.get("code", "")).startswith("bec."):
            return True
    return False


# Finding codes that only exist when an email had a link or a file.
_LINK_OR_FILE_PREFIXES = ("url.", "attachment.", "dynamic.", "file.", "qr.", "link.")


def stored_verdict_is_text_only(verdict: dict | None) -> bool:
    """A stored verdict with no sign of a link or file and no BEC finding:
    what ``reddysec purge-text-only`` may forget. Defensive on purpose: any
    link or file verdict, or any link/file finding, keeps the row even if its
    counters say 0."""
    if not isinstance(verdict, dict) or has_bec_signal(verdict):
        return False
    if verdict.get("urls") or verdict.get("attachments"):
        return False
    for signal in verdict.get("signals") or []:
        if isinstance(signal, dict) and str(signal.get("code", "")).startswith(_LINK_OR_FILE_PREFIXES):
            return False
    return True


__all__ = [
    "Actionability",
    "NOT_A_FILE_TYPES",
    "MONEY_SCAM_CODES",
    "TEXT_SCAM_COMBINED_WEIGHT",
    "TEXT_SCAM_MIN_WEIGHT",
    "assess",
    "clickable_links",
    "has_bec_signal",
    "is_actionable",
    "is_unsubscribe_link",
    "openable_files",
    "stored_verdict_is_text_only",
    "text_scam_signals",
]

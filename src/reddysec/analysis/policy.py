"""Triage policy: which lane a message takes and what gets detonated.

The lanes trade latency against certainty:

* RELEASE_FAST  nothing to open (no links, no real attachments). Sender and
                BEC checks still run, because wire fraud needs neither.
* BLOCK         static evidence is already conclusive, or the sender is on the
                client's block list. No need to spend a sandbox on it.
* TRUSTED       authenticated mail from someone the client actually talks to
                (or a domain they trust), pointing only at well-known places.
* DETONATE      everything else.

URL selection protects the client as much as it protects the sandbox budget:
one-time links from authenticated, well-known senders are never followed,
because following them would consume a login or confirm the address.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from urllib.parse import urlsplit

from reddysec.models import (
    Attachment,
    ExtractedUrl,
    ParsedMessage,
    PolicyConfig,
    SenderHistory,
    Signal,
    TriageLane,
)

from .dynamic import static_risk
from .intel import is_popular, is_tracking_domain
from .urls import registrable_domain

BLOCK_WEIGHT = 90
DANGEROUS_ATTACHMENT_WEIGHT = 35
DANGEROUS_URL_WEIGHT = 35
MAX_URLS_TO_DETONATE = 8
MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024
# SVG is deliberately absent: it is an image that can carry script, so it may be detonated.
_IMAGE_EXTENSIONS = frozenset({"png", "jpg", "jpeg", "gif", "bmp", "webp", "tif", "tiff", "ico"})
_UNSUBSCRIBE_MARKERS = ("unsubscribe", "optout", "opt-out", "opt_out", "list-manage.com/unsubscribe", "/manage-preferences")
_TRACKING_PIXEL_EXTENSIONS = (".gif", ".png", ".jpg", ".jpeg", ".webp", ".bmp")
_SKIP_CONTENT_TYPES = ("text/plain", "text/calendar", "text/vcard", "text/x-vcard")
_SKIP_EXTENSIONS = frozenset({"txt", "ics", "vcf", "csv", "log", "md"})


def _all_signals(groups: Mapping[str, list[Signal]] | Iterable[Signal]) -> list[Signal]:
    if isinstance(groups, Mapping):
        return [s for sigs in groups.values() for s in sigs]
    return list(groups)


def sender_is_blocked(parsed: ParsedMessage, policy: PolicyConfig) -> bool:
    """Blocked entries can be full addresses or whole domains."""
    addr = parsed.from_address.lower()
    domain = parsed.from_domain
    rd = registrable_domain(domain) if domain else ""
    for entry in policy.blocked_senders:
        e = entry.strip().lower().lstrip("@")
        if not e:
            continue
        if "@" in e:
            if e == addr:
                return True
        elif e in (domain, rd):
            return True
    return False


def sender_is_trusted_domain(parsed: ParsedMessage, policy: PolicyConfig) -> bool:
    rd = registrable_domain(parsed.from_domain) if parsed.from_domain else ""
    trusted = {registrable_domain(d.strip().lower()) for d in policy.trusted_domains if d.strip()}
    return bool(rd) and rd in trusted


def sender_authenticated(parsed: ParsedMessage) -> bool:
    auth = parsed.auth
    return bool(auth.aligned) and (auth.dmarc == "pass" or auth.dkim == "pass" or auth.spf == "pass")


def _url_domain_trusted(url: ExtractedUrl, parsed: ParsedMessage, policy: PolicyConfig) -> bool:
    rd = url.registrable_domain
    if not rd or url.is_ip_literal:
        return False
    if is_popular(rd) or is_tracking_domain(rd):
        return True
    trusted = {registrable_domain(d.strip().lower()) for d in policy.trusted_domains if d.strip()}
    if rd in trusted:
        return True
    return rd == registrable_domain(parsed.from_domain) and sender_authenticated(parsed)


def choose_lane(
    parsed: ParsedMessage,
    history: SenderHistory | None,
    policy: PolicyConfig,
    url_static: Mapping[str, list[Signal]],
    attachment_signals: Mapping[str, list[Signal]] | Iterable[Signal],
) -> TriageLane:
    """Pick the triage lane from static evidence alone."""
    att_signals = _all_signals(attachment_signals)
    url_signals = _all_signals(url_static)
    if sender_is_blocked(parsed, policy):
        return TriageLane.BLOCK
    if any(s.weight >= BLOCK_WEIGHT for s in att_signals + url_signals):
        return TriageLane.BLOCK
    if not parsed.urls and not parsed.real_attachments:
        return TriageLane.RELEASE_FAST

    known_correspondent = (
        history is not None
        and history.address.lower() == parsed.from_address.lower()
        and history.message_count >= 3
        and history.replied_to
    )
    if sender_authenticated(parsed) and (known_correspondent or sender_is_trusted_domain(parsed, policy)):
        urls_clean = all(_url_domain_trusted(u, parsed, policy) for u in parsed.urls)
        urls_clean = urls_clean and all(s.weight < DANGEROUS_URL_WEIGHT for s in url_signals)
        attachments_clean = all(s.weight < DANGEROUS_ATTACHMENT_WEIGHT for s in att_signals)
        if urls_clean and attachments_clean:
            return TriageLane.TRUSTED
    return TriageLane.DETONATE


def _is_unsubscribe(url: ExtractedUrl, parsed: ParsedMessage) -> bool:
    low = url.normalized.lower()
    if any(marker in low for marker in _UNSUBSCRIBE_MARKERS):
        return True
    header = parsed.headers.get("list-unsubscribe", "")
    return bool(header) and url.normalized in header


def _is_tracking_pixel(url: ExtractedUrl) -> bool:
    path = urlsplit(url.normalized).path.lower()
    return path.endswith(_TRACKING_PIXEL_EXTENSIONS)


def _is_protected_magic_link(url: ExtractedUrl, parsed: ParsedMessage) -> bool:
    """A one-time link from an authenticated, well-known sender: scoring only, never clicking."""
    if not url.has_opaque_token:
        return False
    if not (parsed.auth.aligned and parsed.auth.dmarc == "pass"):
        return False
    sender_rd = registrable_domain(parsed.from_domain) if parsed.from_domain else ""
    if not sender_rd or not is_popular(sender_rd):
        return False
    return url.registrable_domain == sender_rd or is_popular(url.registrable_domain) or is_tracking_domain(url.registrable_domain)


def select_urls_to_detonate(
    parsed: ParsedMessage, policy: PolicyConfig, url_static: Mapping[str, list[Signal]]
) -> list[ExtractedUrl]:
    """Choose which links the chamber opens: the riskiest distinct destinations, capped."""
    never = {registrable_domain(d.strip().lower()) for d in policy.never_detonate_domains if d.strip()}
    candidates: list[ExtractedUrl] = []
    for url in parsed.urls:
        scheme = url.normalized.split(":", 1)[0].lower()
        if scheme not in {"http", "https"}:
            continue
        if not url.host or _is_unsubscribe(url, parsed) or _is_tracking_pixel(url):
            continue
        if url.registrable_domain in never:
            continue
        if _is_protected_magic_link(url, parsed):
            continue
        candidates.append(url)

    by_key: dict[tuple[str, str], ExtractedUrl] = {}
    risk: dict[str, int] = {u.normalized: static_risk(url_static.get(u.normalized, [])) for u in candidates}
    for url in candidates:
        key = (url.registrable_domain or url.host, urlsplit(url.normalized).path)
        current = by_key.get(key)
        if current is None or risk[url.normalized] > risk[current.normalized]:
            by_key[key] = url
    ranked = sorted(by_key.values(), key=lambda u: (-risk[u.normalized], parsed.urls.index(u)))
    return ranked[:MAX_URLS_TO_DETONATE]


def select_attachments_to_detonate(parsed: ParsedMessage) -> list[Attachment]:
    """Non-inline files worth opening in the chamber: documents, archives, executables."""
    selected: list[Attachment] = []
    for att in parsed.real_attachments:
        if att.size <= 0 or att.size > MAX_ATTACHMENT_BYTES:
            continue
        ctype = (att.content_type or "").lower()
        ext = att.declared_extension.lower()
        sniffed = (att.sniffed_type or "").lower()
        if (ctype.startswith("image/") and "svg" not in ctype) or ext in _IMAGE_EXTENSIONS or sniffed in {"png", "jpeg", "gif", "webp"}:
            continue
        if ctype.startswith(_SKIP_CONTENT_TYPES) or ext in _SKIP_EXTENSIONS:
            continue
        selected.append(att)
    return selected

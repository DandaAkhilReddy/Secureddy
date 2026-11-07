"""Per-URL signals: static (from the URL itself plus intel) and dynamic (from
what the detonation chamber saw when it opened the link).

Static signals are cheap and run for every link. Dynamic signals are the
expensive truth: a login form on a host that is not the brand it dresses up
as is the single strongest piece of evidence this engine produces.
"""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlsplit

from reddysec.models import (
    DetonationResult,
    DetonationStatus,
    DownloadRecord,
    ExtractedUrl,
    SenderHistory,
    Signal,
    SignalStage,
)

from .attachments import DANGEROUS_EXTENSIONS, EXECUTABLE_SNIFFED, _ext_parts
from .click_advice import describe_download
from .common import make_signal
from .domains import brand_for_domain, brands_mentioned, legit_domains_for, lookalike_analysis
from .intel import IntelClient, is_brand_shortener, is_popular, is_tracking_domain
from .lures import (
    clickfix_signals,
    free_hosting_signals,
    kit_signals,
    link_text_signals,
    oauth_consent_signals,
    redirect_signals,
    scam_page_signals,
)
from .trust import SenderTrust, display_mismatch_assessment, shown_domain, skip_opaque_token
from .urls import registrable_domain

SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {"zip", "mov", "top", "xyz", "icu", "tk", "ml", "ga", "cf", "gq", "click", "link", "work", "buzz", "rest",
     "cam", "cfd", "sbs", "bond", "cyou", "surf", "lol", "monster", "quest", "pw", "su", "ws", "live", "fit"}
)
_CREDENTIAL_PATH_RE = ("login", "logon", "signin", "sign-in", "verify", "verification", "secure", "update",
                       "account", "password", "auth", "confirm", "validate", "recover", "unlock", "wallet")
_MACRO_EXTENSIONS: frozenset[str] = frozenset({"docm", "dotm", "xlsm", "xlam", "xlsb", "pptm", "ppsm", "potm"})
_ARCHIVE_EXTENSIONS: frozenset[str] = frozenset({"zip", "7z", "rar", "gz", "tgz", "iso", "img", "cab"})
NEW_DOMAIN_DAYS = 30
YOUNG_DOMAIN_DAYS = 180
MANY_THIRD_PARTIES = 30


def static_risk(signals: Iterable[Signal]) -> int:
    """Sum of positive weights: a quick ranking key, not a score."""
    return sum(s.weight for s in signals if s.weight > 0)


def _evidence(url: ExtractedUrl | str) -> dict[str, str]:
    return {"url": url.normalized if isinstance(url, ExtractedUrl) else url}


# --------------------------------------------------------------------------- static


async def url_static_signals(
    url: ExtractedUrl,
    intel: IntelClient | None,
    history: SenderHistory | None = None,
    contact_domains: tuple[str, ...] = (),
    sender: SenderTrust | None = None,
) -> list[Signal]:
    """Everything we can say about a link without opening it.

    ``sender`` (optional) is what we could verify about the sender; links to
    its own verified domain are judged accordingly (see ``analysis.trust``).
    """
    signals: list[Signal] = []
    ev = _evidence(url)
    scheme = url.normalized.split(":", 1)[0].lower()
    if scheme in {"javascript", "data"}:
        signals.append(
            make_signal(
                "url.dangerous_scheme", SignalStage.STATIC, 50,
                f"A link runs code or embeds content directly ({scheme}:)",
                "Real links point to websites; this one carries its own payload.", **ev,
            )
        )
        return signals

    host = url.host
    rd = url.registrable_domain
    popular = is_popular(rd)

    known_bad: bool | None = None
    age: int | None = None
    if intel is not None:
        try:
            known_bad = await intel.url_is_known_bad(url.normalized)
        except Exception:
            known_bad = None
        try:
            age = await intel.domain_age_days(rd) if rd and not url.is_ip_literal else None
        except Exception:
            age = None
    if known_bad:
        signals.append(
            make_signal(
                "url.known_bad", SignalStage.INTEL, 100,
                f"Link to {host} is on a blocklist of known malicious sites",
                "Threat intelligence has already seen this address used in attacks.", **ev,
            )
        )

    look = lookalike_analysis(host, rd, contact_domains)
    if look.is_lookalike:
        who = look.target_domain or look.target or "a trusted site"
        signals.append(
            make_signal(
                "url.lookalike", SignalStage.STATIC, look.weight,
                f"Link goes to {host}, which imitates {who}",
                look.detail, brand=None if look.is_contact else look.target, target_domain=look.target_domain,
                reason=look.reason.value if look.reason else None, **ev,
            )
        )
    if url.is_ip_literal:
        signals.append(
            make_signal(
                "url.ip_literal", SignalStage.STATIC, 40,
                f"Link points at a bare IP address ({host}) instead of a website name",
                "Legitimate services have domain names; compromised servers often do not.", **ev,
            )
        )
    if url.is_punycode:
        signals.append(
            make_signal(
                "url.punycode", SignalStage.STATIC, 30,
                f"Link uses international characters that can disguise its real name ({host})", **ev,
            )
        )
    if url.is_shortener and not is_brand_shortener(rd):
        signals.append(
            make_signal(
                "url.shortener", SignalStage.STATIC, 15,
                f"Link is shortened ({rd}), hiding where it really goes", **ev,
            )
        )
    if url.display_mismatch:
        weight, impersonates = display_mismatch_assessment(url, sender)
        title = f"Link text says '{(url.display_text or '')[:40]}' but it goes to {host}"
        detail = "The visible address and the real destination differ."
        if impersonates:
            title = f"Link pretends to go to {shown_domain(url.display_text)} but goes to {host}"
            detail = "The text shows a well-known company's website, but the link leads somewhere else."
        elif weight < 35:
            detail += " The link still goes to the sender's own verified website or its mail service, so this counts for little."
        signals.append(
            make_signal(
                "url.display_mismatch", SignalStage.STATIC, weight, title, detail,
                shown=url.display_text, shown_domain=shown_domain(url.display_text) or None,
                impersonates=impersonates, **ev,
            )
        )
    if age is not None and not popular:
        if age < NEW_DOMAIN_DAYS:
            signals.append(
                make_signal(
                    "url.new_domain", SignalStage.INTEL, 35,
                    f"Website {rd} was registered only {age} day{'s' if age != 1 else ''} ago",
                    "Phishing sites live for days; established businesses do not.", age_days=age, **ev,
                )
            )
        elif age < YOUNG_DOMAIN_DAYS:
            signals.append(
                make_signal(
                    "url.young_domain", SignalStage.INTEL, 15,
                    f"Website {rd} is only {age} days old", age_days=age, **ev,
                )
            )
    if url.has_opaque_token and not popular and not url.is_shortener and not skip_opaque_token(url, sender):
        signals.append(
            make_signal(
                "url.opaque_token_unknown_host", SignalStage.STATIC, 10,
                f"Link to {rd} carries a long tracking or one-time code", domain=rd, **ev,
            )
        )
    tld = rd.rsplit(".", 1)[-1] if "." in rd else ""
    if tld in SUSPICIOUS_TLDS and not popular:
        signals.append(
            make_signal(
                "url.suspicious_tld", SignalStage.STATIC, 15,
                f"Link uses a .{tld} address, a domain ending favoured by throwaway phishing sites", **ev,
            )
        )
    if host and not url.is_ip_literal:
        labels = host.split(".")
        rd_labels = rd.count(".") + 1
        if len(labels) - rd_labels > 3:
            signals.append(
                make_signal(
                    "url.many_subdomains", SignalStage.STATIC, 10,
                    f"Link hides behind an unusually long chain of subdomains ({host})", **ev,
                )
            )
    parts = urlsplit(url.normalized)
    path_text = (parts.path + "?" + parts.query).lower()
    if any(word in path_text for word in _CREDENTIAL_PATH_RE) and not popular:
        brand_in_url = brands_mentioned(host.replace("-", " ").replace(".", " ") + " " + path_text.replace("/", " ").replace("-", " "))
        own_site = sender is not None and sender.owns(host or rd)
        # "rei.com/account" from verified rei.com is simply where accounts live.
        if brand_in_url or not own_site:
            signals.append(
                make_signal(
                    "url.credential_words", SignalStage.STATIC, 15 if brand_in_url else 5,
                    f"Link path talks about logging in or verifying ({parts.path[:40]})",
                    brand=brand_in_url[0] if brand_in_url else None, **ev,
                )
            )
    if scheme == "http" and not popular:
        signals.append(
            make_signal(
                "url.insecure_http", SignalStage.STATIC, 10,
                f"Link to {host} is not encrypted (http instead of https)", **ev,
            )
        )
    signals.extend(redirect_signals(url))
    signals.extend(free_hosting_signals(url))
    signals.extend(oauth_consent_signals(url))
    signals.extend(link_text_signals(url))
    if history is not None and history.replied_to and rd and "@" in history.address:
        if registrable_domain(history.address.rsplit("@", 1)[-1]) == rd:
            signals.append(
                make_signal(
                    "url.sender_own_domain", SignalStage.HISTORY, -5,
                    f"Link stays on {rd}, the domain of a contact you write to", **ev,
                )
            )
    return signals


# --------------------------------------------------------------------------- dynamic


def _download_is_dangerous(download: DownloadRecord) -> bool:
    if describe_download(download).dangerous:
        return True
    parts = _ext_parts(download.suggested_filename)
    ext = parts[-1] if parts else ""
    sniffed = (download.sniffed_type or "").lower()
    if ext in DANGEROUS_EXTENSIONS or ext in _MACRO_EXTENSIONS or ext in _ARCHIVE_EXTENSIONS:
        return True
    return sniffed in EXECUTABLE_SNIFFED or sniffed in {"zip", "7z", "rar", "jar", "iso9660"}


def _page_brands(result: DetonationResult, email_brands: Iterable[str]) -> tuple[list[str], bool]:
    """(brands the page presents itself as, whether they came from the page itself)."""
    features = result.features
    page: list[str] = []
    if features is not None:
        page.extend(b.lower() for b in features.brand_keywords)
        page.extend(brands_mentioned(f"{features.title or ''} {features.text_excerpt or ''}"))
    page = list(dict.fromkeys(page))
    if page:
        return page, True
    return list(dict.fromkeys(b.lower() for b in email_brands)), False


def dynamic_signals(
    url: str,
    result: DetonationResult,
    intel_age_days: int | None,
    brands: Iterable[str] = (),
) -> list[Signal]:
    """Signals from one detonation of ``url``. ``brands`` are those the email itself invoked."""
    signals: list[Signal] = []
    ev = {"url": url}
    if result.status in (DetonationStatus.TIMEOUT, DetonationStatus.ERROR):
        signals.append(
            make_signal(
                "dynamic.unavailable", SignalStage.DYNAMIC, 10,
                "We could not finish opening this link safely",
                f"The sandbox reported {result.status.value}" + (f": {result.error}" if result.error else "") + ".",
                status=result.status.value, **ev,
            )
        )
        return signals
    if result.status is DetonationStatus.BLOCKED:
        signals.append(
            make_signal(
                "dynamic.blocked", SignalStage.DYNAMIC, 0,
                "The sandbox refused to open this link",
                result.error or "Unsupported scheme or private address.", status=result.status.value, **ev,
            )
        )
        return signals

    features = result.features
    start_host = (urlsplit(url).hostname or "").lower()
    start_rd = registrable_domain(start_host)
    final_url = (features.final_url if features else None) or (result.redirects[-1].url if result.redirects else url)
    final_host = ((features.final_host if features else None) or urlsplit(final_url).hostname or start_host).lower()
    final_rd = registrable_domain(final_host)
    final_popular = is_popular(final_rd)
    final_brand = brand_for_domain(final_rd)

    page_brands, from_page = _page_brands(result, brands)
    has_password = bool(features and features.has_password_field) or any(f.has_password for f in (features.forms if features else []))
    if has_password:
        impersonated = [b for b in page_brands if final_rd not in legit_domains_for(b) and final_brand != b]
        if impersonated:
            brand = impersonated[0]
            signals.append(
                make_signal(
                    "dynamic.credential_phish", SignalStage.DYNAMIC, 75 if from_page else 60,
                    f"Login page impersonates {brand}",
                    f"The page at {final_host} asks for a password while presenting itself as {brand}, "
                    f"whose real sign-in lives on {', '.join(sorted(legit_domains_for(brand))[:2]) or 'its own domain'}.",
                    brand=brand, final_host=final_host, **ev,
                )
            )
        elif not final_popular:
            signals.append(
                make_signal(
                    "dynamic.password_unknown_host", SignalStage.DYNAMIC, 45,
                    f"Link opens a password form on an unfamiliar site ({final_host})",
                    final_host=final_host, **ev,
                )
            )
    if features and features.external_form_action:
        signals.append(
            make_signal(
                "dynamic.external_form_action", SignalStage.DYNAMIC, 10 if final_popular else 30,
                "The page sends what you type to a different website", final_host=final_host, **ev,
            )
        )

    hop_domains = list(dict.fromkeys([start_rd] + [registrable_domain(urlsplit(h.url).hostname or "") for h in result.redirects] + [final_rd]))
    hop_domains = [d for d in hop_domains if d]
    if len(hop_domains) >= 3:
        signals.append(
            make_signal(
                "dynamic.redirect_chain", SignalStage.DYNAMIC, 20,
                f"Link bounced through {len(hop_domains) - 1} other websites before landing on {final_host}",
                hops=hop_domains[:8], **ev,
            )
        )
    elif start_rd and final_rd != start_rd and not is_tracking_domain(start_rd):
        # Popular-to-popular hops (a Google link landing on YouTube) are routine.
        if not (final_popular and is_popular(start_rd)):
            signals.append(
                make_signal(
                    "dynamic.redirect_offsite", SignalStage.DYNAMIC, 15,
                    f"Link to {start_host} actually lands on {final_host}", final_host=final_host, **ev,
                )
            )

    if intel_age_days is not None and not final_popular:
        if intel_age_days < NEW_DOMAIN_DAYS:
            signals.append(
                make_signal(
                    "dynamic.new_domain", SignalStage.DYNAMIC, 35,
                    f"The destination {final_rd} was registered {intel_age_days} day{'s' if intel_age_days != 1 else ''} ago",
                    age_days=intel_age_days, **ev,
                )
            )
        elif intel_age_days < YOUNG_DOMAIN_DAYS:
            signals.append(
                make_signal(
                    "dynamic.young_domain", SignalStage.DYNAMIC, 15,
                    f"The destination {final_rd} is only {intel_age_days} days old", age_days=intel_age_days, **ev,
                )
            )

    # The lure families: ClickFix / FileFix, scam pages, phishing-kit tells.
    signals.extend(clickfix_signals(url, result))
    signals.extend(scam_page_signals(url, result, final_host, final_popular))
    signals.extend(kit_signals(url, result, final_host=final_host, final_rd=final_rd, final_popular=final_popular,
                               page_brands=page_brands if from_page else ()))

    for download in result.downloads:
        if _download_is_dangerous(download):
            info = describe_download(download)
            signals.append(
                make_signal(
                    "dynamic.dangerous_download", SignalStage.DYNAMIC, 65,
                    f"Opening the link downloads a dangerous file ({download.suggested_filename[:40]})",
                    info.why, filename=download.suggested_filename, sha256=download.sha256,
                    sniffed_type=download.sniffed_type, category=info.category, **ev,
                )
            )
        else:
            signals.append(
                make_signal(
                    "dynamic.unexpected_download", SignalStage.DYNAMIC, 20,
                    f"Opening the link starts a download ({download.suggested_filename[:40]})",
                    filename=download.suggested_filename, sha256=download.sha256, **ev,
                )
            )

    if features:
        if features.meta_refresh or features.js_redirect:
            signals.append(
                make_signal(
                    "dynamic.client_redirect", SignalStage.DYNAMIC, 10,
                    "The page forwards visitors onward with a script or meta refresh", **ev,
                )
            )
        if features.obfuscated_js_score > 60:
            signals.append(
                make_signal(
                    "dynamic.obfuscated_js", SignalStage.DYNAMIC, 25,
                    "The page runs heavily disguised script", score=features.obfuscated_js_score, **ev,
                )
            )
        if features.captcha_detected or features.automation_blocked_hint:
            signals.append(
                make_signal(
                    "dynamic.hidden_from_automation", SignalStage.DYNAMIC, 20,
                    "The page hid itself from automated inspection",
                    "Phishing kits show a CAPTCHA or blank page to scanners and the real page to people.", **ev,
                )
            )
        if features.qr_codes:
            signals.append(
                make_signal(
                    "dynamic.qr_on_page", SignalStage.DYNAMIC, 10,
                    "The page shows a QR code to scan with your phone", codes=features.qr_codes[:3], **ev,
                )
            )
        if features.hidden_text_ratio >= 0.3:
            signals.append(
                make_signal(
                    "dynamic.hidden_text", SignalStage.DYNAMIC, 10,
                    "Much of the page's text is hidden from view", ratio=round(features.hidden_text_ratio, 2), **ev,
                )
            )
    third_parties = {r.host for r in result.requests if r.is_third_party}
    if len(third_parties) > MANY_THIRD_PARTIES:
        signals.append(
            make_signal(
                "dynamic.many_third_parties", SignalStage.DYNAMIC, 5,
                f"The page contacted {len(third_parties)} other websites while loading", **ev,
            )
        )
    return signals


def file_dynamic_signals(filename: str, result: DetonationResult) -> list[Signal]:
    """Signals from opening an attachment in the chamber (FILE detonation)."""
    signals: list[Signal] = []
    ev = {"filename": filename}
    if result.status in (DetonationStatus.TIMEOUT, DetonationStatus.ERROR):
        signals.append(
            make_signal(
                "dynamic.unavailable", SignalStage.DYNAMIC, 10,
                f"We could not finish opening {filename[:40]} safely", status=result.status.value, **ev,
            )
        )
        return signals
    if result.status is DetonationStatus.BLOCKED:
        signals.append(make_signal("dynamic.blocked", SignalStage.DYNAMIC, 0, "The sandbox refused to open this file", **ev))
        return signals
    contacted = sorted({r.host for r in result.requests if r.host and not is_popular(registrable_domain(r.host))})
    if contacted:
        signals.append(
            make_signal(
                "dynamic.file_network_activity", SignalStage.DYNAMIC, 40,
                f"Opening {filename[:40]} contacted the internet ({contacted[0]})",
                "Documents should not phone home.", hosts=contacted[:5], **ev,
            )
        )
    for download in result.downloads:
        signals.append(
            make_signal(
                "dynamic.dangerous_download" if _download_is_dangerous(download) else "dynamic.unexpected_download",
                SignalStage.DYNAMIC, 65 if _download_is_dangerous(download) else 20,
                f"Opening {filename[:40]} fetched another file ({download.suggested_filename[:40]})",
                download=download.suggested_filename, **ev,
            )
        )
    if result.features and result.features.has_password_field:
        signals.append(
            make_signal(
                "dynamic.password_unknown_host", SignalStage.DYNAMIC, 50,
                f"Opening {filename[:40]} shows a password prompt", **ev,
            )
        )
    # An HTML/SVG attachment can be a ClickFix page or a scam page too.
    target = f"file:{filename}"
    for sig in clickfix_signals(target, result) + scam_page_signals(target, result, "", False):
        sig.evidence.pop("url", None)
        sig.evidence["filename"] = filename
        signals.append(sig)
    return signals

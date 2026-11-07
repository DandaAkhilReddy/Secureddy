"""Turn signals into a score, a level and words a person can act on.

Scoring rules:

* Signals are combined with diminishing returns (100% of the strongest, 60%
  of the second, 40% of the third, 25% of the rest). Ten weak hints do not add
  up to a certainty, but three independent medium ones do.
* Negative (trust) weights are added afterwards, capped, and can never hide
  a strong positive signal: a trusted contact whose account was taken over is
  exactly the case trust must not excuse.
* Any single signal at or above 90 forces at least the MALICIOUS threshold.

Summaries are written for the client, not for an analyst: name who the mail
pretends to be, say what the dangerous thing does, say what we did.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from urllib.parse import urlsplit

from reddysec.models import (
    MALICIOUS_THRESHOLD,
    Attachment,
    AttachmentVerdict,
    DetonationResult,
    ExtractedUrl,
    ParsedMessage,
    Signal,
    TriageLane,
    UrlVerdict,
    VerdictLevel,
    level_for_score,
)

from .common import truncate

DIMINISHING_FACTORS = (1.0, 0.6, 0.4)
TAIL_FACTOR = 0.25
MAX_TRUST_REDUCTION = 40
STRONG_SIGNAL = 60  # trust never pulls the score below a signal this strong
FORCE_MALICIOUS_AT = 90


def dedupe_by_code(signals: Iterable[Signal]) -> list[Signal]:
    """Keep the strongest instance of each code: five links on one new domain are one fact."""
    best: dict[str, Signal] = {}
    order: list[str] = []
    for s in signals:
        current = best.get(s.code)
        if current is None:
            order.append(s.code)
            best[s.code] = s
        elif (s.weight > current.weight) if s.weight >= 0 else (s.weight < current.weight):
            best[s.code] = s
    return [best[c] for c in order]


def combine(signals: Iterable[Signal]) -> int:
    """Combine signal weights into a 0..100 score. See the module docstring for the rules."""
    positives = sorted((s.weight for s in signals if s.weight > 0), reverse=True)
    negatives = [s.weight for s in signals if s.weight < 0]
    total = 0.0
    for index, weight in enumerate(positives):
        factor = DIMINISHING_FACTORS[index] if index < len(DIMINISHING_FACTORS) else TAIL_FACTOR
        total += weight * factor
    trust = max(sum(negatives), -MAX_TRUST_REDUCTION)
    score = total + trust
    top = positives[0] if positives else 0
    if top >= STRONG_SIGNAL:
        score = max(score, float(top))
    if top >= FORCE_MALICIOUS_AT:
        score = max(score, float(MALICIOUS_THRESHOLD))
    return int(max(0, min(100, round(score))))


def score_signals(signals: Iterable[Signal]) -> int:
    return combine(dedupe_by_code(signals))


# --------------------------------------------------------------------------- plain-English summaries

_ACTIONS = {
    VerdictLevel.MALICIOUS: "We moved it to Quarantine.",
    VerdictLevel.SUSPICIOUS: "We left it in your inbox with a warning; if you must open a link, use the Reading Room.",
    VerdictLevel.SAFE: "We checked it and found nothing wrong.",
    VerdictLevel.UNKNOWN: "We could not finish checking it, so please treat its links and files with care.",
}

# code -> template. {brand}, {host}, {filename}, {domain}, {days}, {sender} are filled from evidence.
_REASONS: dict[str, str] = {
    "url.known_bad": "The link goes to a site already known for attacks",
    "dynamic.credential_phish": "The link opens a fake {brand} sign-in page that steals passwords",
    "dynamic.password_unknown_host": "The link opens a password form on an unfamiliar website",
    "dynamic.dangerous_download": "The link downloads a program onto your computer",
    "dynamic.new_domain": "The link leads to a website registered {days} days ago",
    "url.new_domain": "The link leads to a website registered {days} days ago",
    "url.lookalike": "The link goes to {host}, a copycat of {domain}",
    "url.display_mismatch": "The link does not go where its text says",
    "url.ip_literal": "The link points at a raw server address instead of a website",
    "url.dangerous_scheme": "A link in the email carries its own code instead of pointing to a website",
    "dynamic.redirect_chain": "The link bounces through several sites before landing",
    "dynamic.hidden_from_automation": "The linked page hid itself from our inspection, which real pages do not do",
    "attachment.dangerous_type": "The attachment {filename} is a program, not a document",
    "attachment.executable_content": "The attachment {filename} is secretly a program",
    "attachment.macros": "The attachment {filename} contains hidden code that runs when opened",
    "attachment.xlm_macros": "The attachment {filename} contains hidden macro code",
    "attachment.remote_template": "The attachment {filename} fetches hidden content from the internet when opened",
    "attachment.dde": "The attachment {filename} launches another program when opened",
    "attachment.pdf_javascript": "The attachment {filename} contains script that runs when opened",
    "attachment.pdf_launch": "The attachment {filename} tries to start a program when opened",
    "attachment.archive_password_in_body": "The attachment {filename} is a locked archive with the password in the email, a trick to hide its contents from scanners",
    "attachment.archive_dangerous_entry": "The attachment {filename} contains a program inside it",
    "attachment.html_smuggling": "The attachment {filename} secretly assembles a file inside your browser",
    "attachment.html_credential_form": "The attachment {filename} is a sign-in page sent as a file",
    "attachment.type_mismatch": "The attachment {filename} is not the kind of file its name claims",
    "attachment.double_extension": "The attachment {filename} hides its real file type behind a fake one",
    "attachment.disk_image": "The attachment {filename} is a disk image, a common malware wrapper",
    "attachment.rtf_object": "The attachment {filename} carries an embedded object used in exploits",
    "attachment.svg_script": "The attachment {filename} is an image file containing script",
    "bec.payment_change": "It asks you to send money to new bank details",
    "bec.gift_card": "It asks for gift cards or card codes",
    "bec.payroll_change": "It asks to change payroll or deposit details",
    "bec.from_lookalike_contact": "It comes from {host}, a copycat of your contact's {domain}",
    "bec.executive_opener": "It reads like a 'quick favour' request used to set up a scam",
    "bec.urgency_secrecy": "It demands speed and secrecy, the pattern of a scam",
    "bec.channel_switch": "It asks to move the conversation to WhatsApp or a personal address",
    "bec.signature_domain_mismatch": "Its signature names a company that does not match the sending address",
    "bec.llm_assessment": "It reads like a scam",
    "sender.display_brand_impersonation": "It pretends to be {brand} but was not sent by them",
    "sender.display_contact_impersonation": "It uses the name of someone you know but a different address",
    "sender.display_contains_other_address": "The sender name shows a different email address than the real one",
    "sender.domain_lookalike": "The sender's address imitates {domain}",
    "sender.freemail_company_name": "It claims to be from a company but was sent from a personal webmail account",
    "sender.reply_to_mismatch": "Replies would go to a different address than the sender's",
    "auth.dmarc_fail": "The sender's own mail system says this message is not genuine",
    "auth.dkim_fail": "The message's digital signature does not check out",
    "dynamic.unavailable": "We could not open one of its links to check it",
    "policy.blocked_sender": "The sender is on your block list",
    "dynamic.clickfix": "The link opens a fake 'I'm not a robot' check that tries to make you paste a command into your computer",
    "dynamic.clipboard_hijack": "The link secretly copies a dangerous command to your clipboard",
    "dynamic.fake_captcha": "The link opens a fake 'I'm not a robot' check",
    "dynamic.tech_support_scam": "The link opens a fake virus warning that tells you to call scammers",
    "dynamic.wallet_drainer": "The link opens a page that tries to empty a crypto wallet",
    "dynamic.aitm_proxy": "The link opens a copy of the {brand} sign-in page that steals passwords and security codes",
    "dynamic.free_hosting_login": "The link opens a sign-in page on a free website service",
    "dynamic.device_code_lure": "The link asks you to type a code that would let someone else into your account",
    "bec.device_code_lure": "It asks you to type a code that would let someone else into your account",
    "url.oauth_consent_lure": "A link asks you to give an app access to your email or files",
    "bec.callback_scam": "It is a fake bill that wants you to call a phone number",
    "attachment.svg_phish": "The attachment {filename} is an 'image' that opens a fake sign-in page",
    "attachment.html_clickfix": "The attachment {filename} tries to make you paste a command into your computer",
    "attachment.filename_trick": "The attachment {filename} hides its real file type",
    "dynamic.notification_spam": "The link asks to send you notifications, a trick used for fake virus alerts",
    "dynamic.captcha_gated_login": "The link hides a sign-in page behind a 'verify you are human' check",
}
_IGNORED_FOR_SUMMARY = frozenset(
    {"sender.first_seen", "auth.dmarc_none", "auth.dkim_none", "auth.spf_none", "auth.missing", "subject.urgency",
     "header.date_skew", "url.insecure_http", "url.opaque_token_unknown_host", "url.credential_words",
     "url.suspicious_tld", "url.many_subdomains", "dynamic.blocked", "dynamic.many_third_parties",
     "attachment.html_attachment", "attachment.pdf_external_links", "attachment.empty", "attachment.oversized",
     "url.free_hosting", "url.open_redirect", "url.hidden_characters", "dynamic.anti_analysis", "dynamic.ua_cloaking"}
)


_BRAND_DISPLAY = {
    "americanexpress": "American Express", "bankofamerica": "Bank of America", "wellsfargo": "Wells Fargo",
    "capitalone": "Capital One", "morganstanley": "Morgan Stanley", "goldmansachs": "Goldman Sachs",
    "jpmorgan": "JPMorgan", "docusign": "DocuSign", "paypal": "PayPal", "linkedin": "LinkedIn", "whatsapp": "WhatsApp",
    "fedex": "FedEx", "usps": "USPS", "ups": "UPS", "dhl": "DHL", "irs": "the IRS", "ssa": "Social Security",
    "att": "AT&T", "tmobile": "T-Mobile", "bestbuy": "Best Buy", "americanairlines": "American Airlines",
    "hellosign": "HelloSign", "godaddy": "GoDaddy", "intuit": "Intuit", "mcafee": "McAfee", "ebay": "eBay",
    "wetransfer": "WeTransfer", "sharefile": "ShareFile", "adp": "ADP", "okta": "Okta", "citi": "Citi",
}


def brand_display_name(brand: str) -> str:
    return _BRAND_DISPLAY.get(brand.lower(), brand.title())


def _who(parsed: ParsedMessage, signals: Sequence[Signal]) -> str:
    for s in signals:
        brand = s.evidence.get("brand")
        if brand:
            return brand_display_name(str(brand))
    if parsed.from_name:
        return truncate(parsed.from_name, 40)
    return parsed.from_address or "an unknown sender"


def _fill(template: str, signal: Signal, parsed: ParsedMessage) -> str:
    ev = signal.evidence
    brand = brand_display_name(str(ev["brand"])) if ev.get("brand") else "a company"
    filename = truncate(str(ev.get("filename") or "it"), 40)
    host = str(ev.get("final_host") or ev.get("host") or "")
    if not host and ev.get("url"):
        host = urlsplit(str(ev["url"])).hostname or ""
    if not host:
        host = parsed.from_domain or "an unknown site"
    domain = str(ev.get("target_domain") or ev.get("domain") or "a trusted site")
    days = str(ev.get("age_days", "a few"))
    return template.format(brand=brand, filename=filename, host=host, domain=domain, days=days, sender=parsed.from_address)


def summarize(
    level: VerdictLevel,
    lane: TriageLane,
    top_signals: Sequence[Signal],
    llm_summary: str | None,
    parsed: ParsedMessage,
) -> str:
    """One or two short sentences for the client: what it pretends to be, what it does, what we did."""
    action = _ACTIONS[level]
    if level is VerdictLevel.SAFE:
        if lane is TriageLane.TRUSTED:
            return f"This email is from {_who(parsed, ())}, a sender we recognise and could verify. {action}"
        if lane is TriageLane.RELEASE_FAST:
            return f"This email from {_who(parsed, ())} has no links or attachments. {action}"
        return f"This email from {_who(parsed, ())} looks ordinary. {action}"

    meaningful = [s for s in sorted(top_signals, key=lambda s: -s.weight) if s.weight > 0 and s.code not in _IGNORED_FOR_SUMMARY]
    if llm_summary and level in (VerdictLevel.MALICIOUS, VerdictLevel.SUSPICIOUS):
        first = truncate(llm_summary.strip(), 240).rstrip(".!")
        return f"{first}. {action}"

    if not meaningful:
        if level is VerdictLevel.UNKNOWN:
            return f"We could not fully check this email from {_who(parsed, ())}. {action}"
        return f"This email from {_who(parsed, ())} shows several small warning signs. {action}"

    primary = meaningful[0]
    who = _who(parsed, meaningful)
    opener = ""
    impersonation_codes = {
        "sender.display_brand_impersonation", "sender.domain_lookalike", "url.lookalike", "dynamic.credential_phish",
        "sender.display_contact_impersonation", "bec.from_lookalike_contact", "dynamic.aitm_proxy",
    }
    if any(s.code in impersonation_codes for s in meaningful):
        opener = f"This email pretends to be from {who}. "
    template = _REASONS.get(primary.code, "It shows signs of a scam ({host})")
    if primary.code == "url.display_mismatch" and primary.evidence.get("shown_domain") and primary.evidence.get("impersonates"):
        template = "A link pretends to go to " + str(primary.evidence["shown_domain"]) + " but goes somewhere else"
    reason = _fill(template, primary, parsed)
    reason = reason[0].upper() + reason[1:]
    second = ""
    for s in meaningful[1:]:
        if s.code in _REASONS and _family(s.code) != _family(primary.code):
            second = _fill(_REASONS[s.code], s, parsed)
            second = ", and " + second[0].lower() + second[1:]
            break
    return f"{opener}{reason}{second}. {action}"


_FAMILIES = {"url": "link", "dynamic": "link", "attachment": "attachment", "bec": "content", "sender": "sender",
             "auth": "sender", "policy": "policy"}


def _family(code: str) -> str:
    """Group signal codes so a summary does not say the same thing twice about one link."""
    return _FAMILIES.get(code.split(".", 1)[0], code)


# --------------------------------------------------------------------------- per-item verdicts


def url_verdict(
    url: ExtractedUrl,
    signals: Sequence[Signal],
    *,
    result: DetonationResult | None = None,
    detonated: bool = False,
    job_id: str | None = None,
    unavailable: bool = False,
) -> UrlVerdict:
    score = score_signals(signals)
    level = level_for_score(score)
    if unavailable and score < MALICIOUS_THRESHOLD:
        level = VerdictLevel.UNKNOWN
    final_url = None
    screenshot = None
    if result is not None:
        screenshot = result.screenshot_ref
        if result.features and result.features.final_url:
            final_url = result.features.final_url
        elif result.redirects:
            final_url = result.redirects[-1].url
    return UrlVerdict(
        url=url.normalized,
        level=level,
        score=score,
        signals=list(signals),
        final_url=final_url,
        screenshot_ref=screenshot,
        detonation_job_id=job_id,
        detonated=detonated,
    )


def attachment_verdict(
    att: Attachment, signals: Sequence[Signal], *, job_id: str | None = None, unavailable: bool = False
) -> AttachmentVerdict:
    score = score_signals(signals)
    level = level_for_score(score)
    if unavailable and score < MALICIOUS_THRESHOLD:
        level = VerdictLevel.UNKNOWN
    return AttachmentVerdict(
        filename=att.filename, sha256=att.sha256, level=level, score=score, signals=list(signals), detonation_job_id=job_id
    )

"""Sender trust: who vouched for a message, and how much that may excuse.

Why this module exists
----------------------
Our heuristics read like a fraud analyst's checklist: "mentions gift cards",
"the link text names another site", "the link bounces through three domains",
"the page hides from robots". Every one of those is also true of ordinary
marketing mail from a large company. Walmart order confirmations mention gift
cards; a blood bank's newsletter links "bigten.org/abbott" to its own donation
site; a financial newsletter routes every link through a click tracker and
lands on a page with a bot wall. Scored naively, real mail from walmart.com,
rei.com, fool.com and bloodworksnw.org was labelled Suspicious.

The rule
--------
``authenticated_bulk_sender`` is true when, and only when:

1. DMARC passed and is aligned with the From domain (Google checked that the
   message really came from the domain in the From line, and the receiver's
   ``header.from`` agrees with what we parsed), and
2. the message is mailing-list mail: a ``List-Unsubscribe`` header,
   ``Precedence: bulk/list``, or the fingerprints of an email service provider
   (Mailgun, SparkPost, SendGrid, Amazon SES, Salesforce, Iterable, ...), and
3. the sender's own domain is not a lookalike of a brand or of a contact, and
   the display name is not impersonating a brand or a contact.

For such mail the *heuristic* signals are switched off or capped:

* BEC wording (gift cards, urgency, "signature names another company",
  "invoice from a new sender", ...) is not counted.
* A link whose text names another site is cheap (5) when the link really goes
  to the sender's own verified domain or through a known tracking service.
* "Long tracking code" signals are not raised for the sender's own domain or
  for tracking services, and are counted once per domain otherwise.
* Sandbox *behaviour* that big marketing sites show (redirect chains through
  trackers, bot walls, slow pages, script-heavy landing pages, forms posting
  to a marketing platform) adds at most 15 points in total.

Never switched off, for anyone, by any trust:

* known-bad intel hits (blocklists, Safe Browsing, URLhaus, known-bad files),
* lookalike / brand-impersonation / contact-impersonation signals,
* a password form on a site that is not the brand it shows, any password form
  on an unfamiliar site, and malicious downloads seen in the sandbox,
* dangerous attachments (every ``attachment.*`` signal),
* links to sites registered in the last 30 days, raw IP addresses, links that
  carry their own code, and requests to change bank details,
* failed authentication, and the client's own block list.

Threat model
------------
* An attacker cannot pass DMARC alignment for walmart.com without controlling
  Walmart's mail infrastructure, so "verified as walmart.com" is a fact, not a
  claim. Spoofed mail (``From: help@walmart.com`` sent from elsewhere) fails
  alignment and gets none of the benefits above.
* An attacker CAN pass DMARC for a domain they own, add List-Unsubscribe and
  send through Mailgun. That is why condition 3 exists and why the lookalike
  and impersonation checks stay fully active: ``walmart-orders-help.com``
  passing DMARC for itself is still flagged as a Walmart lookalike, and a
  password page for another brand still lands the message in Quarantine.
* An attacker who owns a plain, unrelated domain with perfect authentication
  loses only the cheap wording heuristics. Everything that actually harms the
  client (a credential page, a download, a new domain, a known-bad site, a
  bank-detail change) still counts in full.
* A compromised account at a real company (vendor email compromise) is the
  case trust must never excuse; the protected list above is what catches it.

Client feedback
---------------
The same object carries what the client told us ("This is safe" / "This is
fake"); see :class:`reddysec.models.ClientFeedback`. A trusted *domain* only
helps mail that is verified as coming from that domain (spoof protection); a
weakly trusted *address* (from an unverified message) only lowers the score a
little and never stops the sandbox. Blocks always apply, except a block made
from an unverified message, which only catches unverified mail (the address
may have been forged; the real owner's verified mail still arrives). Trust is never
applied when a protected signal of real weight is present, so "you said you
trust this sender" cannot hide a credential page sent from a hacked account.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from reddysec.models import ClientFeedback, ExtractedUrl, ParsedMessage, Signal, SignalStage

from .common import is_freemail, make_signal
from .domains import brand_for_domain, lookalike_analysis
from .intel import is_popular, is_tracking_domain
from .urls import registrable_domain

# --------------------------------------------------------------------------- vocabulary

# Signals no trust may soften. Every ``attachment.*`` code is protected too.
PROTECTED_CODES: frozenset[str] = frozenset(
    {
        "url.known_bad",
        "url.lookalike",
        "url.dangerous_scheme",
        "url.ip_literal",
        "url.punycode",
        "url.new_domain",
        "sender.domain_lookalike",
        "sender.display_brand_impersonation",
        "sender.display_contact_impersonation",
        "sender.display_contains_other_address",
        "sender.missing_from",
        "bec.from_lookalike_contact",
        "bec.payment_change",
        "bec.llm_assessment",
        "dynamic.credential_phish",
        "dynamic.password_unknown_host",
        "dynamic.dangerous_download",
        "dynamic.new_domain",
        "dynamic.file_network_activity",
        "auth.dmarc_fail",
        "auth.dkim_fail",
        "auth.spf_fail",
        "policy.blocked_sender",
        "history.client_blocked",
    }
)
PROTECTED_PREFIXES: tuple[str, ...] = ("attachment.", "engine.")

# Signals that mean "this sender is pretending to be someone": no sender-level
# trust (bulk or client) is granted to a message that carries one.
IMPERSONATION_CODES: frozenset[str] = frozenset(
    {
        "sender.domain_lookalike",
        "sender.display_brand_impersonation",
        "sender.display_contact_impersonation",
        "sender.display_contains_other_address",
        "bec.from_lookalike_contact",
    }
)

# Heuristics that ordinary mailing-list mail trips. Off for authenticated bulk senders.
BULK_SOFT_CODES: frozenset[str] = frozenset(
    {
        "bec.gift_card",
        "bec.signature_domain_mismatch",
        "bec.urgency_secrecy",
        "bec.secrecy",
        "bec.executive_opener",
        "bec.invoice_first_time",
        "bec.wire_request",
        "bec.channel_switch",
        "bec.payroll_change",
        "subject.urgency",
        "sender.first_seen",
        "sender.reply_to_mismatch",
        "sender.return_path_mismatch",
        "header.date_skew",
    }
)

# What big marketing sites do in a sandbox. For authenticated bulk senders their
# combined contribution is capped at BULK_DYNAMIC_CAP.
SOFT_DYNAMIC_CODES: frozenset[str] = frozenset(
    {
        "dynamic.redirect_chain",
        "dynamic.redirect_offsite",
        "dynamic.hidden_from_automation",
        "dynamic.unavailable",
        "dynamic.client_redirect",
        "dynamic.many_third_parties",
        "dynamic.external_form_action",
        "dynamic.obfuscated_js",
        "dynamic.hidden_text",
        "dynamic.qr_on_page",
        "dynamic.young_domain",
        "dynamic.unexpected_download",
    }
)
BULK_DYNAMIC_CAP = 15

# A link that only *looks* odd (text names another site) but goes to the
# sender's own verified domain or through a known tracker.
BENIGN_DISPLAY_MISMATCH_WEIGHT = 5
DISPLAY_MISMATCH_WEIGHT = 35
DISPLAY_IMPERSONATION_WEIGHT = 60

CLIENT_TRUSTED_DOMAIN_WEIGHT = -30
CLIENT_TRUSTED_ADDRESS_WEIGHT = -20
CLIENT_BLOCKED_WEIGHT = 100
# Trust is withheld when any protected signal at least this strong is present.
TRUST_WITHHELD_AT = 35

# Email service provider fingerprints. Any header with one of these names or
# prefixes marks mailing-list infrastructure. Header names are lowercase.
ESP_HEADERS: frozenset[str] = frozenset(
    {
        "feedback-id",
        "x-feedback-id",
        "list-id",
        "x-campaign-id",
        "x-campaignid",
        "x-job",
        "x-msfbl",
        "x-csa-complaints",
        "x-ses-outgoing",
        "x-sg-eid",
        "x-sg-id",
        "x-mc-user",
        "x-pm-message-id",
        "x-rpcampaign",
        "x-listmember",
        "x-sfmc-stack",
    }
)
ESP_HEADER_PREFIXES: tuple[str, ...] = (
    "x-mailgun-",
    "x-sparkpost-",
    "x-msys-",
    "x-sg-",
    "x-ses-",
    "x-mandrill-",
    "x-mc-",
    "x-sfmc",
    "x-mkto",
    "x-marketo",
    "x-iterable",
    "x-braze",
    "x-klaviyo",
    "x-hubspot",
    "x-hs-",
    "x-emarsys",
    "x-responsys",
    "x-eloqua",
    "x-campaign",
    "x-mailjet",
    "x-postmark",
    "x-cmae",
)
_ESP_MAILER_RE = re.compile(
    r"mailchimp|sendgrid|mailgun|sparkpost|amazon ses|salesforce|exacttarget|marketo|hubspot|iterable|braze|"
    r"klaviyo|sailthru|constant ?contact|campaign ?monitor|mailjet|sendinblue|brevo|postmark|emarsys|responsys|"
    r"eloqua|acoustic|cheetah|substack|beehiiv|convertkit",
    re.IGNORECASE,
)
_BULK_PRECEDENCE = frozenset({"bulk", "list"})

# Senders that carry many unrelated people's mail. Trusting the whole domain
# would trust every user of the service (anyone can share a Google Doc or send
# a PayPal invoice), so "This is safe" on one of these trusts the address only.
SHARED_PLATFORM_DOMAINS: frozenset[str] = frozenset(
    {
        "google.com", "googlemail.com", "googlegroups.com", "youtube.com", "microsoft.com", "office.com",
        "office365.com", "sharepoint.com", "onmicrosoft.com", "microsoftonline.com", "live.com", "outlook.com",
        "hotmail.com", "docusign.net", "docusign.com", "paypal.com", "venmo.com", "dropbox.com", "dropboxmail.com",
        "box.com", "facebookmail.com", "facebook.com", "linkedin.com", "amazonses.com", "sendgrid.net",
        "mailchimp.com", "mcsv.net", "mailgun.org", "wetransfer.com", "notion.so", "canva.com", "zoom.us",
        "calendly.com", "intuit.com", "squareup.com", "square.com", "stripe.com", "github.com", "slack.com",
        "eventbrite.com", "surveymonkey.com", "typeform.com", "apple.com", "icloud.com", "adobe.com",
        "adobesign.com", "hellosign.com", "evite.com", "paperlesspost.com", "wixsite.com", "substack.com",
    }
)


def is_shared_platform(domain: str) -> bool:
    rd = registrable_domain(domain) if domain else ""
    return bool(rd) and (rd in SHARED_PLATFORM_DOMAINS or is_freemail(rd) or is_tracking_domain(rd))


def is_protected(signal: Signal | str) -> bool:
    """Protected signals are never softened by any trust (see the module docstring)."""
    if isinstance(signal, Signal):
        if signal.code == "url.display_mismatch" and signal.evidence.get("impersonates"):
            return True  # link text names a brand's site, href goes elsewhere
        code = signal.code
    else:
        code = signal
    return code in PROTECTED_CODES or code.startswith(PROTECTED_PREFIXES)


# --------------------------------------------------------------------------- assessment


@dataclass(frozen=True)
class SenderTrust:
    """What we can vouch for about a message's sender. See the module docstring."""

    from_address: str = ""
    from_domain: str = ""  # registrable domain of the From address
    aligned_domain: str = ""  # same, but only when DMARC verified it; else ""
    bulk: bool = False
    bulk_evidence: str = ""
    impersonation: bool = False
    client_trust: str | None = None  # "domain" | "address" | None
    client_blocked: str | None = None  # "domain" | "address" | None

    @property
    def authenticated(self) -> bool:
        return bool(self.aligned_domain)

    @property
    def authenticated_bulk_sender(self) -> bool:
        return self.authenticated and self.bulk and not self.impersonation

    @property
    def trusted_domain(self) -> bool:
        return self.client_trust == "domain"

    def owns(self, domain: str) -> bool:
        """``domain`` (any host) is on the sender's verified domain."""
        return bool(self.aligned_domain) and registrable_domain(domain) == self.aligned_domain


def verified_domain(parsed: ParsedMessage) -> str:
    """The From domain's registrable domain when DMARC passed and is aligned, else ``""``."""
    auth = parsed.auth
    if auth.dmarc != "pass" or not auth.aligned or not parsed.from_domain:
        return ""
    from_rd = registrable_domain(parsed.from_domain)
    if auth.dmarc_from and registrable_domain(auth.dmarc_from) != from_rd:
        return ""  # the receiver verified some other domain than the one we read
    return from_rd


def bulk_evidence(parsed: ParsedMessage) -> str:
    """Why we think this is mailing-list mail, or ``""``."""
    headers = parsed.headers
    if parsed.has_list_unsubscribe or "list-unsubscribe" in headers:
        return "List-Unsubscribe"
    precedence = headers.get("precedence", "").strip().lower()
    if precedence in _BULK_PRECEDENCE:
        return f"Precedence: {precedence}"
    for name in headers:
        if name in ESP_HEADERS or name.startswith(ESP_HEADER_PREFIXES):
            return name
    mailer = headers.get("x-mailer", "")
    if mailer and _ESP_MAILER_RE.search(mailer):
        return "x-mailer"
    return ""


def _impersonating(parsed: ParsedMessage, contact_domains: Iterable[str], sender_signals: Sequence[Signal]) -> bool:
    if any(s.code in IMPERSONATION_CODES and s.weight > 0 for s in sender_signals):
        return True
    if not parsed.from_domain:
        return False
    return lookalike_analysis(parsed.from_domain, contact_domains=tuple(contact_domains)).is_lookalike


def _norm_domains(values: Iterable[str]) -> set[str]:
    return {registrable_domain(v.strip().lower().lstrip("@")) for v in values if v and v.strip()}


def _norm_addresses(values: Iterable[str]) -> set[str]:
    return {v.strip().lower() for v in values if v and "@" in v}


def assess_sender(
    parsed: ParsedMessage,
    *,
    contact_domains: Iterable[str] = (),
    feedback: ClientFeedback | None = None,
    sender_signals: Sequence[Signal] = (),
) -> SenderTrust:
    """Build the :class:`SenderTrust` for one message. Pure and offline."""
    address = parsed.from_address.strip().lower()
    from_rd = registrable_domain(parsed.from_domain) if parsed.from_domain else ""
    aligned = verified_domain(parsed)
    evidence = bulk_evidence(parsed)
    impersonation = _impersonating(parsed, contact_domains, sender_signals)

    trust: str | None = None
    blocked: str | None = None
    if feedback is not None and not feedback.is_empty:
        if address and address in _norm_addresses(feedback.blocked_addresses):
            blocked = "address"
        elif address and not aligned and address in _norm_addresses(feedback.blocked_unverified_addresses):
            blocked = "address"
        elif from_rd and (from_rd in _norm_domains(feedback.blocked_domains)):
            blocked = "domain"
        if blocked is None and not impersonation:
            if aligned and aligned in _norm_domains(feedback.trusted_domains):
                trust = "domain"
            elif address and aligned and address in _norm_addresses(feedback.verified_addresses):
                trust = "address"
            elif address and address in _norm_addresses(feedback.trusted_addresses):
                trust = "address"
    return SenderTrust(
        from_address=address,
        from_domain=from_rd,
        aligned_domain=aligned,
        bulk=bool(evidence),
        bulk_evidence=evidence,
        impersonation=impersonation,
        client_trust=trust,
        client_blocked=blocked,
    )


# --------------------------------------------------------------------------- per-link rules


def display_mismatch_assessment(url: ExtractedUrl, sender: SenderTrust | None) -> tuple[int, str | None]:
    """How much a "link text names another site" finding is worth, and which
    brand the text pretends to be (or ``None``).

    * Cheap (5) when the href stays on the sender's own verified domain: the
      sender can only send the reader to itself, which is what the reader
      expects (``<a href="https://donate.bloodworksnw.org/..">bigten.org/abbott</a>``
      from verified bloodworksnw.org).
    * Through a known tracking service, from a verified sender: cheap when the
      text names the sender's own site or an unknown one; 35 when it names a
      bank or another well-known site, because a tracker can forward anywhere.
    * Otherwise, text naming a brand's site (``chase.com``) over a link that
      goes somewhere that brand does not own is impersonation: 60, and
      protected from every kind of trust.
    * Anything else: 35.
    """
    host = url.host or url.registrable_domain
    shown = shown_domain(url.display_text)
    shown_brand = brand_for_domain(shown) if shown else None
    impersonated = None
    if shown_brand is not None and brand_for_domain(url.registrable_domain) != shown_brand:
        impersonated = shown_brand
    if sender is not None and sender.authenticated:
        if sender.owns(host):
            return BENIGN_DISPLAY_MISMATCH_WEIGHT, None
        if is_tracking_domain(host):
            if shown and shown != sender.aligned_domain and (shown_brand is not None or is_popular(shown)):
                return DISPLAY_MISMATCH_WEIGHT, None
            return BENIGN_DISPLAY_MISMATCH_WEIGHT, None
    if impersonated is not None:
        return DISPLAY_IMPERSONATION_WEIGHT, impersonated
    return DISPLAY_MISMATCH_WEIGHT, None


_SHOWN_RE = re.compile(r"^(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)", re.IGNORECASE)


def shown_domain(text: str | None) -> str:
    if not text:
        return ""
    m = _SHOWN_RE.match(text.strip().lower())
    return registrable_domain(m.group(1)) if m else ""


def skip_opaque_token(url: ExtractedUrl, sender: SenderTrust | None) -> bool:
    """No "long tracking code" signal for the sender's own verified domain or trackers."""
    if is_tracking_domain(url.registrable_domain):
        return True
    return sender is not None and sender.owns(url.host or url.registrable_domain)


# --------------------------------------------------------------------------- adjustments


def _soften(signal: Signal, weight: int, reason: str) -> Signal:
    if signal.weight == weight:
        return signal
    evidence = {**signal.evidence, "softened_by": reason, "original_weight": signal.weight}
    return signal.model_copy(update={"weight": weight, "evidence": evidence})


def soften_static(signals: Sequence[Signal], sender: SenderTrust) -> list[Signal]:
    """Static (sender, BEC, link, attachment) signals after sender trust."""
    out: list[Signal] = []
    for s in signals:
        if s.weight <= 0 or is_protected(s):
            out.append(s)
        elif sender.trusted_domain:
            out.append(_soften(s, 0, "client_trusted_domain"))
        elif sender.authenticated_bulk_sender and s.code in BULK_SOFT_CODES:
            out.append(_soften(s, 0, "authenticated_bulk_sender"))
        else:
            out.append(s)
    return out


def soften_dynamic(signals: Sequence[Signal], sender: SenderTrust) -> list[Signal]:
    """Sandbox signals after sender trust: off for client-trusted domains, capped for bulk senders."""
    out: list[Signal] = []
    for s in signals:
        if s.weight <= 0 or is_protected(s):
            out.append(s)
        elif sender.trusted_domain:
            out.append(_soften(s, 0, "client_trusted_domain"))
        else:
            out.append(s)
    if sender.authenticated_bulk_sender and not sender.trusted_domain:
        out = cap_soft_dynamic(out)
    return out


def cap_soft_dynamic(signals: Sequence[Signal], cap: int = BULK_DYNAMIC_CAP) -> list[Signal]:
    """Keep the single strongest soft sandbox signal at ``min(weight, cap)`` and
    zero the rest, so their combined contribution can never exceed ``cap``."""
    soft = [i for i, s in enumerate(signals) if s.code in SOFT_DYNAMIC_CODES and s.weight > 0]
    if not soft:
        return list(signals)
    keep = max(soft, key=lambda i: signals[i].weight)
    out = list(signals)
    for i in soft:
        target = min(signals[i].weight, cap) if i == keep else 0
        out[i] = _soften(signals[i], target, "authenticated_bulk_sender")
    return out


def dedupe_opaque_tokens(url_static: dict[str, list[Signal]]) -> None:
    """One "long tracking code" signal per registrable domain, not one per link."""
    seen: set[str] = set()
    for key, sigs in url_static.items():
        kept: list[Signal] = []
        for s in sigs:
            if s.code == "url.opaque_token_unknown_host":
                rd = registrable_domain(str(s.evidence.get("domain") or "")) or key
                if rd in seen:
                    continue
                seen.add(rd)
            kept.append(s)
        url_static[key] = kept


def trust_signals(sender: SenderTrust, protected_weight: int) -> list[Signal]:
    """Positive evidence about the sender ("good signs") and the client's own verdicts."""
    out: list[Signal] = []
    if sender.client_blocked:
        what = sender.from_domain if sender.client_blocked == "domain" else sender.from_address
        out.append(
            make_signal(
                "history.client_blocked", SignalStage.HISTORY, CLIENT_BLOCKED_WEIGHT,
                "You marked this sender as fake",
                f"You told us mail from {what} is fake, so we put it in Quarantine.",
                scope=sender.client_blocked, value=what,
            )
        )
        return out
    if sender.client_trust:
        domain_scope = sender.client_trust == "domain"
        what = sender.aligned_domain if domain_scope else sender.from_address
        weight = CLIENT_TRUSTED_DOMAIN_WEIGHT if domain_scope else CLIENT_TRUSTED_ADDRESS_WEIGHT
        detail = f"You told us mail from {what} is safe."
        if protected_weight >= TRUST_WITHHELD_AT:
            weight = 0
            detail += " We did not count that this time because we found a serious problem."
        out.append(
            make_signal(
                "history.client_trusted", SignalStage.HISTORY, weight,
                "You told us you trust this sender", detail, scope=sender.client_trust, value=what,
            )
        )
    if sender.authenticated_bulk_sender:
        out.append(
            make_signal(
                "sender.authenticated_bulk", SignalStage.STATIC, 0,
                f"A mailing list verified as {sender.aligned_domain}",
                "Google confirmed the sender, and it is ordinary mailing-list mail, so wording that is "
                "normal in newsletters and receipts did not count against it.",
                domain=sender.aligned_domain, evidence_header=sender.bulk_evidence,
            )
        )
    return out


def protected_weight(signals: Iterable[Signal]) -> int:
    return max((s.weight for s in signals if s.weight > 0 and is_protected(s)), default=0)

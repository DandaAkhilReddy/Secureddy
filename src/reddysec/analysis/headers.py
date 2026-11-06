"""Sender and header signals.

These are the cheapest checks and the ones a careful human would do first:
who does this claim to be from, does the mail system vouch for it, and does
the reply go back to the same place. They run for every message, including
the ones with no links or attachments, because wire-fraud mail has neither.

Weights are modest on purpose. Authentication failures and display-name
tricks are strong *in combination*; alone they are common in clumsy but
legitimate mail (a small business whose IT never set up DMARC).
"""

from __future__ import annotations

import re
from datetime import timedelta

from reddysec.models import ParsedMessage, SenderHistory, Signal, SignalStage

from .common import EMAIL_RE, is_freemail, looks_like_company, make_signal
from .domains import brand_for_domain, brands_mentioned, legit_domains_for, lookalike_analysis
from .urls import registrable_domain

# Brand keywords that double as first names or ordinary words. A display name
# consisting only of such a word (a person called Chase) is not impersonation.
_AMBIGUOUS_BRANDS: frozenset[str] = frozenset({"chase", "delta", "united", "target", "meta", "box", "zelle", "marcus"})

_URGENCY_RE = re.compile(
    r"\b(?:urgent(?:ly)?|immediately|immediate action|final (?:notice|warning|reminder)|last (?:chance|warning)|"
    r"account (?:has been |will be |is )?(?:suspended|locked|disabled|closed|limited|compromised|deactivated)|"
    r"verify(?: your)?(?: account| identity| email)?|verification required|action required|action needed|"
    r"respond (?:now|today|within)|expires? (?:today|tonight|in \d+ hours?|soon)|unusual (?:sign-in|login|activity)|"
    r"suspicious activity|payment (?:failed|declined|overdue)|unpaid invoice|past due|security alert|"
    r"your (?:password|account|access) (?:will|has) (?:expire|been)|confirm your|update your (?:account|payment|billing))\b",
    re.IGNORECASE,
)
_DATE_FUTURE_SLACK = timedelta(hours=36)
_DATE_PAST_SLACK = timedelta(days=7)


def _display_name_address(display_name: str | None, from_address: str) -> str | None:
    """An email address embedded in the display name that is not the real sender."""
    if not display_name:
        return None
    for m in EMAIL_RE.finditer(display_name):
        shown = m.group(0).lower()
        if shown != from_address.lower():
            return shown
    return None


def _auth_signals(parsed: ParsedMessage) -> list[Signal]:
    auth = parsed.auth
    signals: list[Signal] = []
    if auth.spf is None and auth.dkim is None and auth.dmarc is None:
        signals.append(
            make_signal(
                "auth.missing", SignalStage.STATIC, 10,
                "Could not verify who sent this email",
                "The mailbox provider recorded no authentication results for this message.",
            )
        )
        return signals
    if auth.dmarc == "fail":
        signals.append(
            make_signal(
                "auth.dmarc_fail", SignalStage.STATIC, 40,
                f"Email failed the sender's own anti-spoofing check (DMARC) for {parsed.from_domain}",
                "The domain owner publishes a policy saying this message should not exist.",
                dmarc=auth.dmarc,
            )
        )
    elif auth.dmarc in (None, "none", "temperror", "permerror"):
        signals.append(
            make_signal(
                "auth.dmarc_none", SignalStage.STATIC, 10,
                "Sender's domain does not protect itself against spoofing (no DMARC)",
                dmarc=auth.dmarc or "absent",
            )
        )
    if auth.dkim == "fail":
        signals.append(
            make_signal(
                "auth.dkim_fail", SignalStage.STATIC, 25,
                "The email's digital signature does not match (DKIM failed)", dkim=auth.dkim,
            )
        )
    elif auth.dkim in (None, "none") and auth.dmarc != "pass":
        signals.append(
            make_signal(
                "auth.dkim_none", SignalStage.STATIC, 8, "The email carries no valid digital signature (DKIM)",
                dkim=auth.dkim or "absent",
            )
        )
    if auth.spf == "fail":
        signals.append(
            make_signal(
                "auth.spf_fail", SignalStage.STATIC, 20,
                "Sent from a server the sender's domain does not authorise (SPF failed)", spf=auth.spf,
            )
        )
    elif auth.spf == "softfail":
        signals.append(
            make_signal(
                "auth.spf_softfail", SignalStage.STATIC, 10,
                "Sent from a server the sender's domain only loosely allows (SPF soft fail)", spf=auth.spf,
            )
        )
    elif auth.spf in (None, "none") and auth.dmarc != "pass":
        signals.append(make_signal("auth.spf_none", SignalStage.STATIC, 5, "Sender's domain publishes no SPF record"))
    if auth.dmarc == "pass" and auth.aligned:
        signals.append(
            make_signal(
                "auth.dmarc_pass_aligned", SignalStage.STATIC, -15,
                f"Verified as genuinely sent by {parsed.from_domain}",
                "DMARC passed and the signing domain matches the From address.",
            )
        )
    return signals


def _history_signals(parsed: ParsedMessage, history: SenderHistory | None) -> list[Signal]:
    signals: list[Signal] = []
    if history is None or history.message_count == 0:
        signals.append(
            make_signal(
                "sender.first_seen", SignalStage.HISTORY, 5,
                f"First email from {parsed.from_address or 'this sender'}",
                "You have never received mail from this address before.",
            )
        )
        return signals
    same_address = history.address.lower() == parsed.from_address.lower()
    if same_address and history.replied_to and history.message_count >= 3:
        signals.append(
            make_signal(
                "sender.known_contact", SignalStage.HISTORY, -20,
                "Someone you correspond with regularly",
                f"{history.message_count} previous emails and you have written back.",
                message_count=history.message_count,
            )
        )
    elif same_address and history.message_count >= 5:
        signals.append(
            make_signal(
                "sender.frequent_sender", SignalStage.HISTORY, -10,
                "A sender you have received mail from before",
                f"{history.message_count} previous emails.", message_count=history.message_count,
            )
        )
    if not same_address and parsed.from_name and parsed.from_name.lower() in {n.lower() for n in history.display_names}:
        signals.append(
            make_signal(
                "sender.display_contact_impersonation", SignalStage.STATIC, 45,
                f"Uses the name of your contact {parsed.from_name} but a different address",
                f"Your contact writes from {history.address}; this came from {parsed.from_address}.",
                known_address=history.address, actual_address=parsed.from_address,
            )
        )
    return signals


def _display_name_signals(parsed: ParsedMessage) -> list[Signal]:
    signals: list[Signal] = []
    name = (parsed.from_name or "").strip()
    from_rd = registrable_domain(parsed.from_domain) if parsed.from_domain else ""
    own_brand = brand_for_domain(from_rd) if from_rd else None
    shown_address = _display_name_address(name, parsed.from_address)
    if shown_address:
        signals.append(
            make_signal(
                "sender.display_contains_other_address", SignalStage.STATIC, 40,
                f"Display name shows {shown_address} but the email came from {parsed.from_address}",
                "Attackers put a trusted address in the name field because mail apps show only the name.",
                shown=shown_address, actual=parsed.from_address,
            )
        )
    freemail = is_freemail(parsed.from_domain)
    brand_hit = False
    mentioned = brands_mentioned(name)
    for brand in mentioned:
        if own_brand == brand or from_rd in legit_domains_for(brand):
            continue
        company_like = looks_like_company(name)
        if brand in _AMBIGUOUS_BRANDS and not company_like:
            continue  # "Chase Williams" is a person, "Chase Fraud Department" is not
        # "DocuSign" or "Netflix Billing" is a flat claim to be the company;
        # "Steve from DocuSign" is a person name-dropping it, a little weaker.
        weight = 45 if company_like or len(name.split()) <= 2 else 35
        signals.append(
            make_signal(
                "sender.display_brand_impersonation", SignalStage.STATIC, weight,
                f"Claims to be {name} but was sent from {parsed.from_domain}",
                f"Real {brand} email comes from {', '.join(sorted(legit_domains_for(brand))[:3])}.",
                brand=brand, from_domain=parsed.from_domain,
            )
        )
        brand_hit = True
        break
    if freemail and not brand_hit and looks_like_company(name):
        signals.append(
            make_signal(
                "sender.freemail_company_name", SignalStage.STATIC, 35,
                f"'{name}' writes from a personal {parsed.from_domain} address",
                "Companies send from their own domain, not from a free webmail account.",
                from_domain=parsed.from_domain,
            )
        )
    return signals


def _domain_signals(parsed: ParsedMessage, contact_domains: tuple[str, ...]) -> list[Signal]:
    signals: list[Signal] = []
    if not parsed.from_domain:
        signals.append(
            make_signal("sender.missing_from", SignalStage.STATIC, 25, "The email has no usable sender address")
        )
        return signals
    look = lookalike_analysis(parsed.from_domain, contact_domains=contact_domains)
    if look.is_lookalike and not look.is_contact:
        signals.append(
            make_signal(
                "sender.domain_lookalike", SignalStage.STATIC, min(50, look.weight),
                f"Sender domain {parsed.from_domain} imitates {look.target_domain}",
                look.detail, brand=look.target, target_domain=look.target_domain, reason=look.reason.value if look.reason else None,
            )
        )
    from_rd = registrable_domain(parsed.from_domain)
    reply_domains = {registrable_domain(a.rsplit("@", 1)[-1]) for a in parsed.reply_to if "@" in a}
    foreign_reply = sorted(d for d in reply_domains if d and d != from_rd)
    if foreign_reply and not parsed.has_list_unsubscribe:
        weight = 30
        if is_freemail(foreign_reply[0]) and not is_freemail(from_rd):
            weight = 35  # company From, personal Reply-To: the BEC signature
        signals.append(
            make_signal(
                "sender.reply_to_mismatch", SignalStage.STATIC, weight,
                f"Replies go to {foreign_reply[0]}, not to the sender's {from_rd}",
                "A reply-to address on another domain diverts the conversation to the attacker.",
                reply_to=parsed.reply_to[:3], from_domain=from_rd,
            )
        )
    return_path = parsed.headers.get("return-path", "")
    m = EMAIL_RE.search(return_path)
    if m and not parsed.has_list_unsubscribe:
        rp_rd = registrable_domain(m.group(0).rsplit("@", 1)[-1])
        dkim_rd = registrable_domain(parsed.auth.dkim_domain) if parsed.auth.dkim_domain else ""
        if rp_rd and rp_rd != from_rd and rp_rd != dkim_rd:
            signals.append(
                make_signal(
                    "sender.return_path_mismatch", SignalStage.STATIC, 15,
                    f"Bounces go to {rp_rd}, a different domain than the sender",
                    return_path=rp_rd, from_domain=from_rd,
                )
            )
    return signals


def _subject_and_date_signals(parsed: ParsedMessage) -> list[Signal]:
    signals: list[Signal] = []
    if parsed.subject and _URGENCY_RE.search(parsed.subject):
        signals.append(
            make_signal(
                "subject.urgency", SignalStage.STATIC, 10,
                "Subject line pushes for urgent action",
                "Pressure to act fast is how scams stop people from thinking.",
                subject=parsed.subject[:120],
            )
        )
    if parsed.date is not None and parsed.received_at is not None:
        received = parsed.received_at
        if received.tzinfo is None:
            received = received.replace(tzinfo=parsed.date.tzinfo)
        delta = parsed.date - received
        if delta > _DATE_FUTURE_SLACK or -delta > _DATE_PAST_SLACK:
            signals.append(
                make_signal(
                    "header.date_skew", SignalStage.STATIC, 5,
                    "The email's date does not match when it arrived",
                    f"Dated {parsed.date.isoformat()}, received {received.isoformat()}.",
                )
            )
    return signals


def sender_signals(
    parsed: ParsedMessage, history: SenderHistory | None, contact_domains: tuple[str, ...] = ()
) -> list[Signal]:
    """Every sender/header signal for a message (STATIC and HISTORY stages)."""
    signals: list[Signal] = []
    signals.extend(_display_name_signals(parsed))
    signals.extend(_domain_signals(parsed, contact_domains))
    signals.extend(_auth_signals(parsed))
    signals.extend(_history_signals(parsed, history))
    signals.extend(_subject_and_date_signals(parsed))
    return signals

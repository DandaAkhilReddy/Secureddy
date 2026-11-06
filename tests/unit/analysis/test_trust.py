"""Sender trust (analysis.trust): who is verified, what is mailing-list mail,
what each kind of trust may soften, and what it never may."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from reddysec.analysis.bec import bec_signals, gift_card_request
from reddysec.analysis.common import make_signal
from reddysec.analysis.domains import brand_for_domain, lookalike_analysis
from reddysec.analysis.intel import is_brand_shortener, is_popular
from reddysec.analysis.trust import (
    BULK_DYNAMIC_CAP,
    SenderTrust,
    assess_sender,
    bulk_evidence,
    cap_soft_dynamic,
    dedupe_opaque_tokens,
    display_mismatch_assessment,
    is_protected,
    is_shared_platform,
    protected_weight,
    shown_domain,
    skip_opaque_token,
    soften_dynamic,
    soften_static,
    trust_signals,
    verified_domain,
)
from reddysec.analysis.urls import build_url
from reddysec.models import AuthResults, ClientFeedback, ParsedMessage, SignalStage, UrlSource

NOW = datetime(2026, 11, 5, tzinfo=UTC)


def msg(
    sender: str = "help@walmart.com",
    *,
    dmarc: str | None = "pass",
    aligned: bool | None = True,
    dmarc_from: str | None = None,
    headers: dict[str, str] | None = None,
    list_unsubscribe: bool = False,
    name: str | None = None,
) -> ParsedMessage:
    return ParsedMessage(
        provider_message_id="p",
        mailbox_id="m",
        received_at=NOW,
        from_address=sender,
        from_name=name,
        auth=AuthResults(dmarc=dmarc, aligned=aligned, dmarc_from=dmarc_from, spf="pass", dkim="pass"),
        headers=headers or {},
        has_list_unsubscribe=list_unsubscribe,
    )


def sig(code: str, weight: int, **ev):
    return make_signal(code, SignalStage.STATIC, weight, code, **ev)


VERIFIED_BULK = SenderTrust(
    from_address="news@rei.com", from_domain="rei.com", aligned_domain="rei.com", bulk=True, bulk_evidence="x"
)
VERIFIED_PERSON = SenderTrust(from_address="a@lawfirm.com", from_domain="lawfirm.com", aligned_domain="lawfirm.com")
UNVERIFIED = SenderTrust(from_address="a@lawfirm.com", from_domain="lawfirm.com")


class TestVerification:
    def test_dmarc_pass_aligned_is_verified(self):
        assert verified_domain(msg("help@email.walmart.com")) == "walmart.com"

    @pytest.mark.parametrize(
        "kw",
        [{"dmarc": "fail"}, {"dmarc": None}, {"aligned": False}, {"dmarc_from": "other.com"}],
    )
    def test_anything_less_is_not(self, kw):
        assert verified_domain(msg(**kw)) == ""

    def test_matching_header_from_is_fine(self):
        assert verified_domain(msg(dmarc_from="walmart.com")) == "walmart.com"

    def test_no_from_address(self):
        assert verified_domain(msg("")) == ""


class TestBulkEvidence:
    @pytest.mark.parametrize(
        ("headers", "lu", "expected"),
        [
            ({}, True, "List-Unsubscribe"),
            ({"list-unsubscribe": "<mailto:x@y>"}, False, "List-Unsubscribe"),
            ({"precedence": "Bulk"}, False, "Precedence: bulk"),
            ({"x-mailgun-sid": "abc"}, False, "x-mailgun-sid"),
            ({"x-msfbl": "abc"}, False, "x-msfbl"),
            ({"feedback-id": "1:2:3:iterable"}, False, "feedback-id"),
            ({"x-mailer": "MailChimp Mailer - **CID**"}, False, "x-mailer"),
            ({"x-mailer": "Apple Mail (2.3654)"}, False, ""),
            ({"precedence": "first-class"}, False, ""),
        ],
    )
    def test_detection(self, headers, lu, expected):
        assert bulk_evidence(msg(headers=headers, list_unsubscribe=lu)) == expected


class TestAssessSender:
    def test_authenticated_bulk_sender(self):
        t = assess_sender(msg(list_unsubscribe=True))
        assert t.authenticated and t.bulk and t.authenticated_bulk_sender
        assert t.aligned_domain == "walmart.com"

    def test_spoof_gets_nothing(self):
        t = assess_sender(msg(dmarc="fail", aligned=False, list_unsubscribe=True))
        assert not t.authenticated and not t.authenticated_bulk_sender

    def test_lookalike_passing_dmarc_for_itself_is_not_trusted_bulk(self):
        t = assess_sender(msg("orders@walrnart.com", list_unsubscribe=True))
        assert t.impersonation and not t.authenticated_bulk_sender

    def test_impersonation_signal_blocks_bulk_trust(self):
        t = assess_sender(
            msg("deals@shop-news.example", list_unsubscribe=True),
            sender_signals=[sig("sender.display_brand_impersonation", 45)],
        )
        assert t.impersonation and not t.authenticated_bulk_sender

    def test_contact_lookalike(self):
        t = assess_sender(msg("ceo@whitfieldlaw-group.com"), contact_domains=("whitfieldlawgroup.com",))
        assert t.impersonation

    def test_feedback_trusted_domain_needs_verification(self):
        fb = ClientFeedback(trusted_domains=["walmart.com"])
        assert assess_sender(msg(), feedback=fb).client_trust == "domain"
        spoof = assess_sender(msg(dmarc="fail", aligned=False), feedback=fb)
        assert spoof.client_trust is None

    def test_feedback_verified_address(self):
        fb = ClientFeedback(verified_addresses=["friend@gmail.com"])
        assert assess_sender(msg("friend@gmail.com"), feedback=fb).client_trust == "address"
        assert assess_sender(msg("friend@gmail.com", dmarc="fail", aligned=False), feedback=fb).client_trust is None
        assert assess_sender(msg("other@gmail.com"), feedback=fb).client_trust is None

    def test_feedback_weak_address_applies_unverified(self):
        fb = ClientFeedback(trusted_addresses=["Office@SmallShop.example"])
        t = assess_sender(msg("office@smallshop.example", dmarc=None, aligned=None), feedback=fb)
        assert t.client_trust == "address"

    def test_blocks(self):
        assert assess_sender(msg(), feedback=ClientFeedback(blocked_domains=["walmart.com"])).client_blocked == "domain"
        # a block on a domain applies even to unverified mail claiming it
        unverified = msg(dmarc="fail", aligned=False)
        assert assess_sender(unverified, feedback=ClientFeedback(blocked_domains=["walmart.com"])).client_blocked
        fb = ClientFeedback(blocked_addresses=["help@walmart.com"])
        assert assess_sender(msg(), feedback=fb).client_blocked == "address"

    def test_unverified_block_spares_the_real_verified_sender(self):
        fb = ClientFeedback(blocked_unverified_addresses=["boss@company.example"])
        assert assess_sender(msg("boss@company.example"), feedback=fb).client_blocked is None
        forged = msg("boss@company.example", dmarc="fail", aligned=False)
        assert assess_sender(forged, feedback=fb).client_blocked == "address"

    def test_block_wins_over_trust_and_impersonators_get_no_trust(self):
        fb = ClientFeedback(trusted_domains=["walmart.com"], blocked_addresses=["help@walmart.com"])
        t = assess_sender(msg(), feedback=fb)
        assert t.client_blocked == "address" and t.client_trust is None
        fb2 = ClientFeedback(trusted_domains=["walrnart.com"])
        assert assess_sender(msg("x@walrnart.com"), feedback=fb2).client_trust is None

    def test_empty_feedback(self):
        assert assess_sender(msg(), feedback=ClientFeedback()).client_trust is None


def _url(href: str, text: str | None):
    url = build_url(href, UrlSource.HTML_HREF, text)
    assert url is not None
    return url


class TestDisplayMismatch:
    def test_unverified_sender_is_strong(self):
        assert display_mismatch_assessment(_url("https://x.example/a", "other.example"), UNVERIFIED) == (35, None)
        assert display_mismatch_assessment(_url("https://x.example/a", "other.example"), None) == (35, None)

    def test_own_domain_is_cheap(self):
        url = _url("https://donate.bloodworksnw.org/x", "bigten.org/abbott")
        sender = SenderTrust(aligned_domain="bloodworksnw.org", from_domain="bloodworksnw.org")
        assert display_mismatch_assessment(url, sender) == (5, None)

    def test_tracker_with_unknown_or_own_text_is_cheap(self):
        assert display_mismatch_assessment(_url("https://ct.sendgrid.net/ls/click?x=1", "rei.com"), VERIFIED_BULK)[0] == 5
        assert display_mismatch_assessment(_url("https://ct.sendgrid.net/ls/click", "tinyshop.example"), VERIFIED_BULK)[0] == 5

    def test_tracker_with_famous_text_stays_35(self):
        assert display_mismatch_assessment(_url("https://ct.sendgrid.net/ls/click", "chase.com"), VERIFIED_BULK) == (35, None)
        assert display_mismatch_assessment(_url("https://ct.sendgrid.net/ls/click", "nytimes.com"), VERIFIED_BULK)[0] == 35

    def test_brand_text_to_unrelated_domain_is_impersonation(self):
        url = _url("https://acct-review.example/x", "www.chase.com/verify")
        assert display_mismatch_assessment(url, VERIFIED_PERSON) == (60, "chase")
        assert display_mismatch_assessment(url, UNVERIFIED) == (60, "chase")

    def test_brand_text_to_brand_shortener_is_not_impersonation(self):
        assert display_mismatch_assessment(_url("https://amzn.to/abc", "amazon.com"), UNVERIFIED) == (35, None)

    def test_shown_domain(self):
        assert shown_domain("https://www.BigTen.org/Abbott") == "bigten.org"
        assert shown_domain("click here") == ""
        assert shown_domain(None) == ""


class TestOpaqueTokens:
    def test_skip_for_tracker_and_own_domain(self):
        assert skip_opaque_token(_url("https://list-manage.com/track?u=abc", None), None)
        assert skip_opaque_token(_url("https://mlinks.rei.com/u/x", None), VERIFIED_BULK)
        assert not skip_opaque_token(_url("https://mlinks.rei.com/u/x", None), UNVERIFIED)
        assert not skip_opaque_token(_url("https://other.example/u/x", None), VERIFIED_BULK)

    def test_once_per_domain(self):
        groups = {
            "u1": [sig("url.opaque_token_unknown_host", 10, domain="a.example"), sig("url.shortener", 15)],
            "u2": [sig("url.opaque_token_unknown_host", 10, domain="a.example")],
            "u3": [sig("url.opaque_token_unknown_host", 10, domain="b.example")],
        }
        dedupe_opaque_tokens(groups)
        assert [s.code for s in groups["u1"]] == ["url.opaque_token_unknown_host", "url.shortener"]
        assert groups["u2"] == [] and len(groups["u3"]) == 1


class TestSoftening:
    def test_bulk_softens_wording_not_protected(self):
        out = soften_static(
            [sig("bec.gift_card", 50), sig("url.known_bad", 100), sig("subject.urgency", 10), sig("url.shortener", 15),
             sig("auth.dmarc_pass_aligned", -15)],
            VERIFIED_BULK,
        )
        weights = {s.code: s.weight for s in out}
        assert weights == {"bec.gift_card": 0, "url.known_bad": 100, "subject.urgency": 0, "url.shortener": 15,
                           "auth.dmarc_pass_aligned": -15}
        softened = next(s for s in out if s.code == "bec.gift_card")
        assert softened.evidence == {"softened_by": "authenticated_bulk_sender", "original_weight": 50}

    def test_person_sender_keeps_everything(self):
        signals = [sig("bec.gift_card", 50), sig("subject.urgency", 10)]
        assert soften_static(signals, VERIFIED_PERSON) == signals

    def test_client_trusted_domain_softens_all_heuristics(self):
        trusted = SenderTrust(aligned_domain="vendor.example", from_domain="vendor.example", client_trust="domain")
        out = soften_static([sig("bec.wire_request", 25), sig("attachment.macros", 70), sig("url.lookalike", 60)], trusted)
        assert {s.code: s.weight for s in out} == {"bec.wire_request": 0, "attachment.macros": 70, "url.lookalike": 60}
        dyn = soften_dynamic([sig("dynamic.redirect_chain", 20), sig("dynamic.credential_phish", 75)], trusted)
        assert {s.code: s.weight for s in dyn} == {"dynamic.redirect_chain": 0, "dynamic.credential_phish": 75}

    def test_brand_impersonating_link_text_is_protected(self):
        impersonating = sig("url.display_mismatch", 60, impersonates="chase")
        assert is_protected(impersonating) and not is_protected(sig("url.display_mismatch", 35))
        assert is_protected("attachment.anything") and not is_protected("bec.gift_card")

    def test_dynamic_cap_for_bulk(self):
        signals = [sig("dynamic.redirect_chain", 20), sig("dynamic.hidden_from_automation", 20),
                   sig("dynamic.external_form_action", 30), sig("dynamic.dangerous_download", 65)]
        out = soften_dynamic(signals, VERIFIED_BULK)
        soft = [s.weight for s in out if s.code != "dynamic.dangerous_download"]
        assert sorted(soft) == [0, 0, BULK_DYNAMIC_CAP]
        assert next(s for s in out if s.code == "dynamic.dangerous_download").weight == 65

    def test_dynamic_untouched_for_unverified(self):
        signals = [sig("dynamic.redirect_chain", 20), sig("dynamic.hidden_from_automation", 20)]
        assert soften_dynamic(signals, UNVERIFIED) == signals

    def test_cap_without_soft_signals(self):
        signals = [sig("dynamic.credential_phish", 75)]
        assert cap_soft_dynamic(signals) == signals


class TestTrustSignals:
    def test_blocked(self):
        t = SenderTrust(from_address="a@x.example", from_domain="x.example", client_blocked="domain")
        (s,) = trust_signals(t, 0)
        assert s.code == "history.client_blocked" and s.weight == 100 and s.evidence["value"] == "x.example"

    def test_trusted_domain_and_address(self):
        dom = SenderTrust(aligned_domain="v.example", from_domain="v.example", client_trust="domain")
        assert trust_signals(dom, 0)[0].weight == -30
        addr = SenderTrust(from_address="a@v.example", client_trust="address")
        assert trust_signals(addr, 0)[0].weight == -20

    def test_trust_withheld_when_something_serious(self):
        dom = SenderTrust(aligned_domain="v.example", from_domain="v.example", client_trust="domain")
        (s,) = trust_signals(dom, 75)
        assert s.weight == 0 and "serious problem" in s.detail

    def test_bulk_good_sign(self):
        (s,) = trust_signals(VERIFIED_BULK, 0)
        assert s.code == "sender.authenticated_bulk" and s.weight == 0

    def test_protected_weight(self):
        assert protected_weight([sig("url.known_bad", 100), sig("bec.gift_card", 50)]) == 100
        assert protected_weight([sig("bec.gift_card", 50)]) == 0


class TestSharedPlatforms:
    @pytest.mark.parametrize("domain", ["gmail.com", "google.com", "paypal.com", "sendgrid.net", "yahoo.co.uk"])
    def test_shared(self, domain):
        assert is_shared_platform(domain)

    @pytest.mark.parametrize("domain", ["walmart.com", "bloodworksnw.org", ""])
    def test_not_shared(self, domain):
        assert not is_shared_platform(domain)


class TestGiftCards:
    @pytest.mark.parametrize(
        "text",
        [
            "I need you to buy 5 Apple gift cards and send me photos of the codes",
            "Please pick up 6 Google Play cards today, scratch off the back and email me the pins.",
            "How many gift cards can you get before noon?",
            "Get two Amazon gift cards. Send pictures of the back of the cards here.",
        ],
    )
    def test_requests_fire(self, text):
        assert gift_card_request(text)

    @pytest.mark.parametrize(
        "text",
        [
            "Shop gift cards for everyone on your list.",
            "Give the gift of adventure. Gift cards available in store.",
            "Walmart eGift Card, Holiday design  Qty 1  $25.00",
            "Payment method: Gift card ending in 4417",
            "Buy a gift card and we will email it with your note.",
            "Send me the codes for the meeting room.",  # codes but no gift cards
        ],
    )
    def test_mentions_do_not(self, text):
        assert not gift_card_request(text)

    def test_bec_signal_shape(self):
        parsed = msg("x@gmail.com")
        parsed = parsed.model_copy(update={"text_body": "I need you to buy 5 Apple gift cards and send me photos of the codes"})
        (s,) = [s for s in bec_signals(parsed, None) if s.code == "bec.gift_card"]
        assert s.weight == 50 and s.evidence["phrases"]


class TestDomainData:
    def test_brand_shorteners_are_popular_and_owned(self):
        for d in ("w-mt.co", "a.co", "goo.gl", "aka.ms"):
            assert is_brand_shortener(d) and is_popular(d)
        assert brand_for_domain("w-mt.co") == "walmart" and brand_for_domain("gmail.app.goo.gl") == "google"
        assert not is_brand_shortener("bit.ly") and not is_brand_shortener("")

    def test_google_brand_tld(self):
        assert brand_for_domain("agents.google") == "google"
        assert is_popular("labs.google")
        assert not lookalike_analysis("gmail.app.goo.gl").is_lookalike
        assert not lookalike_analysis("agents.google").is_lookalike

    def test_new_popular_brands(self):
        assert is_popular("rei.com") and is_popular("fool.com") and not is_popular("bloodworksnw.org")

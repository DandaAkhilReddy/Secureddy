"""Score combination, thresholds, trust handling and plain-English summaries."""

from __future__ import annotations

from reddysec.analysis.parser import parse_raw
from reddysec.analysis.scoring import (
    attachment_verdict,
    brand_display_name,
    combine,
    dedupe_by_code,
    score_signals,
    summarize,
    url_verdict,
)
from reddysec.analysis.urls import build_url
from reddysec.models import (
    MALICIOUS_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    Attachment,
    Signal,
    SignalStage,
    TriageLane,
    UrlSource,
    VerdictLevel,
)

from .support import RECEIVED_AT, build_raw


def sig(code: str, weight: int, **ev) -> Signal:
    return Signal(code=code, stage=SignalStage.STATIC, weight=weight, title=code, evidence=ev)


class TestCombine:
    def test_empty_is_zero(self):
        assert combine([]) == 0

    def test_single_signal(self):
        assert combine([sig("a", 50)]) == 50

    def test_diminishing_returns(self):
        # 50 + 0.6*50 + 0.4*50 + 0.25*50 = 50 + 30 + 20 + 12.5 = 112.5 -> capped 100
        score = combine([sig("a", 50), sig("b", 50), sig("c", 50), sig("d", 50)])
        assert score == 100

    def test_diminishing_three(self):
        # 40 + 0.6*30 + 0.4*20 = 40 + 18 + 8 = 66
        assert combine([sig("a", 40), sig("b", 30), sig("c", 20)]) == 66

    def test_many_weak_signals_do_not_certify(self):
        score = combine([sig(f"s{i}", 10) for i in range(10)])
        assert score < SUSPICIOUS_THRESHOLD + 10  # a pile of 10s stays modest

    def test_strong_signal_floor(self):
        # A single 60 keeps the score at least 60 even with no other positives.
        assert combine([sig("strong", 60)]) >= 60

    def test_force_malicious_at_90(self):
        assert combine([sig("known_bad", 100)]) >= MALICIOUS_THRESHOLD
        assert combine([sig("known_bad", 95)]) >= MALICIOUS_THRESHOLD

    def test_trust_reduces_but_floored(self):
        # Negative trust can lower a weak score but not below zero.
        assert combine([sig("weak", 20), sig("trust", -60)]) == 0

    def test_trust_capped(self):
        # Trust reduction capped at -40, so two -60 still only remove 40.
        score = combine([sig("a", 50), sig("t1", -60), sig("t2", -60)])
        assert score == 10

    def test_trust_cannot_hide_strong_signal(self):
        # A 90 forces malicious regardless of trust.
        assert combine([sig("known_bad", 90), sig("trust", -60)]) >= MALICIOUS_THRESHOLD

    def test_cap_at_100(self):
        assert combine([sig("a", 100), sig("b", 100), sig("c", 100)]) == 100


class TestDedupe:
    def test_keeps_strongest_positive(self):
        result = dedupe_by_code([sig("url.new_domain", 15), sig("url.new_domain", 35)])
        assert len(result) == 1 and result[0].weight == 35

    def test_keeps_most_negative_trust(self):
        result = dedupe_by_code([sig("t", -10), sig("t", -20)])
        assert len(result) == 1 and result[0].weight == -20

    def test_score_signals_dedupes(self):
        # Three "new domain" hits (from three links) should count once.
        score = score_signals([sig("url.new_domain", 35), sig("url.new_domain", 35), sig("url.new_domain", 35)])
        assert score == 35


class TestBrandDisplay:
    def test_known_mappings(self):
        assert brand_display_name("docusign") == "DocuSign"
        assert brand_display_name("paypal") == "PayPal"
        assert brand_display_name("bankofamerica") == "Bank of America"
        assert brand_display_name("irs") == "the IRS"

    def test_fallback_titlecase(self):
        assert brand_display_name("netflix") == "Netflix"


def _parsed(**kw):
    return parse_raw(build_raw(**kw), provider_message_id="pm", mailbox_id="mbx", received_at=RECEIVED_AT)


class TestSummaries:
    def test_safe_release_fast(self):
        p = _parsed(from_header="Maria <maria@friend.example>", text="hi")
        s = summarize(VerdictLevel.SAFE, TriageLane.RELEASE_FAST, [], None, p)
        assert "no links or attachments" in s and "found nothing wrong" in s.lower()

    def test_safe_trusted(self):
        p = _parsed(from_header="Maria <maria@friend.example>", text="hi")
        s = summarize(VerdictLevel.SAFE, TriageLane.TRUSTED, [], None, p)
        assert "recognise" in s or "recognize" in s

    def test_malicious_brand_impersonation(self):
        p = _parsed(from_header="DocuSign <x@docusign-secure.com>", text="x")
        signals = [sig("dynamic.credential_phish", 75, brand="docusign", final_host="docusign-secure.com"),
                   sig("url.new_domain", 35, age_days=3, url="https://docusign-secure.com/x")]
        s = summarize(VerdictLevel.MALICIOUS, TriageLane.DETONATE, signals, None, p)
        assert "DocuSign" in s
        assert "Quarantine" in s

    def test_llm_summary_used(self):
        p = _parsed(from_header="X <x@gmail.com>", text="x")
        signals = [sig("bec.payment_change", 60)]
        s = summarize(VerdictLevel.MALICIOUS, TriageLane.RELEASE_FAST, signals,
                      "This message asks you to redirect a payment to a new account.", p)
        assert "redirect a payment" in s and "Quarantine" in s

    def test_suspicious_action_text(self):
        p = _parsed(from_header="X <x@gmail.com>", text="x")
        s = summarize(VerdictLevel.SUSPICIOUS, TriageLane.RELEASE_FAST, [sig("bec.gift_card", 50)], None, p)
        assert "Reading Room" in s

    def test_unknown_summary(self):
        p = _parsed(from_header="X <x@gmail.com>", text="x")
        s = summarize(VerdictLevel.UNKNOWN, TriageLane.DETONATE, [], None, p)
        assert "could not" in s.lower()

    def test_summary_is_short(self):
        p = _parsed(from_header="DocuSign <x@docusign-secure.com>", text="x")
        signals = [sig("dynamic.credential_phish", 75, brand="docusign")]
        s = summarize(VerdictLevel.MALICIOUS, TriageLane.DETONATE, signals, None, p)
        assert s.count(".") <= 4  # one or two sentences plus the action


class TestItemVerdicts:
    def test_url_verdict_levels(self):
        u = build_url("https://evil.example/x", UrlSource.HTML_HREF)
        v = url_verdict(u, [sig("url.known_bad", 100)])
        assert v.level is VerdictLevel.MALICIOUS and v.score == 100

    def test_url_verdict_unavailable_is_unknown(self):
        u = build_url("https://x.example/y", UrlSource.HTML_HREF)
        v = url_verdict(u, [sig("dynamic.unavailable", 10)], unavailable=True)
        assert v.level is VerdictLevel.UNKNOWN

    def test_url_verdict_unavailable_but_malicious_stays_malicious(self):
        u = build_url("https://x.example/y", UrlSource.HTML_HREF)
        v = url_verdict(u, [sig("url.known_bad", 100), sig("dynamic.unavailable", 10)], unavailable=True)
        assert v.level is VerdictLevel.MALICIOUS

    def test_attachment_verdict(self):
        a = Attachment(filename="x.exe", content_type="application/octet-stream", size=1, sha256="0" * 64, declared_extension="exe")
        v = attachment_verdict(a, [sig("attachment.dangerous_type", 75)])
        assert v.level is VerdictLevel.MALICIOUS and v.filename == "x.exe"

"""Plain-English copy for every signal the engine emits, the report's
sections, list reasons, decision flashes, dashboard cards and tabs."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from reddysec.models import Signal, SignalStage, TriageLane, Verdict, VerdictLevel
from reddysec.store.models import MessageRow, SenderFeedbackRow
from reddysec.web import presenters as p
from reddysec.web.queries import SenderDecision, WeeklyCounts, verified_sender_domain

SRC = Path(p.__file__).resolve().parents[1]
_CODE_RE = re.compile(r'"((?:url|dynamic|attachment|bec|sender|auth|subject|header|policy|engine|history)\.[a-z_]+)"')


def engine_codes() -> set[str]:
    codes: set[str] = set()
    for folder in ("analysis", "worker"):
        for path in (SRC / folder).glob("*.py"):
            codes |= set(_CODE_RE.findall(path.read_text()))
    # Not signal codes: Authentication-Results property names.
    return codes - {"header.d", "header.i", "header.from"}


def sig(code: str, weight: int = 40, **ev) -> Signal:
    return Signal(code=code, stage=SignalStage.STATIC, weight=weight, title=f"engine {code}", evidence=ev)


def message(level: str = "suspicious", *, verdict: dict | None = None, **kw) -> MessageRow:
    defaults = dict(id="msg_1", mailbox_id="mbx_1", provider_message_id="p", from_address="help@walmart.com",
                    subject="s", state="done", level=level, quarantined=False)
    defaults.update(kw)
    return MessageRow(verdict=verdict, **defaults)


def verdict_json(level: str = "suspicious", signals: list[Signal] | None = None, **kw) -> dict:
    v = Verdict(level=VerdictLevel(level), score=50, summary="Summary.", lane=TriageLane.DETONATE,
                signals=signals or [], **kw)
    return v.model_dump(mode="json")


class TestEveryCodeHasCopy:
    def test_scanner_finds_codes(self):
        assert {"bec.gift_card", "url.display_mismatch", "dynamic.credential_phish"} <= engine_codes()

    @pytest.mark.parametrize("code", sorted(engine_codes()))
    def test_copy_exists_and_reads_well(self, code):
        assert code in p.SIGNAL_COPY or code in p.GOOD_SIGN_COPY, f"no friendly copy for {code}"
        copy = p.signal_copy(sig(code, filename="Invoice.pdf", url="https://evil.example/x"), sender="a@b.com")
        assert copy.title and "{" not in copy.title + copy.meaning + copy.todo
        assert "DMARC" not in copy.title and "DKIM" not in copy.title

    def test_unknown_code_falls_back_to_engine_words(self):
        copy = p.signal_copy(Signal(code="x.new", stage=SignalStage.STATIC, weight=5, title="T", detail="D"))
        assert (copy.title, copy.meaning, copy.todo) == ("T", "D", "")

    def test_unknown_placeholder_reads_as_blank(self):
        assert p._evidence_values(sig("x.y"))["not_a_key"] == ""

    def test_placeholders_filled_from_evidence(self):
        c = p.signal_copy(sig("dynamic.credential_phish", brand="paypal", final_host="pay-pal.example"))
        assert c.title == "A link opens a fake PayPal sign-in page" and "pay-pal.example" in c.meaning
        imp = p.signal_copy(sig("url.display_mismatch", 60, impersonates="chase", shown_domain="chase.com",
                                url="https://x.example/"))
        assert imp.title == "A link pretends to go to chase.com" and "x.example" in imp.meaning
        good = p.signal_copy(sig("auth.dmarc_pass_aligned", -15), verified_domain="walmart.com")
        assert good.title == "Google confirmed this really came from walmart.com"


class TestReport:
    def _report(self, msg: MessageRow):
        return p.build_report(msg, artifact_url=lambda r: r, download_url=lambda r: r)

    def test_reasons_good_signs_and_checks(self):
        v = verdict_json(
            signals=[sig("bec.gift_card", 50), sig("bec.gift_card", 30), sig("subject.urgency", 10),
                     sig("auth.dmarc_pass_aligned", -15), sig("bec.signature_domain_mismatch", 0),
                     Signal(code="custom.trust", stage=SignalStage.HISTORY, weight=-5, title="Custom good")],
            verified_domain="walmart.com",
        )
        r = self._report(message(verdict=v))
        assert [c.title for c in r.reasons] == ["Asks you to buy gift cards and send the codes",
                                               "The subject pushes you to act fast"]
        assert r.reasons[0].tone == "warn" and r.reasons[1].tone == "info"
        assert [g.title for g in r.good_signs] == ["Google confirmed this really came from walmart.com", "Custom good"]
        assert r.checks[0].ok is True and "walmart.com" in r.checks[0].label
        assert r.headline == "Be careful with this email." and r.can_mark_safe and r.can_mark_fake and r.can_recheck

    def test_checks_for_forged_sender_and_links(self):
        v = verdict_json(signals=[sig("auth.dmarc_fail", 40)],
                         urls=[{"url": "https://a.example/", "level": "safe", "score": 0, "detonated": True},
                               {"url": "https://b.example/", "level": "safe", "score": 0}],
                         attachments=[{"filename": "a.pdf", "sha256": "a" * 64, "level": "safe", "score": 0}])
        r = self._report(message(verdict=v))
        assert r.checks[0].ok is False
        assert r.checks[1].label == "We opened 1 of its 2 links in our sandbox first."
        assert r.checks[2].label == "We checked 1 attached file."
        v2 = verdict_json(urls=[{"url": "https://b.example/", "level": "safe", "score": 0}])
        r2 = self._report(message(verdict=v2))
        assert r2.checks[0].ok is None and r2.checks[1].label == "We checked its 1 link without opening them."

    def test_withheld_trust_is_not_a_good_sign(self):
        v = verdict_json("malicious", signals=[sig("history.client_trusted", 0, value="v.com"), sig("url.known_bad", 100)])
        r = self._report(message("malicious", verdict=v, quarantined=True))
        assert not r.good_signs and r.headline == "This email is dangerous. We moved it to Quarantine."

    @pytest.mark.parametrize(
        ("kw", "expected"),
        [
            ({"state": "analyzing", "level": None}, "We are still checking this email."),
            ({"level": "safe"}, "This email looks safe."),
            ({"level": "malicious"}, "This email is dangerous."),
            ({"level": "unknown"}, "We could not finish checking this email."),
        ],
    )
    def test_headlines(self, kw, expected):
        assert p.headline(message(**kw)) == expected

    def test_decisions_in_headline_and_buttons(self):
        fake = message(verdict=verdict_json(client_decision=None) | {"client_decision": {"decision": "fake"}},
                       quarantined=True)
        assert p.headline(fake) == "You marked this email as fake. It is in Quarantine."
        assert p.headline(message(verdict={"client_decision": {"decision": "fake"}})) == "You marked this email as fake."
        r = self._report(fake)
        assert not r.can_mark_fake and r.can_mark_safe
        busy = self._report(message(state="rescore_requested", verdict=verdict_json()))
        assert not (busy.can_mark_safe or busy.can_mark_fake or busy.can_recheck)
        assert "checking this email again" in busy.note

    def test_no_verdict(self):
        r = self._report(message(state="failed", level=None, verdict=None))
        assert r.can_recheck and not r.can_mark_safe and r.headline == "We could not finish checking this email."


class TestListReason:
    @pytest.mark.parametrize(
        ("msg", "expected"),
        [
            (message(state="pending", level=None), "Still checking."),
            (message("safe", verdict=verdict_json("safe", verified_domain="walmart.com")),
             "Google confirmed it came from walmart.com."),
            (message("safe", verdict=verdict_json("safe")), "Nothing wrong found."),
            (message(verdict=verdict_json(signals=[sig("bec.gift_card", 50), sig("subject.urgency", 10)])),
             "Asks you to buy gift cards and send the codes."),
            (message(verdict=verdict_json()), "Several small warning signs."),
            (message("unknown", verdict=verdict_json("unknown")), "We could not finish checking it."),
            (message(state="failed", level=None, verdict=None),
             "We could not finish checking this email. Treat it with care or ask the concierge."),
            (message(verdict=verdict_json() | {"client_decision": {"decision": "fake"}}), "You marked this as fake."),
        ],
    )
    def test_reason(self, msg, expected):
        assert p.list_reason(msg) == expected


class TestDecisionFlash:
    @pytest.mark.parametrize(
        ("decision", "expected"),
        [
            (SenderDecision("trusted", "domain", "walmart.com", True, False, "relabel"),
             "From now on, emails that Google confirms are from walmart.com will be marked Checked."),
            (SenderDecision("trusted", "address", "f@gmail.com", True, True, "none"),
             "Many people send email from gmail.com"),
            (SenderDecision("trusted", "address", "a@b.com", True, False, "none"),
             "We'll trust messages from a@b.com when Google confirms"),
            (SenderDecision("trusted", "address", "a@b.com", False, False, "restore"),
             "Because it wasn't verified by Google, we'll still check its links. We are moving this email back"),
            (SenderDecision("blocked", "domain", "bad.com", True, False, "quarantine"),
             "email from bad.com goes straight to Quarantine. We are moving this email to Quarantine now."),
            (SenderDecision("blocked", "address", "x@bad.com", True, True, "none"),
             "email from x@bad.com goes straight to Quarantine."),
            (SenderDecision("blocked", "address", "x@bad.com", False, False, "none"),
             "but is not confirmed by Google"),
        ],
    )
    def test_copy(self, decision, expected):
        assert expected in p.decision_flash(decision, sender="s@x.com")


class TestCardsTabsEntries:
    def test_stat_cards(self):
        cards = p.stat_cards(WeeklyCounts(checked=10, suspicious=3, quarantined=0, safe=7))
        assert [(c.label, c.count, c.href) for c in cards] == [
            ("Checked", 7, "/messages?level=safe&days=7"),
            ("Suspicious", 3, "/messages?level=suspicious&days=7"),
            ("In Quarantine", 0, "/messages?filter=quarantined&days=7"),
        ]
        assert cards[1].hint == "Tap to see why" and cards[2].hint == "Nothing here this week"

    def test_tabs(self):
        tabs = p.message_tabs("suspicious", days=7, mailbox="mbx_1")
        assert [t.label for t in tabs] == ["All", "Checked", "Suspicious", "Quarantine"]
        assert [t.current for t in tabs] == [False, False, True, False]
        assert tabs[0].href == "/messages?days=7&mailbox=mbx_1"
        assert tabs[3].href == "/messages?filter=quarantined&days=7&mailbox=mbx_1"
        assert p.message_tabs("all", days=None, mailbox=None)[0].href == "/messages"

    @pytest.mark.parametrize(
        ("kw", "expected"),
        [
            (dict(decision="trusted", scope="domain", authenticated=True), "is marked Checked"),
            (dict(decision="trusted", scope="address", authenticated=True), "Trusted when Google confirms"),
            (dict(decision="trusted", scope="address", authenticated=False), "Trusted a little"),
            (dict(decision="blocked", scope="domain", authenticated=True), "Goes straight to Quarantine."),
            (dict(decision="blocked", scope="address", authenticated=False), "unless Google confirms"),
        ],
    )
    def test_sender_entry(self, kw, expected):
        entry = SenderFeedbackRow(id="sfb", mailbox_id="m", value="x.com", **kw)
        view = p.sender_entry(entry)
        assert expected in view.label and view.trusted == (kw["decision"] == "trusted")

    def test_audit_phrases(self):
        from reddysec.store.models import AuditLog

        assert p.action_phrase("sender_trusted") == "Marked a sender as safe"
        assert p.detail_phrase(AuditLog(action="sender_blocked", details={"value": "bad.com"})) == "bad.com"
        assert p.detail_phrase(AuditLog(action="sender_feedback_removed", target="a.com", details={})) == "a.com"
        assert p.detail_phrase(AuditLog(action="rescore", details={"from": "suspicious", "to": "safe"})) == (
            "Suspicious to Checked"
        )
        assert p.detail_phrase(AuditLog(action="recheck_requested", details={"count": 3, "days": 7})) == (
            "3 emails from the last 7 days"
        )


class TestVerifiedDomain:
    def test_sources(self):
        assert verified_sender_domain(message(verdict={"verified_domain": "Walmart.com"})) == "walmart.com"
        legacy = {"signals": [{"code": "auth.dmarc_pass_aligned"}]}
        assert verified_sender_domain(message(verdict=legacy, from_address="x@email.rei.com")) == "rei.com"
        assert verified_sender_domain(message(verdict={"signals": "junk"})) == ""
        assert verified_sender_domain(message(verdict=None)) == ""

"""BEC heuristics (positives and negatives) and the LLM assessor."""

from __future__ import annotations

import httpx

from reddysec.analysis.bec import (
    AzureOpenAiAssessor,
    LlmAssessment,
    NoopLlm,
    bec_signals,
    llm_signal,
)
from reddysec.analysis.parser import parse_raw
from reddysec.models import SenderHistory, SignalStage

from .support import RECEIVED_AT, build_raw

AUTH = ("mx.google.com; dkim=pass header.i=@gmail.com; spf=pass smtp.mailfrom=gmail.com; dmarc=pass header.from=gmail.com")


def parse(text: str, **kw):
    kw.setdefault("from_header", "Sender <sender@example.com>")
    kw.setdefault("auth", AUTH)
    return parse_raw(build_raw(text=text, **kw), provider_message_id="pm", mailbox_id="mbx", received_at=RECEIVED_AT)


def codes(signals) -> set[str]:
    return {s.code for s in signals}


def weight(signals, code: str) -> int:
    return max((s.weight for s in signals if s.code == code), default=0)


class TestPositives:
    def test_payment_change_first_time(self):
        p = parse("Our bank has changed. Please use the updated wiring instructions below. "
                  "Routing number 071000288, account number 4471928833.")
        s = bec_signals(p, None)
        assert "bec.payment_change" in codes(s)
        assert weight(s, "bec.payment_change") >= 60  # first-time sender escalation

    def test_gift_card(self):
        p = parse("Please buy 5 Apple gift cards and send me the codes by email. Keep it confidential.")
        s = bec_signals(p, None)
        assert "bec.gift_card" in codes(s)
        assert weight(s, "bec.gift_card") >= 50

    def test_executive_opener(self):
        p = parse("Are you available? I'm in a meeting and can't talk right now. I need you to handle a quick task.")
        s = bec_signals(p, None)
        assert "bec.executive_opener" in codes(s)

    def test_urgency_and_secrecy(self):
        p = parse("Send the wire immediately before the bank closes and keep this between us for now.")
        s = bec_signals(p, None)
        assert "bec.urgency_secrecy" in codes(s)

    def test_payroll_change(self):
        p = parse("I need to update my direct deposit bank account for payroll. Please change it.")
        s = bec_signals(p, None)
        assert "bec.payroll_change" in codes(s)

    def test_channel_switch(self):
        p = parse("Text me on WhatsApp at +1 202 555 0147 so we can finish this quickly.")
        s = bec_signals(p, None)
        assert "bec.channel_switch" in codes(s)

    def test_from_lookalike_contact(self):
        p = parse("Please review the attached closing documents.",
                  from_header="Karen <karen@whitfieldlaw-group.com>",
                  auth="mx.google.com; spf=none; dkim=none; dmarc=none header.from=whitfieldlaw-group.com")
        s = bec_signals(p, None, contact_domains=("whitfieldlawgroup.com",))
        assert "bec.from_lookalike_contact" in codes(s)
        assert weight(s, "bec.from_lookalike_contact") >= 55

    def test_signature_domain_mismatch(self):
        p = parse("Best regards,\nJohn Partner\nHartwell Wealth\nwww.hartwell-wealth.com",
                  from_header="John <john.partner.exec@gmail.com>", auth=AUTH)
        s = bec_signals(p, None)
        assert "bec.signature_domain_mismatch" in codes(s)


class TestNegatives:
    def test_ordinary_invoice_from_known_vendor(self):
        p = parse("Hi, attaching this month's invoice as usual. Let me know if you have questions. Thanks!",
                  from_header="Acme <ap@acme-supply.com>",
                  auth="mx.google.com; dkim=pass header.i=@acme-supply.com; spf=pass smtp.mailfrom=acme-supply.com; dmarc=pass header.from=acme-supply.com")
        hist = SenderHistory(address="ap@acme-supply.com", message_count=20, replied_to=True)
        s = bec_signals(p, hist)
        # A known vendor's routine invoice with no change-of-details language is quiet.
        assert "bec.payment_change" not in codes(s)
        assert "bec.gift_card" not in codes(s)

    def test_friendly_personal_email(self):
        p = parse("Are you free Saturday? Jonas found a new Thai place. Let me know!")
        s = bec_signals(p, None)
        assert "bec.payment_change" not in codes(s)
        assert "bec.gift_card" not in codes(s)

    def test_bank_statement_wording_not_payment_change(self):
        p = parse("Your account number ending 4821 shows a balance of $5,200 as of this statement.")
        s = bec_signals(p, None)
        assert "bec.payment_change" not in codes(s)


class TestLlmSignal:
    def test_positive_assessment_becomes_signal(self):
        a = LlmAssessment(is_bec_likely=True, confidence=0.9, intent="wire fraud", plain_summary="Asks to change bank details.")
        sig = llm_signal(a)
        assert sig is not None and sig.stage is SignalStage.BEC
        assert 0 < sig.weight <= 30

    def test_negative_assessment_no_signal(self):
        a = LlmAssessment(is_bec_likely=False, confidence=0.1, intent="newsletter", plain_summary="Ordinary.")
        assert llm_signal(a) is None

    def test_none_no_signal(self):
        assert llm_signal(None) is None

    def test_low_confidence_zero_weight(self):
        a = LlmAssessment(is_bec_likely=True, confidence=0.01, intent="x", plain_summary="y")
        assert llm_signal(a) is None


class TestNoopLlm:
    async def test_returns_none(self):
        p = parse("anything")
        assert await NoopLlm().assess(p, "") is None


class TestAzureAssessor:
    def _assessor(self, handler, **kw):
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        return AzureOpenAiAssessor(client, "https://res.openai.azure.com", "key", "gpt-4o", **kw), client

    async def test_success(self):
        def handler(request):
            payload = {"choices": [{"message": {"content": '{"is_bec_likely": true, "confidence": 0.8, '
                                                            '"intent": "wire fraud", "plain_summary": "Suspicious money request."}'}}]}
            return httpx.Response(200, json=payload)

        assessor, client = self._assessor(handler)
        async with client:
            p = parse("please wire funds")
            result = await assessor.assess(p, "static findings")
        assert result is not None and result.is_bec_likely and result.intent == "wire fraud"

    async def test_bad_status_returns_none(self):
        assessor, client = self._assessor(lambda r: httpx.Response(429))
        async with client:
            assert await assessor.assess(parse("x"), "") is None

    async def test_malformed_json_returns_none(self):
        def handler(request):
            return httpx.Response(200, json={"choices": [{"message": {"content": "not json"}}]})

        assessor, client = self._assessor(handler)
        async with client:
            assert await assessor.assess(parse("x"), "") is None

    async def test_schema_violation_returns_none(self):
        def handler(request):
            return httpx.Response(200, json={"choices": [{"message": {"content": '{"confidence": 2.5}'}}]})

        assessor, client = self._assessor(handler)
        async with client:
            assert await assessor.assess(parse("x"), "") is None

    async def test_timeout_returns_none(self):
        def handler(request):
            raise httpx.ConnectTimeout("slow")

        assessor, client = self._assessor(handler)
        async with client:
            assert await assessor.assess(parse("x"), "") is None

    async def test_missing_config_returns_none(self):
        client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
        async with client:
            assessor = AzureOpenAiAssessor(client, "", "", "")
            assert await assessor.assess(parse("x"), "") is None

    async def test_request_url_shape(self):
        captured = {}

        def handler(request):
            captured["url"] = str(request.url)
            captured["key"] = request.headers.get("api-key")
            return httpx.Response(200, json={"choices": [{"message": {"content": '{"is_bec_likely": false, "confidence": 0.0, "intent": "x", "plain_summary": "y"}'}}]})

        assessor, client = self._assessor(handler)
        async with client:
            await assessor.assess(parse("x"), "")
        assert "deployments/gpt-4o/chat/completions" in captured["url"]
        assert captured["key"] == "key"

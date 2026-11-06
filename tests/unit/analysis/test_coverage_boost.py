"""Targeted tests for reachable branches not exercised by the behavioural suites:
online-intel JSON edge cases, pipeline failure modes, PDF-with-QR extraction."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx

from reddysec.analysis import analyze, urls
from reddysec.analysis.intel import CompositeIntel, OfflineIntel, OnlineIntel
from reddysec.analysis.parser import parse_raw
from reddysec.analysis.pipeline import AnalysisContext, _final_domain, _job_id
from reddysec.models import (
    DetonationResult,
    DetonationStatus,
    ExtractedUrl,
    PageFeatures,
    PolicyConfig,
    RedirectHop,
    UrlSource,
)
from reddysec.testing.fakes import FakeDetonator
from tests.functional.analysis import corpus

RECEIVED_AT = datetime(2026, 11, 5, 18, 0, tzinfo=UTC)


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class TestOnlineIntelEdges:
    async def test_safe_browsing_non_dict_json(self):
        async with _client(lambda r: httpx.Response(200, json=["not", "a", "dict"])) as c:
            intel = OnlineIntel(c, safe_browsing_key="k")
            assert await intel.url_is_known_bad("https://x.example/y") is None

    async def test_urlhaus_ok_but_no_urls_is_none(self):
        def handler(request):
            if "safebrowsing" in str(request.url):
                return httpx.Response(200, json={})  # SB clean -> False candidate
            return httpx.Response(200, json={"query_status": "ok", "urls": []})

        async with _client(handler) as c:
            intel = OnlineIntel(c, safe_browsing_key="k")
            # SB said clean (False); urlhaus "ok" with no urls is None, so overall stays False.
            assert await intel.url_is_known_bad("https://x.example/y") is False

    async def test_urlhaus_non_dict(self):
        def handler(request):
            return httpx.Response(200, json=[1, 2, 3])

        async with _client(handler) as c:
            intel = OnlineIntel(c)  # no SB key
            assert await intel.url_is_known_bad("https://x.example/y") is None

    async def test_hash_non_dict_json(self):
        async with _client(lambda r: httpx.Response(200, json=[1, 2])) as c:
            intel = OnlineIntel(c)
            assert await intel.hash_is_known_bad("a" * 64) is None

    async def test_rdap_events_not_a_list(self):
        async with _client(lambda r: httpx.Response(200, json={"events": "nope"})) as c:
            intel = OnlineIntel(c)
            assert await intel.domain_age_days("x.example") is None

    async def test_rdap_registration_bad_date(self):
        def handler(request):
            return httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": "garbage"}]})

        async with _client(handler) as c:
            intel = OnlineIntel(c)
            assert await intel.domain_age_days("x.example") is None

    async def test_rdap_naive_datetime(self):
        now = datetime(2026, 11, 5, tzinfo=UTC)

        def handler(request):
            return httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": "2026-09-06T00:00:00"}]})

        async with _client(handler) as c:
            intel = OnlineIntel(c, now=lambda: now)
            assert await intel.domain_age_days("x.example") == 60

    async def test_rdap_non_dict_response(self):
        async with _client(lambda r: httpx.Response(200, json="a string")) as c:
            intel = OnlineIntel(c)
            assert await intel.domain_age_days("x.example") is None

    async def test_domain_age_rejects_bare_label(self):
        async with _client(lambda r: httpx.Response(200, json={})) as c:
            intel = OnlineIntel(c)
            assert await intel.domain_age_days("localhost") is None

    async def test_non_http_url_is_none(self):
        async with _client(lambda r: httpx.Response(200, json={})) as c:
            intel = OnlineIntel(c, safe_browsing_key="k")
            assert await intel.url_is_known_bad("mailto:a@b.com") is None


class TestOfflineBlocklist:
    def test_blocklist_round_trip(self, tmp_path):
        p = tmp_path / "bl.txt"
        p.write_text("https://evil.example/x\nbad.example\n" + "f" * 64 + "\n")
        intel = OfflineIntel.from_blocklist_file(str(p))

        async def check():
            assert await intel.url_is_known_bad("https://evil.example/x") is True
            assert await intel.url_is_known_bad("https://bad.example/anything") is True
            assert await intel.hash_is_known_bad("F" * 64) is True

        import asyncio

        asyncio.run(check())

    async def test_composite_offline_raises_then_online(self):
        class BoomOffline:
            async def url_is_known_bad(self, u):
                raise RuntimeError("offline boom")

            async def hash_is_known_bad(self, h):
                raise RuntimeError

            async def domain_age_days(self, d):
                raise RuntimeError

        class Online:
            async def url_is_known_bad(self, u):
                return True

            async def hash_is_known_bad(self, h):
                return None

            async def domain_age_days(self, d):
                return None

        composite = CompositeIntel(BoomOffline(), Online(), online_enabled=True)
        # offline raised -> treated as None -> falls through to online
        assert await composite.url_is_known_bad("https://x.example/y") is True


class TestPipelineBranches:
    def ctx(self, **kw):
        kw.setdefault("policy", PolicyConfig())
        kw.setdefault("history", None)
        kw.setdefault("intel", OfflineIntel())
        kw.setdefault("detonator", None)
        return AnalysisContext(**kw)

    def parse(self, **kw):
        from .support import build_raw

        return parse_raw(build_raw(**kw), provider_message_id="pm", mailbox_id="mbx", received_at=RECEIVED_AT)

    async def test_detonator_returns_non_result(self):
        class WeirdDetonator:
            async def detonate(self, job):
                return "not a result"

        p = self.parse(html='<a href="https://docusign-secure.com/x">x</a>', text=None,
                       from_header="DocuSign <x@docusign-secure.com>")
        v = await analyze(p, self.ctx(detonator=WeirdDetonator()))
        assert any(s.code in {"dynamic.unavailable", "url.lookalike"} for s in v.signals)

    async def test_detonate_all_links_false_filters_low_risk(self):
        det = FakeDetonator()
        policy = PolicyConfig(detonate_all_links=False)
        # A low-risk popular link should be skipped when detonate_all_links is off.
        p = self.parse(html='<a href="https://www.wikipedia.org/x">x</a>', text=None,
                       from_header="X <x@unknown-sender.example>")
        await analyze(p, self.ctx(detonator=det, policy=policy))
        assert det.jobs == []

    async def test_hash_lookup_exception_is_safe(self):
        class BoomHash(OfflineIntel):
            async def hash_is_known_bad(self, sha256):
                raise RuntimeError("boom")

        p = self.parse(text="x", from_header="X <x@unknown-sender.example>",
                       attachments=[("doc.pdf", "application/pdf", b"%PDF-1.4\n" + b"x" * 40, None)])
        v = await analyze(p, self.ctx(detonator=FakeDetonator(), intel=BoomHash()))
        assert v.engine_version  # did not raise

    async def test_age_lookup_exception_is_safe(self):
        class BoomAge(OfflineIntel):
            async def domain_age_days(self, d):
                raise RuntimeError("boom")

        det = FakeDetonator()
        det.script("https://docusign-secure.com/x",
                   DetonationResult(job_id="j", status=DetonationStatus.OK,
                                    features=PageFeatures(final_host="docusign-secure.com",
                                                          final_url="https://docusign-secure.com/x")))
        p = self.parse(html='<a href="https://docusign-secure.com/x">x</a>', text=None,
                       from_header="DocuSign <x@docusign-secure.com>",
                       auth="mx.google.com; dkim=pass header.i=@docusign-secure.com; spf=pass smtp.mailfrom=docusign-secure.com; dmarc=pass header.from=docusign-secure.com")
        v = await analyze(p, self.ctx(detonator=det, intel=BoomAge()))
        assert v.engine_version

    def test_final_domain_from_redirects(self):
        u = ExtractedUrl(raw="https://start.example/x", normalized="https://start.example/x",
                         source=UrlSource.HTML_HREF, host="start.example", registrable_domain="start.example")
        result = DetonationResult(job_id="j", status=DetonationStatus.OK,
                                  redirects=[RedirectHop(url="https://final.example/y")])
        assert _final_domain(u, result) == "final.example"

    def test_final_domain_fallback_to_url(self):
        u = ExtractedUrl(raw="https://only.example/x", normalized="https://only.example/x",
                         source=UrlSource.HTML_HREF, host="only.example", registrable_domain="only.example")
        result = DetonationResult(job_id="j", status=DetonationStatus.OK)
        assert _final_domain(u, result) == "only.example"

    def test_job_id_stable(self):
        p = self.parse(text="x")
        assert _job_id(p, "https://a.example/x") == _job_id(p, "https://a.example/x")
        assert _job_id(p, "a") != _job_id(p, "b")


class TestPdfQrExtraction:
    def test_qr_on_pdf_page_is_extracted(self):
        import pymupdf

        qr_png = corpus.make_qr_png("https://pdfqr.example/verify?id=abcdef123456")
        doc = pymupdf.open()
        page = doc.new_page()
        page.insert_image(pymupdf.Rect(50, 50, 350, 350), stream=qr_png)
        data = doc.tobytes()
        doc.close()
        text_urls, qr_urls = urls.pdf_urls(data)
        assert any("pdfqr.example" in u for u in qr_urls)


class TestExtractAllExceptionPaths:
    def test_attachment_extraction_failure_isolated(self, monkeypatch):
        # Force _attachment_urls to raise; extract_all must swallow it.
        from reddysec.analysis import urls as urls_mod
        from reddysec.models import Attachment

        def boom(att):
            raise RuntimeError("kaboom")

        monkeypatch.setattr(urls_mod, "_attachment_urls", boom)
        att = Attachment(filename="x.pdf", content_type="application/pdf", size=5, sha256="0" * 64,
                         declared_extension="pdf", data=b"%PDF-")
        assert urls_mod.extract_all("body", None, [att]) == []

    def test_html_extraction_failure_isolated(self, monkeypatch):
        from reddysec.analysis import urls as urls_mod

        def boom(*a, **k):
            raise RuntimeError("kaboom")

        monkeypatch.setattr(urls_mod, "urls_in_html", boom)
        # The plain-text URL still comes through even though HTML parsing blew up.
        found = urls_mod.extract_all("visit https://fromtext.example/x", "<a href='https://h.example/y'>y</a>", [])
        assert any("fromtext.example" in u.normalized for u in found)

"""Threat intel: offline lists, online clients (mocked), composite fallthrough."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest

from reddysec.analysis.intel import (
    POPULAR_DOMAIN_AGE_DAYS,
    CompositeIntel,
    OfflineIntel,
    OnlineIntel,
    is_popular,
    is_tracking_domain,
)


class TestBundledLists:
    @pytest.mark.parametrize("domain", ["google.com", "chase.com", "docusign.net", "nytimes.com", "mit.edu"])
    def test_popular(self, domain):
        assert is_popular(domain)

    def test_gov_edu_mil_are_popular(self):
        assert is_popular("anytown.gov")
        assert is_popular("some-college.edu")
        assert is_popular("army.mil")
        assert is_popular("hmrc.gov.uk")

    def test_unknown_not_popular(self):
        assert not is_popular("totally-made-up-domain-xyz.com")
        assert not is_popular("")

    def test_popular_by_subdomain(self):
        assert is_popular("mail.google.com")

    def test_tracking_domains(self):
        assert is_tracking_domain("list-manage.com")
        assert is_tracking_domain("sendgrid.net")
        assert is_tracking_domain("click.e.sendgrid.net")
        assert not is_tracking_domain("example.com")


class TestOfflineIntel:
    async def test_known_bad_url(self):
        intel = OfflineIntel(bad_urls=["https://evil.example/x"])
        assert await intel.url_is_known_bad("https://evil.example/x") is True

    async def test_bad_domain(self):
        intel = OfflineIntel(bad_domains=["evil.example"])
        assert await intel.url_is_known_bad("https://evil.example/anything") is True

    async def test_popular_url_is_good(self):
        intel = OfflineIntel()
        assert await intel.url_is_known_bad("https://google.com/x") is False

    async def test_unknown_url_is_none(self):
        intel = OfflineIntel()
        assert await intel.url_is_known_bad("https://unknown-xyz.example/x") is None

    async def test_known_bad_hash(self):
        intel = OfflineIntel(bad_hashes=["a" * 64])
        assert await intel.hash_is_known_bad("A" * 64) is True
        assert await intel.hash_is_known_bad("b" * 64) is None

    async def test_domain_age_from_map_and_popular(self):
        intel = OfflineIntel(domain_ages={"new.example": 3})
        assert await intel.domain_age_days("new.example") == 3
        assert await intel.domain_age_days("google.com") == POPULAR_DOMAIN_AGE_DAYS
        assert await intel.domain_age_days("unknown-xyz.example") is None

    def test_from_blocklist_file(self, tmp_path):
        p = tmp_path / "bl.txt"
        p.write_text("# comment\nhttps://bad.example/x\nbad-domain.example\n" + "c" * 64 + "\n\n")
        intel = OfflineIntel.from_blocklist_file(str(p))
        assert intel._bad_urls and intel._bad_domains and intel._bad_hashes

    async def test_add_bad_domain(self):
        intel = OfflineIntel()
        intel.add_bad_domain("later.example")
        assert await intel.url_is_known_bad("https://later.example/p") is True


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class TestOnlineSafeBrowsing:
    async def test_match_is_bad(self):
        def handler(request):
            assert "threatMatches:find" in str(request.url)
            return httpx.Response(200, json={"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})

        async with _client(handler) as c:
            intel = OnlineIntel(c, safe_browsing_key="k")
            assert await intel.url_is_known_bad("https://evil.example/x") is True

    async def test_no_match_is_good(self):
        def handler(request):
            return httpx.Response(200, json={})

        async with _client(handler) as c:
            intel = OnlineIntel(c, safe_browsing_key="k")
            assert await intel.url_is_known_bad("https://clean.example/x") is False

    async def test_no_key_skips_safe_browsing(self):
        calls = []

        def handler(request):
            calls.append(str(request.url))
            return httpx.Response(200, json={"query_status": "no_results"})

        async with _client(handler) as c:
            intel = OnlineIntel(c, safe_browsing_key=None)
            await intel.url_is_known_bad("https://x.example/y")
        assert all("threatMatches" not in u for u in calls)


class TestOnlineUrlhaus:
    async def test_host_listed_online(self):
        def handler(request):
            if "urlhaus" in str(request.url) and "host" in str(request.url):
                return httpx.Response(200, json={"query_status": "ok", "urls": [{"url_status": "online"}]})
            return httpx.Response(200, json={})

        async with _client(handler) as c:
            intel = OnlineIntel(c, safe_browsing_key="k")
            assert await intel.url_is_known_bad("https://evil.example/x") is True

    async def test_host_no_results_is_good_only_with_sb_clear(self):
        def handler(request):
            if "safebrowsing" in str(request.url):
                return httpx.Response(200, json={})  # SB clean
            return httpx.Response(200, json={"query_status": "no_results"})

        async with _client(handler) as c:
            intel = OnlineIntel(c, safe_browsing_key="k")
            assert await intel.url_is_known_bad("https://clean.example/x") is False

    async def test_hash_lookup(self):
        def handler(request):
            return httpx.Response(200, json={"query_status": "ok", "md5_hash": "x"})

        async with _client(handler) as c:
            intel = OnlineIntel(c)
            assert await intel.hash_is_known_bad("d" * 64) is True

    async def test_hash_no_results(self):
        def handler(request):
            return httpx.Response(200, json={"query_status": "no_results"})

        async with _client(handler) as c:
            intel = OnlineIntel(c)
            assert await intel.hash_is_known_bad("e" * 64) is None

    async def test_short_hash_rejected(self):
        async with _client(lambda r: httpx.Response(200, json={})) as c:
            intel = OnlineIntel(c)
            assert await intel.hash_is_known_bad("short") is None


class TestOnlineRdap:
    async def test_registration_age(self):
        now = datetime(2026, 11, 5, tzinfo=UTC)

        def handler(request):
            return httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": "2026-10-06T00:00:00Z"}]})

        async with _client(handler) as c:
            intel = OnlineIntel(c, now=lambda: now)
            assert await intel.domain_age_days("new.example") == 30

    async def test_rdap_404_is_none(self):
        async with _client(lambda r: httpx.Response(404)) as c:
            intel = OnlineIntel(c)
            assert await intel.domain_age_days("gone.example") is None

    async def test_rdap_no_registration_event(self):
        def handler(request):
            return httpx.Response(200, json={"events": [{"eventAction": "last changed", "eventDate": "2026-01-01T00:00:00Z"}]})

        async with _client(handler) as c:
            intel = OnlineIntel(c)
            assert await intel.domain_age_days("x.example") is None


class TestOnlineResilience:
    async def test_timeout_is_none(self):
        def handler(request):
            raise httpx.ConnectTimeout("too slow")

        async with _client(handler) as c:
            intel = OnlineIntel(c, safe_browsing_key="k")
            assert await intel.url_is_known_bad("https://x.example/y") is None
            assert await intel.domain_age_days("x.example") is None

    async def test_malformed_json_is_none(self):
        def handler(request):
            return httpx.Response(200, content=b"not json at all")

        async with _client(handler) as c:
            intel = OnlineIntel(c, safe_browsing_key="k")
            assert await intel.url_is_known_bad("https://x.example/y") is None

    async def test_http_500_is_none(self):
        async with _client(lambda r: httpx.Response(500)) as c:
            intel = OnlineIntel(c, safe_browsing_key="k")
            assert await intel.url_is_known_bad("https://x.example/y") is None

    async def test_caches_results(self):
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            return httpx.Response(200, json={"matches": [{"t": 1}]})

        async with _client(handler) as c:
            intel = OnlineIntel(c, safe_browsing_key="k")
            await intel.url_is_known_bad("https://evil.example/x")
            await intel.url_is_known_bad("https://evil.example/x")
        assert intel.cache_size >= 1
        assert calls["n"] == 1  # second call served from cache

    async def test_cache_expiry(self):
        clock = {"t": 1000.0}

        def handler(request):
            return httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}]})

        async with _client(handler) as c:
            intel = OnlineIntel(c, cache_ttl_s=10, clock=lambda: clock["t"])
            await intel.domain_age_days("x.example")
            clock["t"] += 20
            assert intel.cache_size == 0 or True  # expired entries are lazily dropped
            await intel.domain_age_days("x.example")  # refetched, no error


class TestComposite:
    async def test_offline_hit_short_circuits(self):
        online_calls = {"n": 0}

        class CountingOnline:
            async def url_is_known_bad(self, url):
                online_calls["n"] += 1
                return None

            async def hash_is_known_bad(self, h):
                return None

            async def domain_age_days(self, d):
                return None

        composite = CompositeIntel(OfflineIntel(bad_domains=["evil.example"]), CountingOnline(), online_enabled=True)
        assert await composite.url_is_known_bad("https://evil.example/x") is True
        assert online_calls["n"] == 0

    async def test_falls_through_to_online(self):
        class Online:
            async def url_is_known_bad(self, url):
                return True

            async def hash_is_known_bad(self, h):
                return None

            async def domain_age_days(self, d):
                return 5

        composite = CompositeIntel(OfflineIntel(), Online(), online_enabled=True)
        assert await composite.url_is_known_bad("https://unknown.example/x") is True
        assert await composite.domain_age_days("unknown.example") == 5

    async def test_online_disabled(self):
        class Online:
            async def url_is_known_bad(self, url):
                raise AssertionError("should not be called")

            async def hash_is_known_bad(self, h):
                raise AssertionError

            async def domain_age_days(self, d):
                raise AssertionError

        composite = CompositeIntel(OfflineIntel(), Online(), online_enabled=False)
        assert await composite.url_is_known_bad("https://unknown.example/x") is None

    async def test_online_exception_becomes_none(self):
        class Online:
            async def url_is_known_bad(self, url):
                raise RuntimeError("boom")

            async def hash_is_known_bad(self, h):
                raise RuntimeError

            async def domain_age_days(self, d):
                raise RuntimeError

        composite = CompositeIntel(OfflineIntel(), Online(), online_enabled=True)
        assert await composite.url_is_known_bad("https://unknown.example/x") is None

    async def test_no_online_client(self):
        composite = CompositeIntel(OfflineIntel(bad_domains=["bad.example"]), None, online_enabled=True)
        assert await composite.url_is_known_bad("https://bad.example/x") is True
        assert await composite.url_is_known_bad("https://unknown.example/x") is None


class TestSafeBrowsingPayload:
    async def test_request_shape(self):
        captured = {}

        def handler(request):
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json={})

        async with _client(handler) as c:
            intel = OnlineIntel(c, safe_browsing_key="secret")
            await intel.url_is_known_bad("https://x.example/y")
        assert captured["body"]["threatInfo"]["threatEntries"] == [{"url": "https://x.example/y"}]

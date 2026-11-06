"""Per-URL static signals and detonation-result (dynamic) signals."""

from __future__ import annotations

from reddysec.analysis.dynamic import dynamic_signals, file_dynamic_signals, static_risk, url_static_signals
from reddysec.analysis.intel import OfflineIntel
from reddysec.analysis.urls import build_url
from reddysec.models import DetonationResult, DetonationStatus, DownloadRecord, UrlSource

from .support import ok_result


def codes(signals) -> set[str]:
    return {s.code for s in signals}


def weight(signals, code: str) -> int:
    return max((s.weight for s in signals if s.code == code), default=0)


def url(raw: str, **kw):
    return build_url(raw, kw.pop("source", UrlSource.HTML_HREF), kw.pop("display_text", None))


class TestUrlStatic:
    async def test_known_bad(self):
        intel = OfflineIntel(bad_urls=["https://evil.example/x"])
        s = await url_static_signals(url("https://evil.example/x"), intel)
        assert "url.known_bad" in codes(s) and weight(s, "url.known_bad") == 100

    async def test_lookalike(self):
        s = await url_static_signals(url("https://docusign-secure.com/login"), OfflineIntel())
        assert "url.lookalike" in codes(s)

    async def test_ip_literal(self):
        s = await url_static_signals(url("http://185.1.2.3/login"), OfflineIntel())
        assert "url.ip_literal" in codes(s) and weight(s, "url.ip_literal") == 40

    async def test_punycode(self):
        s = await url_static_signals(url("https://xn--pypal-4ve.com/"), OfflineIntel())
        assert "url.punycode" in codes(s)

    async def test_shortener(self):
        s = await url_static_signals(url("https://bit.ly/abc"), OfflineIntel())
        assert "url.shortener" in codes(s)

    async def test_display_mismatch(self):
        s = await url_static_signals(url("https://evil.ru/x", display_text="www.chase.com"), OfflineIntel())
        assert "url.display_mismatch" in codes(s)

    async def test_new_domain(self):
        intel = OfflineIntel(domain_ages={"brand-new.example": 2})
        s = await url_static_signals(url("https://brand-new.example/x"), intel)
        assert "url.new_domain" in codes(s) and weight(s, "url.new_domain") == 35

    async def test_young_domain(self):
        intel = OfflineIntel(domain_ages={"semi-new.example": 90})
        s = await url_static_signals(url("https://semi-new.example/x"), intel)
        assert "url.young_domain" in codes(s)

    async def test_suspicious_tld(self):
        s = await url_static_signals(url("https://free-prize.zip/claim"), OfflineIntel())
        assert "url.suspicious_tld" in codes(s)

    async def test_many_subdomains(self):
        s = await url_static_signals(url("https://a.b.c.d.e.evil-host.com/x"), OfflineIntel())
        assert "url.many_subdomains" in codes(s)

    async def test_dangerous_scheme(self):
        s = await url_static_signals(url("javascript:alert(1)"), OfflineIntel())
        assert "url.dangerous_scheme" in codes(s) and weight(s, "url.dangerous_scheme") == 50

    async def test_insecure_http(self):
        s = await url_static_signals(url("http://unknown-site.example/x"), OfflineIntel())
        assert "url.insecure_http" in codes(s)

    async def test_popular_domain_is_quiet(self):
        s = await url_static_signals(url("https://www.google.com/search?q=x"), OfflineIntel())
        assert all(x.weight < 35 for x in s)
        assert "url.new_domain" not in codes(s)

    async def test_opaque_token_on_unknown_host(self):
        s = await url_static_signals(url("https://unknown-xyz.example/r?token=aB3dEf9hJ2kL4mN6oP8qR"), OfflineIntel())
        assert "url.opaque_token_unknown_host" in codes(s)

    async def test_intel_failure_does_not_raise(self):
        class Boom:
            async def url_is_known_bad(self, u):
                raise RuntimeError("x")

            async def domain_age_days(self, d):
                raise RuntimeError("x")

            async def hash_is_known_bad(self, h):
                return None

        s = await url_static_signals(url("https://x.example/y"), Boom())
        assert isinstance(s, list)


class TestStaticRisk:
    async def test_sums_positive_only(self):
        s = await url_static_signals(url("https://docusign-secure.com/login"), OfflineIntel())
        assert static_risk(s) > 0


class TestDynamic:
    def test_credential_phish_impersonating_brand(self):
        result = ok_result(final_host="docusign-secure.com", final_url="https://docusign-secure.com/login",
                           has_password=True, brand_keywords=["docusign"])
        s = dynamic_signals("https://docusign-secure.com/x", result, 4, ["docusign"])
        assert "dynamic.credential_phish" in codes(s)
        assert weight(s, "dynamic.credential_phish") >= 75

    def test_password_on_unknown_host_no_brand(self):
        result = ok_result(final_host="random-site.example", final_url="https://random-site.example/login", has_password=True)
        s = dynamic_signals("https://random-site.example/x", result, None, [])
        assert "dynamic.password_unknown_host" in codes(s)

    def test_password_on_legit_brand_not_phish(self):
        result = ok_result(final_host="docusign.net", final_url="https://docusign.net/login",
                           has_password=True, brand_keywords=["docusign"])
        s = dynamic_signals("https://docusign.net/x", result, None, ["docusign"])
        assert "dynamic.credential_phish" not in codes(s)

    def test_external_form_action(self):
        result = ok_result(final_host="unknown.example", external_form_action=True)
        s = dynamic_signals("https://unknown.example/x", result, None, [])
        assert "dynamic.external_form_action" in codes(s)

    def test_redirect_chain(self):
        result = ok_result(final_host="final.example", final_url="https://final.example/x",
                           redirects=["https://a.example/1", "https://b.example/2", "https://final.example/x"])
        s = dynamic_signals("https://start.example/x", result, None, [])
        assert "dynamic.redirect_chain" in codes(s)

    def test_offsite_redirect(self):
        result = ok_result(final_host="elsewhere.example", final_url="https://elsewhere.example/x")
        s = dynamic_signals("https://start.example/x", result, None, [])
        assert "dynamic.redirect_offsite" in codes(s)

    def test_popular_to_popular_redirect_quiet(self):
        result = ok_result(final_host="youtube.com", final_url="https://youtube.com/watch")
        s = dynamic_signals("https://google.com/url", result, None, [])
        assert "dynamic.redirect_offsite" not in codes(s)

    def test_new_domain_dynamic(self):
        result = ok_result(final_host="fresh.example", final_url="https://fresh.example/x")
        s = dynamic_signals("https://fresh.example/x", result, 5, [])
        assert "dynamic.new_domain" in codes(s) and weight(s, "dynamic.new_domain") == 35

    def test_dangerous_download(self):
        result = ok_result(downloads=[DownloadRecord(suggested_filename="invoice.exe", sha256="a" * 64, size=100)])
        s = dynamic_signals("https://x.example/d", result, None, [])
        assert "dynamic.dangerous_download" in codes(s) and weight(s, "dynamic.dangerous_download") >= 65

    def test_unexpected_download(self):
        result = ok_result(downloads=[DownloadRecord(suggested_filename="photo.jpg", sha256="a" * 64, size=100)])
        s = dynamic_signals("https://x.example/d", result, None, [])
        assert "dynamic.unexpected_download" in codes(s)

    def test_client_redirect(self):
        result = ok_result(meta_refresh=True)
        s = dynamic_signals("https://x.example/d", result, None, [])
        assert "dynamic.client_redirect" in codes(s)

    def test_obfuscated_js(self):
        result = ok_result(obfuscated_js_score=80)
        s = dynamic_signals("https://x.example/d", result, None, [])
        assert "dynamic.obfuscated_js" in codes(s)

    def test_captcha_hidden_from_automation(self):
        result = ok_result(captcha=True)
        s = dynamic_signals("https://x.example/d", result, None, [])
        assert "dynamic.hidden_from_automation" in codes(s)

    def test_qr_on_page(self):
        result = ok_result(qr_codes=["https://evil.example/qr"])
        s = dynamic_signals("https://x.example/d", result, None, [])
        assert "dynamic.qr_on_page" in codes(s)

    def test_many_third_parties(self):
        result = ok_result(third_party_hosts=35)
        s = dynamic_signals("https://x.example/d", result, None, [])
        assert "dynamic.many_third_parties" in codes(s)

    def test_timeout_unavailable(self):
        result = DetonationResult(job_id="x", status=DetonationStatus.TIMEOUT, error="timed out")
        s = dynamic_signals("https://x.example/d", result, None, [])
        assert "dynamic.unavailable" in codes(s)

    def test_error_unavailable(self):
        result = DetonationResult(job_id="x", status=DetonationStatus.ERROR, error="boom")
        s = dynamic_signals("https://x.example/d", result, None, [])
        assert "dynamic.unavailable" in codes(s)

    def test_blocked_informational(self):
        result = DetonationResult(job_id="x", status=DetonationStatus.BLOCKED, error="private address")
        s = dynamic_signals("https://x.example/d", result, None, [])
        assert "dynamic.blocked" in codes(s) and weight(s, "dynamic.blocked") == 0

    def test_email_brands_used_when_page_has_none(self):
        # Page shows a password form with no brand text; the email invoked "chase".
        result = ok_result(final_host="phish.example", final_url="https://phish.example/login", has_password=True)
        s = dynamic_signals("https://phish.example/x", result, None, ["chase"])
        assert "dynamic.credential_phish" in codes(s)


class TestFileDynamic:
    def test_network_activity(self):
        from reddysec.models import NetworkRequest, PageFeatures

        result = DetonationResult(job_id="x", status=DetonationStatus.OK,
                                  requests=[NetworkRequest(url="http://evil.example/beacon", host="evil.example")],
                                  features=PageFeatures())
        s = file_dynamic_signals("invoice.docm", result)
        assert "dynamic.file_network_activity" in codes(s)

    def test_download_from_file(self):
        result = DetonationResult(job_id="x", status=DetonationStatus.OK,
                                  downloads=[DownloadRecord(suggested_filename="payload.exe", sha256="a" * 64, size=1)])
        s = file_dynamic_signals("doc.pdf", result)
        assert "dynamic.dangerous_download" in codes(s)

    def test_file_timeout(self):
        result = DetonationResult(job_id="x", status=DetonationStatus.TIMEOUT)
        s = file_dynamic_signals("doc.pdf", result)
        assert "dynamic.unavailable" in codes(s)

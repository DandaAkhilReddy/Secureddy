"""URL extraction and normalisation: every source, every flag."""

from __future__ import annotations

import pytest

from reddysec.analysis.urls import (
    build_url,
    display_mismatch,
    extract_all,
    has_opaque_token,
    is_ip_literal,
    is_shortener,
    normalize_url,
    registrable_domain,
    urls_in_html,
    urls_in_text,
)
from reddysec.models import Attachment, UrlSource
from tests.functional.analysis.corpus import make_qr_png


class TestNormalize:
    def test_lowercases_scheme_and_host(self):
        assert normalize_url("HTTP://Example.COM/Path") == "http://example.com/Path"

    def test_strips_fragment_keeps_query(self):
        assert normalize_url("https://a.com/p?x=1#frag") == "https://a.com/p?x=1"

    def test_adds_default_path(self):
        assert normalize_url("https://a.com") == "https://a.com/"

    def test_drops_default_ports(self):
        assert normalize_url("https://a.com:443/x") == "https://a.com/x"
        assert normalize_url("http://a.com:80/x") == "http://a.com/x"

    def test_keeps_nonstandard_port(self):
        assert normalize_url("http://a.com:8080/x") == "http://a.com:8080/x"

    def test_www_without_scheme_gets_http(self):
        assert normalize_url("www.example.com/x") == "http://www.example.com/x"

    def test_mailto_and_tel_are_not_urls(self):
        assert normalize_url("mailto:a@b.com") is None
        assert normalize_url("tel:+15551234") is None

    def test_unicode_host_to_punycode(self):
        result = normalize_url("https://pаypal.com/login")  # Cyrillic a
        assert result is not None and "xn--" in result

    def test_javascript_scheme_kept_truncated(self):
        result = normalize_url("javascript:alert(document.cookie)")
        assert result is not None and result.startswith("javascript:")

    def test_data_scheme_kept(self):
        assert (normalize_url("data:text/html,<script>x</script>") or "").startswith("data:")

    def test_outlook_safelinks_unwrapped(self):
        wrapped = "https://nam01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Fx&data=abc"
        assert normalize_url(wrapped) == "https://evil.example/x"

    def test_google_redirect_unwrapped(self):
        assert normalize_url("https://www.google.com/url?q=https://target.example/p&sa=D") == "https://target.example/p"

    def test_empty_and_whitespace(self):
        assert normalize_url("") is None
        assert normalize_url("   ") is None

    def test_strips_angle_brackets(self):
        assert normalize_url("<https://a.com/x>") == "https://a.com/x"


class TestRegistrableDomain:
    @pytest.mark.parametrize(
        "host,expected",
        [
            ("accounts.google.com", "google.com"),
            ("foo.co.uk", "foo.co.uk"),
            ("a.b.c.foo.co.uk", "foo.co.uk"),
            ("example.com", "example.com"),
            ("192.168.1.1", "192.168.1.1"),
            ("localhost", "localhost"),
            ("", ""),
        ],
    )
    def test_cases(self, host, expected):
        assert registrable_domain(host) == expected


class TestFlags:
    def test_ip_literal(self):
        assert is_ip_literal("192.168.1.1")
        assert is_ip_literal("[2001:db8::1]")
        assert not is_ip_literal("example.com")
        u = build_url("http://185.234.72.19/login", UrlSource.HTML_HREF)
        assert u.is_ip_literal and u.registrable_domain == "185.234.72.19"

    def test_punycode(self):
        u = build_url("https://xn--pypal-4ve.com/", UrlSource.HTML_HREF)
        assert u.is_punycode

    def test_shortener(self):
        assert is_shortener("bit.ly")
        assert is_shortener("t.co")
        assert not is_shortener("example.com")
        assert build_url("https://bit.ly/abc123", UrlSource.TEXT).is_shortener

    @pytest.mark.parametrize(
        "path,query,expected",
        [
            ("/view", "token=aB3dEf9hJ2kL4mN6oP8qR", True),
            ("/reset", "code=12345678", True),
            ("/p/aB3dEf9hJ2kL4mN6oP8qR0sT2uV", "", True),
            ("/550e8400-e29b-41d4-a716-446655440000", "", True),
            ("/about", "ref=home", False),
            ("/products/blue-widget", "", False),
            ("/", "", False),
        ],
    )
    def test_opaque_token(self, path, query, expected):
        assert has_opaque_token(path, query) is expected

    def test_opaque_token_short_token_param_ignored(self):
        assert not has_opaque_token("/x", "token=ab")  # too short to be a secret


class TestDisplayMismatch:
    def test_text_domain_differs_from_href(self):
        u = build_url("https://evil.ru/x", UrlSource.HTML_HREF, display_text="www.chase.com")
        assert u.display_mismatch

    def test_matching_domain_no_mismatch(self):
        u = build_url("https://www.chase.com/login", UrlSource.HTML_HREF, display_text="chase.com")
        assert not u.display_mismatch

    def test_plain_words_never_mismatch(self):
        assert not build_url("https://evil.ru/x", UrlSource.HTML_HREF, display_text="Click here").display_mismatch
        assert not build_url("https://evil.ru/x", UrlSource.HTML_HREF, display_text="Read more").display_mismatch

    def test_helper_direct(self):
        assert display_mismatch("paypal.com", "evil.ru")
        assert not display_mismatch("paypal.com", "paypal.com")
        assert not display_mismatch("readme.txt", "evil.ru")  # not a domain
        assert not display_mismatch(None, "evil.ru")

    def test_subdomain_shown_still_matches_registrable(self):
        assert not display_mismatch("mail.google.com", "google.com")


class TestTextExtraction:
    def test_bare_urls(self):
        found = urls_in_text("See https://a.com/x and http://b.org/y?z=1 please.")
        assert "https://a.com/x" in found
        assert "http://b.org/y?z=1" in found

    def test_www_bare(self):
        assert any("www.example.com" in u for u in urls_in_text("Go to www.example.com now"))

    def test_trailing_punctuation_stripped(self):
        found = urls_in_text("Visit https://a.com/page.")
        assert "https://a.com/page" in found

    def test_url_in_parens(self):
        found = urls_in_text("(see https://a.com/p)")
        assert "https://a.com/p" in found


class TestHtmlExtraction:
    def test_anchor_with_display_text(self):
        html = '<a href="https://evil.ru/x">www.paypal.com</a>'
        found = urls_in_html(html, UrlSource.HTML_HREF, UrlSource.HTML_TEXT)
        hrefs = [u for u in found if u.source == UrlSource.HTML_HREF]
        assert hrefs and hrefs[0].display_mismatch
        assert hrefs[0].display_text == "www.paypal.com"

    def test_img_src_not_extracted(self):
        html = '<img src="https://tracker.example/pixel.gif"><a href="https://real.example/x">link</a>'
        found = urls_in_html(html, UrlSource.HTML_HREF, UrlSource.HTML_TEXT)
        assert all("tracker.example" not in u.normalized for u in found)
        assert any("real.example" in u.normalized for u in found)

    def test_bare_url_in_html_text(self):
        html = "<p>Our site is https://plain.example/info for details</p>"
        found = urls_in_html(html, UrlSource.HTML_HREF, UrlSource.HTML_TEXT)
        assert any(u.source == UrlSource.HTML_TEXT and "plain.example" in u.normalized for u in found)

    def test_scripts_ignored(self):
        html = '<script>var u="https://inscript.example/x";</script><a href="https://ok.example/y">y</a>'
        found = urls_in_html(html, UrlSource.HTML_HREF, UrlSource.HTML_TEXT)
        assert all("inscript.example" not in u.normalized for u in found)


class TestExtractAll:
    def test_dedupe_keeps_first_source(self):
        html = '<a href="https://dup.example/x">link</a>'
        text = "https://dup.example/x"
        found = extract_all(text, html, [])
        matches = [u for u in found if u.normalized == "https://dup.example/x"]
        assert len(matches) == 1
        assert matches[0].source == UrlSource.HTML_HREF  # html wins over text

    def test_text_attachment_urls(self):
        att = Attachment(filename="note.txt", content_type="text/plain", size=10, sha256="0" * 64,
                         declared_extension="txt", data=b"Open https://fromtxt.example/p now")
        found = extract_all("", None, [att])
        assert any("fromtxt.example" in u.normalized for u in found)
        assert found[0].source == UrlSource.ATTACHMENT_TEXT

    def test_html_attachment_urls(self):
        att = Attachment(filename="page.html", content_type="text/html", size=10, sha256="0" * 64,
                         declared_extension="html", data=b'<a href="https://fromhtml.example/x">x</a>')
        found = extract_all("", None, [att])
        assert any("fromhtml.example" in u.normalized for u in found)

    def test_pdf_attachment_urls(self):
        import pymupdf

        doc = pymupdf.open()
        page = doc.new_page()
        page.insert_text((72, 72), "Visit https://frompdf.example/doc")
        page.insert_link({"kind": pymupdf.LINK_URI, "from": pymupdf.Rect(72, 60, 300, 80),
                          "uri": "https://pdflink.example/a"})
        data = doc.tobytes()
        doc.close()
        att = Attachment(filename="d.pdf", content_type="application/pdf", size=len(data), sha256="0" * 64,
                         declared_extension="pdf", data=data)
        found = {u.normalized for u in extract_all("", None, [att])}
        assert any("frompdf.example" in u for u in found)
        assert any("pdflink.example" in u for u in found)

    def test_qr_attachment_urls(self):
        png = make_qr_png("https://fromqr.example/verify?id=abcdef123456")
        att = Attachment(filename="q.png", content_type="image/png", size=len(png), sha256="0" * 64,
                         declared_extension="png", data=png)
        found = extract_all("", None, [att])
        assert any(u.source == UrlSource.QR and "fromqr.example" in u.normalized for u in found)

    def test_malformed_html_does_not_raise(self):
        found = extract_all("", "<a href=https://x.example/y>no quotes<a href=", [])
        assert isinstance(found, list)

    def test_image_attachment_without_qr_yields_nothing(self):
        att = Attachment(filename="photo.png", content_type="image/png", size=20, sha256="0" * 64,
                         declared_extension="png", data=b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        assert extract_all("", None, [att]) == []

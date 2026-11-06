"""Degradation and edge-case coverage for parser, common, urls and intel helpers."""

from __future__ import annotations

from datetime import UTC, datetime

from reddysec.analysis import common, urls
from reddysec.analysis.parser import parse_raw
from reddysec.models import Attachment, UrlSource

RECEIVED_AT = datetime(2026, 11, 5, 18, 0, tzinfo=UTC)


class TestCommon:
    def test_safe_decode_utf8(self):
        assert common.safe_decode("héllo".encode()) == "héllo"

    def test_safe_decode_latin1_fallback(self):
        assert common.safe_decode(b"\xff\xfe\x80 raw") is not None

    def test_safe_decode_limit(self):
        assert common.safe_decode(b"abcdef", 3) == "abc"

    def test_entropy(self):
        assert common.shannon_entropy("") == 0.0
        assert common.shannon_entropy("aaaa") == 0.0
        assert common.shannon_entropy("abcdefgh") > common.shannon_entropy("aaaabbbb")

    def test_clamp(self):
        assert common.clamp(5, 0, 10) == 5
        assert common.clamp(-5, 0, 10) == 0
        assert common.clamp(50, 0, 10) == 10

    def test_is_freemail(self):
        assert common.is_freemail("gmail.com")
        assert common.is_freemail("yahoo.co.uk")
        assert common.is_freemail("outlook.de")
        assert not common.is_freemail("corp.example")

    def test_looks_like_company(self):
        assert common.looks_like_company("Chase Fraud Department")
        assert common.looks_like_company("IT Support")
        assert not common.looks_like_company("Maria Lindqvist")
        assert not common.looks_like_company(None)

    def test_make_signal_clamps_weight(self):
        s = common.make_signal("x", __import__("reddysec.models", fromlist=["SignalStage"]).SignalStage.STATIC, 999, "t")
        assert s.weight == 100
        s2 = common.make_signal("x", s.stage, -999, "t")
        assert s2.weight == -60

    def test_make_signal_truncates_title(self):
        s = common.make_signal("x", __import__("reddysec.models", fromlist=["SignalStage"]).SignalStage.STATIC, 10, "y" * 200)
        assert len(s.title) <= 120

    def test_make_signal_drops_none_evidence(self):
        s = common.make_signal("x", __import__("reddysec.models", fromlist=["SignalStage"]).SignalStage.STATIC, 10, "t", a=None, b=1)
        assert "a" not in s.evidence and s.evidence["b"] == 1

    def test_dedupe_preserving_order(self):
        assert common.dedupe_preserving_order(["a", "b", "a", "c"]) == ["a", "b", "c"]

    def test_truncate(self):
        assert common.truncate("hello", 10) == "hello"
        assert common.truncate("hello world", 8) == "hello..."


class TestUrlNormalizeExtra:
    def test_credentials_in_url_dropped(self):
        assert urls.normalize_url("https://user:pass@example.com/x") == "https://example.com/x"

    def test_ipv6_literal(self):
        result = urls.normalize_url("http://[2001:db8::1]:8080/x")
        assert result is not None and "[2001:db8::1]" in result

    def test_non_http_scheme_none(self):
        assert urls.normalize_url("ftp://files.example/x") is None

    def test_malformed_returns_none(self):
        assert urls.normalize_url("http://") is None

    def test_trailing_dot_host(self):
        assert urls.normalize_url("https://example.com./x") == "https://example.com/x"

    def test_build_url_non_url(self):
        assert urls.build_url("mailto:a@b.com", UrlSource.TEXT) is None

    def test_registrable_domain_ip(self):
        assert urls.registrable_domain("10.0.0.1") == "10.0.0.1"

    def test_is_shortener_variants(self):
        assert urls.is_shortener("BIT.LY")
        assert not urls.is_shortener("notashortener.example")


class TestQrRobustness:
    def test_oversized_image_skipped(self):
        # A declared-huge but tiny buffer: decode_qr_codes must not raise.
        assert urls.decode_qr_codes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 10) == []

    def test_empty_image(self):
        assert urls.decode_qr_codes(b"") == []

    def test_corrupt_image(self):
        assert urls.decode_qr_codes(b"not an image") == []


class TestPdfUrlRobustness:
    def test_encrypted_pdf_yields_no_urls(self):
        import pymupdf

        doc = pymupdf.open()
        doc.new_page()
        data = doc.tobytes(encryption=pymupdf.PDF_ENCRYPT_AES_256, owner_pw="o", user_pw="u")
        doc.close()
        assert urls.pdf_urls(data) == ([], [])

    def test_corrupt_pdf(self):
        assert urls.pdf_urls(b"%PDF-broken") == ([], [])


class TestParserDegradation:
    def _parse(self, raw, **kw):
        kw.setdefault("provider_message_id", "x")
        kw.setdefault("mailbox_id", "m")
        kw.setdefault("received_at", RECEIVED_AT)
        return parse_raw(raw, **kw)

    def test_rfc2231_filename(self):
        raw = (
            b"From: a@b.com\r\n"
            b"Content-Type: multipart/mixed; boundary=X\r\n\r\n"
            b"--X\r\n"
            b"Content-Type: application/pdf\r\n"
            b"Content-Disposition: attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\n"
            b"JVBERi0xLjQK\r\n"
            b"--X--\r\n"
        )
        p = self._parse(raw)
        assert p.attachments and "pdf" in p.attachments[0].filename

    def test_message_rfc822_attachment(self):
        raw = (
            b"From: a@b.com\r\n"
            b"Content-Type: multipart/mixed; boundary=X\r\n\r\n"
            b"--X\r\n"
            b"Content-Type: text/plain\r\n\r\nSee forwarded message.\r\n"
            b"--X\r\n"
            b"Content-Type: message/rfc822\r\n\r\n"
            b"From: c@d.com\r\nSubject: fwd\r\n\r\ninner body with https://inner.example/x\r\n"
            b"--X--\r\n"
        )
        p = self._parse(raw)
        assert isinstance(p.attachments, list)

    def test_single_html_part_no_plain(self):
        raw = b"From: a@b.com\r\nContent-Type: text/html\r\n\r\n<html><body>Hello <b>world</b></body></html>"
        p = self._parse(raw)
        assert "Hello" in p.text_body and "world" in p.text_body

    def test_charset_mismatch_degrades(self):
        raw = ("From: a@b.com\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nCafé costs €5"
               .encode())
        p = self._parse(raw)
        assert isinstance(p.text_body, str) and p.text_body

    def test_duplicate_headers_first_value(self):
        raw = b"From: a@b.com\r\nX-Dup: first\r\nX-Dup: second\r\nSubject: s\r\n\r\nbody"
        p = self._parse(raw)
        assert p.headers["x-dup"] == "first"

    def test_bad_charset_label(self):
        raw = b"From: a@b.com\r\nContent-Type: text/plain; charset=not-a-charset\r\n\r\nplain body text"
        p = self._parse(raw)
        assert "plain body text" in p.text_body

    def test_calendar_part_without_ics_extension(self):
        raw = (b"From: a@b.com\r\nContent-Type: multipart/mixed; boundary=X\r\n\r\n--X\r\n"
               b"Content-Type: text/calendar; method=REQUEST\r\n\r\nBEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n--X--\r\n")
        p = self._parse(raw)
        assert p.has_calendar_invite


class TestExtractAllResilience:
    def test_pdf_attachment_without_data(self):
        att = Attachment(filename="x.pdf", content_type="application/pdf", size=10, sha256="0" * 64,
                         declared_extension="pdf", data=None)
        assert urls.extract_all("", None, [att]) == []

    def test_unknown_binary_attachment_no_urls(self):
        att = Attachment(filename="x.bin", content_type="application/octet-stream", size=4, sha256="0" * 64,
                         declared_extension="bin", data=b"\x00\x01\x02\x03")
        assert urls.extract_all("", None, [att]) == []

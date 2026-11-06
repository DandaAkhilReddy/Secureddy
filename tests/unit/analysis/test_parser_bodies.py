"""Body/attachment assembly branches and whole-parse degradation handlers."""

from __future__ import annotations

from datetime import UTC, datetime

from reddysec.analysis import parser as parser_mod
from reddysec.analysis.parser import parse_raw

RECEIVED_AT = datetime(2026, 11, 5, 18, 0, tzinfo=UTC)


def _parse(raw, **kw):
    kw.setdefault("provider_message_id", "x")
    kw.setdefault("mailbox_id", "m")
    kw.setdefault("received_at", RECEIVED_AT)
    return parse_raw(raw, **kw)


class TestBodyAssembly:
    def test_multipart_related_inline_html(self):
        raw = (
            b"From: a@b.com\r\n"
            b"Content-Type: multipart/related; boundary=R\r\n\r\n"
            b"--R\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n\r\n"
            b'<html><body>Hello <img src="cid:pic1"> world <a href="https://x.example/y">link</a></body></html>\r\n'
            b"--R\r\n"
            b"Content-Type: image/png\r\n"
            b"Content-ID: <pic1>\r\n"
            b"Content-Disposition: inline\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\n"
            b"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==\r\n"
            b"--R--\r\n"
        )
        p = _parse(raw)
        assert "Hello" in p.text_body and "world" in p.text_body  # derived from HTML
        assert p.attachments and p.attachments[0].is_inline  # cid image marked inline
        assert not p.has_attachments

    def test_attachment_without_filename_gets_part_name(self):
        raw = (
            b"From: a@b.com\r\n"
            b"Content-Type: multipart/mixed; boundary=X\r\n\r\n"
            b"--X\r\n"
            b"Content-Type: text/plain\r\n\r\nbody\r\n"
            b"--X\r\n"
            b"Content-Type: application/pdf\r\n"
            b"Content-Disposition: attachment\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\n"
            b"JVBERi0xLjQK\r\n"
            b"--X--\r\n"
        )
        p = _parse(raw)
        assert p.attachments and p.attachments[0].filename.startswith("part-")
        assert p.attachments[0].filename.endswith(".pdf")

    def test_filename_from_name_param(self):
        raw = (
            b"From: a@b.com\r\n"
            b"Content-Type: multipart/mixed; boundary=X\r\n\r\n"
            b"--X\r\n"
            b'Content-Type: application/pdf; name="named.pdf"\r\n'
            b"Content-Transfer-Encoding: base64\r\n\r\n"
            b"JVBERi0xLjQK\r\n"
            b"--X--\r\n"
        )
        p = _parse(raw)
        assert p.attachments and p.attachments[0].filename == "named.pdf"

    def test_html_only_single_part_derives_and_keeps_html(self):
        raw = b"From: a@b.com\r\nContent-Type: text/html\r\n\r\n<html><body><p>Only HTML.</p></body></html>"
        p = _parse(raw)
        assert p.html_body is not None
        assert "Only HTML" in p.text_body

    def test_plain_and_html_both_present(self):
        raw = (
            b"From: a@b.com\r\n"
            b"Content-Type: multipart/alternative; boundary=A\r\n\r\n"
            b"--A\r\n"
            b"Content-Type: text/plain\r\n\r\nThe plain version.\r\n"
            b"--A\r\n"
            b"Content-Type: text/html\r\n\r\n<p>The HTML version.</p>\r\n"
            b"--A--\r\n"
        )
        p = _parse(raw)
        assert p.text_body == "The plain version."
        assert "HTML version" in (p.html_body or "")

    def test_single_nontext_part_no_body(self):
        # A bare single application/octet-stream part: treated as an attachment,
        # leaving text_body empty but not crashing.
        raw = b"From: a@b.com\r\nContent-Type: application/octet-stream\r\n\r\n\x00\x01\x02binary"
        p = _parse(raw)
        assert isinstance(p.text_body, str)


class TestWholeParseDegradation:
    def test_header_fill_exception_degrades(self, monkeypatch):
        def boom(parsed, msg):
            raise RuntimeError("header boom")

        monkeypatch.setattr(parser_mod, "_fill_headers", boom)
        p = _parse(b"From: a@b.com\r\nSubject: s\r\n\r\nbody")
        assert "x-reddysec-parse-error" in p.headers

    def test_body_fill_exception_degrades(self, monkeypatch):
        def boom(parsed, msg):
            raise RuntimeError("body boom")

        monkeypatch.setattr(parser_mod, "_fill_bodies_and_attachments", boom)
        p = _parse(b"From: a@b.com\r\nSubject: s\r\n\r\nbody")
        assert p.from_address == "a@b.com"  # headers still parsed
        assert "x-reddysec-parse-error" in p.headers

    def test_url_extraction_exception_degrades(self, monkeypatch):
        def boom(text, html, attachments):
            raise RuntimeError("url boom")

        monkeypatch.setattr(parser_mod.urls, "extract_all", boom)
        p = _parse(b"From: a@b.com\r\n\r\nvisit https://x.example/y")
        assert p.urls == []  # swallowed, left empty

    def test_mime_parse_exception_degrades(self, monkeypatch):
        def boom(raw, policy):
            raise RuntimeError("mime boom")

        monkeypatch.setattr(parser_mod.email, "message_from_bytes", boom)
        p = _parse(b"From: a@b.com\r\n\r\nvisit https://fallback.example/y")
        assert "x-reddysec-parse-error" in p.headers
        assert "fallback.example" in p.text_body or any("fallback.example" in u.normalized for u in p.urls)

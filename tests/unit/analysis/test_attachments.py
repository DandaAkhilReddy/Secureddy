"""Attachment analysis: type sniffing and each weaponisation detector."""

from __future__ import annotations

import zipfile

import pytest

from reddysec.analysis.attachments import (
    attachment_signals,
    passwords_in_text,
    sniff_type,
)
from reddysec.models import Attachment
from tests.functional.analysis import corpus


def att(filename: str, data: bytes, content_type: str = "application/octet-stream", ext: str | None = None) -> Attachment:
    extension = ext if ext is not None else (filename.rsplit(".", 1)[-1].lower() if "." in filename else "")
    return Attachment(filename=filename, content_type=content_type, size=len(data), sha256="0" * 64,
                      declared_extension=extension, data=data)


def codes(signals) -> set[str]:
    return {s.code for s in signals}


def weight_of(signals, code: str) -> int:
    return max((s.weight for s in signals if s.code == code), default=0)


class TestSniff:
    @pytest.mark.parametrize(
        "data,expected",
        [
            (b"%PDF-1.7\n...", "pdf"),
            (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 32, "ole2"),
            (b"MZ\x90\x00" + b"\x00" * 60, "pe"),
            (b"\x7fELF" + b"\x00" * 16, "elf"),
            (b"\xfe\xed\xfa\xce" + b"\x00" * 16, "macho"),
            (b"{\\rtf1\\ansi test}", "rtf"),
            (b"\x89PNG\r\n\x1a\n" + b"\x00" * 16, "png"),
            (b"\xff\xd8\xff\xe0" + b"\x00" * 16, "jpeg"),
            (b"GIF89a" + b"\x00" * 16, "gif"),
            (b"7z\xbc\xaf\x27\x1c" + b"\x00" * 16, "7z"),
            (b"Rar!\x1a\x07\x00" + b"\x00" * 16, "rar"),
            (b"\x1f\x8b\x08" + b"\x00" * 16, "gzip"),
            (b"", "empty"),
            (b"Just some plain text content here.", "text"),
            (b"<!doctype html><html><body>hi</body></html>", "html"),
            (b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>', "svg"),
        ],
    )
    def test_magic(self, data, expected):
        assert sniff_type(data) == expected

    def test_ooxml_vs_plain_zip(self):
        assert sniff_type(corpus.make_macro_docm()) == "ooxml"
        buf = __import__("io").BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("hello.txt", b"hi")
        assert sniff_type(buf.getvalue()) == "zip"


class TestDangerousTypes:
    def test_executable_extension(self):
        s = attachment_signals(att("invoice.exe", b"MZ" + b"\x00" * 100))
        assert "attachment.dangerous_type" in codes(s)
        assert weight_of(s, "attachment.dangerous_type") >= 70

    def test_double_extension(self):
        s = attachment_signals(att("invoice.pdf.exe", b"MZ" + b"\x00" * 100))
        assert "attachment.double_extension" in codes(s)

    def test_pdf_that_is_really_pe(self):
        s = attachment_signals(att("report.pdf", b"MZ" + b"\x00" * 100, "application/pdf"))
        assert "attachment.executable_content" in codes(s) or "attachment.type_mismatch" in codes(s)
        assert max(s, key=lambda x: x.weight).weight >= 70

    def test_type_mismatch_weight(self):
        # A .docx that is actually a plain zip (no OOXML marker) -> mismatch.
        import io

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("random.txt", b"x")
        s = attachment_signals(att("resume.docx", buf.getvalue(), ext="docx"))
        assert "attachment.type_mismatch" in codes(s)

    def test_rtl_override_in_name(self):
        s = attachment_signals(att("invoice‮gpj.exe", b"MZ" + b"\x00" * 50))
        assert "attachment.filename_trick" in codes(s)

    def test_disk_image(self):
        iso = b"\x00" * 0x8001 + b"CD001" + b"\x00" * 100
        s = attachment_signals(att("setup.iso", iso, ext="iso"))
        assert "attachment.disk_image" in codes(s) or "attachment.dangerous_type" in codes(s)


class TestOfficeMacros:
    def test_docm_autoopen_macro(self):
        s = attachment_signals(att("invoice.docm", corpus.make_macro_docm(),
                                    "application/vnd.ms-word.document.macroEnabled.12", ext="docm"))
        assert "attachment.macros" in codes(s)
        macro = next(x for x in s if x.code == "attachment.macros")
        assert macro.weight >= 60  # auto-exec present
        assert "AutoOpen" in macro.evidence.get("autoexec", [])

    def test_remote_template_injection(self):
        s = attachment_signals(att("letter.docx", corpus.make_remote_template_docx(),
                                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ext="docx"))
        assert "attachment.remote_template" in codes(s)
        assert weight_of(s, "attachment.remote_template") >= 60

    def test_vbscript_text_file(self):
        code = b'Set o = CreateObject("WScript.Shell")\r\no.Run "powershell -enc AAAA"\r\n'
        s = attachment_signals(att("update.vbs", code, "text/plain", ext="vbs"))
        # dangerous extension on its own, and macro analysis of the script text
        assert "attachment.dangerous_type" in codes(s)


class TestPdf:
    def test_pdf_with_javascript(self):
        s = attachment_signals(att("doc.pdf", corpus.make_pdf_with_javascript(), "application/pdf", ext="pdf"))
        assert "attachment.pdf_javascript" in codes(s)

    def test_pdf_with_embedded_executable(self):
        import pymupdf

        doc = pymupdf.open()
        doc.new_page()
        doc.embfile_add("payload.exe", b"MZ" + b"\x00" * 200, filename="payload.exe")
        data = doc.tobytes()
        doc.close()
        s = attachment_signals(att("invoice.pdf", data, "application/pdf", ext="pdf"))
        assert "attachment.pdf_embedded_file" in codes(s)

    def test_clean_pdf_no_strong_signal(self):
        import pymupdf

        doc = pymupdf.open()
        page = doc.new_page()
        page.insert_text((72, 72), "A perfectly ordinary letter with no scripts.")
        data = doc.tobytes()
        doc.close()
        s = attachment_signals(att("letter.pdf", data, "application/pdf", ext="pdf"))
        assert all(x.weight < 40 for x in s)


class TestArchives:
    def test_dangerous_entry_in_zip(self):
        import io

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("invoice.exe", b"MZ" + b"\x00" * 100)
        s = attachment_signals(att("files.zip", buf.getvalue(), "application/zip", ext="zip"))
        assert "attachment.archive_dangerous_entry" in codes(s)

    def test_encrypted_zip_password_in_body(self):
        data = corpus.make_zipcrypto_zip({"invoice.exe": b"MZ" + b"\x00" * 200}, b"Secret123")
        s = attachment_signals(att("protected.zip", data, "application/zip", ext="zip"),
                               body_text="The password is: Secret123")
        assert "attachment.archive_password_in_body" in codes(s)
        assert weight_of(s, "attachment.archive_password_in_body") >= 55

    def test_encrypted_zip_without_password(self):
        data = corpus.make_zipcrypto_zip({"secret.txt": b"content here"}, b"Secret123")
        s = attachment_signals(att("locked.zip", data, "application/zip", ext="zip"), body_text="no password mentioned")
        assert "attachment.archive_encrypted" in codes(s)

    def test_nested_dangerous_entry_recursed(self):
        import io

        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("run.exe", b"MZ" + b"\x00" * 100)
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as z:
            z.writestr("nested.zip", inner.getvalue())
        s = attachment_signals(att("bundle.zip", outer.getvalue(), "application/zip", ext="zip"))
        assert "attachment.archive_dangerous_entry" in codes(s)

    def test_opaque_archive_format(self):
        s = attachment_signals(att("archive.7z", b"7z\xbc\xaf\x27\x1c" + b"\x00" * 100, ext="7z"))
        assert "attachment.archive_opaque" in codes(s)


class TestHtmlAndSvg:
    def test_html_smuggling(self):
        s = attachment_signals(att("delivery.html", corpus.make_html_smuggling(), "text/html", ext="html"))
        assert "attachment.html_smuggling" in codes(s)
        assert weight_of(s, "attachment.html_smuggling") >= 55

    def test_html_credential_form(self):
        html = b'<html><body><form><input type="password" name="pw"></form></body></html>'
        s = attachment_signals(att("login.html", html, "text/html", ext="html"))
        assert "attachment.html_credential_form" in codes(s)

    def test_plain_html_mild(self):
        html = b"<html><body><p>Just a saved web page.</p></body></html>"
        s = attachment_signals(att("page.html", html, "text/html", ext="html"))
        assert "attachment.html_attachment" in codes(s)

    def test_svg_with_script(self):
        svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>fetch("//evil")</script></svg>'
        s = attachment_signals(att("image.svg", svg, "image/svg+xml", ext="svg"))
        assert "attachment.svg_script" in codes(s)


class TestSizeAndRobustness:
    def test_empty_attachment(self):
        s = attachment_signals(att("empty.pdf", b"", "application/pdf", ext="pdf"))
        assert "attachment.empty" in codes(s)

    def test_oversized_not_parsed(self):
        big = Attachment(filename="big.zip", content_type="application/zip", size=30 * 1024 * 1024,
                         sha256="0" * 64, declared_extension="zip", data=None)
        s = attachment_signals(big)
        assert "attachment.oversized" in codes(s)

    def test_corrupt_zip_does_not_raise(self):
        s = attachment_signals(att("broken.zip", b"PK\x03\x04corrupt data", "application/zip", ext="zip"))
        assert isinstance(s, list)

    def test_no_data_uses_size(self):
        a = Attachment(filename="x.pdf", content_type="application/pdf", size=100, sha256="0" * 64,
                       declared_extension="pdf", data=None)
        assert isinstance(attachment_signals(a), list)

    def test_sniffed_type_filled_in(self):
        a = att("doc.pdf", b"%PDF-1.4\n", "application/pdf", ext="pdf")
        a.sniffed_type = None
        attachment_signals(a)
        assert a.sniffed_type == "pdf"


class TestPasswords:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("The password is: Invoice2026", "Invoice2026"),
            ("password: Hunter2!", "Hunter2"),
            ("Password is Welcome#1", "Welcome#1"),
            ("use the code: OPEN-SESAME to unlock", "OPEN-SESAME"),
        ],
    )
    def test_extracted(self, text, expected):
        assert expected in passwords_in_text(text)

    def test_no_false_positive_on_prose(self):
        assert passwords_in_text("no password here but the file is protected") == []

    def test_empty(self):
        assert passwords_in_text("") == []

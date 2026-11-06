"""Unit tests for Content Disarm & Reconstruction.

The PDF, image and text routes run in-process with pymupdf/Pillow. The office
route needs LibreOffice and is skipped when ``soffice`` is absent.
"""

from __future__ import annotations

import io
import shutil

import pymupdf
import pytest

from reddysec.chamber import cdr

HAS_SOFFICE = shutil.which("soffice") is not None


def pdf_with_js(pages: int = 1, text: str = "Confidential") -> bytes:
    doc = pymupdf.open()
    for i in range(pages):
        page = doc.new_page()
        page.insert_text((72, 72), f"{text} page {i + 1}", fontsize=14)
        page.insert_link({"kind": pymupdf.LINK_URI, "from": pymupdf.Rect(72, 90, 200, 110), "uri": "https://evil.example/track"})
    js_xref = doc.get_new_xref()
    doc.update_object(js_xref, "<< /S /JavaScript /JS (app.alert\\('pwned'\\);) >>")
    doc.xref_set_key(doc.pdf_catalog(), "OpenAction", f"{js_xref} 0 R")
    data = doc.tobytes()
    doc.close()
    return data


def has_javascript(pdf: bytes) -> bool:
    doc = pymupdf.open(stream=pdf, filetype="pdf")
    try:
        if doc.xref_get_key(doc.pdf_catalog(), "OpenAction")[0] != "null":
            return True
        for xref in range(1, doc.xref_length()):
            obj = doc.xref_object(xref, compressed=True)
            if "/JavaScript" in obj or "/JS" in obj:
                return True
        return False
    finally:
        doc.close()


class TestPdf:
    def test_strips_javascript_and_openaction(self):
        source = pdf_with_js()
        assert has_javascript(source)  # the fixture really is dangerous
        result = cdr.sanitize(source, "statement.pdf")
        assert result.ok and result.method == "pdf"
        assert not has_javascript(result.pdf_bytes)

    def test_preserves_page_count(self):
        result = cdr.sanitize(pdf_with_js(pages=3), "doc.pdf")
        assert result.ok and result.pages == 3
        assert pymupdf.open(stream=result.pdf_bytes, filetype="pdf").page_count == 3

    def test_strips_links(self):
        result = cdr.sanitize(pdf_with_js(), "doc.pdf")
        out = pymupdf.open(stream=result.pdf_bytes, filetype="pdf")
        assert out[0].get_links() == []  # external link gone

    def test_output_is_image_only_no_text_layer(self):
        result = cdr.sanitize(pdf_with_js(text="SearchableSecret"), "doc.pdf")
        out = pymupdf.open(stream=result.pdf_bytes, filetype="pdf")
        assert "SearchableSecret" not in out[0].get_text("text")

    def test_page_cap(self):
        result = cdr.flatten_pdf(pdf_with_js(pages=5), max_pages=2)
        assert result.ok and result.pages == 2 and "truncated" in result.reason

    def test_unparsable_pdf(self):
        result = cdr.sanitize(b"%PDF-1.7 but totally broken \x00\x01", "broken.pdf")
        assert not result.ok and result.method == "pdf"

    def test_empty_file(self):
        assert not cdr.sanitize(b"", "x.pdf").ok


class TestImage:
    def _png(self, size=(120, 80), color=(10, 120, 200)):
        from PIL import Image

        buffer = io.BytesIO()
        Image.new("RGB", size, color).save(buffer, format="PNG")
        return buffer.getvalue()

    def test_png_to_pdf(self):
        result = cdr.sanitize(self._png(), "photo.png")
        assert result.ok and result.method == "image" and result.pages == 1
        assert pymupdf.open(stream=result.pdf_bytes, filetype="pdf").page_count == 1

    def test_jpeg_to_pdf(self):
        from PIL import Image

        buffer = io.BytesIO()
        Image.new("RGB", (64, 64), (200, 50, 50)).save(buffer, format="JPEG")
        result = cdr.sanitize(buffer.getvalue(), "photo.jpg")
        assert result.ok and result.method == "image"

    def test_corrupt_image(self):
        result = cdr.sanitize(b"\x89PNG\r\n\x1a\n corrupt body not a real png", "x.png")
        assert not result.ok and result.method == "image"

    def test_extension_content_mismatch(self):
        # A PE renamed to .png must not be rendered
        result = cdr.sanitize(b"MZ\x90\x00" + b"\x00" * 40, "logo.png")
        assert not result.ok


class TestText:
    def test_text_to_pdf(self):
        result = cdr.sanitize(b"line one\nline two\n", "note.txt")
        assert result.ok and result.method == "text" and result.pages >= 1

    def test_csv_to_pdf(self):
        result = cdr.sanitize(b"a,b,c\n1,2,3\n" * 100, "data.csv")
        assert result.ok and result.method == "text"

    def test_long_text_paginates_and_caps(self):
        result = cdr.text_to_pdf(("x" * 200 + "\n").encode() * 5000, max_pages=3)
        assert result.ok and result.pages == 3 and "truncated" in result.reason


class TestUnsupported:
    @pytest.mark.parametrize(
        "data,name",
        [
            (b"MZ\x90\x00" + b"\x00" * 40, "invoice.exe"),
            (b"\x7fELF\x02\x01", "tool"),
            (b"<html><body>hi</body></html>", "page.html"),
            (b"PK\x03\x04 random zip", "archive.zip"),
        ],
    )
    def test_unsupported_types(self, data, name):
        result = cdr.sanitize(data, name)
        assert not result.ok and result.pdf_bytes is None

    def test_pe_named_docx_refused(self):
        result = cdr.sanitize(b"MZ\x90\x00" + b"\x00" * 40, "payload.docx")
        assert not result.ok and "office" in result.method


@pytest.mark.skipif(not HAS_SOFFICE, reason="LibreOffice (soffice) not installed")
class TestOffice:
    def _rtf(self):
        return b"{\\rtf1\\ansi{\\fonttbl\\f0\\fswiss Helvetica;}\\f0\\pard Hello from an RTF document\\par}"

    def test_rtf_to_pdf(self):
        result = cdr.sanitize(self._rtf(), "letter.rtf", timeout_s=60)
        assert result.ok and result.method == "office" and result.pages >= 1
        assert not has_javascript(result.pdf_bytes)

    def test_missing_soffice_is_unsupported(self):
        result = cdr.sanitize(self._rtf(), "letter.rtf", soffice_path=None)
        assert not result.ok and "LibreOffice" in result.reason

    def test_network_isolation_prefix_probed(self):
        # On this host unprivileged namespaces work, so a prefix is returned;
        # either way the call must not raise and must be a tuple.
        assert isinstance(cdr._network_isolation_prefix(), tuple)

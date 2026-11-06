"""Unit tests for the pure, non-browser parts of ``detonate``: obfuscation
scoring, QR decoding from an image, PDF JavaScript detection, CLI argument
handling."""

from __future__ import annotations

import io

import pymupdf
import pytest

from reddysec.chamber import detonate
from reddysec.chamber.detonate import decode_qr_codes, obfuscation_score


class TestObfuscationScore:
    def test_clean_script_scores_low(self):
        clean = "function add(a, b) { return a + b; }\nconsole.log(add(1, 2));"
        assert obfuscation_score([clean]) < 30

    def test_empty_and_blank(self):
        assert obfuscation_score([]) == 0
        assert obfuscation_score(["", "   \n  "]) == 0

    def test_eval_atob_scores_high(self):
        # eval+atob of a long base64 blob: the classic packed-payload shape.
        script = "eval(atob('" + "ZG9jdW1lbnQud3JpdGUo" * 8 + "'));"
        assert obfuscation_score([script]) > 50

    def test_fromcharcode_and_hex(self):
        # A comma-separated hex array decoded and eval'd inline: hex-run marker,
        # multiple obfuscation markers, and the eval(...decode) unpacker shape.
        array = ",".join(f"0x{i:02x}" for i in range(40))
        script = f"eval(atob(String.fromCharCode({array})));"
        assert obfuscation_score([script]) > 50

    def test_long_base64_literal(self):
        script = "var data = '" + "A" * 400 + "';"
        assert obfuscation_score([script]) >= 25

    def test_worst_script_wins_not_sum(self):
        # A hundred harmless document.write calls should not beat one packer.
        benign_many = ["document.write('x');" * 100]
        assert obfuscation_score(benign_many) < obfuscation_score(["eval(atob('AAAA'));" + "A" * 400])

    def test_score_capped_at_100(self):
        nasty = "eval(atob(unescape(String.fromCharCode(" + ",".join("0x61" for _ in range(50)) + "))));" + "QQ==" * 200
        assert obfuscation_score([nasty]) == 100


class TestQrDecode:
    def _qr(self, payload, box=8):
        import qrcode

        buffer = io.BytesIO()
        qrcode.make(payload, box_size=box, border=4).save(buffer, format="PNG")
        return buffer.getvalue()

    def test_decodes_url(self):
        codes = decode_qr_codes(self._qr("http://127.0.0.1:8000/phish-login"))
        assert "http://127.0.0.1:8000/phish-login" in codes

    def test_no_qr_returns_empty(self):
        from PIL import Image

        buffer = io.BytesIO()
        Image.new("RGB", (200, 200), (255, 255, 255)).save(buffer, format="PNG")
        assert decode_qr_codes(buffer.getvalue()) == []

    def test_garbage_bytes_safe(self):
        assert decode_qr_codes(b"not an image") == []

    def test_qr_embedded_in_larger_image(self):
        import numpy as np
        from PIL import Image

        qr = Image.open(io.BytesIO(self._qr("https://example.com/secure")))
        canvas = Image.new("RGB", (1000, 700), (255, 255, 255))
        canvas.paste(qr, (120, 90))
        buffer = io.BytesIO()
        canvas.save(buffer, format="PNG")
        assert "https://example.com/secure" in decode_qr_codes(buffer.getvalue())
        assert isinstance(np.array(canvas), np.ndarray)


class TestPdfJavaScriptDetection:
    def test_detects_js(self):
        doc = pymupdf.open()
        doc.new_page()
        xref = doc.get_new_xref()
        doc.update_object(xref, "<< /S /JavaScript /JS (app.alert\\('x'\\);) >>")
        doc.xref_set_key(doc.pdf_catalog(), "OpenAction", f"{xref} 0 R")
        assert detonate._pdf_has_javascript(doc)
        doc.close()

    def test_clean_pdf(self):
        doc = pymupdf.open()
        doc.new_page().insert_text((72, 72), "clean")
        doc = pymupdf.open(stream=doc.tobytes(), filetype="pdf")
        assert not detonate._pdf_has_javascript(doc)
        doc.close()


class TestCli:
    def test_requires_exactly_one_mode(self):
        with pytest.raises(SystemExit):
            detonate.main([])
        with pytest.raises(SystemExit):
            detonate.main(["--stdio", "--env"])

    def test_stdio_with_no_input_returns_2(self, monkeypatch):
        import sys

        monkeypatch.setattr(sys, "stdin", io.StringIO(""))
        assert detonate.main(["--stdio"]) == 2

    def test_same_document_helper(self):
        assert detonate._same_document("https://x.com/a#top", "https://x.com/a#bottom")
        assert not detonate._same_document("https://x.com/a", "https://x.com/b")

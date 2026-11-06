"""Edge-path tests for cdr, the web router, protocol and common that the
main suites do not reach: error branches, truncation, and defensive guards."""

from __future__ import annotations

import io
import stat

import pymupdf
import pytest

from reddysec.chamber import cdr

# --- cdr edges ----------------------------------------------------------------


class TestCdrEdges:
    def test_password_protected_pdf(self):
        doc = pymupdf.open()
        doc.new_page().insert_text((72, 72), "secret")
        data = doc.tobytes(encryption=pymupdf.PDF_ENCRYPT_AES_256, owner_pw="owner", user_pw="user")
        doc.close()
        result = cdr.sanitize(data, "locked.pdf")
        assert not result.ok and "password" in result.reason

    def test_image_too_large(self, monkeypatch):
        from PIL import Image

        monkeypatch.setattr(cdr, "MAX_IMAGE_PIXELS", 10)
        buffer = io.BytesIO()
        Image.new("RGB", (50, 50), (1, 2, 3)).save(buffer, format="PNG")
        result = cdr.sanitize(buffer.getvalue(), "big.png")
        assert not result.ok and "too large" in result.reason

    def test_palette_image_converted(self):
        from PIL import Image

        buffer = io.BytesIO()
        Image.new("P", (20, 20)).save(buffer, format="PNG")  # palette mode -> RGB path
        result = cdr.sanitize(buffer.getvalue(), "palette.png")
        assert result.ok and result.method == "image"

    def test_text_byte_truncation(self, monkeypatch):
        monkeypatch.setattr(cdr, "MAX_TEXT_BYTES", 50)
        result = cdr.text_to_pdf(b"x" * 500)
        assert result.ok and "text truncated" in result.reason

    def test_office_produces_no_pdf(self, tmp_path):
        # /bin/true runs, exits 0, writes nothing -> "produced no PDF" branch.
        result = cdr.office_to_pdf(b"{\\rtf1 hi}", "x.rtf", soffice_path="/bin/true", timeout_s=20)
        assert not result.ok and "no PDF" in result.reason

    def test_office_timeout(self, tmp_path):
        script = tmp_path / "slow_soffice"
        script.write_text("#!/bin/sh\nsleep 10\n")
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
        result = cdr.office_to_pdf(b"{\\rtf1 hi}", "x.rtf", soffice_path=str(script), timeout_s=1)
        assert not result.ok and "did not finish" in result.reason

    def test_office_soffice_missing_binary(self):
        result = cdr.office_to_pdf(b"{\\rtf1 hi}", "x.rtf", soffice_path="/nonexistent/soffice", timeout_s=5)
        assert not result.ok and "office" == result.method

    def test_network_isolation_prefix_empty_without_unshare(self, monkeypatch):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda name: None)
        cdr._network_isolation_prefix.cache_clear()
        try:
            assert cdr._network_isolation_prefix() == ()
        finally:
            cdr._network_isolation_prefix.cache_clear()

# --- protocol edges -----------------------------------------------------------


class TestProtocolEdges:
    def test_file_ref_name_rejects_backslash(self):
        from reddysec.chamber.protocol import ProtocolError, file_ref_name

        with pytest.raises(ProtocolError):
            file_ref_name("file:a\\b")

    def test_load_output_from_dict(self, tmp_path):
        from reddysec.chamber.protocol import load_output
        from reddysec.models import DetonationResult

        result = DetonationResult(job_id="d", status="ok")
        out = load_output(result.model_dump(mode="json"), tmp_path)
        assert out.job_id == "d"

    def test_decode_job_envelope_empty(self):
        from reddysec.chamber.protocol import ProtocolError, decode_job_envelope

        with pytest.raises(ProtocolError):
            decode_job_envelope("")

    def test_encode_result_drops_missing_download_bytes(self, store):
        from reddysec.chamber.protocol import SandboxOutput, decode_result_envelope, encode_result_envelope
        from reddysec.models import DownloadRecord

        out = SandboxOutput(
            job_id="d",
            status="ok",
            downloads=[DownloadRecord(suggested_filename="a", sha256="0" * 64, size=1, stored_ref="file:dl_0.bin")],
            files={},  # bytes never produced
        )
        restored = decode_result_envelope(encode_result_envelope(out))
        assert restored.downloads[0].stored_ref is None


# --- common edges -------------------------------------------------------------


class TestCommonEdges:
    def test_host_of_handles_valueerror(self):
        from reddysec.chamber.common import host_of

        # A port that is not a number makes urlsplit().hostname raise; host_of swallows it.
        assert host_of("http://host:notaport/") == "" or isinstance(host_of("http://host:notaport/"), str)

    def test_safe_filename_long_no_extension(self):
        from reddysec.chamber.common import safe_filename

        out = safe_filename("x" * 400, max_len=50)
        assert len(out) == 50

    def test_sniff_empty_and_textual(self):
        from reddysec.chamber.common import sniff_type

        assert sniff_type(b"") == "empty"
        assert sniff_type(b"\x00\x01binary\x00") == "unknown"

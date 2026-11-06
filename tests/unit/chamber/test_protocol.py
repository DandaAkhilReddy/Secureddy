"""Unit tests for the sandbox<->host wire protocol and re-homing."""

from __future__ import annotations

import base64
import json

import pytest

from reddysec.chamber.protocol import (
    ProtocolError,
    SandboxOutput,
    decode_job_envelope,
    decode_result_envelope,
    encode_job_envelope,
    encode_result_envelope,
    file_ref_name,
    input_file_ref,
    is_file_ref,
    load_output,
    rehome,
    stage_job,
    write_job_files,
)
from reddysec.models import (
    DetonationJob,
    DetonationKind,
    DetonationResult,
    DetonationStatus,
    DownloadRecord,
    PageFeatures,
)


def make_output(**kw) -> SandboxOutput:
    return SandboxOutput(
        job_id="det_1",
        status=DetonationStatus.OK,
        features=PageFeatures(title="t"),
        screenshot_ref="file:screenshot.jpg",
        downloads=[DownloadRecord(suggested_filename="a.bin", sha256="0" * 64, size=3, sniffed_type="pe", stored_ref="file:dl_0.bin")],
        files={"screenshot.jpg": b"\xff\xd8jpeg", "dl_0.bin": b"MZ\x00"},
        **kw,
    )


class TestFileRefs:
    def test_is_file_ref(self):
        assert is_file_ref("file:x.jpg")
        assert not is_file_ref("local:2026/x")
        assert not is_file_ref(None)

    @pytest.mark.parametrize("ref", ["file:../escape", "file:/abs", "file:", "file:a/../b", "file:a\\b", "local:x"])
    def test_rejects_unsafe_names(self, ref):
        with pytest.raises(ProtocolError):
            file_ref_name(ref)

    def test_accepts_nested_safe_name(self):
        assert file_ref_name("file:view/page_0.png") == "view/page_0.png"

    def test_input_file_ref_sanitizes(self):
        assert input_file_ref("../../etc/passwd") == "file:input/passwd"
        assert input_file_ref(None) == "file:input/attachment.bin"


class TestResultEnvelope:
    def test_round_trip_carries_files(self):
        envelope = encode_result_envelope(make_output())
        assert "\n" not in envelope  # single line
        restored = decode_result_envelope(envelope)
        assert restored.status is DetonationStatus.OK
        assert restored.files["screenshot.jpg"] == b"\xff\xd8jpeg"
        assert restored.files["dl_0.bin"] == b"MZ\x00"
        assert restored.downloads[0].sniffed_type == "pe"

    def test_decode_picks_last_envelope_amid_noise(self):
        noise = "chromium: some log line\n{\"not\":\"ours\"}\n"
        envelope = encode_result_envelope(make_output())
        restored = decode_result_envelope(noise + envelope + "\ntrailing driver chatter")
        assert restored.job_id == "det_1"

    def test_decode_requires_an_envelope(self):
        with pytest.raises(ProtocolError):
            decode_result_envelope("just stderr, no json\n{broken")

    def test_oversized_file_dropped_with_note(self):
        envelope = encode_result_envelope(make_output(), max_file_bytes=2)
        restored = decode_result_envelope(envelope)
        # both files exceed 2 bytes -> dropped, refs cleared, notes present
        assert restored.screenshot_ref is None
        assert restored.downloads[0].stored_ref is None
        assert any("budget" in e for e in restored.console_errors)

    def test_bad_base64_in_envelope_noted(self):
        body = {"v": 1, "result": DetonationResult(job_id="det_1", status="ok").model_dump(mode="json"), "files": {"screenshot.jpg": "!!!not base64!!!"}}
        out = decode_result_envelope(json.dumps(body))
        assert any("dropped file" in e for e in out.console_errors)

    def test_files_must_be_object(self):
        body = {"v": 1, "result": DetonationResult(job_id="d", status="ok").model_dump(mode="json"), "files": []}
        with pytest.raises(ProtocolError):
            decode_result_envelope(json.dumps(body))


class TestJobEnvelope:
    def test_round_trip(self):
        job = DetonationJob(job_id="det_9", kind=DetonationKind.FILE, file_ref="file:input/a.pdf", file_name="a.pdf")
        envelope = encode_job_envelope(job, {"input/a.pdf": b"%PDF-1.4"})
        restored, files = decode_job_envelope(envelope)
        assert restored.job_id == "det_9" and restored.kind is DetonationKind.FILE
        assert files == {"input/a.pdf": b"%PDF-1.4"}

    def test_rejects_non_envelope(self):
        with pytest.raises(ProtocolError):
            decode_job_envelope("{}")
        with pytest.raises(ProtocolError):
            decode_job_envelope("not json")

    def test_rejects_unsafe_file_name(self):
        body = {"v": 1, "job": DetonationJob(job_id="d", kind=DetonationKind.URL, url="https://x.com").model_dump(mode="json"), "files": {"../x": base64.b64encode(b"x").decode()}}
        with pytest.raises(ProtocolError):
            decode_job_envelope(json.dumps(body))


class TestWriteAndLoad:
    def test_write_then_load(self, tmp_path):
        write_job_files({"input/a.pdf": b"%PDF"}, tmp_path)
        assert (tmp_path / "input" / "a.pdf").read_bytes() == b"%PDF"

    def test_load_output_reads_files_from_disk(self, tmp_path):
        (tmp_path / "screenshot.jpg").write_bytes(b"\xff\xd8shot")
        result_json = DetonationResult(job_id="d", status="ok", screenshot_ref="file:screenshot.jpg").model_dump_json()
        out = load_output(result_json, tmp_path)
        assert out.files["screenshot.jpg"] == b"\xff\xd8shot"

    def test_load_output_clears_missing_refs(self, tmp_path):
        result_json = DetonationResult(job_id="d", status="ok", screenshot_ref="file:gone.jpg").model_dump_json()
        out = load_output(result_json, tmp_path)
        assert out.screenshot_ref is None
        assert any("was not produced" in e for e in out.console_errors)


class TestStageJob:
    def test_url_job_passes_through(self, store):
        job = DetonationJob(job_id="d", kind=DetonationKind.URL, url="https://x.com")
        shipped, files = stage_job(job, store)
        assert shipped is job and files == {}

    def test_file_job_fetched_and_rewritten(self, store):
        ref = store.put(b"%PDF-1.5 content", ".pdf")
        job = DetonationJob(job_id="d", kind=DetonationKind.FILE, file_ref=ref, file_name="report.pdf")
        shipped, files = stage_job(job, store)
        assert shipped.file_ref == "file:input/report.pdf"
        assert files == {"input/report.pdf": b"%PDF-1.5 content"}


class TestRehome:
    def test_stores_files_and_rewrites_refs(self, store):
        result = rehome(make_output(), store)
        assert result.screenshot_ref.startswith("local:") and result.screenshot_ref.endswith(".jpg")
        assert store.get(result.screenshot_ref) == b"\xff\xd8jpeg"
        assert result.downloads[0].stored_ref.startswith("local:")
        assert store.get(result.downloads[0].stored_ref) == b"MZ\x00"

    def test_plain_result_passes_through(self, store):
        result = DetonationResult(job_id="d", status="ok", screenshot_ref=None)
        assert rehome(result, store).screenshot_ref is None

    def test_missing_bytes_noted(self, store):
        out = SandboxOutput(job_id="d", status="ok", screenshot_ref="file:screenshot.jpg", files={})
        result = rehome(out, store)
        assert result.screenshot_ref is None
        assert any("no bytes to store" in e for e in result.console_errors)

    def test_already_stored_ref_is_left_alone(self, store):
        existing = store.put(b"data", ".jpg")
        out = SandboxOutput(job_id="d", status="ok", screenshot_ref=existing, files={})
        assert rehome(out, store).screenshot_ref == existing

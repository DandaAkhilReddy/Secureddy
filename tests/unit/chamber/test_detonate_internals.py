"""Unit tests for ``detonate``'s observation and staging internals, driven
with small fakes instead of a browser. The browser-driven paths are covered
by the integration suite."""

from __future__ import annotations

import json

import pytest

from reddysec.chamber import detonate
from reddysec.chamber.detonate import (
    MAX_CONSOLE_ERRORS,
    MAX_REQUESTS,
    _Collector,
    _form_record,
    _is_timeout,
)
from reddysec.chamber.protocol import input_file_ref, write_job_files
from reddysec.models import DetonationJob, DetonationKind, DetonationStatus, NetworkRequest


def collector(tmp_path, **jobkw):
    kind = jobkw.pop("kind", DetonationKind.URL)
    job = DetonationJob(job_id="det_i", kind=kind, url=jobkw.pop("url", "https://example.com"), **jobkw)
    return _Collector(job=job, workdir=tmp_path)


# --- fakes -------------------------------------------------------------------


class FakeFrame:
    def __init__(self, url):
        self.url = url


class FakeRequest:
    def __init__(self, url, resource_type="document", navigation=True, frame=None, redirected_from=None, redirected_to=None, method="GET"):
        self.url = url
        self.method = method
        self.resource_type = resource_type
        self._navigation = navigation
        self.frame = frame
        self.redirected_from = redirected_from
        self.redirected_to = redirected_to

    def is_navigation_request(self):
        return self._navigation


class FakeResponse:
    def __init__(self, request, status=200):
        self.request = request
        self.status = status


class FakePage:
    def __init__(self, main_frame):
        self.main_frame = main_frame


class FakeConsoleMessage:
    def __init__(self, text, type="log"):
        self.text = text
        self.type = type


# --- Collector time / notes ---------------------------------------------------


class TestCollectorBasics:
    def test_remaining_and_deadline(self, tmp_path):
        col = collector(tmp_path, timeout_s=30)
        assert 0 < col.remaining() <= 30
        assert col.remaining_ms(cap_ms=1000) <= 1000

    def test_timeout_floored(self, tmp_path):
        col = collector(tmp_path, timeout_s=1)
        assert col.remaining() <= detonate.MIN_TIMEOUT_S

    def test_note_and_console_caps(self, tmp_path):
        col = collector(tmp_path)
        for i in range(MAX_CONSOLE_ERRORS + 20):
            col.note(f"n{i}")
            col.console_error(f"e{i}")
        assert len(col.notes) == MAX_CONSOLE_ERRORS
        assert len(col.console_errors) == MAX_CONSOLE_ERRORS

    def test_fail_sets_error_then_notes(self, tmp_path):
        col = collector(tmp_path)
        col.fail("first boom", "goto")
        assert col.status is DetonationStatus.ERROR and col.error == "goto: first boom"
        col.fail("second boom", "features")  # error already set -> becomes a note
        assert any("second boom" in n for n in col.notes)

    def test_public_url_hides_workdir(self, tmp_path):
        col = collector(tmp_path, kind=DetonationKind.FILE, url=None)
        inside = (tmp_path / "view" / "index.html").resolve().as_uri()
        assert col.public_url(inside) == "file:///sandbox/view/index.html"
        assert col.public_url("https://example.com/x") == "https://example.com/x"
        assert col.public_url(None) is None


# --- network observers ---------------------------------------------------------


class TestNetworkObservers:
    def test_on_request_records(self, tmp_path):
        col = collector(tmp_path)
        req = FakeRequest("https://cdn.example.com/a.js", resource_type="script")
        col.on_request(req)
        assert col.requests[0].host == "cdn.example.com" and col.requests[0].resource_type == "script"

    def test_file_job_blocks_non_file_requests(self, tmp_path):
        col = collector(tmp_path, kind=DetonationKind.FILE, url=None)
        col.on_request(FakeRequest("https://evil.example/beacon"))
        assert col.requests == []
        assert any("blocked" in n for n in col.notes)
        # a file:// request is recorded
        col.on_request(FakeRequest("file:///sandbox/view/index.html"))
        assert col.requests and col.requests[0].url.startswith("file:")

    def test_request_cap(self, tmp_path):
        col = collector(tmp_path)
        for i in range(MAX_REQUESTS + 10):
            col.on_request(FakeRequest(f"https://example.com/{i}"))
        assert len(col.requests) == MAX_REQUESTS
        assert col.dropped_requests == 10
        # the cap note shows up in the result
        assert any("beyond the" in e for e in col.result().console_errors)

    def test_on_response_sets_status_and_tracks_nav(self, tmp_path):
        col = collector(tmp_path)
        frame = FakeFrame("https://example.com/")
        col.page = FakePage(frame)
        req = FakeRequest("https://example.com/", navigation=True, frame=frame)
        col.on_request(req)
        col.on_response(FakeResponse(req, status=200))
        assert col.requests[0].status == 200
        assert col.nav_responses  # navigation response captured
        assert col.main_response is not None and col.main_response.status == 200

    def test_main_response_skips_redirected(self, tmp_path):
        col = collector(tmp_path)
        frame = FakeFrame("https://example.com/final")
        col.page = FakePage(frame)
        redirected = FakeResponse(FakeRequest("https://example.com/r", frame=frame, redirected_to=object()))
        terminal = FakeResponse(FakeRequest("https://example.com/final", frame=frame))
        col.nav_responses = [redirected, terminal]
        assert col.main_response is terminal

    def test_on_frame_navigated_filters(self, tmp_path):
        col = collector(tmp_path)
        frame = FakeFrame("https://example.com/a")
        col.page = FakePage(frame)
        col.on_frame_navigated(frame)
        assert col.main_frame_urls == ["https://example.com/a"]
        # about:blank and chrome-error are ignored
        frame.url = "about:blank"
        col.on_frame_navigated(frame)
        frame.url = "chrome-error://chromewebdata/"
        col.on_frame_navigated(frame)
        # same-document (hash only) collapses
        frame.url = "https://example.com/a#section"
        col.on_frame_navigated(frame)
        assert col.main_frame_urls == ["https://example.com/a"]
        # a non-main frame is ignored
        col.on_frame_navigated(FakeFrame("https://other.example/"))
        assert col.main_frame_urls == ["https://example.com/a"]

    def test_on_console_meta_channel(self, tmp_path):
        col = collector(tmp_path)
        payload = json.dumps({"doc": "https://example.com/", "target": "https://example.com/final", "top": True})
        col.on_console(FakeConsoleMessage(f"__rs:meta {payload}"))
        assert col.meta_refresh_docs == {"https://example.com/": "https://example.com/final"}

    def test_on_console_meta_ignores_subframe_and_bad_json(self, tmp_path):
        col = collector(tmp_path)
        col.on_console(FakeConsoleMessage("__rs:meta not-json"))
        col.on_console(FakeConsoleMessage("__rs:other x"))
        col.on_console(FakeConsoleMessage("__rs:meta " + json.dumps({"doc": "x", "top": False})))
        assert col.meta_refresh_docs == {}

    def test_on_console_error_recorded(self, tmp_path):
        col = collector(tmp_path)
        col.on_console(FakeConsoleMessage("boom", type="error"))
        col.on_console(FakeConsoleMessage("ignored", type="log"))
        assert any("console.error" in e for e in col.console_errors)
        assert not any("ignored" in e for e in col.console_errors)

    def test_on_page_error(self, tmp_path):
        col = collector(tmp_path)
        col.on_page_error(RuntimeError("TypeError: x is undefined"))
        assert any("pageerror" in e for e in col.console_errors)


# --- helpers -------------------------------------------------------------------


class TestHelpers:
    def test_form_record_normalizes(self):
        rec = _form_record({"action_url": "https://x.com/login", "action_host": "X.COM", "has_password": True, "has_identity_field": True, "field_names": ["user", "pass"]})
        assert rec.action_host == "x.com" and rec.has_password and rec.field_names == ["user", "pass"]

    def test_form_record_empty(self):
        rec = _form_record({})
        assert rec.action_url is None and not rec.has_password

    def test_finish_requests_marks_third_party(self, tmp_path):
        from reddysec.chamber.detonate import _finish_requests
        from reddysec.models import PageFeatures

        col = collector(tmp_path)
        col.features = PageFeatures(final_host="chase.com")
        col.requests = [NetworkRequest(url="https://cdn.evil.com/a", host="cdn.evil.com"), NetworkRequest(url="https://login.chase.com/b", host="login.chase.com")]
        _finish_requests(col)
        assert col.requests[0].is_third_party is True
        assert col.requests[1].is_third_party is False

    @pytest.mark.parametrize(
        "exc,expected",
        [
            (TimeoutError("x"), True),
            (type("TimeoutException", (Exception,), {})("x"), True),
            (RuntimeError("x"), False),
        ],
    )
    def test_is_timeout(self, exc, expected):
        assert _is_timeout(exc) is expected


# --- staging (no browser) ------------------------------------------------------


class TestStageFile:
    def _stage(self, tmp_path, data, name):
        ref = input_file_ref(name)
        write_job_files({ref[len("file:") :]: data}, tmp_path)
        col = collector(tmp_path, kind=DetonationKind.FILE, url=None, file_ref=ref, file_name=name)
        import asyncio

        return asyncio.run(detonate._stage_file(col)), col

    def test_html(self, tmp_path):
        uri, col = self._stage(tmp_path, b"<html><body>hi</body></html>", "page.html")
        assert uri.endswith("/view/index.html")

    def test_svg_via_text(self, tmp_path):
        uri, col = self._stage(tmp_path, b"<svg xmlns='http://www.w3.org/2000/svg'></svg>", "image.svg")
        assert uri.endswith("/view/index.html")

    def test_image(self, tmp_path):
        import io

        from PIL import Image

        buf = io.BytesIO()
        Image.new("RGB", (10, 10), (1, 2, 3)).save(buf, format="PNG")
        uri, col = self._stage(tmp_path, buf.getvalue(), "pic.png")
        assert "/view/image.png" in uri

    def test_plain_text(self, tmp_path):
        uri, col = self._stage(tmp_path, b"just some notes\nsecond line", "notes.txt")
        assert uri.endswith("/view/text.txt")

    def test_executable_not_viewable(self, tmp_path):
        uri, col = self._stage(tmp_path, b"MZ\x90\x00" + b"\x00" * 40, "x.exe")
        assert uri is None and col.features is None
        assert any("not detonated" in n for n in col.notes)

    def test_missing_staged_file(self, tmp_path):
        col = collector(tmp_path, kind=DetonationKind.FILE, url=None, file_ref="file:input/gone.bin", file_name="gone.bin")
        import asyncio

        assert asyncio.run(detonate._stage_file(col)) is None
        assert col.status is DetonationStatus.ERROR

    def test_bad_file_ref(self, tmp_path):
        col = collector(tmp_path, kind=DetonationKind.FILE, url=None, file_ref=None)
        import asyncio

        assert asyncio.run(detonate._stage_file(col)) is None
        assert col.status is DetonationStatus.ERROR


class TestStagePdf:
    def test_renders_pages_and_notes_js(self, tmp_path):
        from .test_cdr import pdf_with_js

        view = tmp_path / "view"
        view.mkdir()
        col = collector(tmp_path, kind=DetonationKind.FILE, url=None, file_name="statement.pdf")
        uri = detonate._stage_pdf(col, pdf_with_js(text="Chase secure message"), view)
        assert uri.endswith("/view/index.html")
        page = (view / "index.html").read_text()
        assert "Chase secure message" in page
        assert "page_0.png" in page
        assert any("OpenAction" in n or "JavaScript" in n for n in col.notes)

    def test_unparsable_pdf(self, tmp_path):
        view = tmp_path / "view"
        view.mkdir()
        col = collector(tmp_path, kind=DetonationKind.FILE, url=None, file_name="broken.pdf")
        assert detonate._stage_pdf(col, b"%PDF broken \x00", view) is None
        assert col.status is DetonationStatus.ERROR

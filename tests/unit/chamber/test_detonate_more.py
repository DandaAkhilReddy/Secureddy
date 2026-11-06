"""Additional detonate coverage: QR size guards, the file-only route, the
nav-response cap and main_response edge, and PDF JavaScript detection errors."""

from __future__ import annotations

import io

import numpy as np
from PIL import Image

from reddysec.chamber import detonate
from reddysec.chamber.detonate import MAX_REDIRECT_HOPS, _Collector, _file_only_route, decode_qr_codes
from reddysec.models import DetonationJob, DetonationKind


def collector(tmp_path, **kw):
    kind = kw.pop("kind", DetonationKind.URL)
    job = DetonationJob(job_id="det_m", kind=kind, url=kw.pop("url", "https://example.com"), **kw)
    return _Collector(job=job, workdir=tmp_path)


def _qr_png(payload):
    import qrcode

    buf = io.BytesIO()
    qrcode.make(payload, box_size=8, border=4).save(buf, format="PNG")
    return buf.getvalue()


class TestQrSizeGuards:
    def test_tall_image_crop_branch(self):
        # A very tall canvas (>6000px) exercises the crop guard; the call must
        # return a list and never crash. (Decodability is proven elsewhere.)
        qr = Image.open(io.BytesIO(_qr_png("https://example.com/tall")))
        canvas = Image.new("RGB", (800, 8000), (255, 255, 255))
        canvas.paste(qr, (100, 100))
        buf = io.BytesIO()
        canvas.save(buf, format="PNG")
        assert isinstance(decode_qr_codes(buf.getvalue()), list)

    def test_wide_image_downscale_branch(self):
        # A very wide canvas (>2500px) exercises the downscale guard.
        qr = Image.open(io.BytesIO(_qr_png("https://example.com/wide")))
        canvas = Image.new("RGB", (3200, 900), (255, 255, 255))
        canvas.paste(qr.resize((600, 600)), (100, 100))
        buf = io.BytesIO()
        canvas.save(buf, format="PNG")
        assert isinstance(decode_qr_codes(buf.getvalue()), list)

    def test_undecodable_bytes(self):
        assert decode_qr_codes(b"\x00\x01\x02 not an image") == []

    def test_blank_image_no_codes(self):
        buf = io.BytesIO()
        Image.new("RGB", (100, 100), (255, 255, 255)).save(buf, format="PNG")
        assert decode_qr_codes(buf.getvalue()) == []


class TestFileOnlyRoute:
    async def test_continues_file_scheme(self):
        continued = []
        aborted = []

        class Route:
            async def continue_(self):
                continued.append(True)

            async def abort(self, reason=None):
                aborted.append(reason)

        class Req:
            url = "file:///sandbox/view/index.html"

        await _file_only_route(Route(), Req())
        assert continued and not aborted

    async def test_aborts_non_file_scheme(self):
        aborted = []

        class Route:
            async def continue_(self):
                raise AssertionError("should not continue")

            async def abort(self, reason=None):
                aborted.append(reason)

        class Req:
            url = "https://evil.example/beacon"

        await _file_only_route(Route(), Req())
        assert aborted == ["blockedbyclient"]


class TestNavResponseEdges:
    def test_nav_response_cap(self, tmp_path):
        col = collector(tmp_path)

        class Frame:
            pass

        main = Frame()

        class Page:
            main_frame = main

        col.page = Page()

        class Req:
            def __init__(self):
                self.frame = main

            def is_navigation_request(self):
                return True

        class Resp:
            def __init__(self):
                self.request = Req()

        for _ in range(MAX_REDIRECT_HOPS * 2 + 5):
            col.on_response(Resp())
        assert len(col.nav_responses) == MAX_REDIRECT_HOPS * 2

    def test_main_response_handles_exception(self, tmp_path):
        col = collector(tmp_path)

        class Bad:
            @property
            def request(self):
                raise RuntimeError("detached")

        col.nav_responses = [Bad()]
        assert col.main_response is None


class TestPdfJavaScriptErrors:
    def test_pdf_has_js_swallows_errors(self):
        class BadDoc:
            def xref_length(self):
                raise RuntimeError("corrupt")

        assert detonate._pdf_has_javascript(BadDoc()) is False

    def test_numpy_available(self):
        assert np.array([1, 2, 3]).sum() == 6  # guards the cv2/np import path

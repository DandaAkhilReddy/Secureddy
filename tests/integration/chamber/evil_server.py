"""A local "evil site" for chamber tests. Everything stays on 127.0.0.1.

Two servers run side by side so redirects can cross *hosts*: the primary is
addressed as ``http://127.0.0.1:<a>`` and the secondary as
``http://localhost:<b>``. Same machine, different hostnames, which is all the
third-party / external-form-action logic needs.

Routes (primary):

    /benign              plain page
    /phish-login         fake bank login, password field, form posts to the other host
    /redirect-chain      302 -> /r2 -> 302 -> <other host>/final
    /meta-refresh        <meta http-equiv=refresh> to /final
    /js-redirect         location.href to /final from a timer
    /download            invoice.exe (MZ header) as an attachment
    /pdf-download        statement.pdf containing JavaScript, as an attachment
    /obfuscated          eval(atob(...)) and friends
    /captcha             turnstile-like markup + "verify you are human"
    /qr                  page with a QR code pointing at /phish-login
    /slow                sleeps 20 s before answering
    /hidden-text         mostly display:none text
    /file-exfil-test     page that beacons home (served, and used as a FILE job fixture)
    /dialog              alert() on load (dialogs must not hang the chamber)
    /popup               window.open() of /benign
    /beacon*, /collect   sinks; every hit is recorded in ``hits``

Lure pages (docs/threat-catalog.md):

    /clickfix            fake reCAPTCHA checkbox; click copies `powershell -w hidden -enc ...`
                         and shows "Windows + R, Ctrl + V, Enter"
    /clickfix-exec       fake "Word Online" error; "How to fix" copies an mshta command with
                         textarea + execCommand('copy'); Win + X -> Terminal instructions
    /filefix             FileFix: copy event puts PowerShell padded behind a fake file path;
                         "File Explorer, address bar, Ctrl + V"
    /macos-terminal      Cmd + Space, Terminal, paste `bash -c "$(curl ...)"`
    /fake-captcha        "I'm not a robot" + Win + R steps, nothing on the clipboard
    /dev-docs            negative: install docs with PowerShell/curl snippets and a Copy button
    /real-captcha        negative: a sign-up form with a (stand-in) reCAPTCHA widget
    /turnstile-login     fake Turnstile gate that reveals a Microsoft sign-in form, proxied
                         Microsoft asset paths, debugger loop
    /device-code         "go to microsoft.com/devicelogin and enter GHK7-PQ2X"
    /tech-support        full screen, keyboard lock, alert loop, "Call Microsoft Support"
    /wallet              airdrop page; "Connect Wallet" calls eth_requestAccounts; seed phrase box
    /notify              Notification.requestPermission() on load
    /open-redirect       ?u=<url> 302 to <url> (l.php-style open redirect)
    /dl/iso /dl/lnk /dl/msi /dl/locked-zip /dl/invoice-pdf   downloads of each kind
"""

from __future__ import annotations

import io
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "evil_site"

# 1x1 transparent PNG.
PIXEL_PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d4944415478da63f8ffff3f0300050001"
    "27f1bd0b0000000049454e44ae426082"
)


def pdf_with_javascript(text: str = "Your statement is ready.") -> bytes:
    """A one-page PDF with an OpenAction JavaScript - the kind of thing CDR must strip."""
    import pymupdf

    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), text, fontsize=14)
    js_xref = doc.get_new_xref()
    doc.update_object(js_xref, "<< /S /JavaScript /JS (app.alert\\('pwned'\\);) >>")
    doc.xref_set_key(doc.pdf_catalog(), "OpenAction", f"{js_xref} 0 R")
    data = doc.tobytes()
    doc.close()
    return data


def qr_png(payload: str) -> bytes:
    import qrcode

    image = qrcode.make(payload, box_size=8, border=4)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def render_fixture(name: str, **values: str) -> str:
    text = (FIXTURES / name).read_text(encoding="utf-8")
    for key, value in values.items():
        text = text.replace("{{" + key + "}}", value)
    return text


_LURE_PAGES: dict[str, str] = {
    "/clickfix": "clickfix.html",
    "/clickfix-exec": "clickfix-execcommand.html",
    "/filefix": "filefix.html",
    "/macos-terminal": "macos-terminal.html",
    "/fake-captcha": "fake-captcha-no-payload.html",
    "/dev-docs": "dev-docs.html",
    "/real-captcha": "real-captcha.html",
    "/turnstile-login": "turnstile-login.html",
    "/device-code": "device-code.html",
    "/tech-support": "tech-support.html",
    "/wallet": "wallet.html",
    "/notify": "notify.html",
}


def iso_image() -> bytes:
    """Smallest thing that sniffs as ISO 9660: the CD001 volume descriptor at 0x8001."""
    data = bytearray(0x8800)
    data[0x8000] = 1
    data[0x8001:0x8006] = b"CD001"
    return bytes(data)


def lnk_file() -> bytes:
    return b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46" + b"\x00" * 200


def msi_file() -> bytes:
    return b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 504


def locked_zip(entry: str = "Invoice_2026.js") -> bytes:
    """A ZIP whose entry is flagged as encrypted (ZipCrypto). The bytes are not
    really encrypted; the listing is what the chamber reads."""
    import struct
    import zlib

    name = entry.encode()
    body = b"\x00" * 12 + b"WScript.Echo(1)"  # 12-byte ZipCrypto header + data
    crc = zlib.crc32(b"WScript.Echo(1)")
    flags = 0x1
    local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags, 0, 0, 0, crc, len(body), 15, len(name), 0) + name + body
    central = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flags, 0, 0, 0, crc, len(body), 15, len(name), 0, 0, 0, 0, 0, 0) + name
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + end


_DOWNLOADS: dict[str, object] = {
    "/dl/iso": lambda: ("Invoice_2026.iso", "application/octet-stream", iso_image()),
    "/dl/lnk": lambda: ("Statement.pdf.lnk", "application/octet-stream", lnk_file()),
    "/dl/msi": lambda: ("ChromeUpdate.msi", "application/x-msi", msi_file()),
    "/dl/locked-zip": lambda: ("Invoice_2026.zip", "application/zip", locked_zip()),
    "/dl/invoice-pdf": lambda: ("invoice.pdf", "application/pdf", b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"),
}


class EvilSite:
    """Start with ``start()``; ``origin`` / ``other_origin`` are the two hosts."""

    def __init__(self, slow_seconds: float = 20.0) -> None:
        self.slow_seconds = slow_seconds
        self.hits: list[str] = []
        self._lock = threading.Lock()
        self._primary: ThreadingHTTPServer | None = None
        self._secondary: ThreadingHTTPServer | None = None
        self._threads: list[threading.Thread] = []
        self.origin = ""
        self.other_origin = ""

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> EvilSite:
        site = self

        class Handler(_EvilHandler):
            pass

        Handler.site = site
        self._primary = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._secondary = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._primary.daemon_threads = True
        self._secondary.daemon_threads = True
        self.origin = f"http://127.0.0.1:{self._primary.server_address[1]}"
        self.other_origin = f"http://localhost:{self._secondary.server_address[1]}"
        for server in (self._primary, self._secondary):
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
            thread.start()
            self._threads.append(thread)
        return self

    def stop(self) -> None:
        for server in (self._primary, self._secondary):
            if server is not None:
                server.shutdown()
                server.server_close()
        for thread in self._threads:
            thread.join(timeout=5)

    def __enter__(self) -> EvilSite:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- helpers -----------------------------------------------------------
    def url(self, path: str) -> str:
        return self.origin + path

    def other_url(self, path: str) -> str:
        return self.other_origin + path

    def record(self, path: str) -> None:
        with self._lock:
            self.hits.append(path)

    def hits_matching(self, prefix: str) -> list[str]:
        with self._lock:
            return [h for h in self.hits if h.startswith(prefix)]

    def exfil_fixture_html(self) -> str:
        """The FILE-job fixture, pointed at this server so a leak would be visible."""
        return render_fixture("file-exfil-test.html", ORIGIN=self.origin)


class _EvilHandler(BaseHTTPRequestHandler):
    site: EvilSite
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:  # keep pytest output clean
        return

    # -- plumbing ------------------------------------------------------------
    def _send(self, body: bytes, status: int = 200, content_type: str = "text/html; charset=utf-8", headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _redirect(self, location: str, status: int = 302) -> None:
        self._send(b"", status, headers={"Location": location})

    def _page(self, name: str, **values: str) -> None:
        self._send(render_fixture(name, **values).encode("utf-8"))

    def _own_origin(self) -> str:
        host = self.headers.get("Host", "")
        return f"http://{host}" if host else self.site.origin

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self.do_GET()

    def do_HEAD(self) -> None:
        self.do_GET()

    # -- routes ----------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: C901 - a flat routing table is the readable form here
        site = self.site
        path = urlsplit(self.path).path
        site.record(self.path)
        if path == "/benign" or path == "/final":
            self._page("benign.html")
        elif path == "/phish-login":
            self._page("phish-login.html", OTHER_ORIGIN=site.other_origin)
        elif path == "/redirect-chain":
            self._redirect("/r2")
        elif path == "/r2":
            self._redirect(site.other_origin + "/final")
        elif path == "/meta-refresh":
            self._send(b"<!doctype html><html><head><meta http-equiv='refresh' content='0;url=/final'><title>Redirecting</title></head><body>Redirecting...</body></html>")
        elif path == "/js-redirect":
            self._send(b"<!doctype html><html><head><title>Loading</title></head><body>One moment<script>setTimeout(function(){location.href='/final'},150)</script></body></html>")
        elif path == "/download":
            body = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00" + b"\x90" * 200
            self._send(body, content_type="application/octet-stream", headers={"Content-Disposition": 'attachment; filename="invoice.exe"'})
        elif path == "/pdf-download":
            self._send(pdf_with_javascript(), content_type="application/pdf", headers={"Content-Disposition": 'attachment; filename="statement.pdf"'})
        elif path == "/obfuscated":
            self._page("obfuscated.html")
        elif path == "/captcha":
            self._page("captcha.html")
        elif path == "/qr":
            self._send(b"<!doctype html><html><head><title>Scan to view</title></head><body><h1>Scan the code with your phone to view the secure document</h1><img src='/qr.png' alt='QR code' width='330' height='330'></body></html>")
        elif path == "/qr.png":
            self._send(qr_png(site.origin + "/phish-login"), content_type="image/png")
        elif path == "/slow":
            time.sleep(site.slow_seconds)
            self._send(b"<!doctype html><html><body>finally</body></html>")
        elif path == "/hidden-text":
            self._page("hidden-text.html")
        elif path == "/file-exfil-test":
            self._page("file-exfil-test.html", ORIGIN=site.origin)
        elif path == "/dialog":
            self._send(b"<!doctype html><html><head><title>Dialog</title></head><body><script>alert('are you there?')</script><p>after the alert</p></body></html>")
        elif path == "/popup":
            self._send(b"<!doctype html><html><head><title>Popup</title></head><body><script>window.open('/benign')</script><p>popup page</p></body></html>")
        elif path in _LURE_PAGES:
            self._page(_LURE_PAGES[path])
        elif path == "/open-redirect":
            from urllib.parse import parse_qs

            target = parse_qs(urlsplit(self.path).query).get("u", [""])[0]
            self._redirect(target or "/benign")
        elif path in _DOWNLOADS:
            name, content_type, body = _DOWNLOADS[path]()
            self._send(body, content_type=content_type, headers={"Content-Disposition": f'attachment; filename="{name}"'})
        elif path == "/static/recaptcha/api.js":
            self._send(b"/* recaptcha stand-in */", content_type="application/javascript")
        elif path.startswith("/shared/1.0/content/"):
            self._send(PIXEL_PNG if path.endswith((".png", ".svg")) else b"/* proxied asset */",
                       content_type="image/png" if path.endswith((".png", ".svg")) else "application/javascript")
        elif path.startswith("/beacon") or path == "/collect":
            self._send(b"", 204, content_type="text/plain")
        elif path == "/static/pixel.png" or path == "/static/logo.png":
            self._send(PIXEL_PNG, content_type="image/png")
        elif path == "/static/turnstile/v0/api.js":
            self._send(b"/* turnstile stand-in */", content_type="application/javascript")
        elif path == "/static/turnstile/frame":
            self._send(b"<!doctype html><html><body>challenge frame</body></html>")
        elif path == "/forbidden":
            self._send(b"", 403, content_type="text/plain")
        else:
            self._send(b"<!doctype html><html><body>not found</body></html>", 404)

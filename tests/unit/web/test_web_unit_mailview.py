"""Reading mail safely: the sanitiser (XSS corpus), link signing, tracking
parameters, parsing, and the image proxy's network rules."""

from __future__ import annotations

import base64
from email.message import EmailMessage
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from reddysec.web import mailview as mv

SECRET = "unit-secret"

XSS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '<a href="javascript:alert(1)">x</a>',
    '<a href="JaVaScRiPt:alert(1)">x</a>',
    '<a href="data:text/html;base64,PHNjcmlwdD4=">x</a>',
    '<a href="vbscript:msgbox(1)">x</a>',
    '<div style="background:url(javascript:alert(1))">x</div>',
    '<div style="width: expression(alert(1))">x</div>',
    '<div style="background-image:url(https://track.example/p.gif)">x</div>',
    '<svg onload="alert(1)"><script>alert(1)</script></svg>',
    '<math><mi xlink:href="javascript:alert(1)">x</mi></math>',
    '<img srcset="https://track.example/a.png 1x" src="cid:nope">',
    '<meta http-equiv="refresh" content="0;url=https://evil.example">',
    '<form action="https://evil.example"><input name="password"><button>Go</button></form>',
    '<iframe src="https://evil.example"></iframe>',
    '<object data="x.swf"></object><embed src="x.swf">',
    '<base href="https://evil.example/">',
    '<link rel="stylesheet" href="https://evil.example/x.css">',
    '<style>@import url(https://evil.example/x.css); body{background:url(https://t.example/x)}</style>',
    '<body onload="alert(1)"><p onclick="alert(1)">hi</p></body>',
    '<template><img src=x onerror=alert(1)></template>',
    '<noscript><img src=x onerror=alert(1)></noscript>',
    '<a href="https://ok.example" onmouseover="alert(1)">x</a>',
    "<!--<img src=x onerror=alert(1)>-->",
    '<img src="https://track.example/pixel.gif">',
    '<video src="https://evil.example/v.mp4"></video><audio src="x"></audio>',
    '<p id="x" class="y" data-x="1">kept text</p>',
]
FORBIDDEN = ("<script", "onerror", "onload", "onclick", "onmouseover", "javascript:", "vbscript:", "data:text",
             "expression(", "<svg", "<math", "srcset", "<meta", "<form", "<input", "<iframe", "<object", "<embed",
             "<base", "<link", "<style", "@import", "track.example", "evil.example", "<template", "<video",
             "<audio", 'class="y"', 'id="x"', "data-x")


@pytest.mark.parametrize("payload", XSS)
def test_xss_corpus_is_neutralised(payload):
    out = mv.sanitize_html(payload, secret=SECRET, message_id="msg_1").html.lower()
    for bad in FORBIDDEN:
        assert bad not in out, (payload, bad, out)


def test_good_markup_kept_links_rewritten_and_signed():
    html = ('<table width="600" cellpadding="4"><tr><td style="color:#c00;position:fixed;background-image:url(x)">'
            '<b>Hi</b> <a href="https://shop.example/a?b=1&c=2">Shop</a> <a href="mailto:x@y.z">mail</a></td></tr></table>')
    result = mv.sanitize_html(html, secret=SECRET, message_id="msg_1")
    assert '<td style="color:#c00">' in result.html and 'width="600"' in result.html
    assert 'target="_top"' in result.html and 'rel="noopener noreferrer nofollow"' in result.html
    assert 'href="mailto:x@y.z"' in result.html and result.links == 1
    href = result.html.split('href="')[1].split('"')[0].replace("&amp;", "&")
    q = parse_qs(urlsplit(href).query)
    assert href.startswith("/go?") and q["u"] == ["https://shop.example/a?b=1&c=2"] and q["m"] == ["msg_1"]
    assert mv.verify_link(SECRET, "msg_1", q["u"][0], q["s"][0])


def test_images_blocked_until_asked_and_cid_inlined():
    png = b"\x89PNG\r\n\x1a\nxx"
    html = '<img src="https://cdn.example/a.png"><img src="cid:logo"><img src="cid:missing"><img src="ftp://x/y.png">'
    blocked = mv.sanitize_html(html, secret=SECRET, message_id="m", inline_images={"logo": ("image/png", png)})
    assert blocked.blocked_images == 1 and "cdn.example" not in blocked.html
    assert f"data:image/png;base64,{base64.b64encode(png).decode()}" in blocked.html
    loaded = mv.sanitize_html(html, secret=SECRET, message_id="m", load_images=True)
    src = loaded.html.split('src="')[1].split('"')[0].replace("&amp;", "&")
    assert src.startswith("/messages/m/image?")
    q = parse_qs(urlsplit(src).query)
    assert mv.verify_link(SECRET, "m", q["u"][0], q["s"][0], purpose="img")
    assert not mv.verify_link(SECRET, "m", q["u"][0], q["s"][0])  # an image signature is not a link signature


def test_signatures_bind_message_url_and_secret():
    sig = mv.sign_link(SECRET, "m1", "https://a.example/")
    assert mv.verify_link(SECRET, "m1", "https://a.example/", sig)
    assert not mv.verify_link(SECRET, "m2", "https://a.example/", sig)
    assert not mv.verify_link(SECRET, "m1", "https://b.example/", sig)
    assert not mv.verify_link("other", "m1", "https://a.example/", sig)
    assert not mv.verify_link(SECRET, "m1", "https://a.example/", None)
    assert not mv.verify_link(SECRET, "", "https://a.example/", sig)


def test_strip_tracking():
    assert mv.strip_tracking("https://x.example/p?utm_source=a&id=5&fbclid=z&mc_eid=1#f") == "https://x.example/p?id=5#f"
    assert mv.strip_tracking("https://x.example/p") == "https://x.example/p"
    assert mv.strip_tracking("http://[::1") == "http://[::1"


def test_text_to_html_escapes_and_links():
    out = mv.text_to_html("Hi <b>&\nGo to https://x.example/a. Bye", secret=SECRET, message_id="m")
    assert "&lt;b&gt;&amp;<br>" in out and "/go?u=https%3A%2F%2Fx.example%2Fa" in out and "</a>. Bye" in out


def make_email(*, html: str | None = None, text: str | None = None, attach: bool = True) -> bytes:
    msg = EmailMessage()
    msg["From"] = "A <a@example.com>"
    msg["To"] = "b@example.com"
    msg["Subject"] = "Hello"
    msg.set_content(text or "plain body")
    if html is not None:
        msg.add_alternative(html, subtype="html")
        html_part = msg.get_payload()[-1]
        html_part.add_related(b"\x89PNGlogo", maintype="image", subtype="png", cid="<logo>")
    if attach:
        msg.add_attachment(b"%PDF-1.4 data", maintype="application", subtype="pdf", filename="Invoice.pdf")
        msg.add_attachment(b"MZ", maintype="application", subtype="octet-stream", filename="tool.exe")
    return msg.as_bytes()


def test_parse_message_bodies_inline_images_and_attachments():
    body = mv.parse_message(make_email(html="<p>Hi <img src='cid:logo'></p>"))
    assert body.subject == "Hello" and body.html and body.text.strip() == "plain body"
    assert body.inline_images["logo"][0] == "image/png"
    assert [(a.index, a.filename, a.size) for a in body.attachments] == [(0, "Invoice.pdf", 13), (1, "tool.exe", 2)]
    assert mv.attachment_bytes(make_email(), 1)[0] == "tool.exe" and mv.attachment_bytes(make_email(), 5) is None
    assert mv.attachment_by_name(make_email(), "Invoice.pdf")[2] == b"%PDF-1.4 data"
    assert mv.attachment_by_name(make_email(), "nope.pdf") is None


def test_plain_text_for_the_assistant():
    raw = make_email(text="  Pay   now\n\n\n\nplease  ", attach=False)
    assert mv.plain_text(raw, 100) == "Pay now\n\nplease"
    html_only = (b"Content-Type: text/html\r\nSubject: s\r\n\r\n<style>x{}</style><p>Wire &amp; <b>send</b></p>")
    assert mv.plain_text(html_only, 100) == "Wire & send"
    assert len(mv.plain_text(make_email(text="x" * 9000, attach=False), 6000)) == 6000


def test_body_document_and_csp():
    doc = mv.body_document("<p>x</p>")
    assert doc.startswith("<!doctype html>") and "<p>x</p>" in doc
    csp = mv.body_csp("https://app.example")
    assert "default-src 'none'" in csp and "img-src data: https://app.example" in csp and "script" not in csp


# --------------------------------------------------------------------------- image proxy


async def public(host: str) -> bool:
    return True


def client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_fetch_image_ok_strips_tracking_and_sends_nothing_personal():
    seen: list[httpx.Request] = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, content=b"GIF89a", headers={"content-type": "image/gif"})

    ctype, data = await mv.fetch_image(client(handler), "https://cdn.example/p.gif?utm_source=x&id=1", max_bytes=100,
                                       resolver=public)
    assert (ctype, data) == ("image/gif", b"GIF89a")
    assert str(seen[0].url) == "https://cdn.example/p.gif?id=1"
    assert "cookie" not in seen[0].headers and "referer" not in seen[0].headers


@pytest.mark.parametrize("url", ["ftp://x/y.png", "https://u:p@x.example/a.png", "https://x.example:8443/a.png",
                                 "https:///nohost"])
async def test_fetch_image_refuses_odd_addresses(url):
    with pytest.raises(mv.ImageRefused):
        await mv.fetch_image(client(lambda r: httpx.Response(200)), url, max_bytes=10, resolver=public)


async def test_fetch_image_refuses_private_svg_big_and_redirect_loops():
    async def private(host):
        return False

    with pytest.raises(mv.ImageRefused, match="private"):
        await mv.fetch_image(client(lambda r: httpx.Response(200)), "https://x.example/a.png", max_bytes=10, resolver=private)
    svg = client(lambda r: httpx.Response(200, content=b"<svg/>", headers={"content-type": "image/svg+xml"}))
    with pytest.raises(mv.ImageRefused, match="not an image"):
        await mv.fetch_image(svg, "https://x.example/a.svg", max_bytes=100, resolver=public)
    big = client(lambda r: httpx.Response(200, content=b"x" * 50, headers={"content-type": "image/png"}))
    with pytest.raises(mv.ImageRefused, match="too big"):
        await mv.fetch_image(big, "https://x.example/a.png", max_bytes=10, resolver=public)
    declared = client(lambda r: httpx.Response(200, content=b"x", headers={"content-type": "image/png", "content-length": "999"}))
    with pytest.raises(mv.ImageRefused, match="too big"):
        await mv.fetch_image(declared, "https://x.example/a.png", max_bytes=10, resolver=public)
    loop = client(lambda r: httpx.Response(302, headers={"location": "/again"}))
    with pytest.raises(mv.ImageRefused, match="redirects"):
        await mv.fetch_image(loop, "https://x.example/a.png", max_bytes=10, resolver=public)
    nowhere = client(lambda r: httpx.Response(302))
    with pytest.raises(mv.ImageRefused, match="location"):
        await mv.fetch_image(nowhere, "https://x.example/a.png", max_bytes=10, resolver=public)
    missing = client(lambda r: httpx.Response(404))
    with pytest.raises(mv.ImageRefused, match="404"):
        await mv.fetch_image(missing, "https://x.example/a.png", max_bytes=10, resolver=public)

    def boom(request):
        raise httpx.ConnectError("x")

    with pytest.raises(mv.ImageRefused):
        await mv.fetch_image(client(boom), "https://x.example/a.png", max_bytes=10, resolver=public)


async def test_redirect_to_private_address_is_checked_again():
    hosts: list[str] = []

    async def resolver(host):
        hosts.append(host)
        return host != "169.254.169.254"

    hop = client(lambda r: httpx.Response(302, headers={"location": "http://169.254.169.254/metadata"}))
    with pytest.raises(mv.ImageRefused, match="private"):
        await mv.fetch_image(hop, "https://x.example/a.png", max_bytes=10, resolver=resolver)
    assert hosts == ["x.example", "169.254.169.254"]


@pytest.mark.parametrize("ip,ok", [("8.8.8.8", True), ("10.0.0.1", False), ("127.0.0.1", False),
                                   ("169.254.169.254", False), ("100.64.1.1", False), ("::1", False),
                                   ("::ffff:10.0.0.1", False), ("2001:4860:4860::8888", True), ("bad", False)])
def test_public_ip(ip, ok):
    assert mv._public_ip(ip) is ok


async def test_resolves_public(monkeypatch):
    assert await mv._resolves_public("127.0.0.1") is False
    assert await mv._resolves_public("") is False
    import asyncio

    loop = asyncio.get_running_loop()

    async def fake(host, port, type=0):
        if host == "fail.example":
            raise OSError("nx")
        return [(0, 0, 0, "", ("93.184.216.34", 0)), (0, 0, 0, "", ("10.1.1.1", 0))] if host == "mixed.example" else \
            [(0, 0, 0, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(loop, "getaddrinfo", fake)
    assert await mv._resolves_public("ok.example") is True
    assert await mv._resolves_public("mixed.example") is False
    assert await mv._resolves_public("fail.example") is False

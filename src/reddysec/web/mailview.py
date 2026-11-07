"""Reading an email inside Secureddy, safely.

The body is fetched live from the provider when the person opens the
"Read email" tab (``connector.fetch_raw``), parsed here, sanitised, and sent
straight to the browser with ``Cache-Control: no-store``. It is never written
to our database, our artifact store or any cache.

Sanitising (:func:`sanitize_html`, built on ``nh3``, the Rust ``ammonia``
sanitiser):

* An allowlist of formatting tags and attributes. Everything else goes:
  ``script``, ``style`` blocks, ``iframe``, ``object``, ``form`` and its
  inputs, ``meta`` (refresh), ``base``, ``link``, SVG and MathML, every
  ``on*`` handler, ``srcset``, ``class``/``id``.
* Inline ``style`` survives only for an allowlist of layout and text
  properties (no ``background-image``, ``position``, ``behavior`` ...).
* Every link is rewritten to our warning page ``/go?u=...&m=...&s=...``. The
  target URL is signed with HMAC (:func:`sign_link`) so ``/go`` can never be
  used as an open redirect for anyone else's URL.
* Remote images are dropped until the person presses "Load images"; then they
  are fetched through ``/messages/{id}/image`` (signed the same way), without
  cookies, referrer or the person's IP address, with tracking parameters
  removed and a size limit. Inline (``cid:``) images from the email itself
  become ``data:`` URLs (raster formats only; never SVG).

The page that shows the result puts it in an ``<iframe sandbox>`` without
``allow-scripts`` or ``allow-same-origin``, and the body response carries its
own CSP (``default-src 'none'``), so even a sanitiser bug could not run code
or reach the network.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html as html_lib
import ipaddress
import re
import socket
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import httpx
import nh3

MAX_HTML_CHARS = 2_000_000
MAX_INLINE_IMAGE = 2 * 1024 * 1024
INLINE_IMAGE_TYPES = frozenset({"image/png", "image/jpeg", "image/gif", "image/webp"})
PROXY_IMAGE_TYPES = frozenset(
    {"image/png", "image/jpeg", "image/gif", "image/webp", "image/avif", "image/bmp", "image/x-icon"}
)

ALLOWED_TAGS = frozenset(
    {
        "a", "abbr", "b", "blockquote", "br", "caption", "center", "code", "col", "colgroup", "dd", "del",
        "div", "dl", "dt", "em", "font", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "img", "ins", "kbd",
        "li", "mark", "ol", "p", "pre", "q", "s", "small", "span", "strike", "strong", "sub", "sup", "table",
        "tbody", "td", "tfoot", "th", "thead", "tr", "tt", "u", "ul",
    }
)
_COMMON = {"style", "align", "valign", "dir", "title", "lang", "width", "height", "bgcolor"}
ALLOWED_ATTRIBUTES: dict[str, set[str]] = {
    "*": {"style", "align", "dir", "title", "lang"},
    "a": {"href"},
    "img": {"src", "alt", "width", "height", "border"},
    "table": _COMMON | {"border", "cellpadding", "cellspacing"},
    "td": _COMMON | {"colspan", "rowspan", "nowrap"},
    "th": _COMMON | {"colspan", "rowspan", "nowrap", "scope"},
    "tr": _COMMON,
    "col": {"span", "width"},
    "colgroup": {"span", "width"},
    "font": {"color", "face", "size"},
    "ol": {"start", "type"},
    "div": _COMMON,
    "p": _COMMON,
    "span": _COMMON,
    "center": _COMMON,
    "blockquote": _COMMON,
}
ALLOWED_STYLE_PROPERTIES = frozenset(
    {
        "color", "background-color", "font", "font-family", "font-size", "font-style", "font-weight",
        "line-height", "letter-spacing", "text-align", "text-decoration", "text-transform", "vertical-align",
        "white-space", "word-break", "word-wrap", "overflow-wrap", "padding", "padding-top", "padding-right",
        "padding-bottom", "padding-left", "margin", "margin-top", "margin-right", "margin-bottom",
        "margin-left", "border", "border-top", "border-right", "border-bottom", "border-left", "border-color",
        "border-style", "border-width", "border-radius", "border-collapse", "border-spacing", "width",
        "max-width", "min-width", "height", "max-height", "min-height", "display", "table-layout",
        "list-style-type",
    }
)
URL_SCHEMES = frozenset({"http", "https", "mailto", "cid"})

# Query parameters that only exist to track the reader.
TRACKING_PARAMS = re.compile(
    r"^(utm_[a-z]+|mc_eid|mc_cid|_hsenc|_hsmi|hsctatracking|mkt_tok|fbclid|gclid|dclid|msclkid|yclid|"
    r"igshid|oly_enc_id|oly_anon_id|vero_id|_bta_tid|_bta_c|trk|trkcampaign|sc_cid|ss_source|ss_campaign_id)$",
    re.I,
)


# --------------------------------------------------------------------------- signing


def _key(secret: str, purpose: str) -> bytes:
    return hashlib.sha256(f"reddysec.web.{purpose}\x00{secret}".encode()).digest()


def sign_link(secret: str, message_id: str, url: str, *, purpose: str = "go") -> str:
    """HMAC-SHA256 over (purpose, message id, url), base64url, 22 chars."""
    mac = hmac.new(_key(secret, purpose), f"{message_id}\n{url}".encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac[:16]).decode().rstrip("=")


def verify_link(secret: str, message_id: str, url: str, signature: str | None, *, purpose: str = "go") -> bool:
    if not signature or not url or not message_id:
        return False
    return hmac.compare_digest(sign_link(secret, message_id, url, purpose=purpose), signature)


def go_href(secret: str, message_id: str, url: str) -> str:
    return "/go?" + urlencode({"u": url, "m": message_id, "s": sign_link(secret, message_id, url)})


def image_href(secret: str, message_id: str, url: str) -> str:
    return f"/messages/{quote(message_id)}/image?" + urlencode(
        {"u": url, "s": sign_link(secret, message_id, url, purpose="img")}
    )


def strip_tracking(url: str) -> str:
    """Drop ``utm_*`` and friends from a URL's query string."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.query:
        return url
    kept = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if not TRACKING_PARAMS.match(k)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(kept), parts.fragment))


# --------------------------------------------------------------------------- parsing


@dataclass(frozen=True)
class Attachment:
    index: int
    filename: str
    content_type: str
    size: int


@dataclass
class MailBody:
    html: str | None = None
    text: str | None = None
    inline_images: dict[str, tuple[str, bytes]] = field(default_factory=dict)  # cid -> (mime, bytes)
    attachments: list[Attachment] = field(default_factory=list)
    subject: str = ""
    from_: str = ""
    to: str = ""
    date: str = ""


def _payload_text(part: EmailMessage) -> str:
    try:
        content = part.get_content()
    except (LookupError, ValueError, AssertionError):
        raw = part.get_payload(decode=True) or b""
        content = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
    return content if isinstance(content, str) else ""


def parse_message(raw: bytes) -> MailBody:
    """The readable parts of an RFC 5322 message: the HTML and plain-text
    bodies, inline images by Content-ID, and the attachment list (names and
    sizes only; their bytes are fetched again on a download)."""
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    assert isinstance(msg, EmailMessage)
    body = MailBody(
        subject=str(msg.get("Subject", "") or ""),
        from_=str(msg.get("From", "") or ""),
        to=str(msg.get("To", "") or ""),
        date=str(msg.get("Date", "") or ""),
    )
    for index, part in enumerate(attachment_parts(msg)):
        payload = part.get_payload(decode=True) or b""
        body.attachments.append(
            Attachment(index, _filename(part, index), part.get_content_type(), len(payload))
        )
    html_part = msg.get_body(preferencelist=("html",))
    text_part = msg.get_body(preferencelist=("plain",))
    if html_part is not None:
        body.html = _payload_text(html_part)[:MAX_HTML_CHARS]
    if text_part is not None:
        body.text = _payload_text(text_part)[:MAX_HTML_CHARS]
    for part in msg.walk():
        cid = str(part.get("Content-ID", "") or "").strip().strip("<>")
        ctype = part.get_content_type()
        if cid and ctype in INLINE_IMAGE_TYPES:
            data = part.get_payload(decode=True) or b""
            if isinstance(data, bytes) and 0 < len(data) <= MAX_INLINE_IMAGE:
                body.inline_images[cid] = (ctype, data)
    return body


def attachment_parts(msg: EmailMessage) -> list[EmailMessage]:
    out: list[EmailMessage] = []
    for part in msg.iter_attachments():
        if isinstance(part, EmailMessage):
            out.append(part)
    return out


def _filename(part: EmailMessage, index: int) -> str:
    name = part.get_filename() or ""
    name = "".join(ch for ch in name if ch.isprintable()).strip()
    return name[:200] or f"attachment-{index + 1}"


def attachment_bytes(raw: bytes, index: int) -> tuple[str, str, bytes] | None:
    """(filename, content type, bytes) of attachment ``index``, or None."""
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    assert isinstance(msg, EmailMessage)
    parts = attachment_parts(msg)
    if not 0 <= index < len(parts):
        return None
    part = parts[index]
    data = part.get_payload(decode=True) or b""
    return _filename(part, index), part.get_content_type(), data if isinstance(data, bytes) else b""


def attachment_by_name(raw: bytes, filename: str) -> tuple[str, str, bytes] | None:
    """The first attachment called ``filename``, as (name, type, bytes)."""
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    assert isinstance(msg, EmailMessage)
    for index, part in enumerate(attachment_parts(msg)):
        if _filename(part, index) == filename:
            data = part.get_payload(decode=True) or b""
            return filename, part.get_content_type(), data if isinstance(data, bytes) else b""
    return None


def plain_text(raw: bytes, limit: int) -> str:
    """Plain text of an email for the assistant (only when the person clicked
    "Let the assistant read this email"): the text part, or the HTML with all
    markup removed, whitespace collapsed, cut to ``limit`` characters."""
    body = parse_message(raw)
    text = body.text or ""
    if not text.strip() and body.html:
        stripped = nh3.clean(body.html, tags=set(), clean_content_tags={"script", "style", "head", "title"})
        text = html_lib.unescape(stripped)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n\n", text).strip()
    return text[:limit]


# --------------------------------------------------------------------------- sanitising


_STYLE_BAD = ("url(", "expression", "javascript", "vbscript", "\\", "@", "behavior", "binding", "attr(", "image-set")


def clean_style(value: str) -> str | None:
    """Inline CSS without anything that can fetch, run or escape: whole
    declarations with url(), expression(), backslash escapes and the like are
    dropped (the property allowlist is applied after this)."""
    kept = [d.strip() for d in value.split(";") if d.strip() and not any(b in d.lower() for b in _STYLE_BAD)]
    return "; ".join(kept) or None


@dataclass
class SanitizeResult:
    html: str
    blocked_images: int = 0
    links: int = 0


def sanitize_html(
    source: str,
    *,
    secret: str,
    message_id: str,
    load_images: bool = False,
    inline_images: dict[str, tuple[str, bytes]] | None = None,
) -> SanitizeResult:
    inline = inline_images or {}
    counts = {"blocked": 0, "links": 0}

    def attribute_filter(tag: str, attr: str, value: str) -> str | None:
        if tag == "a" and attr == "href":
            url = value.strip()
            if url.lower().startswith(("http://", "https://")):
                counts["links"] += 1
                return go_href(secret, message_id, url)
            if url.lower().startswith("mailto:"):
                return url
            return None
        if tag == "img" and attr == "src":
            url = value.strip()
            if url.lower().startswith("cid:"):
                found = inline.get(url[4:].strip("<>"))
                if found is None:
                    return None
                mime, data = found
                return f"data:{mime};base64,{base64.b64encode(data).decode()}"
            if url.lower().startswith(("http://", "https://")):
                if load_images:
                    return image_href(secret, message_id, url)
                counts["blocked"] += 1
                return None
            return None
        if attr == "style":
            return clean_style(value)
        return value

    cleaned = nh3.clean(
        source,
        tags=set(ALLOWED_TAGS),
        clean_content_tags={"script", "style", "head", "title", "template", "noscript", "svg", "math", "object"},
        attributes={k: set(v) for k, v in ALLOWED_ATTRIBUTES.items()},
        attribute_filter=attribute_filter,
        strip_comments=True,
        link_rel="noopener noreferrer nofollow",
        set_tag_attribute_values={"a": {"target": "_top"}},
        url_schemes=set(URL_SCHEMES),
        filter_style_properties=set(ALLOWED_STYLE_PROPERTIES),
    )
    return SanitizeResult(cleaned, counts["blocked"], counts["links"])


_URL_IN_TEXT = re.compile(r"https?://[^\s<>\"')\]]+", re.I)


def text_to_html(text: str, *, secret: str, message_id: str) -> str:
    """A plain-text email as HTML: escaped, line breaks kept, URLs as links
    through ``/go``."""
    out: list[str] = []
    last = 0
    for match in _URL_IN_TEXT.finditer(text):
        out.append(html_lib.escape(text[last : match.start()]))
        url = match.group(0).rstrip(".,;:!?")
        rest = match.group(0)[len(url) :]
        out.append(
            f'<a href="{html_lib.escape(go_href(secret, message_id, url))}" target="_top" '
            f'rel="noopener noreferrer nofollow">{html_lib.escape(url)}</a>{html_lib.escape(rest)}'
        )
        last = match.end()
    out.append(html_lib.escape(text[last:]))
    return '<div class="plain">' + "".join(out).replace("\n", "<br>\n") + "</div>"


BODY_SHELL = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<style>
html{{-webkit-text-size-adjust:100%}}
body{{margin:0;padding:16px;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
color:#1c1c1c;background:#fff;overflow-wrap:anywhere;word-break:break-word}}
img{{max-width:100%;height:auto}}
table{{max-width:100%}}
a{{color:#0b57d0}}
.plain{{white-space:normal;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px}}
</style></head><body>{body}</body></html>"""


def body_document(fragment: str) -> str:
    return BODY_SHELL.format(body=fragment)


def body_csp(origin: str) -> str:
    """The email's own policy: nothing may load except our image proxy and
    inline data images; no scripts, no forms, no plugins, no base changes."""
    return (
        "default-src 'none'; "
        f"img-src data: {origin}; "
        "style-src 'unsafe-inline'; "
        "form-action 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'self'"
    )


# --------------------------------------------------------------------------- image proxy


class ImageRefused(Exception):
    """The image cannot be fetched (bad address, too big, not an image)."""


def _public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
        or ip.is_unspecified or (isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"))
    )


async def _resolves_public(host: str) -> bool:
    """Every address the host resolves to must be public: the proxy must never
    reach our own network (metadata service, databases, the managed identity
    endpoint)."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return _public_ip(host)
    except ValueError:
        pass
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return False
    addresses = {info[4][0] for info in infos}
    return bool(addresses) and all(_public_ip(a) for a in addresses)


async def fetch_image(
    http: httpx.AsyncClient,
    url: str,
    *,
    max_bytes: int,
    resolver: Any = None,
    max_redirects: int = 2,
) -> tuple[str, bytes]:
    """Fetch one remote image for "Load images". No cookies, no referrer, no
    client IP; at most ``max_bytes``; raster image types only; each redirect
    hop checked again."""
    check = resolver or _resolves_public
    current = strip_tracking(url)
    for _hop in range(max_redirects + 1):
        parts = urlsplit(current)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
            raise ImageRefused("not a web address")
        if parts.port not in (None, 80, 443):
            raise ImageRefused("unusual port")
        if not await check(parts.hostname):
            raise ImageRefused("private address")
        try:
            async with http.stream(
                "GET",
                current,
                headers={"Accept": "image/avif,image/webp,image/png,image/jpeg,image/gif;q=0.9", "User-Agent": "Secureddy-ImageProxy/1.0"},
                follow_redirects=False,
                timeout=10.0,
            ) as resp:
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if not location:
                        raise ImageRefused("redirect without a location")
                    current = strip_tracking(str(httpx.URL(current).join(location)))
                    continue
                if resp.status_code != 200:
                    raise ImageRefused(f"HTTP {resp.status_code}")
                ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
                if ctype not in PROXY_IMAGE_TYPES:
                    raise ImageRefused("not an image")
                declared = resp.headers.get("content-length", "")
                if declared.isdigit() and int(declared) > max_bytes:
                    raise ImageRefused("too big")
                data = bytearray()
                async for chunk in resp.aiter_bytes():
                    data.extend(chunk)
                    if len(data) > max_bytes:
                        raise ImageRefused("too big")
                return ctype, bytes(data)
        except httpx.HTTPError as exc:
            raise ImageRefused(type(exc).__name__) from None
    raise ImageRefused("too many redirects")


__all__ = [
    "ALLOWED_TAGS",
    "Attachment",
    "ImageRefused",
    "MailBody",
    "SanitizeResult",
    "attachment_bytes",
    "body_csp",
    "body_document",
    "fetch_image",
    "go_href",
    "image_href",
    "parse_message",
    "plain_text",
    "sanitize_html",
    "sign_link",
    "strip_tracking",
    "text_to_html",
    "verify_link",
]

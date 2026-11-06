"""URL extraction and normalisation.

Every place a link can hide in an email is a source here: anchors and bare
text in the HTML body, the plain-text body, QR codes in images (the
"quishing" trick that defeats URL-only scanners), link annotations and text in
PDFs, and text/HTML attachments. The output is a de-duplicated list of
:class:`ExtractedUrl` with the flags the policy and scoring layers need.

Nothing in this module touches the network. tldextract runs from its bundled
public suffix snapshot; image and PDF decoding happen in-process.
"""

from __future__ import annotations

import io
import ipaddress
import re
from collections.abc import Iterable
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

import tldextract
from bs4 import BeautifulSoup

from reddysec.core.logging import get_logger
from reddysec.models import Attachment, ExtractedUrl, UrlSource

from .common import cached_lines, shannon_entropy

log = get_logger(__name__)

# Offline on purpose: the default extractor would try to download a fresh
# public suffix list on first use, which must never happen inside the engine.
_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)

URL_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"'`{}|\\^\[\]]+""")
_TRAILING_PUNCT = ".,;:!?'\")]}>"
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_ALNUM_RUN_RE = re.compile(r"[A-Za-z0-9]+")
_DOMAINISH_RE = re.compile(r"^(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?:[/:?#].*)?$", re.I)

# Query parameters that carry one-time or session-bound secrets. Following such
# a link can consume it (magic links) or confirm the recipient to an attacker.
TOKEN_PARAMS: frozenset[str] = frozenset(
    {
        "token",
        "tkn",
        "code",
        "key",
        "auth",
        "sig",
        "signature",
        "ticket",
        "otp",
        "nonce",
        "hash",
        "verify",
        "confirm",
        "confirmation",
        "activation",
        "access_token",
        "id_token",
        "session",
        "sid",
        "login_token",
        "magic",
        "oobcode",
        "t",
        "k",
    }
)

MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_IMAGE_PIXELS = 30_000_000
MAX_TEXT_ATTACHMENT_BYTES = 2 * 1024 * 1024
MAX_PDF_PAGES = 50
MAX_PDF_QR_PAGES = 5

_IMAGE_EXTENSIONS = frozenset({"png", "jpg", "jpeg", "gif", "bmp", "webp", "tif", "tiff"})
_TEXT_EXTENSIONS = frozenset({"txt", "text", "csv", "md", "log", "rtf"})
_HTML_EXTENSIONS = frozenset({"html", "htm", "shtml", "xhtml", "mht", "mhtml"})


def shorteners() -> frozenset[str]:
    return cached_lines("shorteners.txt")


# --------------------------------------------------------------------------- hosts


def is_ip_literal(host: str) -> bool:
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
    except ValueError:
        return False
    return True


def registrable_domain(host: str) -> str:
    """``accounts.google.com`` -> ``google.com``; ``foo.co.uk`` -> ``foo.co.uk``.

    IP literals come back unchanged, and hosts without a known public suffix
    (``localhost``, ``intranet``) come back as themselves, so callers can
    always compare the result with a domain list.
    """
    host = host.strip().lower().rstrip(".")
    if not host:
        return ""
    if is_ip_literal(host):
        return host.strip("[]")
    ext = _EXTRACTOR(host)
    if ext.suffix and ext.domain:
        return f"{ext.domain}.{ext.suffix}"
    return host


def split_host(host: str) -> tuple[str, str, str]:
    """Return (subdomain, domain label, public suffix) for a host."""
    ext = _EXTRACTOR(host.strip().lower().rstrip("."))
    return ext.subdomain, ext.domain, ext.suffix


def is_shortener(host: str) -> bool:
    h = host.lower()
    return h in shorteners() or registrable_domain(h) in shorteners()


# --------------------------------------------------------------------------- normalisation


def _unwrap_redirector(url: str) -> str:
    """Return the real target behind well-known enterprise link wrappers.

    Outlook Safe Links and Google's redirector put the destination in a query
    parameter. The destination is what the client would reach, so it is what
    we score and detonate; the wrapper stays in ``raw`` for the record.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    host = (parts.hostname or "").lower()
    params = dict(parse_qsl(parts.query, keep_blank_values=True))
    if host.endswith("safelinks.protection.outlook.com") and params.get("url"):
        return params["url"]
    if host in {"www.google.com", "google.com"} and parts.path == "/url" and (params.get("q") or params.get("url")):
        return params.get("q") or params["url"]
    return url


def normalize_url(raw: str) -> str | None:
    """Canonical form used for de-duplication, scoring and detonation.

    Lowercases scheme and host, converts Unicode hosts to punycode, drops
    default ports, fragments and credentials, and keeps the query (one-time
    tokens live there). ``data:`` and ``javascript:`` links are kept (truncated)
    because their presence is itself a signal. Anything else that is not
    http(s) (``mailto:``, ``tel:``) returns ``None``: it is not a page.
    """
    s = raw.strip()
    if not s:
        return None
    s = s.strip("<>").strip()
    s = s.replace("\n", "").replace("\r", "").replace("\t", "")
    lowered = s.lower()
    if lowered.startswith(("javascript:", "data:")):
        scheme, _, rest = s.partition(":")
        return f"{scheme.lower()}:{rest[:200]}"
    if lowered.startswith("www."):
        s = "http://" + s
    elif "://" not in s[:12]:
        return None
    s = _unwrap_redirector(s)
    if s.lower().startswith("www."):
        s = "http://" + s
    try:
        parts = urlsplit(s)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"} or not host:
        return None
    host = host.lower().rstrip(".")
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    netloc = f"{host}:{port}" if port else host
    if parts.netloc.startswith("["):
        netloc = f"[{host}]" + (f":{port}" if port else "")
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def _opaque_segment(segment: str) -> bool:
    s = unquote(segment).strip()
    if len(s) < 20:
        return False
    if _UUID_RE.match(s):
        return True
    runs = _ALNUM_RUN_RE.findall(s)
    if not runs:
        return False
    longest = max(runs, key=len)
    if len(longest) < 16:
        return False
    has_digit = any(c.isdigit() for c in longest)
    has_alpha = any(c.isalpha() for c in longest)
    mixed_case = any(c.islower() for c in longest) and any(c.isupper() for c in longest)
    if not (has_digit and has_alpha) and not (mixed_case and len(longest) >= 24):
        return False
    return shannon_entropy(longest) >= 3.3


def has_opaque_token(path: str, query: str) -> bool:
    """True when the URL carries something that looks like a secret or tracking id."""
    for seg in path.split("/"):
        if _opaque_segment(seg):
            return True
    for name, value in parse_qsl(query, keep_blank_values=True):
        if name.lower() in TOKEN_PARAMS and len(value) >= 8:
            return True
        if _opaque_segment(value):
            return True
    return bool(query) and "=" not in query and _opaque_segment(query)


def display_mismatch(display_text: str | None, href_registrable: str) -> bool:
    """The visible text names a domain, and it is not the domain the link goes to.

    ``<a href="http://evil.ru/x">www.chase.com</a>`` is the oldest phishing
    trick there is; plain words ("click here") are never a mismatch.
    """
    if not display_text or not href_registrable:
        return False
    text = display_text.strip().strip(_TRAILING_PUNCT + "([{<").lower()
    if not text or " " in text or "@" in text:
        return False
    m = _DOMAINISH_RE.match(text)
    if not m:
        return False
    shown_host = m.group(1)
    sub, dom, suffix = split_host(shown_host)
    if not suffix or not dom:
        return False  # "readme.txt" or "v1.2" are not domains
    return registrable_domain(shown_host) != href_registrable


def build_url(raw: str, source: UrlSource, display_text: str | None = None) -> ExtractedUrl | None:
    """Create an :class:`ExtractedUrl` or ``None`` when ``raw`` is not a link."""
    normalized = normalize_url(raw)
    if normalized is None:
        return None
    if normalized.startswith(("javascript:", "data:")):
        return ExtractedUrl(raw=raw[:500], normalized=normalized, source=source, display_text=display_text)
    parts = urlsplit(normalized)
    host = parts.hostname or ""
    rd = registrable_domain(host)
    return ExtractedUrl(
        raw=raw[:2000],
        normalized=normalized,
        source=source,
        display_text=(display_text or None) and display_text[:200],
        host=host,
        registrable_domain=rd,
        is_ip_literal=is_ip_literal(host),
        is_shortener=is_shortener(host),
        is_punycode=any(label.startswith("xn--") for label in host.split(".")),
        has_opaque_token=has_opaque_token(parts.path, parts.query),
        display_mismatch=display_mismatch(display_text, rd),
    )


# --------------------------------------------------------------------------- text sources


def _clean_match(candidate: str) -> str:
    """Strip punctuation that regexes drag along ("(see https://x.y/)." -> "https://x.y/")."""
    c = candidate
    while c and c[-1] in _TRAILING_PUNCT:
        if c[-1] == ")" and c.count("(") >= c.count(")"):
            break
        c = c[:-1]
    return c


def urls_in_text(text: str) -> list[str]:
    if not text:
        return []
    out: list[str] = []
    for m in URL_RE.finditer(text):
        c = _clean_match(m.group(0))
        if c:
            out.append(c)
    return out


def _soup(html: str) -> BeautifulSoup:
    try:
        return BeautifulSoup(html, "lxml")
    except Exception:  # pragma: no cover - lxml is robust; html.parser is the safety net
        return BeautifulSoup(html, "html.parser")


def urls_in_html(html: str, href_source: UrlSource, text_source: UrlSource) -> list[ExtractedUrl]:
    """Anchors (with their visible text) first, then bare URLs in the visible text.

    ``<img src>`` is deliberately not a source: an image URL is fetched by the
    mail client, not clicked, and detonating tracking pixels only tells the
    sender the message was opened.
    """
    out: list[ExtractedUrl] = []
    if not html:
        return out
    soup = _soup(html)
    for tag in soup.find_all(["a", "area"]):
        href = tag.get("href")
        if not href or not isinstance(href, str):
            continue
        text = tag.get_text(" ", strip=True) or (tag.get("title") if isinstance(tag.get("title"), str) else None)
        url = build_url(href, href_source, text)
        if url:
            out.append(url)
        # The anchor's visible text was captured as display_text above; a
        # domain shown as link text is not itself a second link to follow.
        tag.decompose()
    for tag in soup(["script", "style"]):
        tag.decompose()
    for raw in urls_in_text(soup.get_text(" ")):
        url = build_url(raw, text_source)
        if url:
            out.append(url)
    return out


# --------------------------------------------------------------------------- images / QR


def _image_to_bgr(image_bytes: bytes):
    """Decode with Pillow (handles GIF/WebP, enforces pixel limits) into a BGR array for OpenCV."""
    import numpy as np
    from PIL import Image

    img = Image.open(io.BytesIO(image_bytes))
    w, h = img.size
    if w * h > MAX_IMAGE_PIXELS or w < 20 or h < 20:
        return None
    img = img.convert("RGB")
    if max(w, h) > 1600:
        img.thumbnail((1600, 1600))
    elif max(w, h) < 300:
        # Tiny QR codes in signatures decode far better when upscaled.
        img = img.resize((w * 3, h * 3), Image.NEAREST)
    return np.asarray(img)[:, :, ::-1].copy()


def decode_qr_codes(image_bytes: bytes) -> list[str]:
    """Return the payloads of every QR code found in an image. Never raises."""
    if not image_bytes or len(image_bytes) > MAX_IMAGE_BYTES:
        return []
    try:
        import cv2

        mat = _image_to_bgr(image_bytes)
        if mat is None:
            return []
        return _decode_qr_from_array(cv2, mat)
    except Exception as exc:  # corrupt image, decompression bomb, cv2 internals
        log.debug("qr_decode_failed", error=str(exc))
        return []


def _decode_qr_from_array(cv2, mat) -> list[str]:
    detector = cv2.QRCodeDetector()
    results: list[str] = []
    try:
        ok, infos, _points, _ = detector.detectAndDecodeMulti(mat)
        if ok:
            results = [s for s in infos if s]
    except cv2.error:
        results = []
    if not results:
        try:
            text, _points, _ = detector.detectAndDecode(mat)
            if text:
                results = [text]
        except cv2.error:
            results = []
    return results


def _is_image(att: Attachment) -> bool:
    ct = (att.content_type or "").lower()
    return ct.startswith("image/") or att.declared_extension.lower() in _IMAGE_EXTENSIONS


# --------------------------------------------------------------------------- pdf


def _pixmap_to_bgr(pix):
    import numpy as np

    arr = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width, pix.n)
    if pix.n == 4:
        arr = arr[:, :, :3]
    if pix.n >= 3:
        arr = arr[:, :, ::-1]
    return arr.copy()


def pdf_urls(data: bytes) -> tuple[list[str], list[str]]:
    """(URLs from link annotations and page text, URLs decoded from QR codes on pages)."""
    try:
        import pymupdf
    except ImportError:  # pragma: no cover
        return [], []
    text_urls: list[str] = []
    qr_urls: list[str] = []
    try:
        doc = pymupdf.open(stream=data, filetype="pdf")
    except Exception as exc:
        log.debug("pdf_open_failed", error=str(exc))
        return [], []
    try:
        if doc.needs_pass:
            return [], []
        for index, page in enumerate(doc):
            if index >= MAX_PDF_PAGES:
                break
            try:
                for link in page.get_links():
                    uri = link.get("uri")
                    if isinstance(uri, str) and uri:
                        text_urls.append(uri)
                text_urls.extend(urls_in_text(page.get_text()))
                if index < MAX_PDF_QR_PAGES:
                    import cv2

                    pix = page.get_pixmap(dpi=96)
                    qr_urls.extend(_decode_qr_from_array(cv2, _pixmap_to_bgr(pix)))
            except Exception as exc:
                log.debug("pdf_page_failed", page=index, error=str(exc))
    finally:
        doc.close()
    return text_urls, qr_urls


# --------------------------------------------------------------------------- entry point


def _attachment_urls(att: Attachment) -> Iterable[ExtractedUrl]:
    data = att.data
    if not data:
        return
    ext = att.declared_extension.lower()
    ct = (att.content_type or "").lower()
    sniffed = (att.sniffed_type or "").lower()
    if _is_image(att) or sniffed in {"png", "jpeg", "gif"}:
        for payload in decode_qr_codes(data):
            for raw in urls_in_text(payload) or ([payload] if payload.lower().startswith(("http", "www.")) else []):
                url = build_url(raw, UrlSource.QR)
                if url:
                    yield url
        return
    if data[:5] == b"%PDF-" or ext == "pdf" or ct == "application/pdf" or sniffed == "pdf":
        text_urls, qr_payloads = pdf_urls(data)
        for raw in text_urls:
            url = build_url(raw, UrlSource.PDF)
            if url:
                yield url
        for payload in qr_payloads:
            for raw in urls_in_text(payload):
                url = build_url(raw, UrlSource.QR)
                if url:
                    yield url
        return
    is_html = ext in _HTML_EXTENSIONS or ct in {"text/html", "application/xhtml+xml"} or sniffed == "html"
    is_text = ext in _TEXT_EXTENSIONS or ct.startswith("text/") or sniffed == "text"
    if not (is_html or is_text):
        return
    if len(data) > MAX_TEXT_ATTACHMENT_BYTES:
        data = data[:MAX_TEXT_ATTACHMENT_BYTES]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1", errors="replace")
    if is_html:
        yield from urls_in_html(text, UrlSource.ATTACHMENT_TEXT, UrlSource.ATTACHMENT_TEXT)
    else:
        for raw in urls_in_text(text):
            url = build_url(raw, UrlSource.ATTACHMENT_TEXT)
            if url:
                yield url


def extract_all(text_body: str, html_body: str | None, attachments: Iterable[Attachment]) -> list[ExtractedUrl]:
    """Collect every link in a message, de-duplicated by normalised URL.

    Order of sources matters for the ``source`` attribution: an anchor in the
    HTML wins over the same URL repeated in the plain-text part, which wins
    over the same URL inside an attachment. The first sighting is kept.
    """
    found: dict[str, ExtractedUrl] = {}

    def add(url: ExtractedUrl | None) -> None:
        if url is not None and url.normalized not in found:
            found[url.normalized] = url

    try:
        if html_body:
            for url in urls_in_html(html_body, UrlSource.HTML_HREF, UrlSource.HTML_TEXT):
                add(url)
    except Exception as exc:
        log.warning("html_url_extraction_failed", error=str(exc))
    for raw in urls_in_text(text_body or ""):
        add(build_url(raw, UrlSource.TEXT))
    for att in attachments:
        try:
            for url in _attachment_urls(att):
                add(url)
        except Exception as exc:
            log.warning("attachment_url_extraction_failed", filename=att.filename, error=str(exc))
    return list(found.values())

"""Small helpers shared by the detonation chamber, the Reading Room and CDR.

Everything here is deliberately dependency-light and side-effect free so it
can run inside the sandbox (where only the chamber package and Playwright are
installed) as well as on the host.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

import tldextract

# A current desktop Chrome on Windows. Phishing kits fingerprint the UA first:
# "HeadlessChrome" or an old major version is enough to get served a benign
# decoy page. Keep the major version aligned with the bundled Chromium when
# possible (see ``user_agent_for``); this constant is the fallback.
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/153.0.0.0 Safari/537.36"
)

_CHROME_VERSION_RE = re.compile(r"^(\d+)\.")


def user_agent_for(browser_version: str | None) -> str:
    """Build the default UA with the major version of the actual engine.

    A mismatch between the UA string and the engine's real behaviour (JS
    features, client hints) is a classic bot tell, so we follow the engine.
    """
    if browser_version:
        match = _CHROME_VERSION_RE.match(browser_version)
        if match:
            return DEFAULT_USER_AGENT.replace("Chrome/153.0.0.0", f"Chrome/{match.group(1)}.0.0.0")
    return DEFAULT_USER_AGENT


# --- host / domain helpers --------------------------------------------------

# Offline: the bundled public-suffix snapshot is good enough for "is this the
# same site" decisions and must never trigger a network fetch from inside a
# sandbox that is supposed to talk only to the target.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True, cache_dir=None)


def host_of(url: str | None) -> str:
    """Lower-cased hostname of ``url`` ('' when absent or unparsable)."""
    if not url:
        return ""
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def registrable_domain(host: str | None) -> str:
    """eTLD+1 for ``host`` (``login.chase.com`` -> ``chase.com``).

    IP literals and suffix-less names (``localhost``, ``intranet``) are
    returned unchanged so that "same registrable domain" still means "same
    site" for them.
    """
    if not host:
        return ""
    host = host.strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    ext = _EXTRACT(host)
    if ext.ipv4:
        return ext.ipv4
    if not ext.suffix:
        return host
    return ext.top_domain_under_public_suffix or host


def is_third_party(host: str, site_domain: str) -> bool:
    """True when ``host`` belongs to a different registrable domain than the
    page we ended up on. Used for "who else does this page talk to"."""
    if not host or not site_domain:
        return False
    return registrable_domain(host) != site_domain


# --- content sniffing -------------------------------------------------------

# A tiny magic table. The analysis engine has the authoritative one; this copy
# exists so the sandbox (which does not import the analysis package) can label
# what it downloaded.
_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"PK\x07\x08", "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"{\\rtf", "rtf"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"\x1f\x8b", "gzip"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\xca\xfe\xba\xbe", "macho"),
    (b"\xfe\xed\xfa\xce", "macho"),
    (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"ITSF", "chm"),
    (b"\x4d\x53\x43\x46", "cab"),
    (b"#!", "script"),
)

_HTML_RE = re.compile(rb"^\s*(?:<!doctype\s+html|<html|<head|<body|<script|<iframe|<!--|<\?xml)", re.IGNORECASE)
_SCRIPT_RE = re.compile(
    rb"^\s*(?:@echo\s+off|powershell|cmd\s*/c|set-executionpolicy|invoke-expression|iex\s*\(|wscript|"
    rb"createobject\(|var\s+\w+\s*=|function\s*\w*\s*\(|on\s+error\s+resume\s+next|dim\s+\w+)",
    re.IGNORECASE,
)


def sniff_type(data: bytes) -> str:
    """Label the first bytes of a blob: pe, elf, pdf, zip, ole, html, script,
    an image type, an archive type, text or unknown.

    Deliberately conservative: an attacker controls the bytes, so only a
    confident label is returned and everything else is ``unknown``.
    """
    if not data:
        return "empty"
    head = data[:4096]
    for magic, label in _MAGIC:
        if head.startswith(magic):
            return label
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    # "BM" alone is too weak a magic (any text starting with BM would match), so
    # require the two reserved words of the bitmap header to be zero as well.
    if head[:2] == b"BM" and len(head) >= 14 and head[6:10] == b"\x00\x00\x00\x00":
        return "bmp"
    if _HTML_RE.search(head):
        return "html"
    if _SCRIPT_RE.search(head):
        return "script"
    if _looks_textual(head):
        return "text"
    return "unknown"


_ONENOTE_MAGIC = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")
_LNK_MAGIC = b"L\x00\x00\x00\x01\x14\x02\x00"
# Text formats that Windows treats as programs or remote shortcuts. Matched on
# the first few KB of a download that otherwise sniffs as text/html/unknown.
_TEXT_FORMATS: tuple[tuple[re.Pattern[bytes], str], ...] = (
    (re.compile(rb"<\s*AppInstaller\b", re.I), "appinstaller"),
    (re.compile(rb"<\s*libraryDescription\b", re.I), "library-ms"),
    (re.compile(rb"<\s*searchConnectorDescription\b", re.I), "searchconnector-ms"),
    (re.compile(rb"^\s*\[InternetShortcut\]", re.I), "url-shortcut"),
    (re.compile(rb"<\s*HTA:APPLICATION\b", re.I), "hta"),
    (re.compile(rb"<\s*job\b[^>]*>\s*<\s*script\b", re.I), "wsf"),
    (re.compile(rb"<\s*svg\b", re.I), "svg"),
)


def refine_download_type(head: bytes, filename: str | None, label: str) -> str:
    """Sharpen ``sniff_type``'s label for downloads, where the dangerous
    formats matter most: ISO / VHD(X) disk images, Windows shortcuts, OneNote,
    MSI installers, App Installer / .library-ms / .url files and HTA.

    ``head`` should hold at least 0x8006 bytes to recognise ISO images.
    """
    if not head:
        return label
    if head.startswith(_LNK_MAGIC):
        return "lnk"
    if head.startswith(_ONENOTE_MAGIC):
        return "one"
    if len(head) > 0x8006 and head[0x8001:0x8006] == b"CD001":
        return "iso9660"
    if head.startswith(b"vhdxfile"):
        return "vhdx"
    if head.startswith(b"conectix"):
        return "vhd"
    if label == "ole" and extension_of(filename) in {"msi", "msp"}:
        return "msi"
    if label in {"text", "html", "unknown", "script"}:
        sample = head[:8192]
        for pattern, name in _TEXT_FORMATS:
            if pattern.search(sample):
                return name
    return label


def _looks_textual(sample: bytes) -> bool:
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return printable / max(1, len(sample)) > 0.9


# Types a browser can show without an exploit surface we do not control. Office
# and executable formats need a Windows chamber (future work).
BROWSER_VIEWABLE_TYPES = frozenset({"html", "pdf", "png", "jpeg", "gif", "bmp", "webp", "text"})

_IMAGE_TYPES = frozenset({"png", "jpeg", "gif", "bmp", "webp"})


def is_image_type(label: str | None) -> bool:
    return label in _IMAGE_TYPES


# --- filenames --------------------------------------------------------------

_UNSAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(name: str | None, default: str = "download.bin", max_len: int = 120) -> str:
    """Reduce an attacker-chosen filename to something safe for a path
    segment: no separators, no control characters, no leading dots."""
    base = (name or "").replace("\\", "/").rsplit("/", 1)[-1]
    base = _UNSAFE_FILENAME_RE.sub("_", base).lstrip(".")
    if not base or base in {"_", "-"}:
        base = default
    if len(base) > max_len:
        stem, dot, ext = base.rpartition(".")
        if dot and len(ext) <= 10:
            base = stem[: max_len - len(ext) - 1] + "." + ext
        else:
            base = base[:max_len]
    return base


def extension_of(name: str | None) -> str:
    """Lower-cased extension without the dot ('' when none)."""
    if not name or "." not in name:
        return ""
    return name.rsplit(".", 1)[-1].lower()


# --- brand keywords ---------------------------------------------------------

# A small, intentionally duplicated list (the analysis engine owns the
# authoritative one). Matched against title, visible text and image alt text.
BRAND_KEYWORDS: tuple[str, ...] = (
    "paypal",
    "chase",
    "bank of america",
    "wells fargo",
    "citibank",
    "citi",
    "capital one",
    "american express",
    "amex",
    "usaa",
    "hsbc",
    "barclays",
    "jpmorgan",
    "goldman sachs",
    "morgan stanley",
    "charles schwab",
    "fidelity",
    "vanguard",
    "truist",
    "pnc",
    "td bank",
    "apple",
    "icloud",
    "microsoft",
    "office 365",
    "office365",
    "outlook",
    "onedrive",
    "sharepoint",
    "google",
    "gmail",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
    "linkedin",
    "dropbox",
    "docusign",
    "adobe",
    "fedex",
    "ups",
    "usps",
    "dhl",
    "irs",
    "coinbase",
    "binance",
    "venmo",
    "zelle",
    "cash app",
)

_BRAND_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (kw, re.compile(r"(?<![a-z0-9])" + re.escape(kw).replace(r"\ ", r"\s+") + r"(?![a-z0-9])"))
    for kw in BRAND_KEYWORDS
)


def find_brand_keywords(text: str) -> list[str]:
    """Return the brand keywords present in ``text`` (lower-cased, whole-word)."""
    haystack = re.sub(r"\s+", " ", text.lower())
    return [kw for kw, pattern in _BRAND_PATTERNS if pattern.search(haystack)]

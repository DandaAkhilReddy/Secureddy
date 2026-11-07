"""Per-link "is it safe to click?" advice, and what a link downloads.

The client asked one question about every link: *can I click it?* The answer
is one of three, with a plain-English reason:

* ``do_not_open``: we saw it steal passwords, push a ClickFix command, start a
  dangerous download, show a tech-support or wallet scam, or a blocklist
  already knows it. Also any link whose own verdict is MALICIOUS.
* ``open_in_reading_room``: nothing conclusive, but something we cannot vouch
  for: an unfamiliar or brand-new site, a CAPTCHA wall that hid the page from
  us, redirects, a free hosting service, a download, a link we could not open
  in time, or a link that was not opened at all and is not on a site we know.
* ``safe_to_open``: a clean result on a well-known site or on the sender's own
  verified site, with no downloads and no warning signs.

Signals that trust softened to 0 do not count against a link (the trust
rules in ``analysis.trust`` already decided they are routine for this sender);
protected signals are never softened, so they always count.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from urllib.parse import urlsplit

from reddysec.models import (
    DetonationResult,
    DetonationStatus,
    DownloadRecord,
    Signal,
    UrlVerdict,
    VerdictLevel,
)
from reddysec.models.verdict import DownloadInfo

from .attachments import DANGEROUS_EXTENSIONS, _ext_parts
from .intel import is_popular
from .urls import registrable_domain

SAFE = "safe_to_open"
READING_ROOM = "open_in_reading_room"
DO_NOT_OPEN = "do_not_open"

# --------------------------------------------------------------------------- downloads

_PROGRAM_EXT = frozenset({"exe", "scr", "pif", "com", "dll", "cpl", "ocx", "xll", "app"})
_SCRIPT_EXT = frozenset({"js", "jse", "vbs", "vbe", "wsf", "wsh", "wsc", "sct", "hta", "ps1", "psm1", "bat", "cmd", "sh",
                         "py", "jar", "reg", "inf", "scf", "vb", "vba", "bas", "iqy", "slk"})
_INSTALLER_EXT = frozenset({"msi", "msp", "msix", "msixbundle", "appx", "appxbundle", "appinstaller", "pkg", "dmg", "deb",
                            "rpm", "apk", "application", "diagcab"})
_DISK_IMAGE_EXT = frozenset({"iso", "img", "vhd", "vhdx", "wim"})
_SHORTCUT_EXT = frozenset({"lnk", "url", "library-ms", "searchconnector-ms", "search-ms", "settingcontent-ms", "website"})
_ARCHIVE_EXT = frozenset({"zip", "7z", "rar", "gz", "tgz", "bz2", "xz", "tar", "cab", "arj", "ace", "z"})
_MACRO_EXT = frozenset({"docm", "dotm", "xlsm", "xlam", "xlsb", "pptm", "ppsm", "potm"})
_DOCUMENT_EXT = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "odt", "ods", "jpg",
                           "jpeg", "png", "gif", "webp", "mp3", "mp4", "mov", "ics", "vcf", "html", "htm", "svg"})

_SNIFF_CATEGORY: dict[str, str] = {
    "pe": "program", "elf": "program", "macho": "program",
    "script": "script", "hta": "script", "wsf": "script",
    "msi": "installer", "appinstaller": "installer",
    "iso9660": "disk_image", "vhd": "disk_image", "vhdx": "disk_image",
    "lnk": "shortcut", "url-shortcut": "shortcut", "library-ms": "shortcut", "searchconnector-ms": "shortcut",
    "one": "onenote", "chm": "program",
    "zip": "archive", "7z": "archive", "rar": "archive", "gzip": "archive", "cab": "archive", "jar": "script",
}
_DANGEROUS_CATEGORIES = frozenset({"program", "script", "installer", "disk_image", "shortcut", "password_archive", "onenote", "macro_document"})
_WHY: dict[str, str] = {
    "program": "It is a program. Opening it would run it on your computer.",
    "script": "It is a script. Opening it would run commands on your computer.",
    "installer": "It is an installer. Opening it would install software.",
    "disk_image": "It is a disk image, a common wrapper that hides malware from warnings.",
    "shortcut": "It is a shortcut that can run a program or connect to another computer.",
    "password_archive": "It is a locked archive, a trick to hide what is inside from scanners.",
    "onenote": "It is a OneNote file, often used to hide a program behind a fake button.",
    "macro_document": "It is an Office file with macros, small programs that run when opened.",
    "archive": "It is an archive (zip). We list what is inside.",
    "document": "It is a document.",
    "other": "It is a file we could not identify.",
}


def describe_download(record: DownloadRecord) -> DownloadInfo:
    """What a download is, whether it is dangerous, and why, in plain words."""
    parts = _ext_parts(record.suggested_filename)
    ext = parts[-1] if parts else ""
    sniffed = (record.sniffed_type or "").lower()
    category = _SNIFF_CATEGORY.get(sniffed, "")
    if category == "archive" and sniffed == "zip" and ext in _DOCUMENT_EXT:
        category = ""  # .docx / .xlsx / .pptx are zip containers; the name decides
    if ext in _PROGRAM_EXT:
        category = "program"
    elif ext in _SCRIPT_EXT:
        category = category if category == "program" else "script"
    elif ext in _INSTALLER_EXT and category not in {"program"}:
        category = "installer"
    elif ext in _DISK_IMAGE_EXT and category not in {"program"}:
        category = "disk_image"
    elif ext in _SHORTCUT_EXT and category not in {"program"}:
        category = "shortcut"
    elif ext == "one":
        category = "onenote"
    elif ext in _MACRO_EXT:
        category = "macro_document"
    elif ext in _ARCHIVE_EXT and not category:
        category = "archive"
    elif not category:
        category = "document" if ext in _DOCUMENT_EXT or sniffed in {"pdf", "png", "jpeg", "gif", "text", "html"} else "other"
    if ext in DANGEROUS_EXTENSIONS and category in {"document", "other", "archive"}:
        category = "program"

    why = _WHY.get(category, _WHY["other"])
    dangerous = category in _DANGEROUS_CATEGORIES
    if category == "archive":
        if record.encrypted:
            category, dangerous, why = "password_archive", True, _WHY["password_archive"]
        else:
            inner = [n for n in record.archive_entries if _ext_parts(n) and _ext_parts(n)[-1] in DANGEROUS_EXTENSIONS]
            if inner:
                dangerous = True
                why = f"It is an archive with a program inside ({inner[0].rsplit('/', 1)[-1][:40]})."
            elif record.archive_entries:
                why = "It is an archive (zip) with: " + ", ".join(n.rsplit("/", 1)[-1][:30] for n in record.archive_entries[:3]) + "."
            else:
                # We could not look inside: treat an unknown archive from a link as dangerous.
                dangerous = True
                why = "It is an archive we could not look inside."
    if len(parts) >= 2 and dangerous and any(p in _DOCUMENT_EXT for p in parts[:-1]):
        why = f"It pretends to be a .{parts[-2]} file but is really a .{parts[-1]}. " + why
    return DownloadInfo(
        filename=record.suggested_filename[:200], sha256=record.sha256, size=record.size, file_type=sniffed,
        category=category, dangerous=dangerous, why=why,
    )


def download_is_dangerous(record: DownloadRecord) -> bool:
    return describe_download(record).dangerous


# --------------------------------------------------------------------------- advice

# code -> reason. Any of these (weight > 0) means "do not open".
DO_NOT_OPEN_REASONS: dict[str, str] = {
    "url.known_bad": "Security services already list this website as dangerous.",
    "url.lookalike": "The website is a fake copy of a real company's site.",
    "url.dangerous_scheme": "The link runs code instead of opening a website.",
    "url.oauth_consent_lure": "It asks you to give an app access to your email or files.",
    "dynamic.clickfix": "The page tries to make you paste a command into your computer. That would install malware.",
    "dynamic.clipboard_hijack": "The page secretly copies a dangerous command to your clipboard.",
    "dynamic.fake_captcha": "The page shows a fake 'I'm not a robot' check.",
    "dynamic.credential_phish": "The page is a fake sign-in page that steals passwords.",
    "dynamic.password_unknown_host": "The page asks for a password on a website we do not know.",
    "dynamic.aitm_proxy": "The page copies a real sign-in page to steal passwords and security codes.",
    "dynamic.free_hosting_login": "The page asks you to sign in on a free website service.",
    "dynamic.dangerous_download": "Opening the link downloads a dangerous file.",
    "dynamic.tech_support_scam": "The page is a fake virus warning that wants you to call scammers.",
    "dynamic.wallet_drainer": "The page tries to take money from a crypto wallet.",
    "dynamic.device_code_lure": "The page asks you to type a code that would let someone else into your account.",
    "bec.device_code_lure": "The email asks you to type a code that would let someone else into your account.",
}
# Reasons to keep a link in the Reading Room even when its score is low.
READING_ROOM_REASONS: dict[str, str] = {
    "url.new_domain": "The website is brand new.",
    "dynamic.new_domain": "The website is brand new.",
    "url.young_domain": "The website is only a few months old.",
    "dynamic.young_domain": "The website is only a few months old.",
    "dynamic.hidden_from_automation": "The page hid itself behind a 'verify you are human' check, so we could not see it all.",
    "dynamic.captcha_gated_login": "A 'verify you are human' check hides a sign-in form.",
    "dynamic.redirect_chain": "The link bounces through several websites.",
    "dynamic.redirect_offsite": "The link ends up on a different website than it shows.",
    "url.open_redirect": "The link starts on a trusted site but forwards you somewhere else.",
    "url.free_hosting": "The page is on a free website service.",
    "url.shortener": "The link is shortened, so its destination is hidden.",
    "url.ip_literal": "The link points to a bare server number.",
    "url.punycode": "The address uses look-alike letters.",
    "url.display_mismatch": "The link does not go where its text says.",
    "url.hidden_characters": "The link text hides invisible characters.",
    "dynamic.notification_spam": "The page asks to send you notifications.",
    "dynamic.anti_analysis": "The page tries to stop security tools from inspecting it.",
    "dynamic.ua_cloaking": "The page shows scanners something different from people.",
    "dynamic.unexpected_download": "Opening the link starts a download.",
    "dynamic.obfuscated_js": "The page runs disguised code.",
    "dynamic.external_form_action": "The page sends what you type to another website.",
}


def _active(signals: Iterable[Signal]) -> list[Signal]:
    return [s for s in signals if s.weight > 0]


def _destination_domain(verdict: UrlVerdict, result: DetonationResult | None) -> str:
    final = verdict.final_url or ""
    if result is not None and result.features and result.features.final_host:
        return registrable_domain(result.features.final_host)
    return registrable_domain(urlsplit(final or verdict.url).hostname or "")


def advise(
    verdict: UrlVerdict,
    result: DetonationResult | None = None,
    *,
    detonated: bool = False,
    verified_domain: str = "",
    message_signals: Sequence[Signal] = (),
) -> tuple[str, str, list[DownloadInfo]]:
    """(advice, plain-English reason, downloads) for one link.

    ``message_signals`` are message-level signals (e.g. ``bec.device_code_lure``)
    that make every link in the email unsafe to follow.
    """
    downloads = [describe_download(d) for d in (result.downloads if result is not None else [])]
    active = sorted(_active(verdict.signals), key=lambda s: -s.weight)
    dangerous = [d for d in downloads if d.dangerous]
    download_reason = f"Opening the link downloads {dangerous[0].filename}. {dangerous[0].why}" if dangerous else ""
    for s in active + sorted(_active(message_signals), key=lambda s: -s.weight):
        if s.code == "dynamic.dangerous_download" and download_reason:
            return DO_NOT_OPEN, download_reason, downloads
        if s.code in DO_NOT_OPEN_REASONS:
            return DO_NOT_OPEN, DO_NOT_OPEN_REASONS[s.code], downloads
        if s.code == "url.display_mismatch" and s.evidence.get("impersonates"):
            return DO_NOT_OPEN, "The link pretends to go to a well-known company's site but goes somewhere else.", downloads
    if download_reason:
        return DO_NOT_OPEN, download_reason, downloads
    if verdict.level is VerdictLevel.MALICIOUS:
        reason = active[0].title if active else "We found serious warning signs."
        return DO_NOT_OPEN, reason, downloads

    if downloads:
        return READING_ROOM, f"Opening the link downloads a file ({downloads[0].filename}). Open it only in the Reading Room.", downloads
    for s in active:
        if s.code in READING_ROOM_REASONS:
            return READING_ROOM, READING_ROOM_REASONS[s.code], downloads
    if verdict.level is VerdictLevel.SUSPICIOUS:
        reason = active[0].title if active else "It shows several small warning signs."
        return READING_ROOM, reason, downloads
    if verdict.level is VerdictLevel.UNKNOWN or (result is not None and result.status in (DetonationStatus.TIMEOUT, DetonationStatus.ERROR)):
        return READING_ROOM, "We could not finish opening this link to check it.", downloads

    scheme = verdict.url.split(":", 1)[0].lower()
    if scheme not in {"http", "https"}:
        return READING_ROOM, "This is not an ordinary web link.", downloads
    domain = _destination_domain(verdict, result)
    known = bool(domain) and (is_popular(domain) or (bool(verified_domain) and domain == registrable_domain(verified_domain)))
    if not known:
        if detonated:
            return READING_ROOM, "We opened it and found nothing wrong, but we do not know this website well.", downloads
        return READING_ROOM, "We did not open this link, and we do not know this website.", downloads
    if active and not detonated:
        return READING_ROOM, active[0].title, downloads
    if detonated:
        return SAFE, "We opened it in our sandbox. It is a normal page on a well-known website.", downloads
    return SAFE, "It goes to a well-known website and shows no warning signs.", downloads


def links_summary(verdicts: Sequence[UrlVerdict]) -> tuple[str, dict[str, int]]:
    """``"Links: 2 safe · 1 open only in Reading Room · 1 do not open"`` and the counts."""
    counts = {SAFE: 0, READING_ROOM: 0, DO_NOT_OPEN: 0}
    for v in verdicts:
        if v.click_advice in counts:
            counts[v.click_advice] += 1
    if not any(counts.values()):
        return "", {}
    parts = []
    if counts[SAFE]:
        parts.append(f"{counts[SAFE]} safe")
    if counts[READING_ROOM]:
        parts.append(f"{counts[READING_ROOM]} open only in Reading Room")
    if counts[DO_NOT_OPEN]:
        parts.append(f"{counts[DO_NOT_OPEN]} do not open")
    return "Links: " + " · ".join(parts), counts

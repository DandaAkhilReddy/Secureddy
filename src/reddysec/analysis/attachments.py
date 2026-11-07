"""Static attachment analysis.

The question for every attachment is "what would happen if the client
double-clicked this?". We answer it without opening anything: identify the real
file type from its bytes (names lie), look for the handful of features that
distinguish weaponised documents from ordinary ones (macros that auto-run,
remote templates, PDF scripts, HTML that assembles a download in the browser),
and look inside archives, including password-protected ones when the password
is helpfully printed in the email body.

Weights follow the engine's convention: >= 70 is conclusive on its own
(executables), 55-65 is a strong indicator (auto-run macros, HTML smuggling,
password-in-body archives), 35-45 is a mismatch that needs company
(type/extension disagreement, double extensions).
"""

from __future__ import annotations

import gzip
import io
import re
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field
from xml.etree import ElementTree

from reddysec.core.crypto import sha256_hex
from reddysec.core.logging import get_logger
from reddysec.models import Attachment, Signal, SignalStage

from .common import make_signal, safe_decode, truncate
from .intel import is_popular
from .urls import registrable_domain

log = get_logger(__name__)

MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024
MAX_ARCHIVE_DEPTH = 2
MAX_ARCHIVE_ENTRIES = 50
MAX_ENTRY_BYTES = 20 * 1024 * 1024
ZIP_BOMB_RATIO = 100
ZIP_BOMB_MIN_UNCOMPRESSED = 50 * 1024 * 1024
MAX_PDF_OBJECTS = 5000
MAX_TEXT_SCAN_BYTES = 2 * 1024 * 1024

# Extension -> weight. Anything here is something a mail client would hand
# straight to the operating system to execute or mount.
DANGEROUS_EXTENSIONS: dict[str, int] = {
    "exe": 75, "scr": 75, "pif": 75, "com": 75, "bat": 70, "cmd": 70, "ps1": 70, "vbs": 75, "vbe": 75,
    "js": 65, "jse": 75, "wsf": 75, "wsh": 75, "hta": 75, "msi": 70, "msp": 70, "lnk": 75, "iso": 70,
    "img": 70, "vhd": 70, "vhdx": 70, "chm": 70, "one": 75, "jar": 65, "reg": 60, "scf": 70, "url": 60,
    "inf": 60, "dll": 70, "cpl": 70, "msc": 65, "ocx": 70, "xll": 70, "wsc": 70, "sct": 70, "vb": 70,
    "vba": 70, "bas": 60, "pub": 55, "appx": 65, "msix": 65, "apk": 55, "app": 60, "ade": 60, "adp": 60,
    "mde": 60, "accde": 60, "py": 45, "sh": 45, "dmg": 45, "pkg": 45, "deb": 45, "rpm": 45, "ps1xml": 60,
    "psm1": 60, "diagcab": 65, "settingcontent-ms": 75, "library-ms": 70, "search-ms": 70, "wim": 55,
    # App Installer / MSIX (Storm-1113), Windows Search connectors and other
    # "opens something else" formats seen in 2023-2026 campaigns.
    "appinstaller": 70, "searchconnector-ms": 70, "msixbundle": 65, "appxbundle": 65, "application": 65,
    "iqy": 60, "slk": 55, "website": 60, "xbap": 60, "jnlp": 55, "mam": 60, "theme": 55, "themepack": 55,
}
ARCHIVE_EXTENSIONS: frozenset[str] = frozenset({"zip", "7z", "rar", "gz", "tgz", "bz2", "xz", "tar", "cab", "arj", "ace", "z"})
DOCUMENT_LIKE_EXTENSIONS: frozenset[str] = frozenset(
    {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg", "png", "gif",
     "mp3", "mp4", "wav", "avi", "mov", "zip", "html", "htm", "odt", "ods", "eml", "msg", "xml", "json"}
)
OFFICE_EXTENSIONS: frozenset[str] = frozenset(
    {"doc", "dot", "docm", "docx", "dotm", "dotx", "xls", "xlt", "xla", "xlsm", "xlsx", "xlsb", "xltm", "xlam",
     "ppt", "pot", "pps", "ppa", "pptm", "pptx", "ppsm", "potm", "ppam", "sldm", "rtf", "pub", "wiz", "mht"}
)
SCRIPT_TEXT_EXTENSIONS: frozenset[str] = frozenset({"vbs", "vba", "bas", "vb", "wsf", "hta", "js", "jse", "vbe", "ps1"})
HTML_EXTENSIONS: frozenset[str] = frozenset({"html", "htm", "shtml", "xhtml", "mht", "mhtml"})
EXECUTABLE_SNIFFED: frozenset[str] = frozenset({"pe", "elf", "macho", "lnk", "msi", "chm", "one", "iso9660"})

# Declared extension -> sniffed types that are honest for it.
_EXT_FAMILIES: dict[str, frozenset[str]] = {
    "pdf": frozenset({"pdf"}),
    "doc": frozenset({"ole2", "rtf", "html", "text", "ooxml"}),
    "dot": frozenset({"ole2"}),
    "docx": frozenset({"ooxml"}),
    "docm": frozenset({"ooxml"}),
    "dotx": frozenset({"ooxml"}),
    "dotm": frozenset({"ooxml"}),
    "xls": frozenset({"ole2", "html", "text"}),
    "xlsx": frozenset({"ooxml"}),
    "xlsm": frozenset({"ooxml"}),
    "xlsb": frozenset({"ooxml"}),
    "ppt": frozenset({"ole2"}),
    "pptx": frozenset({"ooxml"}),
    "pptm": frozenset({"ooxml"}),
    "ppsx": frozenset({"ooxml"}),
    "zip": frozenset({"zip", "ooxml", "jar"}),
    "jar": frozenset({"jar", "zip"}),
    "7z": frozenset({"7z"}),
    "rar": frozenset({"rar"}),
    "gz": frozenset({"gzip"}),
    "tgz": frozenset({"gzip"}),
    "bz2": frozenset({"bzip2"}),
    "xz": frozenset({"xz"}),
    "png": frozenset({"png"}),
    "jpg": frozenset({"jpeg"}),
    "jpeg": frozenset({"jpeg"}),
    "gif": frozenset({"gif"}),
    "webp": frozenset({"webp"}),
    "txt": frozenset({"text", "empty"}),
    "csv": frozenset({"text", "empty"}),
    "md": frozenset({"text"}),
    "ics": frozenset({"text"}),
    "vcf": frozenset({"text"}),
    "eml": frozenset({"text"}),
    "json": frozenset({"text"}),
    "xml": frozenset({"text", "svg", "html"}),
    "html": frozenset({"html", "text", "svg"}),
    "htm": frozenset({"html", "text", "svg"}),
    "svg": frozenset({"svg", "text"}),
    "rtf": frozenset({"rtf", "text"}),
    "iso": frozenset({"iso9660"}),
    "exe": frozenset({"pe"}),
    "dll": frozenset({"pe"}),
    "msi": frozenset({"msi", "ole2"}),
    "lnk": frozenset({"lnk"}),
    "one": frozenset({"one"}),
    "chm": frozenset({"chm"}),
}

_ONENOTE_MAGIC = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")
_MACHO_MAGICS = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
_MSI_CLSID_PREFIX = "000c108"
_HTML_MARKERS = ("<!doctype html", "<html", "<head", "<body", "<script", "<iframe", "<meta ", "<form", "<title")

_BIDI_CONTROL_RE = re.compile("[‪-‮⁦-⁩‎‏]")
_ZERO_WIDTH_RE = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e]")
# Characters that look like a full stop: "Invoice.pdf\u2024exe" reads as
# "Invoice.pdf.exe" to the eye but the real extension is the whole tail.
_LOOKALIKE_DOT_RE = re.compile("[\u2024\uff0e\u3002\u2027\u0701\u0702\ua4f8\u00b7\u2219\u2e31]")
# "Invoice.pdf                       .exe": spaces push the real extension out of view.
_PADDING_RE = re.compile(r"\.[A-Za-z0-9]{2,5}\s{6,}")
_PASSWORD_RE = re.compile(
    r"(?<![a-z])(?:password|passcode|passphrase|pass|pwd|pw|pin|unlock code|access code|code|key)(?![a-z])"
    r"\s*(?:(?:is|are|will be|=|:|-|–|would be)\s*){0,3}"
    r"[\"'“‘]?([^\s\"'”’<>]{3,64})",
    re.IGNORECASE,
)
_PASSWORD_STOPWORDS = frozenset(
    {"is", "the", "to", "for", "protected", "will", "has", "and", "your", "you", "with", "below", "above",
     "this", "that", "please", "required", "reset", "change", "expires", "expired", "attached", "file", "in",
     "of", "on", "be", "sent", "was", "are", "not", "it", "a", "an", "we", "our", "my", "me", "same", "as",
     "following", "provided", "enter", "use", "zip", "pdf", "document", "archive", "see", "given", "which",
     "here", "there", "needed", "inside", "if", "when", "after", "before"}
)
_AUTOEXEC_RE = re.compile(
    rb"Auto_?Open|Auto_?Close|Auto_?Exec|Document_Open|Document_Close|Workbook_Open|Workbook_Activate|"
    rb"Workbook_BeforeClose|Auto_?New|Document_New|Presentation_Open",
    re.IGNORECASE,
)
_SUSPICIOUS_VBA_RE = re.compile(
    rb"Shell|CreateObject|PowerShell|URLDownloadToFile|WScript|Base64|cmd\.exe|mshta|rundll32|certutil|"
    rb"bitsadmin|regsvr32|XMLHTTP|ADODB\.Stream|Environ|ShellExecute|CallByName|Chr\(|VirtualAlloc",
    re.IGNORECASE,
)
_RTF_OBJDATA_RE = re.compile(rb"\\objdata", re.IGNORECASE)
_RTF_OBJUPDATE_RE = re.compile(rb"\\objupdate", re.IGNORECASE)
_RTF_DDE_RE = re.compile(rb"\\ddeauto|\\dde\b", re.IGNORECASE)
_RTF_OBJEMB_RE = re.compile(rb"\\objemb|\\objautlink|\\objlink", re.IGNORECASE)
_DDE_FIELD_RE = re.compile(rb"DDEAUTO|(?<![A-Za-z])DDE\s", re.IGNORECASE)
_PDF_KEYS = ("/JavaScript", "/JS", "/Launch", "/EmbeddedFile", "/AA", "/OpenAction", "/SubmitForm", "/GoToR", "/RichMedia")
_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{2000,}={0,2}")


# --------------------------------------------------------------------------- type sniffing


def _ole_kind(data: bytes) -> str:
    try:
        import olefile

        ole = olefile.OleFileIO(data)
        try:
            clsid = (ole.root.clsid or "").lower() if ole.root is not None else ""
        finally:
            ole.close()
        if clsid.startswith(_MSI_CLSID_PREFIX):
            return "msi"
    except Exception:
        pass
    return "ole2"


def _zip_kind(data: bytes) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = {n.lower() for n in z.namelist()[:2000]}
    except Exception:
        return "zip"
    if "[content_types].xml" in names:
        return "ooxml"
    if "meta-inf/manifest.mf" in names or "androidmanifest.xml" in names:
        return "jar"
    return "zip"


def _looks_like_text(head: bytes) -> bool:
    if not head:
        return False
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return True  # UTF-16 BOM
    if b"\x00" in head:
        return False
    printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13) or b >= 128)
    return printable / len(head) >= 0.95


def sniff_type(data: bytes) -> str:
    """Identify a file by content, not by name. Returns a short lowercase tag.

    Tags: pdf, ole2, msi, zip, ooxml, jar, pe, elf, macho, rtf, html, svg,
    iso9660, lnk, one, chm, png, jpeg, gif, webp, 7z, rar, gzip, bzip2, xz, cab,
    text, empty, unknown.
    """
    if not data:
        return "empty"
    head = data[:4096]
    if head.startswith(b"%PDF-") or b"%PDF-" in head[:1024]:
        return "pdf"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return _ole_kind(data)
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return _zip_kind(data)
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head[:4] in _MACHO_MAGICS:
        return "macho"
    if head.startswith(b"{\\rtf"):
        return "rtf"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "webp"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"BZh"):
        return "bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if head.startswith(b"MSCF"):
        return "cab"
    if head.startswith(b"ITSF"):
        return "chm"
    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "lnk"
    if head.startswith(_ONENOTE_MAGIC):
        return "one"
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso9660"
    text_head = head[3:] if head.startswith(b"\xef\xbb\xbf") else head
    if _looks_like_text(text_head):
        lowered = safe_decode(text_head[:2048]).lower().lstrip()
        probe = re.sub(r"^<\?xml[^>]*\?>\s*", "", lowered)
        probe = re.sub(r"^(?:<!--.*?-->\s*|<!doctype[^>]*>\s*)*", "", probe, flags=re.S)
        if probe.startswith("<svg") or "<svg" in probe[:512]:
            return "svg"
        if any(marker in lowered[:2048] for marker in _HTML_MARKERS):
            return "html"
        return "text"
    return "unknown"


# --------------------------------------------------------------------------- helpers


def _ext_parts(filename: str) -> list[str]:
    """``'Invoice.pdf .exe'`` -> ``['pdf', 'exe']`` (lowercased, whitespace-stripped)."""
    name = filename.strip()
    parts = [p.strip().lower() for p in name.split(".")]
    return [p for p in parts[1:] if p] if len(parts) > 1 else []


def passwords_in_text(text: str) -> list[str]:
    """Candidate passwords announced in an email body ("Password: Inv2024!")."""
    if not text:
        return []
    out: list[str] = []
    for m in _PASSWORD_RE.finditer(text):
        candidate = m.group(1).rstrip(".,;:!?)")
        if len(candidate) < 3 or candidate.lower() in _PASSWORD_STOPWORDS:
            continue
        if candidate not in out:
            out.append(candidate)
        if len(out) >= 10:
            break
    return out


def _short(name: str) -> str:
    return truncate(name, 40)


@dataclass
class _Context:
    body_text: str
    passwords: list[str]
    depth: int = 0
    seen_hashes: set[str] = field(default_factory=set)


# --------------------------------------------------------------------------- detectors


def filename_tricks(filename: str) -> list[str]:
    """Unicode and spacing tricks that disguise a file's real type."""
    tricks: list[str] = []
    if _BIDI_CONTROL_RE.search(filename):
        tricks.append("right-to-left override")
    if _ZERO_WIDTH_RE.search(filename):
        tricks.append("zero-width characters")
    if _LOOKALIKE_DOT_RE.search(filename):
        tricks.append("look-alike dot")
    if _PADDING_RE.search(filename):
        tricks.append("space padding")
    return tricks


def clean_filename(filename: str) -> str:
    """``filename`` as the operating system sees its type: invisible characters
    removed, look-alike dots turned into real ones."""
    cleaned = _ZERO_WIDTH_RE.sub("", _BIDI_CONTROL_RE.sub("", filename))
    return _LOOKALIKE_DOT_RE.sub(".", cleaned)


def _filename_signals(filename: str, declared_ext: str) -> list[Signal]:
    signals: list[Signal] = []
    tricks = filename_tricks(filename)
    if tricks:
        detail = {
            "right-to-left override": "Right-to-left override characters make 'exe' read as 'pdf'.",
            "zero-width characters": "Invisible characters hide the real name from filters.",
            "look-alike dot": "A character that looks like a dot hides the real file type.",
            "space padding": "Long runs of spaces push the real file type out of view.",
        }[tricks[0]]
        signals.append(
            make_signal(
                "attachment.filename_trick", SignalStage.STATIC, 50,
                "Attachment name uses hidden characters to disguise its type",
                detail, filename=filename, tricks=tricks,
            )
        )
    parts = _ext_parts(clean_filename(filename))
    final = ((parts[-1] if parts else "") if tricks else (declared_ext or (parts[-1] if parts else ""))).lower()
    if final in DANGEROUS_EXTENSIONS:
        signals.append(
            make_signal(
                "attachment.dangerous_type", SignalStage.STATIC, DANGEROUS_EXTENSIONS[final],
                f"Attachment {_short(filename)} is a program or script (.{final})",
                "Legitimate correspondence does not arrive as runnable files.", filename=filename, extension=final,
            )
        )
    if len(parts) >= 2 and final in DANGEROUS_EXTENSIONS and any(p in DOCUMENT_LIKE_EXTENSIONS for p in parts[:-1]):
        signals.append(
            make_signal(
                "attachment.double_extension", SignalStage.STATIC, 45,
                f"Attachment {_short(filename)} pretends to be a document but ends in .{final}",
                filename=filename, extensions=parts,
            )
        )
    return signals


def _mismatch_signals(filename: str, declared_ext: str, sniffed: str) -> list[Signal]:
    signals: list[Signal] = []
    if sniffed in EXECUTABLE_SNIFFED and declared_ext not in DANGEROUS_EXTENSIONS:
        signals.append(
            make_signal(
                "attachment.executable_content", SignalStage.STATIC, 75,
                f"Attachment {_short(filename)} is really a program ({sniffed})",
                "The file content is an executable even though its name says otherwise.",
                filename=filename, sniffed_type=sniffed,
            )
        )
    allowed = _EXT_FAMILIES.get(declared_ext)
    if allowed and sniffed not in allowed and sniffed not in {"unknown", "empty"}:
        weight = 70 if sniffed in EXECUTABLE_SNIFFED else 35
        signals.append(
            make_signal(
                "attachment.type_mismatch", SignalStage.STATIC, weight,
                f"Attachment {_short(filename)} is not a real .{declared_ext} file (it is {sniffed})",
                filename=filename, declared=declared_ext, sniffed_type=sniffed,
            )
        )
    return signals


def _olevba_signals(filename: str, data: bytes, ctx: _Context) -> list[Signal]:
    """Office macros via oletools. Handles OLE2, OOXML, MHT and plain VBScript text."""
    signals: list[Signal] = []
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:  # pragma: no cover - oletools is a hard dependency
        return signals
    try:
        parser = VBA_Parser(filename, data=data)
    except Exception as exc:
        log.debug("olevba_open_failed", filename=filename, error=str(exc))
        return signals
    try:
        has_macros = False
        try:
            has_macros = bool(parser.detect_vba_macros())
        except Exception as exc:
            log.debug("olevba_detect_failed", filename=filename, error=str(exc))
        if has_macros:
            autoexec: list[str] = []
            suspicious: list[str] = []
            try:
                for kind, keyword, _desc in parser.analyze_macros() or []:
                    if kind == "AutoExec":
                        autoexec.append(str(keyword))
                    elif kind == "Suspicious":
                        suspicious.append(str(keyword))
            except Exception as exc:
                log.debug("olevba_analyze_failed", filename=filename, error=str(exc))
            signals.append(_macro_signal(filename, autoexec, suspicious, source="olevba"))
        for method, code, weight, title in (
            ("detect_xlm_macros", "attachment.xlm_macros", 60, "Spreadsheet contains Excel 4.0 macro sheets"),
            ("detect_vba_stomping", "attachment.vba_stomping", 60, "Document hides its real macro code (VBA stomping)"),
        ):
            try:
                if getattr(parser, method)():
                    signals.append(make_signal(code, SignalStage.STATIC, weight, title, filename=filename))
            except Exception as exc:
                log.debug("olevba_probe_failed", method=method, filename=filename, error=str(exc))
        try:
            if parser.detect_is_encrypted():
                weight = 55 if ctx.passwords else 40
                signals.append(
                    make_signal(
                        "attachment.office_encrypted", SignalStage.STATIC, weight,
                        f"Attachment {_short(filename)} is an encrypted Office document",
                        "Encryption stops scanners from seeing the content; the password is "
                        + ("in the email itself." if ctx.passwords else "not in the email."),
                        filename=filename, password_in_body=bool(ctx.passwords),
                    )
                )
        except Exception as exc:
            log.debug("olevba_encrypted_probe_failed", filename=filename, error=str(exc))
    finally:
        try:
            parser.close()
        except Exception:
            pass
    return signals


def _macro_signal(filename: str, autoexec: list[str], suspicious: list[str], *, source: str) -> Signal:
    weight = 45
    title = f"Attachment {_short(filename)} contains macros"
    detail = "Macros are small programs inside a document."
    if autoexec:
        weight = 65
        title = f"Attachment {_short(filename)} has macros that run as soon as it is opened"
        detail = f"Auto-run entry points: {', '.join(autoexec[:4])}."
    if suspicious:
        weight = max(weight, 55) + (5 if autoexec else 0)
        detail += f" Suspicious calls: {', '.join(suspicious[:6])}."
    return make_signal(
        "attachment.macros", SignalStage.STATIC, min(weight, 70), title, detail,
        filename=filename, autoexec=autoexec[:8], suspicious=suspicious[:12], source=source,
    )


def _ooxml_signals(filename: str, data: bytes, ctx: _Context) -> list[Signal]:
    signals: list[Signal] = []
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return signals
    with z:
        infos = z.infolist()[:2000]
        names = [i.filename for i in infos]
        lower = {n.lower(): n for n in names}

        vba_names = [n for n in names if n.lower().endswith("vbaproject.bin")]
        if vba_names:
            blob = b""
            try:
                blob = z.read(vba_names[0])[:5 * 1024 * 1024]
            except Exception:
                pass
            autoexec = sorted({m.decode("latin-1") for m in _AUTOEXEC_RE.findall(blob)})
            suspicious = sorted({m.decode("latin-1") for m in _SUSPICIOUS_VBA_RE.findall(blob)})
            sig = _macro_signal(filename, autoexec, suspicious, source="ooxml")
            if not autoexec and not suspicious:
                sig = make_signal(
                    "attachment.macros", SignalStage.STATIC, 55,
                    f"Attachment {_short(filename)} is a macro-enabled Office file",
                    "It carries a VBA project (vbaProject.bin).", filename=filename, source="ooxml",
                )
            signals.append(sig)

        if any(n.startswith("xl/macrosheets/") for n in lower):
            signals.append(
                make_signal(
                    "attachment.xlm_macros", SignalStage.STATIC, 60,
                    "Spreadsheet contains Excel 4.0 macro sheets", filename=filename,
                )
            )
        if any(n.startswith("xl/externallinks/") for n in lower):
            signals.append(
                make_signal(
                    "attachment.excel_external_links", SignalStage.STATIC, 15,
                    "Spreadsheet pulls data from external workbooks", filename=filename,
                )
            )

        for info in infos:
            name = info.filename
            low = name.lower()
            if low.endswith(".rels") and info.file_size < 2 * 1024 * 1024:
                signals.extend(_rels_signals(filename, name, _read_bounded(z, info)))
            elif low in {"word/document.xml", "word/settings.xml"} and info.file_size < MAX_ENTRY_BYTES:
                if _DDE_FIELD_RE.search(_read_bounded(z, info)):
                    signals.append(
                        make_signal(
                            "attachment.dde", SignalStage.STATIC, 60,
                            f"Attachment {_short(filename)} launches another program when opened (DDE)",
                            filename=filename,
                        )
                    )
            elif "/embeddings/" in low and info.file_size < MAX_ENTRY_BYTES:
                inner = _read_bounded(z, info)
                inner_kind = sniff_type(inner)
                weight = 70 if inner_kind in EXECUTABLE_SNIFFED else 30
                signals.append(
                    make_signal(
                        "attachment.embedded_object", SignalStage.STATIC, weight,
                        f"Attachment {_short(filename)} has an embedded file inside it ({inner_kind})",
                        filename=filename, entry=name, sniffed_type=inner_kind,
                    )
                )
    return signals


def _read_bounded(z: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int = MAX_ENTRY_BYTES, pwd: bytes | None = None) -> bytes:
    try:
        with z.open(info, pwd=pwd) as fh:
            return fh.read(limit)
    except Exception:
        return b""


def _rels_signals(filename: str, rels_name: str, xml_bytes: bytes) -> list[Signal]:
    signals: list[Signal] = []
    if not xml_bytes:
        return signals
    try:
        root = ElementTree.fromstring(xml_bytes)
    except ElementTree.ParseError:
        return signals
    for rel in root.iter():
        if not rel.tag.endswith("Relationship"):
            continue
        if (rel.get("TargetMode") or "").lower() != "external":
            continue
        target = rel.get("Target") or ""
        rtype = (rel.get("Type") or "").rsplit("/", 1)[-1].lower()
        if rtype == "hyperlink":
            continue  # ordinary clickable links; scored by the URL engine
        low_target = target.lower()
        is_remote = low_target.startswith(("http://", "https://", "file:", "\\\\", "ftp://"))
        if rtype == "attachedtemplate" and is_remote:
            signals.append(
                make_signal(
                    "attachment.remote_template", SignalStage.STATIC, 60,
                    f"Attachment {_short(filename)} loads a template from the internet when opened",
                    "Remote template injection downloads the real payload after the file passes scanning.",
                    filename=filename, target=target[:200], rels=rels_name,
                )
            )
        elif is_remote:
            signals.append(
                make_signal(
                    "attachment.external_reference", SignalStage.STATIC, 35,
                    f"Attachment {_short(filename)} references external content ({rtype or 'object'})",
                    filename=filename, target=target[:200], relationship=rtype,
                )
            )
    return signals


def _rtf_signals(filename: str, data: bytes) -> list[Signal]:
    signals: list[Signal] = []
    sample = data[:MAX_TEXT_SCAN_BYTES]
    if _RTF_OBJUPDATE_RE.search(sample):
        weight, why = 65, "It carries an object that updates itself as soon as the file opens (exploit pattern)."
    elif _RTF_DDE_RE.search(sample):
        weight, why = 60, "It launches another program through DDE."
    elif _RTF_OBJDATA_RE.search(sample) or _RTF_OBJEMB_RE.search(sample):
        weight, why = 55, "It carries an embedded OLE object, a common exploit carrier."
    else:
        return signals
    signals.append(
        make_signal(
            "attachment.rtf_object", SignalStage.STATIC, weight,
            f"Attachment {_short(filename)} is an RTF file with embedded objects", why, filename=filename,
        )
    )
    return signals


def _pdf_signals(filename: str, data: bytes, ctx: _Context) -> list[Signal]:
    signals: list[Signal] = []
    try:
        import pymupdf
    except ImportError:  # pragma: no cover
        return signals
    try:
        doc = pymupdf.open(stream=data, filetype="pdf")
    except Exception as exc:
        log.debug("pdf_open_failed", filename=filename, error=str(exc))
        return signals
    try:
        if doc.needs_pass:
            unlocked = any(doc.authenticate(p) for p in ctx.passwords)
            weight = 55 if unlocked else (45 if ctx.passwords else 30)
            signals.append(
                make_signal(
                    "attachment.pdf_encrypted", SignalStage.STATIC, weight,
                    f"Attachment {_short(filename)} is a password-protected PDF"
                    + (" (password given in the email)" if unlocked else ""),
                    "Encryption hides content from scanners; mailing the password alongside defeats the point.",
                    filename=filename, unlocked=unlocked,
                )
            )
            if not unlocked:
                return signals
        found = _pdf_keys(doc, data)
        has_js = "/JavaScript" in found or "/JS" in found
        if has_js:
            auto = "/OpenAction" in found or "/AA" in found
            signals.append(
                make_signal(
                    "attachment.pdf_javascript", SignalStage.STATIC, 55 if auto else 40,
                    f"Attachment {_short(filename)} contains script that runs "
                    + ("automatically when opened" if auto else "inside the PDF"),
                    "Ordinary documents do not need scripts.", filename=filename, auto_run=auto,
                )
            )
        if "/Launch" in found:
            signals.append(
                make_signal(
                    "attachment.pdf_launch", SignalStage.STATIC, 60,
                    f"Attachment {_short(filename)} tries to launch a program", filename=filename,
                )
            )
        if "/EmbeddedFile" in found:
            names: list[str] = []
            try:
                names = [str(n) for n in doc.embfile_names()]
            except Exception:
                names = []
            dangerous = [n for n in names if _ext_parts(n) and _ext_parts(n)[-1] in DANGEROUS_EXTENSIONS]
            signals.append(
                make_signal(
                    "attachment.pdf_embedded_file", SignalStage.STATIC, 50 if dangerous else 35,
                    f"Attachment {_short(filename)} has files hidden inside it"
                    + (f" ({_short(dangerous[0])})" if dangerous else ""),
                    filename=filename, embedded=names[:10],
                )
            )
        if "/AA" in found and not has_js:
            signals.append(
                make_signal(
                    "attachment.pdf_auto_actions", SignalStage.STATIC, 15,
                    f"Attachment {_short(filename)} has automatic actions attached to it", filename=filename,
                )
            )
        if "/SubmitForm" in found:
            signals.append(
                make_signal(
                    "attachment.pdf_form_submit", SignalStage.STATIC, 20,
                    f"Attachment {_short(filename)} is a form that sends what you type to a server",
                    filename=filename,
                )
            )
        if "/GoToR" in found or "/RichMedia" in found:
            signals.append(
                make_signal(
                    "attachment.pdf_remote_content", SignalStage.STATIC, 25,
                    f"Attachment {_short(filename)} loads remote or rich-media content", filename=filename,
                )
            )
        signals.extend(_pdf_page_signals(filename, doc))
    finally:
        doc.close()
    return signals


def _pdf_keys(doc, data: bytes) -> set[str]:
    """PDF dictionary keys of interest, from parsed objects first, raw bytes as fallback."""
    found: set[str] = set()
    try:
        for xref in range(1, min(doc.xref_length(), MAX_PDF_OBJECTS)):
            try:
                obj = doc.xref_object(xref, compressed=True)
            except Exception:
                continue
            for key in _PDF_KEYS:
                if key in found:
                    continue
                if re.search(re.escape(key) + r"(?![A-Za-z])", obj):
                    found.add(key)
    except Exception as exc:
        log.debug("pdf_xref_scan_failed", error=str(exc))
    sample = data[:MAX_TEXT_SCAN_BYTES * 4]
    for key in _PDF_KEYS:
        if key not in found and re.search(re.escape(key).encode() + rb"(?![A-Za-z])", sample):
            found.add(key)
    return found


def _pdf_page_signals(filename: str, doc) -> list[Signal]:
    signals: list[Signal] = []
    try:
        page_count = doc.page_count
    except Exception:
        return signals
    unknown_domains: set[str] = set()
    image_only = 0
    checked = 0
    for index, page in enumerate(doc):
        if index >= 5:
            break
        checked += 1
        try:
            for link in page.get_links():
                uri = link.get("uri")
                if isinstance(uri, str) and "://" in uri:
                    host = uri.split("://", 1)[1].split("/", 1)[0].split("@")[-1].split(":")[0].lower()
                    rd = registrable_domain(host)
                    if rd and not is_popular(rd):
                        unknown_domains.add(rd)
            text = page.get_text().strip()
            if len(text) < 20 and page.get_images():
                image_only += 1
        except Exception as exc:
            log.debug("pdf_page_scan_failed", page=index, error=str(exc))
    if unknown_domains:
        signals.append(
            make_signal(
                "attachment.pdf_external_links", SignalStage.STATIC, 10,
                f"Attachment {_short(filename)} links to {len(unknown_domains)} unfamiliar website(s)",
                filename=filename, domains=sorted(unknown_domains)[:10],
            )
        )
    if checked and page_count <= 3 and image_only / checked >= 0.8:
        signals.append(
            make_signal(
                "attachment.pdf_image_only", SignalStage.STATIC, 15,
                f"Attachment {_short(filename)} is a picture posing as a document",
                "Phishing lures are often screenshots so text filters cannot read them.", filename=filename,
            )
        )
    return signals


def _html_signals(filename: str, text: str) -> list[Signal]:
    signals: list[Signal] = []
    lower = text.lower()
    indicators: list[str] = []
    has_blob = bool(_BASE64_BLOB_RE.search(text))
    if has_blob:
        indicators.append("large base64 blob")
    has_atob = "atob(" in lower
    if has_atob:
        indicators.append("atob()")
    has_mssave = "mssaveoropenblob" in lower or "mssaveblob" in lower
    if has_mssave:
        indicators.append("msSaveOrOpenBlob")
    has_blob_api = "new blob(" in lower or "createobjecturl" in lower
    if has_blob_api:
        indicators.append("Blob/createObjectURL")
    has_doc_write = "document.write(" in lower and (has_atob or "unescape(" in lower)
    if has_doc_write:
        indicators.append("document.write of decoded content")
    has_download_attr = re.search(r"\bdownload\s*=", lower) is not None
    if has_download_attr:
        indicators.append("forced download attribute")
    obfuscated = "unescape(" in lower or "string.fromcharcode" in lower or re.search(r"\beval\s*\(", lower) is not None
    has_password_field = re.search(r"type\s*=\s*[\"']?password", lower) is not None
    has_password_prompt = (
        re.search(r"prompt\s*\([^)]*pass", lower) is not None or ("<form" in lower and "password" in lower)
    )
    redirect = (
        re.search(r"http-equiv\s*=\s*[\"']?refresh", lower) is not None
        or re.search(r"(?:window\.)?location(?:\.href|\.replace)?\s*=|location\.replace\(", lower) is not None
    )

    smuggling_weight = 0
    if has_mssave or (has_blob and (has_atob or has_blob_api or has_doc_write)) or (has_blob_api and has_atob):
        smuggling_weight = 55
    elif has_atob or has_blob_api or has_doc_write or has_blob:
        smuggling_weight = 35
    if smuggling_weight:
        signals.append(
            make_signal(
                "attachment.html_smuggling", SignalStage.STATIC, smuggling_weight,
                f"Attachment {_short(filename)} builds a hidden file inside the browser (HTML smuggling)",
                "Indicators: " + ", ".join(indicators) + ".", filename=filename, indicators=indicators,
            )
        )
    if has_password_field or has_password_prompt:
        signals.append(
            make_signal(
                "attachment.html_credential_form", SignalStage.STATIC, 50 if has_password_field else 40,
                f"Attachment {_short(filename)} asks for a password",
                "A sign-in page delivered as an attachment bypasses web filters.", filename=filename,
            )
        )
    hidden_redirect = redirect and (has_atob or has_blob or "data:text/html" in lower or "fromcharcode" in lower)
    if redirect:
        signals.append(
            make_signal(
                "attachment.html_redirect", SignalStage.STATIC, 50 if hidden_redirect else 30,
                f"Attachment {_short(filename)} " + ("secretly forwards you to a hidden website when opened" if hidden_redirect
                                                    else "redirects to another website when opened"),
                filename=filename, hidden=hidden_redirect,
            )
        )
    signals.extend(_html_clickfix_signals(filename, text))
    if obfuscated and not smuggling_weight:
        signals.append(
            make_signal(
                "attachment.html_obfuscated_script", SignalStage.STATIC, 25,
                f"Attachment {_short(filename)} contains disguised script", filename=filename,
            )
        )
    if not signals:
        signals.append(
            make_signal(
                "attachment.html_attachment", SignalStage.STATIC, 15,
                f"Attachment {_short(filename)} is a web page sent as a file", filename=filename,
            )
        )
    return signals


_SVG_REDIRECT_RE = re.compile(
    r"(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=|location\.(?:replace|assign)\s*\(|window\.open\s*\(|"
    r"http-equiv\s*=\s*[\"']?refresh",
    re.IGNORECASE,
)
_SVG_DECODE_RE = re.compile(r"\batob\s*\(|fromcharcode|unescape\s*\(|\beval\s*\(|new\s+function\s*\(", re.IGNORECASE)


def _html_clickfix_signals(filename: str, text: str) -> list[Signal]:
    """A ClickFix page delivered as an HTML attachment (Microsoft and Proofpoint
    saw this from 2024): clipboard code plus "Win + R, Ctrl + V" steps."""
    from reddysec.chamber import lures as page_lures

    lower = text.lower()
    copies = "navigator.clipboard" in lower or "execcommand(" in lower or "clipboarddata" in lower
    visible = re.sub(r"<script\b.*?</script>|<style\b.*?</style>", " ", text, flags=re.I | re.S)
    visible = re.sub(r"<[^>]+>", "\n", visible)
    hits = page_lures.instruction_hits(visible)
    if not (copies and page_lures.clickfix_instructions(hits)):
        return []
    commands = [line for line in text.splitlines() if page_lures.is_dangerous_command(line)]
    return [
        make_signal(
            "attachment.html_clickfix", SignalStage.STATIC, 90 if commands else 70,
            f"Attachment {_short(filename)} is a fake check that makes you paste a command into Windows",
            "It copies a command and tells you to press keys to run it. That would install malware.",
            filename=filename, steps=hits[:10], command_seen=bool(commands),
        )
    ]


def _svg_signals(filename: str, text: str) -> list[Signal]:
    """SVG is an image format that is also a web page: it can run script,
    embed HTML forms (``<foreignObject>``) and redirect. In 2025 SVG
    attachments became a top phishing carrier (docs/threat-catalog.md)."""
    signals: list[Signal] = []
    lower = text.lower()
    scripted = "<script" in lower or re.search(r"\son[a-z]+\s*=", lower) is not None or "javascript:" in lower
    foreign = "<foreignobject" in lower
    form = foreign and re.search(r"<form|<input|<iframe|type\s*=\s*[\"']?password", lower) is not None
    redirect = _SVG_REDIRECT_RE.search(text) is not None
    data_url = re.search(r"(?:href|src)\s*=\s*[\"']?data:text/html", lower) is not None
    decoded = _SVG_DECODE_RE.search(text) is not None or bool(_BASE64_BLOB_RE.search(text))
    indicators = [name for name, hit in (
        ("script", scripted), ("embedded HTML form", form), ("redirect", redirect),
        ("data: page", data_url), ("decoded/obfuscated script", decoded and scripted),
    ) if hit]
    if form or data_url or (scripted and (redirect or decoded)):
        signals.append(
            make_signal(
                "attachment.svg_phish", SignalStage.STATIC, 70,
                f"Attachment {_short(filename)} is an 'image' that opens a web page or sign-in form",
                "Opening it in a browser would run code, show a fake sign-in form or send you to a phishing site.",
                filename=filename, indicators=indicators,
            )
        )
    elif scripted:
        signals.append(
            make_signal(
                "attachment.svg_script", SignalStage.STATIC, 55,
                f"Attachment {_short(filename)} is an image file that contains script", filename=filename,
            )
        )
    elif foreign or re.search(r"href\s*=\s*[\"']https?://", lower):
        signals.append(
            make_signal(
                "attachment.svg_external", SignalStage.STATIC, 20,
                f"Attachment {_short(filename)} is an image that loads external content", filename=filename,
            )
        )
    return signals


# --------------------------------------------------------------------------- archives


def _open_aes_zip(data: bytes, password: bytes):
    """pyzipper is optional; without it AES archives stay sealed (and are flagged)."""
    try:
        import pyzipper
    except ImportError:
        return None
    try:
        z = pyzipper.AESZipFile(io.BytesIO(data))
        z.setpassword(password)
        return z
    except Exception:
        return None


def _try_unlock(data: bytes, infos: list[zipfile.ZipInfo], passwords: list[str]) -> tuple[str | None, bool]:
    """Return (working password, needs_pyzipper) for the first encrypted entry."""
    encrypted = [i for i in infos if i.flag_bits & 0x1 and not i.is_dir()]
    if not encrypted:
        return None, False
    probe = min(encrypted, key=lambda i: i.compress_size)
    is_aes = probe.compress_type == 99
    for pwd in passwords:
        pwd_bytes = pwd.encode("utf-8", errors="ignore")
        if is_aes:
            z = _open_aes_zip(data, pwd_bytes)
            if z is None:
                return None, True
            try:
                with z:
                    z.read(probe.filename)
                return pwd, False
            except Exception:
                continue
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                with z.open(probe, pwd=pwd_bytes) as fh:
                    fh.read(64)
            return pwd, False
        except (RuntimeError, zipfile.BadZipFile, NotImplementedError, zlib.error, ValueError, EOFError):
            continue
        except Exception:
            continue
    return None, False


def _entry_bytes(data: bytes, info: zipfile.ZipInfo, password: str | None) -> bytes:
    pwd = password.encode("utf-8", errors="ignore") if password else None
    if info.compress_type == 99 and pwd is not None:
        z = _open_aes_zip(data, pwd)
        if z is None:
            return b""
        try:
            with z:
                return z.read(info.filename)[:MAX_ENTRY_BYTES]
        except Exception:
            return b""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            return _read_bounded(z, info, pwd=pwd)
    except Exception:
        return b""


def _zip_signals(filename: str, data: bytes, ctx: _Context) -> list[Signal]:
    signals: list[Signal] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = [i for i in z.infolist() if not i.is_dir()][:1000]
    except Exception as exc:
        log.debug("zip_open_failed", filename=filename, error=str(exc))
        return signals
    total_uncompressed = sum(i.file_size for i in infos)
    total_compressed = max(1, sum(i.compress_size for i in infos))
    if total_uncompressed / total_compressed > ZIP_BOMB_RATIO and total_uncompressed > ZIP_BOMB_MIN_UNCOMPRESSED:
        signals.append(
            make_signal(
                "attachment.zip_bomb", SignalStage.STATIC, 60,
                f"Attachment {_short(filename)} expands to an absurd size (decompression bomb)",
                filename=filename, ratio=round(total_uncompressed / total_compressed),
            )
        )
        return signals

    names = [i.filename for i in infos]
    dangerous = [n for n in names if _ext_parts(n) and _ext_parts(n)[-1] in DANGEROUS_EXTENSIONS]
    if dangerous:
        top = max(DANGEROUS_EXTENSIONS[_ext_parts(n)[-1]] for n in dangerous)
        signals.append(
            make_signal(
                "attachment.archive_dangerous_entry", SignalStage.STATIC, top,
                f"Archive {_short(filename)} contains a program or script ({_short(dangerous[0].rsplit('/', 1)[-1])})",
                filename=filename, entries=dangerous[:10],
            )
        )

    encrypted = [i for i in infos if i.flag_bits & 0x1]
    password: str | None = None
    if encrypted:
        password, needs_pyzipper = _try_unlock(data, infos, ctx.passwords)
        if password is not None:
            signals.append(
                make_signal(
                    "attachment.archive_password_in_body", SignalStage.STATIC, 55,
                    f"Archive {_short(filename)} is password-protected and the password is in the email",
                    "Encrypting the file hides it from scanners; sending the password alongside is a classic evasion.",
                    filename=filename, entries=names[:10],
                )
            )
        else:
            detail = "We could not look inside it."
            if needs_pyzipper:
                detail += " (AES archives need the optional pyzipper package.)"
            elif ctx.passwords:
                detail += " None of the passwords mentioned in the email opened it."
            signals.append(
                make_signal(
                    "attachment.archive_encrypted", SignalStage.STATIC, 35,
                    f"Archive {_short(filename)} is password-protected",
                    detail, filename=filename, entries=names[:10], aes=any(i.compress_type == 99 for i in encrypted),
                )
            )

    if ctx.depth >= MAX_ARCHIVE_DEPTH:
        if any(_ext_parts(n) and _ext_parts(n)[-1] in ARCHIVE_EXTENSIONS for n in names):
            signals.append(
                make_signal(
                    "attachment.archive_nested_deep", SignalStage.STATIC, 30,
                    f"Archive {_short(filename)} nests archives several levels deep", filename=filename,
                )
            )
        return signals

    for info in infos[:MAX_ARCHIVE_ENTRIES]:
        if info.file_size > MAX_ENTRY_BYTES or (info.flag_bits & 0x1 and password is None):
            continue
        inner = _entry_bytes(data, info, password if info.flag_bits & 0x1 else None)
        if not inner:
            continue
        inner_name = info.filename.rsplit("/", 1)[-1]
        child = _Context(ctx.body_text, ctx.passwords, ctx.depth + 1, ctx.seen_hashes)
        for sig in _analyze_bytes(inner_name, inner, _ext_parts(inner_name)[-1] if _ext_parts(inner_name) else "", child):
            sig.evidence.setdefault("archive", filename)
            sig.evidence.setdefault("entry", info.filename)
            signals.append(sig)
    return signals


def _gunzip_bounded(data: bytes, limit: int = MAX_ENTRY_BYTES) -> bytes:
    try:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        return d.decompress(data, limit)
    except zlib.error:
        try:
            return gzip.decompress(data)[:limit]
        except Exception:
            return b""


def _gzip_signals(filename: str, data: bytes, ctx: _Context) -> list[Signal]:
    signals: list[Signal] = []
    inner = _gunzip_bounded(data)
    if not inner or ctx.depth >= MAX_ARCHIVE_DEPTH:
        return signals
    inner_name = re.sub(r"\.(gz|tgz)$", "", filename, flags=re.I)
    if filename.lower().endswith(".tgz"):
        inner_name += ".tar"
    child = _Context(ctx.body_text, ctx.passwords, ctx.depth + 1, ctx.seen_hashes)
    if inner_name.lower().endswith(".tar") or inner.startswith(b"ustar", 257):
        try:
            with tarfile.open(fileobj=io.BytesIO(inner), mode="r:") as tar:
                for member in tar.getmembers()[:MAX_ARCHIVE_ENTRIES]:
                    if not member.isfile() or member.size > MAX_ENTRY_BYTES:
                        continue
                    fh = tar.extractfile(member)
                    if fh is None:
                        continue
                    member_name = member.name.rsplit("/", 1)[-1]
                    ext = _ext_parts(member_name)[-1] if _ext_parts(member_name) else ""
                    for sig in _analyze_bytes(member_name, fh.read(MAX_ENTRY_BYTES), ext, child):
                        sig.evidence.setdefault("archive", filename)
                        sig.evidence.setdefault("entry", member.name)
                        signals.append(sig)
        except Exception as exc:
            log.debug("tar_open_failed", filename=filename, error=str(exc))
        return signals
    ext = _ext_parts(inner_name)[-1] if _ext_parts(inner_name) else ""
    for sig in _analyze_bytes(inner_name, inner, ext, child):
        sig.evidence.setdefault("archive", filename)
        signals.append(sig)
    return signals


# --------------------------------------------------------------------------- orchestration


def _analyze_bytes(filename: str, data: bytes, declared_ext: str, ctx: _Context) -> list[Signal]:
    """Run every applicable detector on one file. Used for attachments and archive members."""
    signals: list[Signal] = list(_filename_signals(filename, declared_ext))
    if not data:
        return signals
    digest = sha256_hex(data)
    if digest in ctx.seen_hashes:
        return signals  # identical member already analysed (zip of the same payload twice)
    ctx.seen_hashes.add(digest)

    sniffed = sniff_type(data)
    signals.extend(_mismatch_signals(filename, declared_ext, sniffed))
    ext = declared_ext.lower()
    try:
        if sniffed == "pdf":
            signals.extend(_pdf_signals(filename, data, ctx))
        elif sniffed == "ooxml":
            signals.extend(_ooxml_signals(filename, data, ctx))
            signals.extend(_olevba_signals(filename, data, ctx))
        elif sniffed in {"ole2", "msi"}:
            signals.extend(_olevba_signals(filename, data, ctx))
            if sniffed == "msi" and ext != "msi":
                signals.append(
                    make_signal(
                        "attachment.executable_content", SignalStage.STATIC, 70,
                        f"Attachment {_short(filename)} is a Windows installer", filename=filename, sniffed_type=sniffed,
                    )
                )
        elif sniffed == "rtf":
            signals.extend(_rtf_signals(filename, data))
        elif sniffed in {"zip", "jar"}:
            signals.extend(_zip_signals(filename, data, ctx))
        elif sniffed == "gzip":
            signals.extend(_gzip_signals(filename, data, ctx))
        elif sniffed in {"7z", "rar", "cab", "bzip2", "xz"}:
            signals.append(
                make_signal(
                    "attachment.archive_opaque", SignalStage.STATIC, 25,
                    f"Attachment {_short(filename)} is a {sniffed} archive we cannot look inside",
                    "Attackers favour archive formats that mail scanners do not unpack.",
                    filename=filename, sniffed_type=sniffed,
                )
            )
        elif sniffed == "iso9660":
            signals.append(
                make_signal(
                    "attachment.disk_image", SignalStage.STATIC, 70,
                    f"Attachment {_short(filename)} is a disk image", "Disk images mount silently and bypass download warnings.",
                    filename=filename,
                )
            )
        elif sniffed == "svg" or (ext == "svg" and sniffed == "text"):
            signals.extend(_svg_signals(filename, safe_decode(data, MAX_TEXT_SCAN_BYTES)))
        elif sniffed == "html" or ext in HTML_EXTENSIONS:
            signals.extend(_html_signals(filename, safe_decode(data, MAX_TEXT_SCAN_BYTES)))
        elif sniffed == "text" and ext in SCRIPT_TEXT_EXTENSIONS:
            signals.extend(_olevba_signals(filename, data, ctx))
        elif ext in OFFICE_EXTENSIONS and sniffed in {"text", "unknown"}:
            signals.extend(_olevba_signals(filename, data, ctx))
    except Exception as exc:  # a detector bug must never block a verdict
        log.warning("attachment_detector_failed", filename=filename, sniffed=sniffed, error=str(exc))
    return signals


def attachment_signals(att: Attachment, body_text: str = "") -> list[Signal]:
    """All static signals for one attachment. Never raises.

    ``body_text`` is used to find passwords announced in the email so that
    protected archives and PDFs can be opened and inspected. As a side effect
    the attachment's ``sniffed_type`` is filled in when it was unknown.
    """
    signals: list[Signal] = []
    try:
        data = att.data or b""
        if att.data is not None and att.sniffed_type is None:
            att.sniffed_type = sniff_type(data)
        size = len(data) if att.data is not None else att.size
        if size == 0:
            signals.append(
                make_signal(
                    "attachment.empty", SignalStage.STATIC, 5,
                    f"Attachment {_short(att.filename)} is empty", filename=att.filename,
                )
            )
            signals.extend(_filename_signals(att.filename, att.declared_extension))
            return signals
        if size > MAX_ATTACHMENT_BYTES:
            signals.append(
                make_signal(
                    "attachment.oversized", SignalStage.STATIC, 5,
                    f"Attachment {_short(att.filename)} is too large to inspect ({size // (1024 * 1024)} MB)",
                    filename=att.filename, size=size,
                )
            )
            signals.extend(_filename_signals(att.filename, att.declared_extension))
            return signals
        ctx = _Context(body_text=body_text or "", passwords=passwords_in_text(body_text or ""))
        signals.extend(_analyze_bytes(att.filename, data, att.declared_extension, ctx))
    except Exception as exc:
        log.warning("attachment_analysis_failed", filename=att.filename, error=str(exc))
    return signals

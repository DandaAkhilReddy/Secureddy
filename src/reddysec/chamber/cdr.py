"""Content Disarm & Reconstruction: turn a document we do not trust into one
we do, by keeping only what a person needs to see.

The output is always a PDF made of page *images*. Rasterizing is a blunt
instrument, and that is the point: JavaScript, forms, launch actions, embedded
files, external links, macros, OLE objects, fonts with parser bugs - none of
it survives a trip through pixels. The client reads the same words and
pictures; nothing executable or interactive remains. Text is not searchable in
the safe copy, which is an accepted trade-off for mail attachments.

Routes by *sniffed* content first, extension second, because attackers lie
about extensions:

* PDF            -> pymupdf renders each page at ``dpi`` -> image-only PDF
* Office / RTF / ODF -> LibreOffice headless converts to PDF (private profile,
                    network namespace removed when ``unshare`` allows it, hard
                    timeout) -> the PDF route
* images         -> Pillow re-encode to PNG (drops metadata and malformed
                    chunks) -> single-page PDF
* txt / csv      -> text laid out onto pages by pymupdf
* anything else  -> ``unsupported``; the caller decides what to tell the client

``sanitize`` is synchronous and CPU-bound; call it through
``asyncio.to_thread`` from async code (the Reading Room does).
"""

from __future__ import annotations

import io
import os
import shutil
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .common import extension_of, is_image_type, safe_filename, sniff_type

MAX_PAGES = 200
DEFAULT_DPI = 110
OFFICE_EXTENSIONS = frozenset(
    {"doc", "docx", "docm", "dot", "dotx", "dotm", "xls", "xlsx", "xlsm", "xlt", "xltx", "ppt", "pptx", "pptm", "pps", "ppsx", "rtf", "odt", "ods", "odp", "odg"}
)
# What an office file may look like on the inside. HTML-named-as-.doc and
# executables are refused rather than handed to LibreOffice.
OFFICE_CONTENT_TYPES = frozenset({"zip", "ole", "rtf", "text", "unknown"})
IMAGE_EXTENSIONS = frozenset({"png", "jpg", "jpeg", "gif", "bmp", "webp"})
TEXT_EXTENSIONS = frozenset({"txt", "csv", "log", "md", "text", "tsv"})
MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_IMAGE_PIXELS = 50_000_000


@dataclass(frozen=True)
class CdrResult:
    ok: bool
    pdf_bytes: bytes | None
    pages: int
    method: str  # pdf | office | image | text | unsupported
    reason: str | None = None

    @classmethod
    def unsupported(cls, reason: str, method: str = "unsupported") -> CdrResult:
        return cls(False, None, 0, method, reason)


def sanitize(
    data: bytes,
    filename: str,
    *,
    soffice_path: str | None = shutil.which("soffice"),
    timeout_s: int = 60,
    dpi: int = DEFAULT_DPI,
    max_pages: int = MAX_PAGES,
) -> CdrResult:
    """Produce a safe, image-only PDF for ``data`` or explain why we cannot."""
    if not data:
        return CdrResult.unsupported("empty file")
    label = sniff_type(data)
    ext = extension_of(filename)

    if label == "pdf":
        return flatten_pdf(data, dpi=dpi, max_pages=max_pages)
    if ext in OFFICE_EXTENSIONS:
        if label not in OFFICE_CONTENT_TYPES:
            return CdrResult.unsupported(f"content looks like {label}, not an office document", "office")
        if not soffice_path:
            return CdrResult.unsupported("LibreOffice (soffice) is not available", "office")
        return office_to_pdf(data, filename, soffice_path=soffice_path, timeout_s=timeout_s, dpi=dpi, max_pages=max_pages)
    if is_image_type(label) or (ext in IMAGE_EXTENSIONS and is_image_type(label)):
        return image_to_pdf(data)
    if label == "text" and (ext in TEXT_EXTENSIONS or ext == ""):
        return text_to_pdf(data, max_pages=max_pages)
    if ext in IMAGE_EXTENSIONS or ext in TEXT_EXTENSIONS:
        return CdrResult.unsupported(f"content looks like {label}, which does not match .{ext}")
    return CdrResult.unsupported(f"no safe rendering for {label} ({ext or 'no extension'})")


# --- PDF ------------------------------------------------------------------------


def flatten_pdf(data: bytes, *, dpi: int = DEFAULT_DPI, max_pages: int = MAX_PAGES) -> CdrResult:
    """Render every page to a bitmap and rebuild a PDF from the bitmaps only."""
    import pymupdf

    try:
        source = pymupdf.open(stream=data, filetype="pdf")
    except Exception as exc:
        return CdrResult.unsupported(f"pdf could not be parsed: {exc}", "pdf")
    try:
        if source.needs_pass:
            return CdrResult.unsupported("pdf is password protected", "pdf")
        total = source.page_count
        if total == 0:
            return CdrResult.unsupported("pdf has no pages", "pdf")
        count = min(total, max_pages)
        output = pymupdf.open()
        try:
            for index in range(count):
                page = source[index]
                pixmap = page.get_pixmap(dpi=dpi, alpha=False)
                rect = page.rect
                target = output.new_page(width=rect.width or 612, height=rect.height or 792)
                target.insert_image(target.rect, stream=pixmap.tobytes("png"))
            pdf = output.tobytes(garbage=4, deflate=True)
        finally:
            output.close()
    except Exception as exc:
        return CdrResult.unsupported(f"pdf rendering failed: {exc}", "pdf")
    finally:
        source.close()
    reason = f"truncated to the first {count} of {total} pages" if total > count else None
    return CdrResult(True, pdf, count, "pdf", reason)


# --- Office -------------------------------------------------------------------


@lru_cache(maxsize=1)
def _network_isolation_prefix() -> tuple[str, ...]:
    """``unshare`` arguments that drop LibreOffice into an empty network
    namespace, when this host allows unprivileged namespaces; otherwise empty.
    A document that phones home on open would otherwise tell its sender we
    looked at it."""
    unshare = shutil.which("unshare")
    if not unshare:
        return ()
    for candidate in ((unshare, "--user", "--map-root-user", "--net"), (unshare, "--net")):
        try:
            probe = subprocess.run([*candidate, "true"], capture_output=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return candidate
    return ()


def office_to_pdf(
    data: bytes,
    filename: str,
    *,
    soffice_path: str,
    timeout_s: int = 60,
    dpi: int = DEFAULT_DPI,
    max_pages: int = MAX_PAGES,
) -> CdrResult:
    """LibreOffice headless conversion followed by the PDF flatten.

    A private ``UserInstallation`` profile per call keeps concurrent
    conversions from fighting over the profile lock and starts every run
    with LibreOffice's defaults (macros disabled, no recent documents).
    """
    name = safe_filename(filename, default="document.bin")
    with tempfile.TemporaryDirectory(prefix="rs-cdr-") as tmp:
        root = Path(tmp)
        source_dir = root / "in"
        out_dir = root / "out"
        profile = root / "profile"
        for directory in (source_dir, out_dir, profile):
            directory.mkdir()
        source = source_dir / name
        source.write_bytes(data)
        command = [
            *_network_isolation_prefix(),
            soffice_path,
            "--headless",
            "--norestore",
            "--nologo",
            "--nolockcheck",
            "--nodefault",
            f"-env:UserInstallation={profile.as_uri()}",
            "--convert-to",
            "pdf",
            "--outdir",
            str(out_dir),
            str(source),
        ]
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": str(root),
            "TMPDIR": str(root),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "SAL_USE_VCLPLUGIN": "svp",  # the headless VCL plug-in; no display needed
        }
        try:
            proc = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=str(root),
                start_new_session=True,
            )
        except OSError as exc:
            return CdrResult.unsupported(f"could not start LibreOffice: {exc}", "office")
        try:
            _stdout, stderr = proc.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            return CdrResult.unsupported(f"LibreOffice did not finish within {timeout_s}s", "office")

        produced = sorted(out_dir.glob("*.pdf"))
        if not produced:
            tail = stderr.decode("utf-8", errors="replace").strip()[-500:]
            return CdrResult.unsupported(f"LibreOffice produced no PDF (exit {proc.returncode}): {tail or 'no output'}", "office")
        pdf = produced[0].read_bytes()
    flattened = flatten_pdf(pdf, dpi=dpi, max_pages=max_pages)
    if not flattened.ok:
        return CdrResult.unsupported(f"converted PDF could not be flattened: {flattened.reason}", "office")
    return CdrResult(True, flattened.pdf_bytes, flattened.pages, "office", flattened.reason)


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        proc.kill()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover
        pass


# --- images ---------------------------------------------------------------------


def image_to_pdf(data: bytes) -> CdrResult:
    """Decode with Pillow, re-encode as a fresh PNG (no metadata, no trailing
    data, no exotic chunks), wrap as a one-page PDF."""
    import pymupdf
    from PIL import Image, ImageFile

    ImageFile.LOAD_TRUNCATED_IMAGES = False
    try:
        with Image.open(io.BytesIO(data)) as image:
            if image.width * image.height > MAX_IMAGE_PIXELS:
                return CdrResult.unsupported(f"image too large ({image.width}x{image.height})", "image")
            image.load()
            if image.mode not in ("RGB", "RGBA", "L"):
                image = image.convert("RGB")
            buffer = io.BytesIO()
            image.save(buffer, format="PNG", optimize=False)
    except Exception as exc:
        return CdrResult.unsupported(f"image could not be decoded: {type(exc).__name__}: {exc}", "image")
    png = buffer.getvalue()
    try:
        picture = pymupdf.open(stream=png, filetype="png")
        pdf = picture.convert_to_pdf()
        picture.close()
    except Exception as exc:
        return CdrResult.unsupported(f"image could not be wrapped as pdf: {exc}", "image")
    return CdrResult(True, pdf, 1, "image")


# --- text -----------------------------------------------------------------------


def text_to_pdf(data: bytes, *, max_pages: int = MAX_PAGES) -> CdrResult:
    """Lay plain text onto letter-size pages with a monospaced font. Nothing
    in a text file is dangerous, but the client's viewer may still be, so a
    PDF of glyphs keeps the delivery path uniform."""
    import pymupdf

    text = data[:MAX_TEXT_BYTES].decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("\t", "    ")
    lines = text.split("\n") or [""]
    width, height, margin, font_size, leading = 612.0, 792.0, 48.0, 9.5, 12.0
    chars_per_line = int((width - 2 * margin) / (font_size * 0.6))
    lines_per_page = int((height - 2 * margin) / leading)
    wrapped: list[str] = []
    for line in lines:
        if not line:
            wrapped.append("")
            continue
        while line:
            wrapped.append(line[:chars_per_line])
            line = line[chars_per_line:]
    total_pages = max(1, -(-len(wrapped) // lines_per_page))
    count = min(total_pages, max_pages)
    output = pymupdf.open()
    try:
        for index in range(count):
            page = output.new_page(width=width, height=height)
            chunk = wrapped[index * lines_per_page : (index + 1) * lines_per_page]
            y = margin
            for line in chunk:
                page.insert_text((margin, y + font_size), line, fontsize=font_size, fontname="cour")
                y += leading
        pdf = output.tobytes(garbage=4, deflate=True)
    finally:
        output.close()
    reason = f"truncated to the first {count} of {total_pages} pages" if total_pages > count else None
    if len(data) > MAX_TEXT_BYTES:
        reason = (reason + "; " if reason else "") + f"text truncated to {MAX_TEXT_BYTES} bytes"
    return CdrResult(True, pdf, count, "text", reason)

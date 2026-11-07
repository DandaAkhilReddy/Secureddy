"""Signals for "do it yourself" attacks: the victim is talked into running,
approving or calling something, so there is no malware for a scanner to find.

Covered here (see docs/threat-catalog.md for how each works and the sources):

* **ClickFix / FileFix / macOS Terminal lures** (sandbox): a fake CAPTCHA or
  fake error puts a command on the clipboard and asks for Win + R / Win + X /
  File Explorer / Terminal, Ctrl + V, Enter.
* **AiTM phishing kits** (sandbox): Microsoft sign-in assets on a non-Microsoft
  host, a CAPTCHA gate in front of a sign-in form, anti-debugging, bot cloaking.
* **Tech-support scam pages, wallet drainers, notification spam** (sandbox).
* **Free hosting** (static + sandbox) and **open redirects** (static).
* **Device-code phishing, OAuth consent phishing, callback (TOAD) scams**
  (email text and link structure).
* **Hidden characters** in link text and display names (static).

Every builder is pure: it reads a parsed message, a URL or a
``DetonationResult`` and returns ``Signal`` objects. Plain-English copy for
each code lives in ``analysis.signal_copy``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import parse_qsl, unquote, urlsplit

from reddysec.chamber import lures as page_lures
from reddysec.models import DetonationResult, ExtractedUrl, ParsedMessage, Signal, SignalStage

from .common import is_freemail, make_signal, truncate
from .domains import brand_for_domain, legit_domains_for
from .intel import is_popular
from .redirects import HIDDEN_DESTINATION, OPEN_REDIRECT, free_hosting_match, unwrap_chain
from .urls import registrable_domain

# --------------------------------------------------------------------------- weights

CLICKFIX_WEIGHT = 100
CLIPBOARD_HIJACK_WEIGHT = 90
FAKE_CAPTCHA_WEIGHT = 40
TECH_SUPPORT_WEIGHT = 80
WALLET_DRAINER_WEIGHT = 85
NOTIFICATION_SPAM_WEIGHT = 25
AITM_PROXY_WEIGHT = 70
CAPTCHA_GATED_LOGIN_WEIGHT = 30
ANTI_ANALYSIS_WEIGHT = 25
UA_CLOAKING_WEIGHT = 20
FREE_HOSTING_WEIGHT = 12
FREE_HOSTING_LOGIN_WEIGHT = 60
OPEN_REDIRECT_WEIGHT = 20
HIDDEN_DESTINATION_WEIGHT = 10
DEVICE_CODE_WEIGHT = 70
OAUTH_CONSENT_WEIGHT = 50
CALLBACK_SCAM_WEIGHT = 45
CALLBACK_SCAM_FREEMAIL_WEIGHT = 55
HIDDEN_CHARS_LINK_WEIGHT = 20

# --------------------------------------------------------------------------- sandbox: ClickFix family


def clickfix_signals(url: str, result: DetonationResult) -> list[Signal]:
    """``dynamic.clickfix`` / ``dynamic.clipboard_hijack`` / ``dynamic.fake_captcha``.

    * clickfix (100): a dangerous command reached the clipboard and the page
      tells the reader where to paste it (or shows fake CAPTCHA steps), or the
      page prints a dangerous command next to Run-dialog steps inside a fake
      check / fake error.
    * clipboard_hijack (90): a dangerous command reached the clipboard with no
      instructions we could read (they may be in an image or a later step).
    * fake_captcha (40): a CAPTCHA-looking check with keyboard steps or a fake
      verification id, but no payload we could capture.

    A real CAPTCHA, or developer docs that show a PowerShell snippet with a
    Copy button, trigger none of these.
    """
    features = result.features
    if features is None:
        return []
    ev = {"url": url}
    clipboard = list(features.clipboard_writes)
    text = "\n".join(x for x in (features.instruction_excerpt, features.text_excerpt) if x)
    found = page_lures.analyse_page(text, clipboard)
    hits = set(features.instruction_hits) | set(found.hits)
    dangerous = [c for c in clipboard if page_lures.is_dangerous_command(c)]
    families: list[str] = []
    for entry in dangerous:
        families.extend(f for f in page_lures.command_families(entry) if f not in families)
    lure_steps = page_lures.lure_run_dialog(hits)  # Win+R / Win+X / Explorer bar / Cmd+Space
    instructions = features.clickfix_instructions or page_lures.clickfix_instructions(hits)
    fake_captcha = features.fake_captcha or found.fake_captcha
    lure_context = fake_captcha or bool(hits & {"fix_error", "verification_steps", "fake_verification_id", "ray_id"})
    sample = truncate(dangerous[0], 300) if dangerous else ""
    where = _paste_place(hits)

    # "Open PowerShell and paste" alone is how install docs read; it only
    # counts next to a fake check, a fake error or a decoy comment.
    if dangerous and (lure_steps or fake_captcha or "decoy_comment" in families or (instructions and lure_context)):
        return [
            make_signal(
                "dynamic.clickfix", SignalStage.DYNAMIC, CLICKFIX_WEIGHT,
                "The page tries to make you paste a command into Windows. This is a known hacking trick.",
                f"After a fake check, the page copied a hidden command and told the reader to paste it into {where}. "
                "Running it would install malware.",
                command=sample, families=families[:8], steps=sorted(hits)[:10], where=where,
                lure_clicks=features.lure_clicks[:3], **ev,
            )
        ]
    if found.shown_command and lure_context and instructions:
        return [
            make_signal(
                "dynamic.clickfix", SignalStage.DYNAMIC, CLICKFIX_WEIGHT,
                "The page tries to make you paste a command into Windows. This is a known hacking trick.",
                f"The page shows a command and tells the reader to paste it into {where} to 'fix' or 'verify' something.",
                steps=sorted(hits)[:10], where=where, shown_on_page=True, **ev,
            )
        ]
    if dangerous:
        return [
            make_signal(
                "dynamic.clipboard_hijack", SignalStage.DYNAMIC, CLIPBOARD_HIJACK_WEIGHT,
                "The page secretly copied a dangerous command to your clipboard",
                "If you pasted it anywhere that runs commands, it would install malware.",
                command=sample, families=families[:8], **ev,
            )
        ]
    if fake_captcha or (lure_steps and lure_context):
        return [
            make_signal(
                "dynamic.fake_captcha", SignalStage.DYNAMIC, FAKE_CAPTCHA_WEIGHT,
                "The page shows a fake 'I'm not a robot' check",
                "Real CAPTCHAs never ask you to press keys or paste anything.",
                steps=sorted(hits)[:10], **ev,
            )
        ]
    return []


def _paste_place(hits: set[str]) -> str:
    if hits & {"file_explorer", "address_bar", "ctrl_l"}:
        return "the File Explorer address bar"
    if hits & {"terminal_mac", "cmd_space"}:
        return "the Terminal"
    if "win_x" in hits or "powershell_open" in hits:
        return "PowerShell or Terminal"
    if hits & {"win_r", "run_dialog"}:
        return "the Windows Run box"
    return "your computer"


# --------------------------------------------------------------------------- sandbox: other scam pages

_WALLET_METHODS = frozenset(
    {"eth_requestaccounts", "wallet_requestpermissions", "eth_sendtransaction", "eth_sign", "personal_sign",
     "eth_signtypeddata", "eth_signtypeddata_v3", "eth_signtypeddata_v4", "wallet_switchethereumchain",
     "wallet_addethereumchain", "enable"}
)


def scam_page_signals(url: str, result: DetonationResult, final_host: str, final_popular: bool) -> list[Signal]:
    """Tech-support scams, wallet drainers and push-notification spam."""
    features = result.features
    if features is None:
        return []
    signals: list[Signal] = []
    ev = {"url": url, "final_host": final_host or None}
    text = f"{features.title or ''}\n{features.text_excerpt}\n{features.instruction_excerpt}"

    support = page_lures.tech_support_hits(text)
    phones = features.phone_numbers or page_lures.phone_numbers(text)
    locking = sum([features.fullscreen_requested, features.keyboard_lock, features.dialog_count >= 2, features.beforeunload_trap])
    if support and phones and (locking >= 1 or len(support) >= 2) and not final_popular:
        signals.append(
            make_signal(
                "dynamic.tech_support_scam", SignalStage.DYNAMIC, TECH_SUPPORT_WEIGHT,
                "The page is a fake virus warning that tells you to call 'support'",
                "It tries to lock the screen and scare you into calling a scammer's phone number.",
                phones=phones[:3], phrases=support[:5], fullscreen=features.fullscreen_requested,
                keyboard_lock=features.keyboard_lock, dialogs=features.dialog_count, **ev,
            )
        )

    wallet_text = page_lures.wallet_hits(text)
    methods = [m for m in features.wallet_requests if m.lower() in _WALLET_METHODS]
    seed = features.seed_phrase_inputs > 0 and (page_lures.seed_phrase_text(text) or bool(wallet_text))
    if not final_popular and (seed or (methods and wallet_text)):
        signals.append(
            make_signal(
                "dynamic.wallet_drainer", SignalStage.DYNAMIC, WALLET_DRAINER_WEIGHT,
                "The page tries to empty a crypto wallet",
                "It asks to connect a wallet or for a recovery phrase. Anyone with that phrase owns the money.",
                wallet_methods=methods[:5], seed_phrase_inputs=features.seed_phrase_inputs, phrases=wallet_text[:5], **ev,
            )
        )

    if features.notification_permission_requested and not final_popular:
        signals.append(
            make_signal(
                "dynamic.notification_spam", SignalStage.DYNAMIC, NOTIFICATION_SPAM_WEIGHT,
                "The page asks to send you notifications",
                "Scam sites use 'Allow' to flood your screen with fake virus alerts and ads.", **ev,
            )
        )
    return signals


# --------------------------------------------------------------------------- sandbox: phishing-kit tells

# Microsoft sign-in assets. A page that loads them (or proxies their paths)
# while living on another domain is a reverse proxy (Evilginx, Tycoon 2FA,
# EvilProxy...) or a kit that copied the real page.
_MS_ASSET_HOSTS = ("aadcdn.msftauth.net", "aadcdn.msauth.net", "logincdn.msauth.net", "aadcdn.msftauthimages.net",
                   "login.microsoftonline.com", "login.live.com", "acctcdn.msauth.net")
_MS_ASSET_PATHS = ("/shared/1.0/content/", "convergedlogin", "/aadcdn/", "/ests/2.1/content/")
_OKTA_ASSET_HOSTS = ("ok1static.oktacdn.com", "ok2static.oktacdn.com", "ok3static.oktacdn.com", "ok4static.oktacdn.com")
_STRONG_CAPTCHA = frozenset({"turnstile", "hcaptcha"})


def _brand_assets(result: DetonationResult, final_rd: str) -> tuple[str | None, list[str]]:
    """(brand whose sign-in assets the page loads from elsewhere, sample URLs)."""
    ms: list[str] = []
    okta: list[str] = []
    for r in result.requests:
        host = (r.host or "").lower()
        low = r.url.lower()
        if registrable_domain(host) == final_rd and not any(p in low for p in _MS_ASSET_PATHS):
            continue
        if host in _MS_ASSET_HOSTS or any(p in urlsplit(low).path for p in _MS_ASSET_PATHS):
            ms.append(r.url[:200])
        elif host in _OKTA_ASSET_HOSTS:
            okta.append(r.url[:200])
    if ms:
        return "microsoft", ms[:3]
    if okta:
        return "okta", okta[:3]
    return None, []


def kit_signals(
    url: str,
    result: DetonationResult,
    *,
    final_host: str,
    final_rd: str,
    final_popular: bool,
    page_brands: Iterable[str] = (),
) -> list[Signal]:
    """AiTM proxy assets, CAPTCHA-gated sign-in, anti-debugging, bot cloaking, free hosting."""
    features = result.features
    if features is None:
        return []
    signals: list[Signal] = []
    ev = {"url": url, "final_host": final_host or None}
    login = features.has_password_field or any(f.has_password or f.has_identity_field for f in features.forms)

    brand, samples = _brand_assets(result, final_rd)
    if brand and login and final_rd not in legit_domains_for(brand) and brand_for_domain(final_rd) != brand:
        signals.append(
            make_signal(
                "dynamic.aitm_proxy", SignalStage.DYNAMIC, AITM_PROXY_WEIGHT,
                f"The page copies the real {brand.title()} sign-in page from another website",
                "This is how kits that steal passwords and the one-time codes that protect them work.",
                brand=brand, assets=samples, **ev,
            )
        )

    providers = set(features.captcha_providers)
    gate = bool(providers & _STRONG_CAPTCHA) or (features.captcha_detected and "recaptcha" not in providers)
    if gate and login and not final_popular:
        signals.append(
            make_signal(
                "dynamic.captcha_gated_login", SignalStage.DYNAMIC, CAPTCHA_GATED_LOGIN_WEIGHT,
                "A 'verify you are human' check stands in front of a sign-in form",
                "Phishing kits do this so security scanners never see the fake sign-in page.",
                providers=sorted(providers), **ev,
            )
        )

    if features.anti_debug or features.console_clear_count >= 5:
        signals.append(
            make_signal(
                "dynamic.anti_analysis", SignalStage.DYNAMIC, ANTI_ANALYSIS_WEIGHT,
                "The page tries to stop security tools from inspecting it",
                console_clears=features.console_clear_count, **ev,
            )
        )
    if features.ua_cloaking:
        signals.append(
            make_signal(
                "dynamic.ua_cloaking", SignalStage.DYNAMIC, UA_CLOAKING_WEIGHT,
                "The page shows security scanners something different from people", **ev,
            )
        )

    hosting = free_hosting_match(features.final_url or url) if final_host else None
    brands = [b for b in page_brands if b]
    if hosting and (login or brands):
        signals.append(
            make_signal(
                "dynamic.free_hosting_login", SignalStage.DYNAMIC, FREE_HOSTING_LOGIN_WEIGHT,
                f"A sign-in page or brand page on a free hosting service ({hosting})",
                "Real companies do not ask you to sign in on free website builders.",
                hosting=hosting, brand=brands[0] if brands else None, **ev,
            )
        )
    if features.text_excerpt and device_code_lure(features.text_excerpt):
        signals.append(_device_code_signal("dynamic.device_code_lure", SignalStage.DYNAMIC, features.text_excerpt, **ev))
    return signals


# --------------------------------------------------------------------------- static: link structure


def redirect_signals(url: ExtractedUrl) -> list[Signal]:
    """``url.open_redirect``: the link starts on a trusted site's redirector."""
    chain = unwrap_chain(url.raw) if url.raw else []
    abused = [h for h in chain if h.kind in {OPEN_REDIRECT, HIDDEN_DESTINATION}]
    if not abused:
        return []
    final = chain[-1].url
    final_rd = registrable_domain(urlsplit(final).hostname or "")
    hidden = chain[-1].kind == HIDDEN_DESTINATION
    if not hidden and is_popular(final_rd):
        return []  # google.com/url -> youtube.com is ordinary
    via = abused[0].via or (urlsplit(abused[0].url).hostname or "")
    return [
        make_signal(
            "url.open_redirect", SignalStage.STATIC, HIDDEN_DESTINATION_WEIGHT if hidden else OPEN_REDIRECT_WEIGHT,
            f"Link starts on {via} but forwards you somewhere else"
            + ("" if hidden else f" ({final_rd})"),
            "Scammers start links on a trusted name so they look safe.",
            via=via, chain=[h.url[:300] for h in chain][:6], hidden_destination=hidden, url=url.normalized,
        )
    ]


def free_hosting_signals(url: ExtractedUrl) -> list[Signal]:
    hosting = free_hosting_match(url.normalized)
    if not hosting:
        return []
    return [
        make_signal(
            "url.free_hosting", SignalStage.STATIC, FREE_HOSTING_WEIGHT,
            f"Link goes to a free website service ({hosting})",
            "Anyone can make a page there in minutes. Real companies rarely send you to one.",
            hosting=hosting, url=url.normalized,
        )
    ]


# OAuth authorize endpoints and the scopes that hand over a mailbox or files.
_OAUTH_ENDPOINTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("login.microsoftonline.com", re.compile(r"/oauth2/(?:v2\.0/)?authorize", re.I)),
    ("login.live.com", re.compile(r"/oauth20_authorize\.srf", re.I)),
    ("accounts.google.com", re.compile(r"/o/oauth2/(?:v2/)?auth|/signin/oauth", re.I)),
    ("github.com", re.compile(r"/login/oauth/authorize", re.I)),
    ("www.dropbox.com", re.compile(r"/oauth2/authorize", re.I)),
)
_BROAD_SCOPES = re.compile(
    r"mail\.readwrite|mail\.read\b|mail\.send|mailboxsettings\.readwrite|files\.readwrite(?:\.all)?|files\.read\.all|"
    r"sites\.readwrite\.all|contacts\.read|user\.readwrite\.all|directory\.|full_access_as_user|ews\.accessasuser\.all|"
    r"offline_access|https://mail\.google\.com/|gmail\.(?:modify|readonly|send|compose|insert)|"
    r"auth/drive\b(?!\.file)|auth/drive\.readonly|auth/contacts|\brepo\b|admin:org|delete_repo",
    re.I,
)


def oauth_consent_signals(url: ExtractedUrl) -> list[Signal]:
    """``url.oauth_consent_lure``: a link straight to an "allow this app to read
    your mail" screen, or an authorize URL that bounces to an unknown site."""
    try:
        parts = urlsplit(url.normalized)
    except ValueError:
        return []
    host = (parts.hostname or "").lower()
    if not any(host == h and p.search(parts.path or "") for h, p in _OAUTH_ENDPOINTS):
        return []
    params = {k.lower(): unquote(v) for k, v in parse_qsl(parts.query, keep_blank_values=True)}
    if not params.get("client_id"):
        return []
    scopes = sorted({m.group(0).lower() for m in _BROAD_SCOPES.finditer(params.get("scope", ""))})
    redirect = params.get("redirect_uri", "")
    redirect_rd = registrable_domain(urlsplit(redirect).hostname or "") if redirect else ""
    odd_redirect = bool(redirect_rd) and not is_popular(redirect_rd) and redirect_rd != registrable_domain(host)
    if not scopes and not odd_redirect:
        return []
    detail = (
        "Clicking 'Accept' would let an unknown app read your email or files, even after you change your password."
        if scopes else
        "The link starts on a real sign-in site but is set up to send you on to an unknown website."
    )
    return [
        make_signal(
            "url.oauth_consent_lure", SignalStage.STATIC, OAUTH_CONSENT_WEIGHT,
            "Link asks you to give an app access to your account",
            detail, scopes=scopes[:8], client_id=params.get("client_id", "")[:80],
            redirect_domain=redirect_rd or None, url=url.normalized,
        )
    ]


_ZERO_WIDTH_RE = re.compile("[​‌‍⁠﻿­᠎]")
_BIDI_RE = re.compile("[‪-‮⁦-⁩‎‏]")


def hidden_characters(text: str | None) -> list[str]:
    """Names of invisible / direction-changing characters in ``text``."""
    if not text:
        return []
    found: list[str] = []
    if _ZERO_WIDTH_RE.search(text):
        found.append("zero-width")
    if _BIDI_RE.search(text):
        found.append("right-to-left")
    return found


def link_text_signals(url: ExtractedUrl) -> list[Signal]:
    kinds = hidden_characters(url.display_text)
    if not kinds:
        return []
    return [
        make_signal(
            "url.hidden_characters", SignalStage.STATIC, HIDDEN_CHARS_LINK_WEIGHT,
            "Link text hides invisible characters",
            "Invisible characters break up words so filters cannot read them; real companies do not need them.",
            kinds=kinds, url=url.normalized,
        )
    ]


# --------------------------------------------------------------------------- email text

_DEVICE_URL_RE = re.compile(
    r"(?:https?://)?(?:www\.)?(?:microsoft\.com/devicelogin|aka\.ms/devicelogin|login\.microsoft(?:online)?\.com/"
    r"(?:common/oauth2/deviceauth|device)|microsoft\.com/link\b|google\.com/device|github\.com/login/device)",
    re.I,
)
_DEVICE_CODE_RE = re.compile(r"\b(?=[A-Z0-9-]*\d)(?=[A-Z0-9-]*[A-Z])[A-Z0-9]{3,5}(?:-[A-Z0-9]{3,5}){1,2}\b|\b(?=[A-Z0-9]*\d)(?=[A-Z0-9]*[A-Z])[A-Z0-9]{8,9}\b")
_CODE_WORD_RE = re.compile(r"\b(?:code|meeting id|pin|enter)\b", re.I)


def device_code_lure(text: str) -> bool:
    """A device sign-in address next to a short code to type there."""
    if not text:
        return False
    for m in _DEVICE_URL_RE.finditer(text):
        window = text[max(0, m.start() - 300): m.end() + 300]
        if _DEVICE_CODE_RE.search(window) and _CODE_WORD_RE.search(window):
            return True
    return False


def _device_code_signal(code: str, stage: SignalStage, text: str, **ev: object) -> Signal:
    m = _DEVICE_URL_RE.search(text)
    return make_signal(
        code, stage, DEVICE_CODE_WEIGHT,
        "Asks you to type a code on a Microsoft or Google sign-in page",
        "Typing someone else's code there signs THEM in to your account. No real meeting or document needs this.",
        site=m.group(0) if m else None, **ev,
    )


_RENEWAL_RE = re.compile(
    r"\b(?:auto[- ]?renew(?:al|ed)?|renew(?:al|ed)|subscription|membership|has been (?:charged|debited|deducted|processed)|"
    r"(?:order|invoice|receipt|transaction) (?:id|number|no\.?|#)|annual plan|amount (?:charged|debited)|"
    r"geek ?squad|norton|mcafee|antivirus|paypal|coinbase|best ?buy)\b",
    re.I,
)
_CALL_RE = re.compile(
    r"\b(?:call|dial|phone|contact (?:us|our)|reach (?:us|our)|helpline|toll[- ]free|billing (?:department|team|support)|"
    r"customer (?:care|support|service))\b",
    re.I,
)
_CANCEL_RE = re.compile(r"\b(?:cancel|refund|dispute|did ?n[o']t (?:authori[sz]e|make|order|recogni[sz]e)|not authori[sz]ed|unauthori[sz]ed|stop (?:the )?(?:payment|renewal))\b", re.I)


def email_lure_signals(parsed: ParsedMessage, body: str) -> list[Signal]:
    """Device-code lures and callback (TOAD) scams in the email itself."""
    signals: list[Signal] = []
    text = f"{parsed.subject}\n{body}"
    if device_code_lure(text):
        signals.append(_device_code_signal("bec.device_code_lure", SignalStage.BEC, text))
    phones = page_lures.phone_numbers(text)
    if phones and _RENEWAL_RE.search(text) and _CALL_RE.search(text) and _CANCEL_RE.search(text) and len(parsed.urls) <= 1:
        freemail = is_freemail(parsed.from_domain)
        signals.append(
            make_signal(
                "bec.callback_scam", SignalStage.BEC, CALLBACK_SCAM_FREEMAIL_WEIGHT if freemail else CALLBACK_SCAM_WEIGHT,
                "A fake bill that wants you to call a phone number",
                "Scammers send fake renewals or charges so you call them. On the phone they take your card or your computer.",
                phones=phones[:3], freemail=freemail,
            )
        )
    return signals

"""Recognise "do it yourself" malware lures in page text and clipboard data.

ClickFix (and its FileFix / macOS Terminal cousins) is the trick behind most
"I'm not a robot" pages in 2025-2026: a fake CAPTCHA or a fake error asks the
visitor to press Windows + R (or Win + X, or open File Explorer / Terminal),
paste with Ctrl + V and press Enter. The page has already put a command on
the clipboard. The victim runs malware by hand, so no download warning, no
attachment scanner and no browser exploit is ever involved.

This module is pure and dependency-free (``re`` only) because it runs in two
places: inside the sandbox (``chamber.detonate`` fills ``PageFeatures``
booleans with it) and on the host (``analysis.lures`` turns those features
into signals). Nothing here touches the network.

Design rules:

* **A command on the page is not a crime.** Developer docs show PowerShell all
  the time. ClickFix needs *both* a dangerous command (on the clipboard, or
  shown for copying) *and* instructions that tell a non-technical reader where
  to paste it (Run dialog, Explorer address bar, Terminal).
* **A CAPTCHA is not a crime.** Real CAPTCHAs are served by Google, hCaptcha,
  Cloudflare and friends. A "CAPTCHA" is only *fake* when it comes with
  keyboard / paste steps or with the tell-tale fake "Verification ID".

Sources for the patterns: docs/threat-catalog.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

CLIPBOARD_MAX_CHARS = 2000
MAX_CLIPBOARD_WRITES = 10
INSTRUCTION_EXCERPT_MAX = 1000

# --------------------------------------------------------------------------- clipboard payloads

# (family, pattern). Families are stable strings used in evidence and tests.
_COMMAND_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("powershell", re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b", re.I)),
    ("powershell_encoded", re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,200}?\s[-/]e(?:nc(?:odedcommand)?|c)?\s+[A-Za-z0-9+/=]{16,}", re.I)),
    ("powershell_hidden", re.compile(r"\s[-/]w(?:indowstyle)?\s+(?:h(?:idden)?|1|min(?:imized)?)\b", re.I)),
    ("download_cradle", re.compile(
        r"\b(?:iex|invoke-expression|iwr|invoke-webrequest|irm|invoke-restmethod|downloadstring|downloadfile|"
        r"net\.webclient|start-bitstransfer|frombase64string)\b", re.I)),
    ("mshta", re.compile(r"\bmshta(?:\.exe)?\b", re.I)),
    ("cmd", re.compile(r"\bcmd(?:\.exe)?\s+/[ck]\b", re.I)),
    ("rundll32", re.compile(r"\brundll32(?:\.exe)?\b", re.I)),
    ("regsvr32", re.compile(r"\bregsvr32(?:\.exe)?\b", re.I)),
    ("msiexec_remote", re.compile(r"\bmsiexec(?:\.exe)?\b[^\n]{0,80}?/(?:i|package|q)\b[^\n]{0,40}?(?:https?://|\\\\)", re.I)),
    ("msiexec", re.compile(r"\bmsiexec(?:\.exe)?\b", re.I)),
    ("certutil", re.compile(r"\bcertutil(?:\.exe)?\b[^\n]{0,80}?(?:-urlcache|-decode|-f\b)", re.I)),
    ("bitsadmin", re.compile(r"\bbitsadmin(?:\.exe)?\b[^\n]{0,40}?/transfer", re.I)),
    ("wscript", re.compile(r"\b(?:wscript|cscript)(?:\.exe)?\b", re.I)),
    ("conhost", re.compile(r"\bconhost(?:\.exe)?\b[^\n]{0,40}?--headless", re.I)),
    ("finger", re.compile(r"\bfinger(?:\.exe)?\s+\S+@\S+", re.I)),
    ("nslookup", re.compile(r"\bnslookup\b[^\n]{0,120}?\|\s*(?:findstr|iex|cmd|powershell)", re.I)),
    ("curl_pipe_shell", re.compile(
        r"\b(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|"
        r"\b(?:ba|z)?sh\s+-c\s+[\"']?\$\(\s*(?:curl|wget)\b", re.I)),
    ("curl_download_exec", re.compile(r"\b(?:curl|wget)\b[^\n]{0,300}?(?:&&|;)\s*(?:chmod\s+\+x|sudo|bash|sh|open|\./)", re.I)),
    ("shell_base64", re.compile(r"\bbase64\s+(?:-d|--decode|-D)\b[^\n]{0,80}?\|\s*(?:ba|z)?sh\b", re.I)),
    ("osascript", re.compile(r"\bosascript\b", re.I)),
    ("xattr_quarantine", re.compile(r"\bxattr\s+-[a-z]*[cd]\b", re.I)),
    ("explorer_search_ms", re.compile(r"\bsearch-ms:|\bsearch:query=", re.I)),
)
_BASE64_BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/])")
# The fake "comment" ClickFix/FileFix appends so the Run box / address bar only
# shows something reassuring: ``... # I am not a robot - reCAPTCHA Verification ID: 7516``.
_DECOY_COMMENT_RE = re.compile(
    r"(?:#|::|rem\s|REM\s|//)[^\n]{0,80}?(?:not a robot|human|captcha|verification|verify|verified|ray id|"
    r"cloudflare|\.pdf|\.docx?|\\\\|c:\\\\)",
    re.I,
)
# Families that on their own mean "this runs code or fetches a payload".
DANGEROUS_FAMILIES: frozenset[str] = frozenset(
    {"powershell_encoded", "download_cradle", "mshta", "rundll32", "regsvr32", "msiexec_remote", "certutil",
     "bitsadmin", "conhost", "finger", "nslookup", "curl_pipe_shell", "curl_download_exec", "shell_base64",
     "osascript", "xattr_quarantine"}
)
# Families that are dangerous when they appear together with anything else.
WEAK_FAMILIES: frozenset[str] = frozenset({"powershell", "powershell_hidden", "cmd", "wscript", "msiexec", "explorer_search_ms", "base64_blob", "decoy_comment"})


def command_families(text: str) -> list[str]:
    """Which command families appear in ``text`` (clipboard content or page text)."""
    if not text:
        return []
    sample = text[:CLIPBOARD_MAX_CHARS * 2]
    found = [name for name, pattern in _COMMAND_PATTERNS if pattern.search(sample)]
    if _BASE64_BLOB_RE.search(sample):
        found.append("base64_blob")
    if _DECOY_COMMENT_RE.search(sample) and found:
        found.append("decoy_comment")
    return found


def is_dangerous_command(text: str) -> bool:
    """True when ``text`` would run code or fetch a payload if pasted into a
    Run dialog, an Explorer address bar or a terminal."""
    families = set(command_families(text))
    if families & DANGEROUS_FAMILIES:
        return True
    shells = families & {"powershell", "cmd", "wscript", "msiexec"}
    if not shells:
        return False
    # "powershell -w hidden ...", "cmd /c ... # I am not a robot", "powershell <base64>",
    # "cmd /c powershell ...": a shell plus something that hides what it does.
    return bool(families & {"powershell_hidden", "base64_blob", "decoy_comment"}) or len(shells) > 1


# --------------------------------------------------------------------------- instructions

# key -> pattern. Keys are stable (evidence, tests, copy).
_INSTRUCTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("win_r", re.compile(r"(?:\bwin(?:dows)?\b|[\u229e\u2756\U0001fa9f])[^\n+&]{0,30}?(?:\+|\band\b|&|plus)\s*[\"'\[(]?\s*R\b", re.I)),
    ("win_x", re.compile(r"(?:\bwin(?:dows)?\b|[\u229e\u2756\U0001fa9f])[^\n+&]{0,30}?(?:\+|\band\b|&|plus)\s*[\"'\[(]?\s*X\b", re.I)),
    ("run_dialog", re.compile(r"\b(?:run (?:dialog|box|window|command)|open (?:the )?run\b|windows run)", re.I)),
    ("powershell_open", re.compile(r"\b(?:open|launch|start)\s+(?:windows\s+)?(?:powershell|terminal|command prompt|cmd)\b|\bterminal \(admin\)|\bwindows powershell \(admin\)", re.I)),
    ("ctrl_v", re.compile(r"\b(?:ctrl|control|cmd|command|⌘)\s*(?:\+|and|&|-)?\s*(?:\[|\")?\s*V\b", re.I)),
    ("paste", re.compile(r"\b(?:paste|right[- ]click to paste)\b", re.I)),
    ("press_enter", re.compile(r"\b(?:press|hit|tap)\s+(?:the\s+)?(?:enter|return)\b|\benter\s+key\b", re.I)),
    ("file_explorer", re.compile(r"\b(?:file explorer|windows explorer|explorer\.exe|open explorer)\b", re.I)),
    ("address_bar", re.compile(r"\b(?:address bar|location bar|path bar)\b", re.I)),
    ("ctrl_l", re.compile(r"\b(?:ctrl|control)\s*(?:\+|and|&)?\s*L\b", re.I)),
    ("terminal_mac", re.compile(r"\b(?:open\s+(?:the\s+)?terminal(?:\s+app)?|terminal\.app|applications\s*/\s*utilities)\b", re.I)),
    ("cmd_space", re.compile(r"(?:\b(?:cmd|command)|⌘)\s*(?:\+|and|&)?\s*space\b", re.I)),
    ("verification_steps", re.compile(r"\b(?:verification steps|verify(?:ing)? (?:you are|you're) (?:a )?human|complete (?:the|these) (?:verification )?steps|to prove you are (?:not a robot|human)|follow (?:these|the) steps)\b", re.I)),
    ("fake_verification_id", re.compile(r"\b(?:recaptcha|captcha|cloudflare|human)\s+verification\s+(?:id|code|hash)\b|\bverification id\s*[:#]\s*\w+", re.I)),
    ("ray_id", re.compile(r"\bray id\s*[:#]?\s*[0-9a-f]{6,}", re.I)),
    ("fix_error", re.compile(r"\b(?:how to fix|fix it|fix the (?:issue|error|problem)|to fix this|font (?:is )?(?:missing|not found)|update (?:the |your )?root certificate|(?:browser|chrome) update (?:required|failed)|word online extension|aw,? snap)\b", re.I)),
)
_CAPTCHA_TEXT_RE = re.compile(
    r"\b(?:i'?m not a robot|i am not a robot|i am human|i'?m human|verify (?:that )?you are (?:a )?human|"
    r"are you (?:a )?(?:robot|human)|captcha|human verification|bot verification|security check|"
    r"checking (?:if the site connection is secure|your browser)|press (?:and|&) hold)\b",
    re.I,
)
# Where-to-paste and paste-action keys (see :func:`run_dialog_lure`).
_PLACE_KEYS = frozenset({"win_r", "win_x", "run_dialog", "powershell_open", "terminal_mac", "cmd_space"})
_EXPLORER_KEYS = frozenset({"file_explorer", "address_bar", "ctrl_l"})
_PASTE_KEYS = frozenset({"ctrl_v", "paste"})


def instruction_hits(text: str) -> list[str]:
    """Which lure instructions appear in ``text`` (stable keys, in table order)."""
    if not text:
        return []
    return [key for key, pattern in _INSTRUCTION_PATTERNS if pattern.search(text)]


def captcha_text(text: str) -> bool:
    return bool(text) and _CAPTCHA_TEXT_RE.search(text) is not None


def run_dialog_lure(hits: list[str] | set[str]) -> bool:
    """Instructions name a place to paste AND a paste action: the ClickFix /
    FileFix / Terminal recipe ("Win + R, then Ctrl + V, then Enter")."""
    hit = set(hits)
    place = bool(hit & _PLACE_KEYS) or ("file_explorer" in hit and bool(hit & {"address_bar", "ctrl_l"}))
    return place and bool(hit & _PASTE_KEYS)


# Places only a lure sends a non-technical reader: the Run box, the Win + X
# menu, the Explorer address bar, Spotlight -> Terminal. "Open PowerShell and
# paste" is also how real install docs read, so it is not on this list.
_LURE_PLACE_KEYS = frozenset({"win_r", "win_x", "run_dialog", "cmd_space"})


def lure_run_dialog(hits: list[str] | set[str]) -> bool:
    """The ClickFix / FileFix recipe with a place real documentation never
    uses: Win + R / Win + X / Run box / Explorer address bar / Cmd + Space,
    plus paste or Enter."""
    hit = set(hits)
    place = bool(hit & _LURE_PLACE_KEYS) or ("file_explorer" in hit and bool(hit & {"address_bar", "ctrl_l"}))
    return place and bool(hit & (_PASTE_KEYS | {"press_enter"}))


def clickfix_instructions(hits: list[str] | set[str]) -> bool:
    """Weaker than :func:`run_dialog_lure`: keyboard/paste steps of any kind."""
    hit = set(hits)
    return run_dialog_lure(hit) or (bool(hit & (_PLACE_KEYS | _EXPLORER_KEYS)) and bool(hit & ({"press_enter"} | _PASTE_KEYS)))


def is_fake_captcha(text: str, hits: list[str] | set[str], *, clipboard_dangerous: bool = False) -> bool:
    """A CAPTCHA-looking check that asks for keyboard steps, shows a fake
    verification id, or put a command on the clipboard. Real CAPTCHAs do none
    of these, so a genuine reCAPTCHA / Turnstile page is never "fake"."""
    hit = set(hits)
    if not (captcha_text(text) or "fake_verification_id" in hit):
        return False
    return (
        clipboard_dangerous
        or "fake_verification_id" in hit
        or clickfix_instructions(hit)
        or ("verification_steps" in hit and bool(hit & (_PLACE_KEYS | _PASTE_KEYS | {"press_enter"})))
    )


def instruction_excerpt(text: str, limit: int = INSTRUCTION_EXCERPT_MAX) -> str:
    """The lines of ``text`` that carry lure instructions, for the report."""
    out: list[str] = []
    size = 0
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or len(line) > 400:
            continue
        if instruction_hits(line) or captcha_text(line):
            out.append(line)
            size += len(line) + 1
            if size >= limit:
                break
    return "\n".join(out)[:limit]


# --------------------------------------------------------------------------- other scam pages

_TECH_SUPPORT_RE = re.compile(
    r"\b(?:call (?:microsoft|apple|windows|technical|tech|customer)?\s*(?:support|help ?desk|helpline|technician)|"
    r"(?:microsoft|windows|apple|mac) (?:support|security|defender)\s*(?:center|team|helpline)?\s*(?:toll[- ]free)?\s*[:\-]?\s*\+?\(?\d|"
    r"your (?:computer|pc|system|device|mac|iphone) (?:has been|is) (?:locked|blocked|infected|compromised)|"
    r"(?:virus|spyware|trojan|malware|pornographic spyware) (?:detected|alert|found)|"
    r"(?:access to this pc|windows) (?:has been|is) blocked|do not (?:restart|shut down|turn off) your (?:computer|pc)|"
    r"error code\s*[:#]?\s*0x[0-9a-f]{4,}|toll[- ]free)\b",
    re.I,
)
PHONE_RE = re.compile(r"(?<![\w+])(?:\+?1[\s.-]?)?\(?\b[2-9]\d{2}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b|\+\d{1,3}[\s.-]?\d{2,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b")
_WALLET_TEXT_RE = re.compile(
    r"\b(?:connect (?:your )?wallet|wallet ?connect|metamask|trust ?wallet|phantom wallet|claim (?:your )?(?:airdrop|tokens?|rewards?|nft)|"
    r"seed phrase|secret recovery phrase|recovery phrase|mnemonic phrase|private key|eligible for (?:the )?airdrop)\b",
    re.I,
)
_SEED_TEXT_RE = re.compile(r"\b(?:seed phrase|secret recovery phrase|recovery phrase|mnemonic|12[- ]word|24[- ]word|private key)\b", re.I)


def tech_support_hits(text: str) -> list[str]:
    return sorted({m.group(0).lower()[:60] for m in _TECH_SUPPORT_RE.finditer(text or "")})[:8]


def wallet_hits(text: str) -> list[str]:
    return sorted({m.group(0).lower() for m in _WALLET_TEXT_RE.finditer(text or "")})[:8]


def seed_phrase_text(text: str) -> bool:
    return bool(text) and _SEED_TEXT_RE.search(text) is not None


def phone_numbers(text: str, limit: int = 5) -> list[str]:
    out: list[str] = []
    for m in PHONE_RE.finditer(text or ""):
        number = m.group(0).strip()
        if len(re.sub(r"\D", "", number)) < 10 or number in out:
            continue
        out.append(number)
        if len(out) >= limit:
            break
    return out


# --------------------------------------------------------------------------- anti-analysis

_ANTI_DEBUG_RE = re.compile(
    r"(?:setInterval|setTimeout|while\s*\(\s*(?:true|1|!0)\s*\))[^;]{0,200}?\bdebugger\b|"
    r"\bdebugger\b[^;]{0,40}?(?:setInterval|setTimeout)|"
    r"(?:outerWidth|outerHeight)\s*-\s*(?:window\.)?inner(?:Width|Height)\s*>\s*\d{2,}|"
    r"\bdevtools(?:Detector|-detect|open|Open|\.isOpen)|"
    r"\bconstructor\s*\(\s*['\"]debugger['\"]\s*\)|"
    r"(?:keyCode|which)\s*===?\s*123\b|['\"]F12['\"]",
)
_BOT_CHECK_RE = re.compile(
    r"navigator\.webdriver|HeadlessChrome|phantom|_phantom|callPhantom|__nightmare|selenium|puppeteer|"
    r"navigator\.plugins\.length\s*===?\s*0|navigator\.languages\.length\s*===?\s*0",
    re.I,
)
_LOCATION_CHANGE_RE = re.compile(r"(?:window\.|document\.|top\.)?location(?:\.href)?\s*=|location\.(?:replace|assign)\s*\(", re.I)


def anti_debug_script(scripts: list[str]) -> bool:
    return any(_ANTI_DEBUG_RE.search(s or "") for s in scripts)


def ua_cloaking_script(scripts: list[str]) -> bool:
    """A script that checks for automation and changes location: shows bots
    one page and people another."""
    for s in scripts:
        if s and _BOT_CHECK_RE.search(s) and _LOCATION_CHANGE_RE.search(s):
            return True
    return False


# --------------------------------------------------------------------------- one-shot summary


@dataclass
class LureFindings:
    """Everything this module can say about one page."""

    hits: list[str] = field(default_factory=list)
    clipboard_dangerous: bool = False
    clipboard_families: list[str] = field(default_factory=list)
    run_dialog_lure: bool = False
    clickfix_instructions: bool = False
    fake_captcha: bool = False
    shown_command: bool = False  # a dangerous command is printed on the page for copying
    excerpt: str = ""


def analyse_page(text: str, clipboard: list[str] | None = None) -> LureFindings:
    clipboard = clipboard or []
    hits = instruction_hits(text)
    families: list[str] = []
    for entry in clipboard:
        for fam in command_families(entry):
            if fam not in families:
                families.append(fam)
    dangerous = any(is_dangerous_command(entry) for entry in clipboard)
    shown = False
    if text and clickfix_instructions(hits):
        shown = any(is_dangerous_command(line) for line in text.splitlines() if 8 <= len(line) <= 3000)
    return LureFindings(
        hits=hits,
        clipboard_dangerous=dangerous,
        clipboard_families=families,
        run_dialog_lure=run_dialog_lure(hits),
        clickfix_instructions=clickfix_instructions(hits),
        fake_captcha=is_fake_captcha(text, hits, clipboard_dangerous=dangerous),
        shown_command=shown,
        excerpt=instruction_excerpt(text) if hits else "",
    )

"""The code that runs *inside* the sandbox: open one URL or file in a fresh
Chromium, watch everything it does, and write down what we saw.

Nothing here knows about mailboxes, clients or the artifact store. The input
is a ``DetonationJob``; the output is a ``DetonationResult`` plus files in a
scratch directory (``screenshot.jpg``, ``dl_<n>.bin``) referenced with
``file:`` refs (see ``protocol``). Backends decide how the scratch directory
gets back to the host.

Design points worth knowing before changing this file:

* **Partial results beat no results.** Every observation goes straight into a
  ``_Collector`` as it happens, so when the deadline cancels the run or
  Playwright throws, whatever was gathered up to that point is still returned
  (status TIMEOUT / ERROR). The analyst sees a half-loaded phishing page
  rather than "error".
* **Look like a person.** Headless Chromium advertises itself ("HeadlessChrome",
  ``navigator.webdriver``). We disable the automation flag, send a current
  desktop UA, use the job's locale/timezone/viewport and, if asked, move the
  mouse and scroll before reading the page. Kits that cloak to bots show us
  the real page more often this way.
* **Observe without touching the network path.** Request interception would
  change timing and headers, so for URL jobs we only *listen*. FILE jobs are
  the exception: the file is opened from ``file://`` and every non-file
  request is aborted, so an HTML attachment cannot phone home from here.
* **Meta refresh detection** uses an init script that runs before any page
  script and reports ``<meta http-equiv=refresh>`` through a private console
  channel. Reading the response body after the fact does not work: a 0-second
  refresh has already navigated away by then.

What is *not* detonated here: Office documents, archives, executables and
scripts. They are recorded (type, hash) but opening them safely needs a
Windows chamber with Office installed, which is future work. CDR (``cdr``)
still produces a safe PDF for the viewable ones.

CLI (what the backends invoke)::

    python -m reddysec.chamber.detonate --job job.json --out result.json --workdir DIR
    python -m reddysec.chamber.detonate --stdio                 # Docker: envelope in, envelope out
    python -m reddysec.chamber.detonate --env                   # ACI: RS_JOB env var in, envelope on stdout
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import html
import json
import os
import re
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reddysec.models import (
    DetonationJob,
    DetonationKind,
    DetonationResult,
    DetonationStatus,
    DownloadRecord,
    FormRecord,
    NetworkRequest,
    PageFeatures,
    RedirectHop,
)

from . import lures
from .common import (
    BROWSER_VIEWABLE_TYPES,
    extension_of,
    find_brand_keywords,
    host_of,
    is_image_type,
    is_third_party,
    refine_download_type,
    registrable_domain,
    safe_filename,
    sniff_type,
    user_agent_for,
)
from .protocol import (
    SCREENSHOT_NAME,
    SandboxOutput,
    decode_job_envelope,
    encode_result_envelope,
    file_ref_name,
    is_file_ref,
    write_job_files,
)

MAX_REQUESTS = 500
MAX_DOWNLOADS = 5
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024
MAX_CONSOLE_ERRORS = 50
MAX_REDIRECT_HOPS = 30
MAX_FRAMES_INSPECTED = 20
MAX_PDF_PAGES_RENDERED = 20
SCREENSHOT_QUALITY = 60
MIN_TIMEOUT_S = 5
MAX_LURE_CLICKS = 3
LURE_CLICK_TIMEOUT_MS = 1500
LURE_SETTLE_S = 0.8
SNIFF_HEAD_BYTES = 0x9000  # enough to see an ISO 9660 volume descriptor at 0x8001
MAX_ARCHIVE_NAMES = 50

LAUNCH_ARGS: tuple[str, ...] = (
    "--disable-blink-features=AutomationControlled",
    "--no-first-run",
    "--disable-dev-shm-usage",
)

# Private console channel between the init script and us. Prefixed messages
# are consumed here and never surface as page console errors.
_CHANNEL = "__rs:"

_INIT_SCRIPT = """
(() => {
  const emit = console.debug.bind(console);
  const report = () => {
    try {
      const metas = Array.from(document.querySelectorAll('meta[http-equiv]'));
      for (const m of metas) {
        if ((m.getAttribute('http-equiv') || '').trim().toLowerCase() !== 'refresh') continue;
        const content = m.getAttribute('content') || '';
        const match = /^\\s*[\\d.]*\\s*[;,\\s]\\s*(?:url\\s*=\\s*)?['"]?([^'"]+)/i.exec(content);
        let target = null;
        if (match) { try { target = new URL(match[1].trim(), document.baseURI).href; } catch (e) {} }
        emit('__rs:meta ' + JSON.stringify({doc: location.href, target: target, top: window.top === window.self}));
        return;
      }
    } catch (e) {}
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', report, {once: true});
  else report();

  // --- lure instrumentation (see chamber.lures) -----------------------------
  // Record, never block: every hook calls through (or resolves) so the page
  // behaves as it would for a person, and we learn what it tried to do.
  const send = (kind, data) => { try { emit('__rs:' + kind + ' ' + JSON.stringify(data || {})); } catch (e) {} };
  const clip = (text, via) => {
    try {
      if (text === null || text === undefined) return;
      const t = String(text);
      if (!t.trim()) return;
      send('clip', {t: t.slice(0, 2000), via: via});
    } catch (e) {}
  };
  try {
    if (window.Clipboard && Clipboard.prototype) {
      const origWrite = Clipboard.prototype.writeText;
      Clipboard.prototype.writeText = function (text) {
        clip(text, 'writeText');
        try { return Promise.resolve(origWrite ? origWrite.call(this, text) : undefined).catch(() => undefined); }
        catch (e) { return Promise.resolve(); }
      };
      const origWriteItems = Clipboard.prototype.write;
      Clipboard.prototype.write = function (items) {
        try {
          for (const item of Array.from(items || [])) {
            if (item && item.types && Array.from(item.types).some(t => /^text[/]/i.test(t))) {
              const type = Array.from(item.types).find(t => /^text[/]plain/i.test(t)) || Array.from(item.types).find(t => /^text[/]/i.test(t));
              Promise.resolve(item.getType(type)).then(b => b.text()).then(t => clip(t, 'write')).catch(() => {});
            }
          }
        } catch (e) {}
        try { return Promise.resolve(origWriteItems ? origWriteItems.call(this, items) : undefined).catch(() => undefined); }
        catch (e) { return Promise.resolve(); }
      };
    }
  } catch (e) {}
  try {
    const origExec = Document.prototype.execCommand;
    Document.prototype.execCommand = function (command) {
      try {
        if (String(command).toLowerCase() === 'copy' || String(command).toLowerCase() === 'cut') {
          let t = '';
          const ae = document.activeElement;
          if (ae && (ae.tagName === 'TEXTAREA' || ae.tagName === 'INPUT')) {
            try { t = String(ae.value).substring(ae.selectionStart || 0, ae.selectionEnd || String(ae.value).length); } catch (e) {}
          }
          if (!t) { const sel = document.getSelection(); t = sel ? sel.toString() : ''; }
          clip(t, 'execCommand');
        }
      } catch (e) {}
      return origExec.apply(this, arguments);
    };
  } catch (e) {}
  try {
    const origSet = DataTransfer.prototype.setData;
    DataTransfer.prototype.setData = function (type, data) {
      try { if (/^text/i.test(String(type))) clip(data, 'setData'); } catch (e) {}
      return origSet.apply(this, arguments);
    };
  } catch (e) {}
  try {
    if (window.Notification && typeof Notification.requestPermission === 'function') {
      Notification.requestPermission = function () { send('perm', {k: 'notifications'}); return Promise.resolve('default'); };
    }
    if (window.PushManager && PushManager.prototype.subscribe) {
      PushManager.prototype.subscribe = function () { send('perm', {k: 'push'}); return Promise.reject(new DOMException('denied', 'NotAllowedError')); };
    }
  } catch (e) {}
  try {
    if (!('ethereum' in window)) {
      const reject = () => Promise.reject(Object.assign(new Error('User rejected the request.'), {code: 4001}));
      const eth = {
        isMetaMask: true, chainId: '0x1', networkVersion: '1', selectedAddress: null,
        request: (args) => { send('wallet', {m: String((args && args.method) || '').slice(0, 60)}); return reject(); },
        enable: () => { send('wallet', {m: 'enable'}); return reject(); },
        send: (m) => { send('wallet', {m: String((m && m.method) || m || '').slice(0, 60)}); return reject(); },
        sendAsync: (m, cb) => { send('wallet', {m: String((m && m.method) || '').slice(0, 60)}); try { cb && cb(new Error('rejected')); } catch (e) {} },
        on: () => eth, removeListener: () => eth, isConnected: () => true,
      };
      Object.defineProperty(window, 'ethereum', {value: eth, configurable: true, writable: true});
    }
  } catch (e) {}
  try {
    for (const name of ['requestFullscreen', 'webkitRequestFullscreen', 'webkitRequestFullScreen', 'mozRequestFullScreen']) {
      const orig = Element.prototype[name];
      if (typeof orig !== 'function') continue;
      Element.prototype[name] = function () { send('fs', {}); try { return orig.apply(this, arguments); } catch (e) { return Promise.resolve(); } };
    }
    if (navigator.keyboard && typeof navigator.keyboard.lock === 'function') {
      const origLock = navigator.keyboard.lock.bind(navigator.keyboard);
      navigator.keyboard.lock = function () { send('klock', {}); try { return origLock.apply(null, arguments); } catch (e) { return Promise.resolve(); } };
    }
  } catch (e) {}
  try {
    const origAdd = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function (type) {
      try { if (type === 'beforeunload' && this === window) send('unload', {}); } catch (e) {}
      return origAdd.apply(this, arguments);
    };
    const desc = Object.getOwnPropertyDescriptor(window, 'onbeforeunload') || Object.getOwnPropertyDescriptor(Window.prototype, 'onbeforeunload');
    if (desc && desc.set && desc.configurable !== false) {
      Object.defineProperty(window, 'onbeforeunload', {
        configurable: true, enumerable: true,
        get() { return desc.get.call(window); },
        set(v) { if (v) send('unload', {}); desc.set.call(window, v); },
      });
    }
  } catch (e) {}
  try {
    const origClear = console.clear;
    let clears = 0;
    console.clear = function () { if (clears++ < 50) send('cclear', {}); try { return origClear.apply(console, arguments); } catch (e) {} };
  } catch (e) {}
})();
"""

# One snippet, two modes: 'page' returns everything, 'frame' only what matters
# inside an iframe (forms and password fields), so cross-origin login frames
# are not missed while keeping per-frame work small.
_FEATURES_JS = """
(mode) => {
  const out = {};
  const bodyText = document.body ? (document.body.innerText || '') : '';
  const forms = Array.from(document.forms).slice(0, 50).map(f => {
    const action = f.getAttribute('action');
    let actionUrl = null, actionHost = null;
    try {
      const u = new URL(action && action.trim() ? action.trim() : location.href, location.href);
      actionUrl = u.href; actionHost = u.hostname;
    } catch (e) {}
    const names = [];
    let hasPassword = false, hasIdentity = false;
    for (const el of f.querySelectorAll('input,select,textarea')) {
      const type = (el.getAttribute('type') || (el.tagName === 'INPUT' ? 'text' : el.tagName.toLowerCase())).toLowerCase();
      const name = el.getAttribute('name') || el.getAttribute('id') || '';
      if (name && names.length < 30) names.push(name.slice(0, 60));
      if (type === 'password') hasPassword = true;
      const auto = el.getAttribute('autocomplete') || '';
      if (type === 'email' || type === 'tel' || /user|email|login|phone|account|mail/i.test(name) || /user|email|tel|username/i.test(auto)) hasIdentity = true;
    }
    return {action_url: actionUrl, action_host: actionHost, has_password: hasPassword, has_identity_field: hasIdentity, field_names: names};
  });
  out.forms = forms;
  out.has_password_field = !!document.querySelector('input[type=password i]');
  out.lure_text = bodyText.slice(0, 20000);
  const seedRe = /seed|mnemonic|recovery ?phrase|secret ?phrase|private ?key|passphrase|word ?(?:#|no[.]?|number)? ?\\d{1,2}\\b/i;
  out.seed_inputs = Array.from(document.querySelectorAll('input,textarea')).slice(0, 300).filter(el => {
    const t = (el.getAttribute('type') || 'text').toLowerCase();
    if (!['text', 'password', 'search', ''].includes(t) && el.tagName !== 'TEXTAREA') return false;
    const label = [el.getAttribute('name'), el.getAttribute('id'), el.getAttribute('placeholder'), el.getAttribute('aria-label')].join(' ');
    return seedRe.test(label);
  }).length;
  if (mode === 'frame') return out;

  out.title = document.title || null;
  out.url = location.href;
  out.host = location.hostname;
  out.iframe_count = document.querySelectorAll('iframe,frame').length;
  out.text_excerpt = bodyText.slice(0, 2000);
  out.body_text_length = bodyText.trim().length;
  out.alt_text = Array.from(document.images).slice(0, 200).map(i => (i.alt || '') + ' ' + (i.title || '')).join(' ').slice(0, 5000);
  out.meta_refresh = Array.from(document.querySelectorAll('meta[http-equiv]')).some(m => (m.getAttribute('http-equiv') || '').trim().toLowerCase() === 'refresh');

  // Hidden text: text under display:none / visibility:hidden / opacity:0 /
  // font-size:0 / parked far off-screen, measured against all text. Kits hide
  // keyword salad from humans but not from scanners.
  const cache = new Map();
  const isHidden = (el) => {
    if (!el || el === document.documentElement) return false;
    if (cache.has(el)) return cache.get(el);
    let hidden = false;
    try {
      const cs = getComputedStyle(el);
      hidden = cs.display === 'none' || cs.visibility === 'hidden' || parseFloat(cs.opacity) === 0 ||
               parseFloat(cs.fontSize) === 0 || el.hasAttribute('hidden') ||
               (cs.position === 'absolute' && (parseFloat(cs.left) < -2000 || parseFloat(cs.top) < -2000)) ||
               (cs.clip === 'rect(0px, 0px, 0px, 0px)');
    } catch (e) {}
    if (!hidden) hidden = isHidden(el.parentElement);
    cache.set(el, hidden);
    return hidden;
  };
  let total = 0, hidden = 0, n = 0;
  const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT);
  while (walker.nextNode() && n++ < 5000) {
    const node = walker.currentNode;
    const text = (node.nodeValue || '').trim();
    if (!text) continue;
    const parent = node.parentElement;
    if (!parent) continue;
    const tag = parent.tagName;
    if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'NOSCRIPT' || tag === 'TEMPLATE' || tag === 'TITLE') continue;
    total += text.length;
    if (isHidden(parent)) hidden += text.length;
  }
  out.hidden_text_ratio = total ? hidden / total : 0;

  const srcs = Array.from(document.querySelectorAll('iframe[src],script[src]')).map(e => e.getAttribute('src') || '').join(' ').toLowerCase();
  const classes = Array.from(document.querySelectorAll('[class]')).slice(0, 3000).map(e => e.getAttribute('class') || '').join(' ').toLowerCase();
  const lowered = (bodyText + ' ' + (document.title || '')).toLowerCase();
  out.captcha_detected = /recaptcha|hcaptcha|turnstile|challenges\\.cloudflare\\.com|cf-challenge|arkoselabs|funcaptcha|geetest/.test(srcs + ' ' + classes) ||
      /verify (that )?you are (a )?human|are you a robot|i'?m not a robot|checking your browser|confirm you are human|complete the security check|security verification/.test(lowered);
  out.blocked_text = /access denied|enable javascript and cookies|checking your browser|unusual traffic|attention required|request blocked|bot detected|automated access|403 forbidden/.test(lowered);
  out.captcha_srcs = Array.from(document.querySelectorAll('script[src],iframe[src]')).map(e => e.getAttribute('src') || '').filter(u => /recaptcha|hcaptcha|turnstile|challenges[.]cloudflare[.]com|arkoselabs|funcaptcha|geetest/i.test(u)).slice(0, 10);
  out.inline_scripts = Array.from(document.scripts).filter(s => !s.src).map(s => (s.textContent || '').slice(0, 20000)).slice(0, 50);
  return out;
}
"""

_OBFUSCATION_MARKERS = re.compile(
    r"\beval\s*\(|\batob\s*\(|\bunescape\s*\(|String\.fromCharCode|document\.write\s*\(|\.charCodeAt\s*\(|new\s+Function\s*\(|\bFunction\s*\(\s*['\"]",
    re.IGNORECASE,
)
_UNPACKER_RE = re.compile(r"\beval\s*\([^;]{0,200}(atob|unescape|fromCharCode|\.join\(|\.replace\()", re.IGNORECASE)
_LONG_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{64,}={0,2}")
_HEX_RUN_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){10,}|(?:\\u[0-9a-fA-F]{4}){8,}|(?:0x[0-9a-fA-F]{2},\s*){16,}")


def obfuscation_score(scripts: list[str]) -> int:
    """0..100: how much the page's inline JavaScript looks like it is hiding
    something. Scored per script and the worst one wins (summing would punish
    large legitimate sites for a hundred harmless ``document.write`` calls),
    with a small bonus when several scripts look suspicious."""
    best = 0
    suspicious = 0
    for script in scripts:
        if not script or not script.strip():
            continue
        score = 0
        markers = len(_OBFUSCATION_MARKERS.findall(script))
        score += min(45, markers * 15)
        if _UNPACKER_RE.search(script):
            score += 20
        if _LONG_BASE64_RE.search(script):
            score += 25
        if _HEX_RUN_RE.search(script):
            score += 20
        longest_line = max((len(line) for line in script.splitlines()), default=0)
        if longest_line > 1500:
            score += 15
        stripped = re.sub(r"\s+", "", script)
        if len(stripped) > 500:
            symbols = sum(1 for c in stripped if not c.isalnum())
            if symbols / len(stripped) > 0.35:
                score += 15
        if score >= 30:
            suspicious += 1
        best = max(best, score)
    if suspicious > 3:
        best += 10
    return max(0, min(100, best))


# --- collector ---------------------------------------------------------------


@dataclass
class _Collector:
    """Everything observed so far. Lives outside the cancellable task so a
    timeout or crash still yields a (partial) result."""

    job: DetonationJob
    workdir: Path
    started_wall: float = field(default_factory=time.time)
    started: float = field(default_factory=time.monotonic)
    deadline: float = 0.0
    status: DetonationStatus = DetonationStatus.OK
    error: str | None = None
    redirects: list[RedirectHop] = field(default_factory=list)
    requests: list[NetworkRequest] = field(default_factory=list)
    downloads: list[DownloadRecord] = field(default_factory=list)
    console_errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    features: PageFeatures | None = None
    screenshot_ref: str | None = None
    main_frame_urls: list[str] = field(default_factory=list)
    meta_refresh_docs: dict[str, str | None] = field(default_factory=dict)
    nav_responses: list[Any] = field(default_factory=list)
    download_attempts: int = 0
    dropped_requests: int = 0
    clipboard_writes: list[str] = field(default_factory=list)
    permission_requests: list[str] = field(default_factory=list)
    wallet_methods: list[str] = field(default_factory=list)
    fullscreen_requested: bool = False
    keyboard_lock: bool = False
    beforeunload_trap: bool = False
    console_clears: int = 0
    dialog_count: int = 0
    lure_clicks: list[str] = field(default_factory=list)
    pending: set[asyncio.Task[Any]] = field(default_factory=set)
    popups: list[Any] = field(default_factory=list)
    playwright: Any = None
    browser: Any = None
    context: Any = None
    page: Any = None
    _req_index: dict[int, NetworkRequest] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.deadline = self.started + max(MIN_TIMEOUT_S, self.job.timeout_s)
        self._workdir_uri = self.workdir.resolve().as_uri().rstrip("/") + "/"

    def public_url(self, url: str | None) -> str | None:
        """Hide the scratch directory: ``file:///tmp/rs-det-x/view/index.html``
        becomes ``file:///sandbox/view/index.html``. The path is noise to the
        analyst and tells an attacker-controlled page nothing useful."""
        if url and url.startswith(self._workdir_uri):
            return "file:///sandbox/" + url[len(self._workdir_uri) :]
        return url

    # -- time budget --------------------------------------------------------
    def remaining(self) -> float:
        return max(0.0, self.deadline - time.monotonic())

    def remaining_ms(self, cap_ms: int | None = None) -> int:
        ms = int(self.remaining() * 1000)
        if cap_ms is not None:
            ms = min(ms, cap_ms)
        return max(1, ms)

    # -- notes --------------------------------------------------------------
    def note(self, text: str) -> None:
        if len(self.notes) < MAX_CONSOLE_ERRORS:
            self.notes.append(text)

    def console_error(self, text: str) -> None:
        if len(self.console_errors) < MAX_CONSOLE_ERRORS:
            self.console_errors.append(text[:500])

    def fail(self, exc: BaseException | str, where: str) -> None:
        message = f"{where}: {exc}" if where else str(exc)
        message = message.splitlines()[0][:500]
        if self.status is DetonationStatus.OK:
            self.status = DetonationStatus.ERROR
        if self.error is None:
            self.error = message
        else:
            self.note(message)

    # -- network observation -------------------------------------------------
    def on_request(self, request: Any) -> None:
        url = request.url
        if self.job.kind is DetonationKind.FILE and not url.startswith("file:"):
            # Aborted by the route handler; keep it as evidence, not as traffic.
            self.note(f"blocked: {request.method} {url[:300]}")
            return
        if len(self.requests) >= MAX_REQUESTS:
            self.dropped_requests += 1
            return
        url = self.public_url(url) or url
        record = NetworkRequest(url=url[:2000], host=host_of(url), resource_type=request.resource_type or "")
        self.requests.append(record)
        self._req_index[id(request)] = record

    def on_response(self, response: Any) -> None:
        record = self._req_index.get(id(response.request))
        if record is not None:
            record.status = response.status
        if self.page is None or len(self.nav_responses) >= MAX_REDIRECT_HOPS * 2:
            return
        try:
            request = response.request
            if request.is_navigation_request() and request.frame == self.page.main_frame:
                self.nav_responses.append(response)
        except Exception:  # frame may be gone; never let an observer break the run
            pass

    @property
    def main_response(self) -> Any:
        """The response that produced the document we ended up on: the last
        main-frame navigation response that was not itself redirected."""
        for response in reversed(self.nav_responses):
            try:
                if response.request.redirected_to is None:
                    return response
            except Exception:
                continue
        return None

    def on_frame_navigated(self, frame: Any) -> None:
        if self.page is None or frame != self.page.main_frame:
            return
        url = frame.url
        if not url or url == "about:blank" or url.startswith("chrome-error://"):
            return
        url = self.public_url(url) or url
        if self.main_frame_urls and _same_document(self.main_frame_urls[-1], url):
            return
        self.main_frame_urls.append(url)

    def on_console(self, message: Any) -> None:
        text = message.text or ""
        if text.startswith(_CHANNEL):
            self._on_channel(text[len(_CHANNEL) :])
            return
        if message.type in ("error", "assert"):
            self.console_error(f"console.{message.type}: {text}")

    def _on_channel(self, payload: str) -> None:
        kind, _, body = payload.partition(" ")
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            return
        if not isinstance(data, dict):
            return
        if kind == "meta":
            if data.get("top"):
                self.meta_refresh_docs[str(data.get("doc"))] = data.get("target")
        elif kind == "clip":
            self.record_clipboard(str(data.get("t") or ""))
        elif kind == "perm":
            what = str(data.get("k") or "")[:30]
            if what and what not in self.permission_requests:
                self.permission_requests.append(what)
        elif kind == "wallet":
            method = str(data.get("m") or "")[:60]
            if method and method not in self.wallet_methods and len(self.wallet_methods) < 20:
                self.wallet_methods.append(method)
        elif kind == "fs":
            self.fullscreen_requested = True
        elif kind == "klock":
            self.keyboard_lock = True
        elif kind == "unload":
            self.beforeunload_trap = True
        elif kind == "cclear":
            self.console_clears += 1

    def record_clipboard(self, text: str) -> None:
        text = text[: lures.CLIPBOARD_MAX_CHARS]
        if not text.strip() or text in self.clipboard_writes or len(self.clipboard_writes) >= lures.MAX_CLIPBOARD_WRITES:
            return
        self.clipboard_writes.append(text)

    def on_dialog(self, dialog: Any) -> None:
        self.dialog_count += 1

    def on_page_error(self, error: Any) -> None:
        self.console_error(f"pageerror: {getattr(error, 'message', error)}")

    # -- result -------------------------------------------------------------
    def result(self) -> DetonationResult:
        errors = list(self.notes) + self.console_errors
        if self.dropped_requests:
            errors.append(f"sandbox: {self.dropped_requests} requests beyond the {MAX_REQUESTS} cap were not recorded")
        return DetonationResult(
            job_id=self.job.job_id,
            status=self.status,
            duration_ms=int((time.monotonic() - self.started) * 1000),
            redirects=self.redirects,
            requests=self.requests,
            features=self.features,
            downloads=self.downloads,
            screenshot_ref=self.screenshot_ref,
            console_errors=errors[: MAX_CONSOLE_ERRORS * 2],
            error=self.error,
        )


def _same_document(a: str, b: str) -> bool:
    return a.split("#", 1)[0] == b.split("#", 1)[0]


# --- public entry point -------------------------------------------------------


async def detonate(job: DetonationJob, workdir: Path) -> DetonationResult:
    """Detonate ``job`` and return a result whose binary outputs live in
    ``workdir`` (``file:`` refs). Never raises for page/browser problems: those
    become ``status`` ERROR / TIMEOUT with partial data."""
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    col = _Collector(job=job, workdir=workdir)
    try:
        await asyncio.wait_for(_run(col), timeout=max(MIN_TIMEOUT_S, job.timeout_s))
    except TimeoutError:
        col.status = DetonationStatus.TIMEOUT
        if col.error is None:
            col.error = f"sandbox deadline of {job.timeout_s}s reached"
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # anything Playwright or our own code throws
        col.fail(exc, "detonate")
    finally:
        await _shutdown(col)
    return col.result()


async def _run(col: _Collector) -> None:
    job = col.job
    from playwright.async_api import async_playwright

    col.playwright = await async_playwright().start()
    args = list(LAUNCH_ARGS)
    if os.environ.get("RS_CHAMBER_NO_SANDBOX") == "1":
        # Only for containers that cannot create user namespaces; the container
        # boundary is then the only sandbox. See backends/docker.py.
        args.append("--no-sandbox")
    col.browser = await col.playwright.chromium.launch(args=args)
    profile = job.profile
    col.context = await col.browser.new_context(
        user_agent=profile.user_agent or user_agent_for(col.browser.version),
        locale=profile.locale,
        timezone_id=profile.timezone,
        viewport={"width": profile.viewport_width, "height": profile.viewport_height},
        accept_downloads=True,
        ignore_https_errors=True,
        java_script_enabled=True,
    )
    await col.context.add_init_script(_INIT_SCRIPT)

    target: str | None
    if job.kind is DetonationKind.FILE:
        target = await _stage_file(col)
        if target is None:
            return  # not browser-viewable; result already explains why
        await col.context.route("**/*", _file_only_route)
    else:
        target = job.url or ""

    col.page = await col.context.new_page()
    _wire_page(col, col.page, popup=False)
    # Registered after the main page exists so only window.open() children
    # are treated as popups.
    col.context.on("page", lambda page: _wire_page(col, page, popup=True))

    await _navigate(col, target)
    await _settle(col)
    if profile.interact and col.remaining() > 2.5:
        await _interact(col)
    if profile.click_lures and col.remaining() > 3.0:
        await _click_lures(col)
    await _drain_pending(col)
    await _extract_features(col)
    await _screenshot(col)
    await _finish_redirects(col)
    _finish_requests(col)


def _wire_page(col: _Collector, page: Any, *, popup: bool) -> None:
    page.on("request", col.on_request)
    page.on("response", col.on_response)
    page.on("console", col.on_console)
    page.on("pageerror", col.on_page_error)
    page.on("download", lambda download: _track(col, _save_download(col, download)))
    # alert()/confirm()/prompt() would otherwise block the page forever.
    page.on("dialog", lambda dialog: (col.on_dialog(dialog), _track(col, dialog.dismiss())))
    if popup:
        col.popups.append(page)
        col.note(f"popup opened: {page.url[:300]}")
    else:
        page.on("framenavigated", col.on_frame_navigated)


def _track(col: _Collector, coro: Any) -> None:
    task = asyncio.ensure_future(coro)
    col.pending.add(task)
    task.add_done_callback(col.pending.discard)


async def _file_only_route(route: Any, request: Any) -> None:
    if request.url.startswith("file:"):
        await route.continue_()
    else:
        await route.abort("blockedbyclient")


# --- navigation ---------------------------------------------------------------


async def _navigate(col: _Collector, url: str) -> None:
    profile = col.job.profile
    timeout_ms = col.remaining_ms(max(1000, profile.max_wait_ms))
    try:
        await col.page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms, referer=profile.referer)
    except Exception as exc:
        message = str(exc).splitlines()[0]
        if "Download is starting" in message:
            col.note("navigation produced a download instead of a page")
        elif "interrupted by another navigation" in message:
            col.note("navigation interrupted by a client-side redirect")
        elif _is_timeout(exc):
            col.status = DetonationStatus.TIMEOUT
            col.error = col.error or f"page did not reach DOMContentLoaded within {timeout_ms}ms"
        else:
            col.fail(message, "goto")


def _is_timeout(exc: BaseException) -> bool:
    return type(exc).__name__ in {"TimeoutError", "TimeoutException"} or "Timeout" in type(exc).__name__


async def _settle(col: _Collector) -> None:
    """Wait for the network to go quiet - or for our budget to run out,
    whichever comes first. Timeouts here are expected (ad beacons never
    stop) and swallowed."""
    budget_ms = col.remaining_ms(max(500, col.job.profile.max_wait_ms))
    if budget_ms <= 1:
        return
    try:
        await col.page.wait_for_load_state("networkidle", timeout=budget_ms)
    except Exception:
        pass


async def _interact(col: _Collector) -> None:
    """A deterministic, human-looking dwell: a short mouse path, a scroll down
    and back. No randomness, so two detonations of the same page behave the
    same (reproducibility matters more than realism here)."""
    page = col.page
    w, h = col.job.profile.viewport_width, col.job.profile.viewport_height
    try:
        for fx, fy in ((0.30, 0.40), (0.55, 0.50), (0.50, 0.66), (0.62, 0.42)):
            await page.mouse.move(w * fx, h * fy, steps=5)
        await page.mouse.wheel(0, 300)
        await asyncio.sleep(0.6)
        await page.mouse.wheel(0, -300)
        await asyncio.sleep(0.5)
    except Exception as exc:  # the page may have navigated or closed under us
        col.note(f"interaction skipped: {str(exc).splitlines()[0][:200]}")


# Finds the next lure to click: "I'm not a robot" checkboxes, "Verify",
# "Fix it", "Connect wallet". Candidates inside a form with a password field
# are skipped (we never submit credentials forms), as are links that leave
# for another site. The chosen element is tagged with a data attribute so
# Playwright can scroll to it and click it with a real (trusted) mouse event.
_LURE_FINDER_JS = """
(clicked) => {
  const done = new Set(clicked || []);
  const textRe = /^(?:[\\u2610\\u2611\\u2713\\u2714\\u25a1\\s]*)(?:i'?m not a robot|i am not a robot|i'?m (?:a )?human|i am (?:a )?human|not a robot|verify(?: (?:you are|you're|i am|that you are) (?:a )?human)?|verify (?:now|me|identity)|click (?:here )?to verify|verification|human verification|confirm (?:you are|you're|i'?m) (?:a )?human|press (?:&|and) hold|fix it|fix(?: (?:it|error|issue|now))?|how to fix|show (?:the )?solution|solution|repair|open file explorer|connect (?:your )?wallet|claim(?: (?:now|airdrop|reward|rewards|tokens?|nft))?)[\\s.!]*$/i;
  const hintRe = /captcha|recaptcha|checkbox|check-box|verify|robot|human|turnstile|challenge/i;
  const rank = (t) => /robot|human|hold/i.test(t) ? 0 : /verif/i.test(t) ? 1 : /fix|solution|repair/i.test(t) ? 2 : 3;
  const els = Array.from(document.querySelectorAll('button,a,input[type=checkbox],input[type=button],input[type=submit],[role=button],[role=checkbox],label,div,span')).slice(0, 4000);
  const found = [];
  for (const el of els) {
    if (el.closest('form') && el.closest('form').querySelector('input[type=password i]')) continue;
    const rect = el.getBoundingClientRect();
    if (rect.width < 4 || rect.height < 4) continue;
    const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none' || parseFloat(cs.opacity) === 0) continue;
    let text = ((el.innerText || el.value || el.getAttribute('aria-label') || '') + '').trim().replace(/\\s+/g, ' ');
    const hint = (el.id || '') + ' ' + (typeof el.className === 'string' ? el.className : '');
    const tag = el.tagName;
    const clickable = /^(BUTTON|A|INPUT|LABEL)$/.test(tag) || /^(button|checkbox)$/.test(el.getAttribute('role') || '') || el.hasAttribute('onclick') || cs.cursor === 'pointer';
    if (!clickable) continue;
    let ok = text.length > 0 && text.length <= 60 && textRe.test(text);
    if (!ok && text.length <= 60 && hintRe.test(hint) && (tag === 'INPUT' || rect.width <= 120)) { ok = true; text = text || hint.trim().slice(0, 40); }
    if (!ok) continue;
    if (tag === 'A') {
      const href = el.getAttribute('href') || '';
      try { const u = new URL(href, location.href); if (u.hostname && u.hostname !== location.hostname && !href.startsWith('#') && !href.startsWith('javascript:')) continue; } catch (e) {}
    }
    const key = text.toLowerCase().slice(0, 60) || hint.slice(0, 60);
    if (done.has(key)) continue;
    // Prefer the innermost element carrying the text.
    if (found.some(f => el.contains(f.el))) continue;
    for (let i = found.length - 1; i >= 0; i--) if (found[i].el.contains(el)) found.splice(i, 1);
    found.push({el, key, rank: rank(text)});
  }
  if (!found.length) return null;
  found.sort((a, b) => a.rank - b.rank);
  for (const old of document.querySelectorAll('[data-rs-lure]')) old.removeAttribute('data-rs-lure');
  found[0].el.setAttribute('data-rs-lure', '1');
  return found[0].key;
}
"""


async def _click_lures(col: _Collector) -> None:
    """Click up to ``MAX_LURE_CLICKS`` obvious lure elements so a fake CAPTCHA
    or fake error reveals what it puts on the clipboard and what it tells
    the reader to do. Bounded by short timeouts; never raises."""
    clicked: list[str] = []
    for _ in range(MAX_LURE_CLICKS):
        if col.remaining() < 2.5 or col.page is None:
            break
        target = None
        key = None
        frames = [col.page.main_frame] + [f for f in col.page.frames if f != col.page.main_frame][:5]
        for frame in frames:
            try:
                key = await asyncio.wait_for(frame.evaluate(_LURE_FINDER_JS, clicked), timeout=2.0)
            except Exception:
                key = None
            if key:
                target = frame
                break
        if not target or not key:
            break
        clicked.append(str(key))
        try:
            await target.locator('[data-rs-lure="1"]').first.click(timeout=col.remaining_ms(LURE_CLICK_TIMEOUT_MS), no_wait_after=True)
            col.lure_clicks.append(str(key)[:60])
        except Exception as exc:
            col.note(f"lure click skipped: {str(exc).splitlines()[0][:160]}")
            continue
        await asyncio.sleep(min(LURE_SETTLE_S, max(0.1, col.remaining() - 2.0)))
        try:
            await col.page.wait_for_load_state("domcontentloaded", timeout=col.remaining_ms(1500))
        except Exception:
            pass


async def _drain_pending(col: _Collector) -> None:
    """Let in-flight downloads finish within what is left of the budget."""
    if not col.pending:
        return
    _done, still = await asyncio.wait(set(col.pending), timeout=max(0.5, col.remaining() - 2.0))
    if still:
        col.note(f"{len(still)} download(s) still in progress at deadline")


# --- downloads ----------------------------------------------------------------


async def _save_download(col: _Collector, download: Any) -> None:
    col.download_attempts += 1
    index = col.download_attempts - 1
    suggested = (download.suggested_filename or "download")[:200]
    if index >= MAX_DOWNLOADS:
        col.note(f"download ignored (cap of {MAX_DOWNLOADS}): {suggested}")
        await _quiet(download.cancel())
        return
    name = f"dl_{index}.bin"
    path = col.workdir / name
    try:
        await download.save_as(path)
    except Exception as exc:
        failure = await _quiet(download.failure())
        col.note(f"download failed: {suggested}: {failure or str(exc).splitlines()[0][:200]}")
        return
    size = path.stat().st_size
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        head = fh.read(SNIFF_HEAD_BYTES)
        digest.update(head)
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    sniffed = refine_download_type(head, suggested, sniff_type(head))
    record = DownloadRecord(
        suggested_filename=suggested,
        sha256=digest.hexdigest(),
        size=size,
        sniffed_type=sniffed,
        stored_ref=f"file:{name}",
    )
    if sniffed == "zip" and size <= MAX_DOWNLOAD_BYTES:
        record.archive_entries, record.encrypted = _zip_listing(path)
    if size > MAX_DOWNLOAD_BYTES:
        path.unlink(missing_ok=True)
        record.stored_ref = None
        col.note(f"download {suggested} ({size} bytes) exceeds {MAX_DOWNLOAD_BYTES} bytes; hash recorded, bytes dropped")
    col.downloads.append(record)


def _zip_listing(path: Path) -> tuple[list[str], bool]:
    """Entry names and "password-protected?" for a downloaded ZIP. Reads the
    central directory only; nothing is extracted."""
    import zipfile

    try:
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()[:1000]
    except Exception:
        return [], False
    names = [i.filename[:200] for i in infos if not i.is_dir()][:MAX_ARCHIVE_NAMES]
    return names, any(i.flag_bits & 0x1 for i in infos)


async def _quiet(coro: Any) -> Any:
    try:
        return await coro
    except Exception:
        return None


# --- features ---------------------------------------------------------------


async def _extract_features(col: _Collector) -> None:
    page = col.page
    try:
        raw = await asyncio.wait_for(page.main_frame.evaluate(_FEATURES_JS, "page"), timeout=max(1.0, min(10.0, col.remaining())))
    except Exception as exc:
        col.fail(exc, "features")
        raw = {}
    if not isinstance(raw, dict):
        raw = {}

    final_url = col.public_url(raw.get("url") or page.url)
    if not final_url or final_url == "about:blank" or final_url.startswith("chrome-error://"):
        # Navigation never committed (a download, a dead page): report the
        # address we were sent to so the analyst still knows where we went.
        final_url = col.main_frame_urls[-1] if col.main_frame_urls else (col.job.url if col.job.kind is DetonationKind.URL else None)
    final_host = host_of(final_url)
    if col.job.kind is DetonationKind.FILE:
        final_host = ""

    forms = [_form_record(f) for f in raw.get("forms") or [] if isinstance(f, dict)]
    has_password = bool(raw.get("has_password_field"))
    frame_forms, frame_password, frame_text, frame_seed = await _inspect_frames(col)
    forms.extend(frame_forms)
    has_password = has_password or frame_password
    lure_text = str(raw.get("lure_text") or "")
    if frame_text:
        lure_text = (lure_text + "\n" + frame_text)[:40000]
    found = lures.analyse_page(lure_text, col.clipboard_writes)

    status_code = col.main_response.status if col.main_response is not None else None
    if col.job.kind is DetonationKind.FILE:
        status_code = None  # file:// has no HTTP status worth reporting
    body_len = int(raw.get("body_text_length") or 0)
    blocked = bool(raw.get("blocked_text")) or (status_code == 403 and body_len < 200)
    text_for_brands = " ".join(str(raw.get(k) or "") for k in ("title", "text_excerpt", "alt_text"))
    scripts = [s for s in raw.get("inline_scripts") or [] if isinstance(s, str)]

    col.features = PageFeatures(
        title=(raw.get("title") or None),
        final_url=final_url,
        final_host=final_host or None,
        forms=forms[:50],
        has_password_field=has_password,
        external_form_action=any(f.action_host and final_host and f.action_host.lower() != final_host for f in forms),
        brand_keywords=find_brand_keywords(text_for_brands),
        meta_refresh=bool(raw.get("meta_refresh")) or bool(col.meta_refresh_docs),
        js_redirect=False,  # decided in _finish_redirects
        obfuscated_js_score=obfuscation_score(scripts),
        iframe_count=int(raw.get("iframe_count") or 0),
        hidden_text_ratio=float(raw.get("hidden_text_ratio") or 0.0),
        text_excerpt=str(raw.get("text_excerpt") or "")[:2000],
        captcha_detected=bool(raw.get("captcha_detected")),
        automation_blocked_hint=blocked,
        status_code=status_code,
        clipboard_writes=list(col.clipboard_writes),
        clickfix_instructions=found.clickfix_instructions,
        fake_captcha=found.fake_captcha,
        run_dialog_lure=found.run_dialog_lure,
        instruction_hits=found.hits,
        instruction_excerpt=found.excerpt,
        lure_clicks=list(col.lure_clicks),
        captcha_providers=_captcha_providers(col, raw.get("captcha_srcs") or []),
        notification_permission_requested=bool(col.permission_requests),
        wallet_requests=list(col.wallet_methods),
        seed_phrase_inputs=int(raw.get("seed_inputs") or 0) + frame_seed,
        fullscreen_requested=col.fullscreen_requested,
        keyboard_lock=col.keyboard_lock,
        dialog_count=col.dialog_count,
        beforeunload_trap=col.beforeunload_trap,
        console_clear_count=col.console_clears,
        anti_debug=lures.anti_debug_script(scripts) or col.console_clears >= 5,
        ua_cloaking=lures.ua_cloaking_script(scripts),
        phone_numbers=lures.phone_numbers(lure_text) if lures.tech_support_hits(lure_text) else [],
    )


_CAPTCHA_HOSTS: tuple[tuple[str, str], ...] = (
    ("challenges.cloudflare.com", "turnstile"),
    ("hcaptcha.com", "hcaptcha"),
    ("recaptcha.net", "recaptcha"),
    ("www.google.com/recaptcha", "recaptcha"),
    ("gstatic.com/recaptcha", "recaptcha"),
    ("arkoselabs.com", "arkose"),
    ("funcaptcha.com", "arkose"),
    ("geetest.com", "geetest"),
)


def _captcha_providers(col: _Collector, srcs: list[Any]) -> list[str]:
    """Real CAPTCHA services the page loaded (from requests and script/iframe
    sources). A page that *looks* like a CAPTCHA but loads none is suspect."""
    found: list[str] = []
    urls = [str(u) for u in srcs][:20] + [r.url for r in col.requests[:MAX_REQUESTS]]
    for url in urls:
        low = url.lower()
        for marker, name in _CAPTCHA_HOSTS:
            if marker in low and name not in found:
                found.append(name)
    return found


def _form_record(raw: dict[str, Any]) -> FormRecord:
    return FormRecord(
        action_url=(str(raw.get("action_url"))[:2000] if raw.get("action_url") else None),
        action_host=(str(raw.get("action_host")).lower() if raw.get("action_host") else None),
        has_password=bool(raw.get("has_password")),
        has_identity_field=bool(raw.get("has_identity_field")),
        field_names=[str(n)[:60] for n in (raw.get("field_names") or [])][:30],
    )


async def _inspect_frames(col: _Collector) -> tuple[list[FormRecord], bool, str, int]:
    """Forms, password fields, lure text and seed-phrase inputs inside child
    frames (Playwright can evaluate in cross-origin frames, which is exactly
    where login iframes and fake CAPTCHA widgets live)."""
    forms: list[FormRecord] = []
    has_password = False
    texts: list[str] = []
    seed = 0
    frames = [f for f in col.page.frames if f != col.page.main_frame][:MAX_FRAMES_INSPECTED]
    for frame in frames:
        if col.remaining() < 1.0:
            break
        try:
            raw = await asyncio.wait_for(frame.evaluate(_FEATURES_JS, "frame"), timeout=2.0)
        except Exception:
            continue  # detached / navigating frames are normal
        if not isinstance(raw, dict):
            continue
        forms.extend(_form_record(f) for f in raw.get("forms") or [] if isinstance(f, dict))
        has_password = has_password or bool(raw.get("has_password_field"))
        text = str(raw.get("lure_text") or "")[:5000]
        if text.strip():
            texts.append(text)
        seed += int(raw.get("seed_inputs") or 0)
    return forms, has_password, "\n".join(texts)[:20000], seed


# --- screenshot + QR ----------------------------------------------------------


async def _screenshot(col: _Collector) -> None:
    path = col.workdir / SCREENSHOT_NAME
    try:
        await col.page.screenshot(
            path=str(path), full_page=True, type="jpeg", quality=SCREENSHOT_QUALITY, timeout=col.remaining_ms(10000)
        )
    except Exception as exc:
        col.note(f"screenshot failed: {str(exc).splitlines()[0][:200]}")
        return
    col.screenshot_ref = f"file:{SCREENSHOT_NAME}"
    if col.features is not None and col.remaining() > 0.5:
        try:
            codes = await asyncio.wait_for(asyncio.to_thread(decode_qr_codes, path.read_bytes()), timeout=max(0.5, min(8.0, col.remaining())))
        except Exception as exc:
            col.note(f"qr decode skipped: {type(exc).__name__}")
            codes = []
        col.features.qr_codes = codes


def decode_qr_codes(image_bytes: bytes) -> list[str]:
    """Decode QR codes in a screenshot. Bounded: very tall pages are cropped
    and very wide ones downscaled before OpenCV sees them, because the
    detector's cost grows quickly with pixel count and a hostile page can be
    arbitrarily large."""
    import cv2
    import numpy as np

    image = cv2.imdecode(np.frombuffer(image_bytes, np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        return []
    h, w = image.shape[:2]
    if h > 6000:
        image = image[:6000]
    if w > 2500:
        scale = 2500 / w
        image = cv2.resize(image, (2500, max(1, int(image.shape[0] * scale))), interpolation=cv2.INTER_AREA)
    detector = cv2.QRCodeDetector()
    found: list[str] = []
    for candidate in (image, cv2.resize(image, (max(1, image.shape[1] // 2), max(1, image.shape[0] // 2)), interpolation=cv2.INTER_AREA)):
        try:
            ok, texts, _points, _straight = detector.detectAndDecodeMulti(candidate)
        except cv2.error:
            continue
        if ok:
            for text in texts:
                if text and text not in found:
                    found.append(text[:2000])
        if found:
            break
    return found[:20]


# --- redirects + requests ---------------------------------------------------------


async def _finish_redirects(col: _Collector) -> None:
    """Assemble the redirect chain.

    Every document the main frame committed came from a *terminal* navigation
    response (one that was not itself a 30x). Walking ``redirected_from`` from
    each terminal response gives the HTTP hops with their status codes; the
    seam between two terminal responses is a client-side redirect, which was
    a meta refresh if the previous document reported one through the init
    script channel and JavaScript otherwise. Commits seen by ``framenavigated``
    that no response explains (history API, dead pages) are kept as "client".
    """
    hops: list[RedirectHop] = []
    js_redirect = False
    terminals = [r for r in col.nav_responses if _terminal(r)]
    for response in terminals:
        chain = await _http_chain(col, response)
        if not chain:
            continue
        if hops:
            previous_doc = hops[-1].url
            if _same_document(previous_doc, chain[0].url) and len(chain) == 1:
                continue  # a reload of the same document
            if previous_doc in col.meta_refresh_docs:
                chain[0].kind = "meta"
            else:
                chain[0].kind = "js"
                js_redirect = True
        hops.extend(chain)
        if len(hops) >= MAX_REDIRECT_HOPS:
            break

    if not hops and col.job.kind is DetonationKind.URL and col.job.url:
        hops.append(RedirectHop(url=col.job.url, status=None, kind="http"))

    known = {h.url.split("#", 1)[0] for h in hops}
    for url in col.main_frame_urls:
        if url.split("#", 1)[0] in known or len(hops) >= MAX_REDIRECT_HOPS:
            continue
        hops.append(RedirectHop(url=url, status=None, kind="client"))
        known.add(url.split("#", 1)[0])

    col.redirects = hops
    if col.features is not None:
        col.features.js_redirect = js_redirect
        if any(h.kind == "meta" for h in hops):
            col.features.meta_refresh = True


def _terminal(response: Any) -> bool:
    try:
        return response.request.redirected_to is None
    except Exception:
        return False


async def _http_chain(col: _Collector, response: Any) -> list[RedirectHop]:
    hops: list[RedirectHop] = []
    request = response.request
    while request is not None and len(hops) < MAX_REDIRECT_HOPS:
        status: int | None = None
        try:
            prior = await request.response()
            status = prior.status if prior is not None else None
        except Exception:
            status = None
        hops.append(RedirectHop(url=col.public_url(request.url) or request.url, status=status, kind="http"))
        request = request.redirected_from
    hops.reverse()
    return hops


def _finish_requests(col: _Collector) -> None:
    final_host = col.features.final_host if col.features else None
    site = registrable_domain(final_host) if final_host else ""
    for record in col.requests:
        record.is_third_party = is_third_party(record.host, site)


# --- FILE jobs ----------------------------------------------------------------


async def _stage_file(col: _Collector) -> str | None:
    """Turn the staged input file into something Chromium can show safely, or
    explain why we are not opening it. Returns the ``file://`` URL to open."""
    job = col.job
    if not is_file_ref(job.file_ref):
        col.fail(f"file job needs a staged file: ref {job.file_ref!r}", "file")
        return None
    path = col.workdir / file_ref_name(job.file_ref)  # type: ignore[arg-type]
    if not path.is_file():
        col.fail(f"staged file missing: {job.file_ref}", "file")
        return None
    data = path.read_bytes()
    label = sniff_type(data)
    name = safe_filename(job.file_name, default="attachment.bin")
    ext = extension_of(name)
    view_dir = col.workdir / "view"
    view_dir.mkdir(exist_ok=True)

    if label == "pdf":
        return _stage_pdf(col, data, view_dir)
    if label == "html" or (label == "text" and ext in {"html", "htm", "xhtml", "svg", "mht", "mhtml"}):
        target = view_dir / "index.html"
        target.write_bytes(data)
        return target.as_uri()
    if is_image_type(label):
        target = view_dir / f"image.{'jpg' if label == 'jpeg' else label}"
        target.write_bytes(data)
        return target.as_uri()
    if label == "text":
        target = view_dir / "text.txt"
        target.write_bytes(data)
        return target.as_uri()

    if label in BROWSER_VIEWABLE_TYPES:  # pragma: no cover - every member handled above
        return None
    col.features = None
    col.note(
        f"file type not detonated in browser: {label} ({name}); Office/executable detonation needs the Windows chamber (future work)"
    )
    return None


def _stage_pdf(col: _Collector, data: bytes, view_dir: Path) -> str | None:
    """Headless Chromium downloads PDFs instead of rendering them, so we
    rasterize the pages ourselves (pymupdf) and wrap them in a local HTML page:
    the screenshot shows the document, QR codes in it decode, link targets
    are listed, and the extracted text feeds the brand/keyword checks."""
    import pymupdf

    try:
        doc = pymupdf.open(stream=data, filetype="pdf")
    except Exception as exc:
        col.fail(f"pdf could not be opened: {exc}", "file")
        return None
    parts = ["<!doctype html><html><head><meta charset='utf-8'><title>", html.escape(col.job.file_name or "document.pdf"), "</title>"]
    parts.append("<style>body{margin:0;background:#fff;font-family:sans-serif}img{display:block;max-width:100%}pre{white-space:pre-wrap;padding:12px}</style></head><body>")
    links: list[str] = []
    texts: list[str] = []
    try:
        count = doc.page_count
        for index in range(min(count, MAX_PDF_PAGES_RENDERED)):
            page = doc[index]
            pix = page.get_pixmap(dpi=96)
            png = view_dir / f"page_{index}.png"
            png.write_bytes(pix.tobytes("png"))
            parts.append(f"<img src='{png.name}' alt='page {index + 1}'>")
            texts.append(page.get_text("text") or "")
            for link in page.get_links():
                uri = link.get("uri")
                if uri and uri not in links:
                    links.append(str(uri)[:2000])
        if count > MAX_PDF_PAGES_RENDERED:
            col.note(f"pdf has {count} pages; rendered the first {MAX_PDF_PAGES_RENDERED}")
        if doc.xref_get_key(doc.pdf_catalog(), "OpenAction")[0] != "null" or _pdf_has_javascript(doc):
            col.note("pdf contains an OpenAction and/or JavaScript")
    except Exception as exc:
        col.note(f"pdf rendering stopped early: {str(exc)[:200]}")
    finally:
        doc.close()
    if links:
        parts.append("<h3>Links in document</h3><ul>")
        parts.extend(f"<li><a href='{html.escape(uri, quote=True)}'>{html.escape(uri)}</a></li>" for uri in links[:200])
        parts.append("</ul>")
    parts.append("<pre>")
    parts.append(html.escape("\n".join(texts))[:20000])
    parts.append("</pre></body></html>")
    target = view_dir / "index.html"
    target.write_text("".join(parts), encoding="utf-8")
    return target.as_uri()


def _pdf_has_javascript(doc: Any) -> bool:
    try:
        for xref in range(1, doc.xref_length()):
            obj = doc.xref_object(xref, compressed=True)
            if "/JavaScript" in obj or "/JS" in obj:
                return True
    except Exception:
        return False
    return False


# --- teardown -------------------------------------------------------------------


async def _shutdown(col: _Collector) -> None:
    """Close everything with short, independent timeouts. On a TIMEOUT we first
    grab a last screenshot: the page that would not finish loading is often
    the most interesting evidence."""
    if col.page is not None and col.screenshot_ref is None and col.status is not DetonationStatus.OK and col.main_frame_urls:
        try:
            path = col.workdir / SCREENSHOT_NAME
            await asyncio.wait_for(col.page.screenshot(path=str(path), type="jpeg", quality=SCREENSHOT_QUALITY, timeout=1500), timeout=2.0)
            col.screenshot_ref = f"file:{SCREENSHOT_NAME}"
        except Exception:
            pass
    for task in list(col.pending):
        task.cancel()
    for handle, closer in ((col.context, "close"), (col.browser, "close"), (col.playwright, "stop")):
        if handle is None:
            continue
        try:
            await asyncio.wait_for(getattr(handle, closer)(), timeout=5.0)
        except Exception:
            pass


# --- CLI -------------------------------------------------------------------------


def _write_result(result: DetonationResult, out: Path) -> None:
    out.write_text(result.model_dump_json(indent=2), encoding="utf-8")


def _emit_envelope(result: DetonationResult, workdir: Path, max_file_bytes: int | None) -> None:
    from .protocol import load_output

    output: SandboxOutput = load_output(result.model_dump(mode="json"), workdir)
    sys.stdout.write(encode_result_envelope(output, max_file_bytes=max_file_bytes) + "\n")
    sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m reddysec.chamber.detonate", description=__doc__.split("\n\n")[0])
    parser.add_argument("--job", type=Path, help="DetonationJob JSON file")
    parser.add_argument("--out", type=Path, help="where to write the DetonationResult JSON")
    parser.add_argument("--workdir", type=Path, help="scratch directory (default: a fresh temp dir)")
    parser.add_argument("--stdio", action="store_true", help="read a job envelope on stdin, write a result envelope on stdout")
    parser.add_argument("--env", action="store_true", help="read the job envelope from the RS_JOB environment variable")
    parser.add_argument("--max-file-bytes", type=int, default=None, help="drop envelope files larger than this")
    ns = parser.parse_args(argv)

    modes = sum(bool(x) for x in (ns.job, ns.stdio, ns.env))
    if modes != 1:
        parser.error("exactly one of --job, --stdio or --env is required")

    workdir = ns.workdir or Path(tempfile.mkdtemp(prefix="rs-det-"))
    workdir.mkdir(parents=True, exist_ok=True)

    if ns.job:
        job = DetonationJob.model_validate_json(ns.job.read_text(encoding="utf-8"))
        result = asyncio.run(detonate(job, workdir))
        if ns.out:
            _write_result(result, ns.out)
        else:
            sys.stdout.write(result.model_dump_json() + "\n")
        return 0 if result.status is not DetonationStatus.ERROR else 1

    raw = os.environ.get("RS_JOB", "") if ns.env else sys.stdin.read()
    if not raw.strip():
        sys.stderr.write("no job envelope provided\n")
        return 2
    job, files = decode_job_envelope(raw)
    write_job_files(files, workdir)
    result = asyncio.run(detonate(job, workdir))
    _emit_envelope(result, workdir, ns.max_file_bytes)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through the local backend
    sys.exit(main())

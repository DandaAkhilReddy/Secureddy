# Security model

Who we protect: a few private individuals on consumer mailboxes. Who attacks
them: phishing crews, business-email-compromise (wire fraud) crews, and
occasionally someone who targets them by name. What we hold on their behalf: a
token that can read and move their mail. That token is the crown jewel of this
system; most of the design below exists to protect it.

## 1. Threat model

| Attacker wants | How they would try | What stops it |
|----------------|--------------------|---------------|
| The client to open a malicious link or file | phishing mail | detonation before delivery; Hold mode; verdict labels; Reading Room for anything they still want to open |
| To learn who we protect | fingerprint the detonation visitor | jobs carry no client data (`models/jobs.py`); dirty egress IPs belong to the sandbox, never to the apps; a current desktop Chrome profile with human-like interaction |
| To attack us through the sandbox | browser exploit, drive-by download, request to internal services | ACI hypervisor isolation; one container per detonation, deleted afterwards; NSG denies all private ranges and IMDS; no identity in the container (Azure Policy); no shell/curl in the image; read-only, `/tmp` only |
| The Gmail tokens | steal the database, steal a backup, SQL injection | tokens encrypted with AES-GCM under a KEK that lives only in Key Vault and in process memory; database private, Entra admin, 35-day backups also encrypted; key id per ciphertext allows rotation |
| To take over the product | credential theft, exposed admin | Google, Microsoft or Yahoo sign-in (a local password only as an extra way in); optional two-step sign-in with an authenticator app on every sign-in (section 3a); Front Door WAF + rate limit; private origin; audit log of every privileged action |
| To make us release held mail | kill the worker | the dead man's switch does release mail after 10 minutes, on purpose: availability of mail beats security of mail. It pages us at the same time. |
| To hide in the data we keep | | we keep very little, for a short time (section 4) |

## 2. Isolation boundaries, outside in

1. **Edge**: Azure Front Door Premium. TLS 1.2+, managed certificate, WAF with
   Microsoft Default Rule Set 2.1 and Bot Manager 1.1 in Prevention mode, 300
   requests/minute per IP (3000 for `/hooks/*`). The origin is reached by
   Private Link; it has no public address.
2. **Apps subnet** (web, worker, deadman). Internal Container Apps environment,
   mTLS between apps, NSG denies anything from the detonation subnet. Each app
   has its own managed identity with the least roles it needs (table below).
   Egress via its own NAT gateway IP, so Google and IMAP providers never see a
   detonation address.
3. **Data subnet**. Key Vault, Blob Storage, Postgres and ACR are reachable
   only through private endpoints. Public network access is disabled on all
   four (Key Vault keeps a single operator IP until `--lockdown`). Storage has
   shared-key auth disabled; Service Bus has SAS auth disabled; ACR has the
   admin user disabled.
4. **Detonation subnet**. One ACI container group per detonation. ACI runs each
   group in its own lightweight VM (hypervisor isolation), so a kernel exploit
   from the browser stays in that VM. The NSG is deny-by-default both ways:
   inbound nothing; outbound only DNS to Azure DNS, 443 to the ACR private
   endpoint (two fixed IPs, image pull) and 80/443/53 to the Internet. RFC
   1918, carrier-grade NAT, the IMDS address and the whole VNet are denied
   explicitly. Egress goes through a NAT gateway with two public IPs reserved
   for this purpose: these are what the phishing site sees.
   Azure Policy on the detonation resource group denies container groups with
   a public IP, a restart policy other than Never, no subnet, or any managed
   identity, and denies every resource type other than container groups.
5. **The chamber process**. Non-root (uid 10001), no shell, no curl/wget/git,
   no pip, writable `/tmp` only. It receives the job in a secure environment
   variable and prints the result to stdout. It never talks to our data
   services; the worker collects the result through the ACI logs API and
   stores artifacts itself.

### Identities and roles

| Identity | Roles |
|----------|-------|
| web | AcrPull; Key Vault Secrets User; Storage Blob Data Contributor; Service Bus Data Sender |
| worker | AcrPull; Key Vault Secrets User; Storage Blob Data Contributor; Service Bus Data Owner; **Contributor on the detonation RG only**; Network Contributor on the detonation **subnet** only |
| deadman | AcrPull; Key Vault Secrets User; Storage Blob Data Reader; Service Bus Data Sender |
| github-deploy (OIDC) | Contributor + RBAC Administrator (conditioned) on both RGs; AcrPush; Key Vault Secrets Officer; Resource Policy Contributor at subscription scope |
| chamber container | none |

Nobody has a password or key for any Azure resource. The one standing
credential is the repository-scoped ACR token the chamber uses to pull its
image (pull of one repository, nothing else), stored in Key Vault, rotated
yearly.

## 3. Secrets

| Secret | Where it lives | Who can read it |
|--------|----------------|-----------------|
| Gmail refresh tokens, IMAP app passwords | Postgres, encrypted (`v1.<kid>.<AES-GCM>`) | web, worker, deadman via the KEK |
| `RS_TOKEN_KEK` | Key Vault `rs-token-kek` | the three app identities |
| `RS_SECRET_KEY` (CSRF/flow cookie, link and image signatures) | Key Vault | the three app identities |
| Claude access | nothing stored: keyless (Workload Identity Federation, `core/anthropic_auth.py`) trades the app's managed-identity token for a Claude token that lives minutes, in memory. A static `rs-anthropic-api-key` is only a fallback | web, worker |
| Sign-in sessions | Postgres `user_sessions`: only SHA-256 of the 256-bit cookie token | nobody can turn a row back into a cookie |
| App lock PINs / passwords | Postgres `app_locks`: argon2id hashes | nobody |
| Authenticator (TOTP) secrets | Postgres `users.totp_secret_enc`, AES-GCM under the KEK with the user id as associated data | web, via the KEK |
| Two-step recovery codes | Postgres `mfa_recovery_codes`: argon2id hashes, each usable once | nobody |
| "Remember this device" tokens | Postgres `mfa_trusted_devices`: SHA-256 of a random 256-bit cookie token, 30 days | nobody can turn a row back into a cookie |
| Google client secret | Key Vault | the three app identities |
| Postgres admin password | Key Vault; also inside `rs-database-url` | the three app identities; operator |
| ACR chamber pull token | Key Vault | worker |
| nothing | the chamber container | |

Key Vault: RBAC mode, soft delete 90 days, purge protection, audit logs to Log
Analytics. Secret values never appear in Bicep or deployment history; the
bootstrap script writes them.

How a stolen secret would be noticed and limited:

- **Logs never carry secrets.** Every structlog event and every standard
  library log record passes through `core/redact.py`, which masks values of
  keys such as `access_token`, `refresh_token`, `app_password`, `password`,
  `authorization`, `assertion`, and anything that looks like an Anthropic key
  (`sk-ant-…`), a Google client secret (`GOCSPX-…`), a GitHub token, a bearer
  token, a JWT or `user:password@` in a URL. `repr(Settings)` masks them too,
  and error pages show plain sentences, never exception text.
- **Git never carries secrets.** `gitleaks` runs on every push and pull request
  over the full history (`.github/workflows/security.yml`, `.gitleaks.toml`) and
  as a pre-commit hook. OAuth client ids and Azure/Entra object, client and
  tenant ids are public identifiers and may appear in `infra/azure/*.bicepparam`
  and the docs; nothing else may.
- **Mail tokens** are AES-GCM encrypted with the mailbox id as associated data
  under a KEK that lives only in Key Vault (`core/crypto.py`), so a database
  copy without the KEK is useless and a row copied onto another mailbox fails
  to decrypt.

## 3a. Browser sessions and the app lock

- **Sign-in** is a server-side session: the `rs_sid` cookie holds a random
  256-bit token (HttpOnly, SameSite=Lax, Secure in production, Path=/); the
  database keeps only its hash. It slides forward with use (90 days idle,
  renewed at most hourly) and ends one year after sign-in regardless. Sign out,
  "Sign out everywhere", signing out one device from Settings, a password change
  and an app-lock change revoke rows at once. The signed `rs_session` cookie
  holds only the CSRF token, flash messages and OAuth flow state; it identifies
  nobody.
- **App lock** (optional): a 6-digit PIN or a password (argon2id) and/or
  passkeys (WebAuthn, user verification required). Lock state lives on the
  server session; a locked session reaches only `/lock`, pages redirect there
  and JSON or event-stream requests get `423 Locked`. Five wrong answers pause
  unlocking for 15 minutes; ten sign the person out on every device. "Forgot
  PIN" is a full sign-in with Google, Microsoft, Yahoo or the password.
- **Ways to sign in**: more identities (Google, Microsoft, Yahoo) can be added
  to the same account only while signed in on that device (the OAuth state
  carries the account id and is checked against the session at the callback).
  An identity already linked to another account is refused; at least one way
  in always remains. Email addresses alone never link accounts.

- **Two-step sign-in** (optional, `web/mfa.py`): a TOTP authenticator app
  (Microsoft Authenticator, Google Authenticator, Authy; 6 digits, 30 s,
  SHA-1). Setup shows a QR code drawn server side as inline SVG and the key in
  groups of four; the secret is stored only after one correct code. When it
  is on, every sign-in (Google, Microsoft, Yahoo, password, developer) stops
  before a session exists: the pending sign-in waits 10 minutes in the signed
  flow cookie and `/auth/mfa` asks for a code or one of 10 single-use
  recovery codes (argon2id). A code is accepted once (the last accepted time
  step is stored; the same or an older code is refused), with one step of
  clock drift either way. Five wrong codes in 15 minutes pause code entry for
  that person for the rest of the 15 minutes, everywhere a code is asked:
  sign-in, unlocking, turning it off and new recovery codes. "Remember this
  device for 30 days" keeps a random token in an HttpOnly cookie
  (`rs_mfa_dev`) and its hash on the server; signing that device out, "Sign
  out everywhere", "Forget all" and turning two-step off forget it. Turning
  it off needs a current code (or a recovery code). The authenticator code
  also unlocks the app lock.

## 3b. Reading mail inside Secureddy

- The body is fetched live from the provider when the person opens "Read
  email", sanitised server side (`web/mailview.py`, nh3/ammonia allowlist,
  CSS property allowlist, no `url()`/`expression()`), and returned with
  `Cache-Control: no-store, private` and its own CSP
  (`default-src 'none'; img-src data: <origin>; style-src 'unsafe-inline';
  form-action 'none'; base-uri 'none'; frame-ancestors 'self'`). It is shown in
  an `<iframe sandbox="allow-top-navigation-by-user-activation">`: no scripts,
  no same-origin access, no forms. Nothing is stored.
- Every link goes to `/go`, which shows our verdict and the engine's
  `click_advice` (safe to open / Reading Room only / do not open). The target
  is HMAC-signed with the message id, so `/go` is not an open redirect.
- Remote images are blocked until "Load images"; then each one is fetched by
  our server (signed URL, no cookies, no referrer, tracking parameters removed,
  raster types only, 5 MB cap, every redirect hop re-checked) and private,
  loopback, link-local (including the metadata and managed-identity
  endpoints) and carrier-grade-NAT addresses are refused.
- Attachments: the original only when our verdict for that file is safe;
  otherwise the flattened safe copy.
- The assistant never sees a body unless the person ticks "Let the assistant
  read this email" for that one email; then at most 6,000 characters of plain
  text go to the model once, wrapped as untrusted data, and an
  `assistant_read_email` row is written to the audit log.

## 4. Data minimization and retention

- **Never stored**: message bodies, attachments as received, the client's
  contacts beyond sender addresses seen, the content of pages visited in the
  Reading Room.
- **Stored**: message metadata (from, subject, received time, counts), verdicts
  and signals, detonation results (URLs, hosts, form fields seen, screenshot),
  sender history per mailbox, audit log, notification log.
- **Artifacts** (screenshots, downloaded files, sanitized copies): Blob
  container `artifacts`, deleted 30 days after last write by a lifecycle rule.
  Blob soft delete is off so "deleted" means gone.
- **Quarantined originals**: Blob container `quarantine-originals`, 90 days.
  Only the quarantined message's raw bytes, so a false positive can be
  recovered after the client's provider has expired it.
- **Logs**: 90 days (prod). Log lines carry ids and verdict codes, not
  addresses, subjects or bodies (`core/logging.py`).
- **Backups**: Postgres 35 days, geo-redundant. The same encryption applies;
  a restored backup needs the KEK to be useful.

## 5. Who can see what

| Role | Sees |
|------|------|
| principal (the client) | their mailboxes, verdicts, screenshots, quarantine, audit log of actions on their mailboxes |
| family | the principal's verdicts; can release quarantined mail only if the principal allows it |
| assistant | like family, plus the Reading Room |
| concierge (our analyst) | verdicts and detonation evidence for every client; no raw mail; every view is in the audit log |
| admin (Reddy) | everything above plus user management; still no mail bodies, because none are stored |

Every privileged action (release, quarantine, restore, mode change, token
reconnect, admin login) is a row in `audit_log` and shown to the client.

## 6. What this product does not stop

Say this to clients plainly.

- **Zero-click exploits** on their phone or laptop (iMessage, WhatsApp, PDF
  renderer bugs). Nothing in the mail path touches that.
- **SMS, WhatsApp, Signal, Telegram phishing**. We see email only.
- **Account takeover without email**: SIM swap, password reuse on another
  site, a stolen session cookie.
- **Deepfake voice or video calls** asking for a wire. The BEC detector
  catches the *email* that sets up the call, not the call.
- **A compromised mailbox provider or Google account**: if the attacker is
  already inside Gmail, labels and quarantine are theirs to undo.
- **Malicious attachments we cannot open**: encrypted archives, unusual
  formats. We mark them Suspicious and leave the decision to the client.
- **Time-delayed or targeted payloads**: a page that is clean for our
  detonation IPs and malicious for the client's. We detonate with a realistic
  profile and the Reading Room exists for exactly this case, but the gap is real.

## 7. Hygiene we enroll every client in

Part of onboarding, done together on their devices:

- **Google Advanced Protection Program** with two hardware security keys
  (one on the keyring, one in a drawer). It blocks password phishing of the
  Google account itself and restricts third-party app access, which is why our
  OAuth client must be verified before APP users can approve it.
- **Apple Lockdown Mode** on iPhone, iPad and Mac for anyone who has been
  targeted before. It disables the attachment previews and link previews that
  zero-click exploits use.
- Phone carrier account PIN / port-out lock (SIM swap).
- A separate, never-published email address for banking and brokers.
- A standing rule with their bank and their office: wire instructions by email
  are never acted on without a call-back to a known number.
- Password manager, and passkeys where offered.

## 8. What we monitor

Dead man's switch firing or failing (severity 0), deadman replica missing (0),
worker replica missing or crash-looping (1), ACI create failures, 5xx at the
edge and at the app, origin health, Postgres storage, application error
bursts, and the monthly budget. Everything logs to
one Log Analytics workspace with 90-day retention. See `operations-runbook.md`.

## 9. Known gaps and next steps

- Chamber image is the full Playwright image (~1 GB compressed). A
  Chromium-only build from `python:3.12-slim` is smaller, faster to start and
  has less in it to abuse.
- Reading Room v1 runs inside the web replicas. Phase 2 moves each session to
  its own sandbox pod with the same isolation as a detonation.
- The image proxy checks DNS before connecting; a host that changes its
  answer between the check and the fetch (DNS rebinding) could still reach a
  private address once. Pinning the resolved IP in the connection closes it.
- Postgres uses password auth for the app. Moving the three identities to
  Entra token auth removes the last database password.
- Service Bus is Standard tier (public endpoint, Entra-only auth). Premium
  buys a private endpoint for about USD 680/month.
- `TokenCipher.from_settings` reads one key; the dual-key rotation window
  (`RS_TOKEN_KEK_PREVIOUS`) needs a small change in `core/crypto.py` and `config.py`.
- CASA Tier 2 assessment for the Gmail restricted scope is a yearly external
  review; this document is the starting point for it.

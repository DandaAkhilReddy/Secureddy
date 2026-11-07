# Secureddy

A bodyguard for a private client's inbox. Every email with a link or an
attachment is opened first inside a disposable, isolated environment. The
client sees a verdict in plain English, and when they want to open a link
themselves they open it in the **Reading Room**: a browser that runs on our
servers and streams only pixels to their device.

Built for people who use consumer mailboxes (Gmail, Yahoo, iCloud,
Outlook.com), where enterprise email security products do not reach.

## How it works (one paragraph)

The client signs in with Google, Microsoft or Yahoo (or adds an IMAP
mailbox). We ask Gmail or Microsoft Graph for the minimum access needed to
read, label and move mail; Yahoo Mail connects with an app password. New messages are
fetched within seconds. Messages without links or attachments are released at
once. Messages with links or attachments go through static analysis (sender
authentication, lookalike domains, domain age, attachment type checks, QR
codes, wire-fraud language) and, when needed, the **detonation chamber**: a
sandboxed Chromium that follows every redirect, records every request, and
looks for credential-harvesting forms, brand impersonation and drive-by
downloads. The result is a score, a verdict (Checked / Suspicious /
Quarantine) and a short explanation. In **Hold mode** the message does not
reach the inbox until the verdict exists; a dead man's switch releases
everything if our pipeline ever stops.

## Repository layout

```
src/reddysec/
  models/     shared data contracts (start here)
  core/       crypto (token encryption), ids, artifact store, job queue, logging
  analysis/   parsing, URL + attachment analysis, intel, BEC, policy, scoring, pipeline
  chamber/    detonation backends (local / docker / Azure ACI), Reading Room (RBI), CDR
  mail/       Gmail (OAuth + API), Microsoft Graph (Outlook.com / Microsoft 365) and IMAP
              (Yahoo / iCloud / Outlook.com app passwords) connectors; Google, Microsoft and
              Yahoo sign-in
  store/      SQLAlchemy schema (metadata + verdicts only; never bodies)
  worker/     the processing loop and verdict actions
  web/        FastAPI app: sign-in, onboarding, dashboard, reports
tests/
  unit/ functional/ integration/ fixtures/
infra/azure/  Bicep for the production deployment
docker/       images and docker-compose for local full-stack runs
docs/         runbooks (Google OAuth client setup, Azure deployment, operations)
```

## Quick start (development)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m playwright install chromium
cp .env.example .env            # then fill RS_GOOGLE_CLIENT_ID / SECRET
reddysec init-db
reddysec web                     # http://localhost:8000
reddysec worker                  # in a second terminal
```

Schema upgrades: `reddysec migrate` (also run by `init-db`, by the worker at
startup and by the web app in dev) creates missing tables, widens columns
whose models became wider (PostgreSQL), merges duplicate mailboxes and adds
the one-mailbox-per-address index. It is idempotent and takes a PostgreSQL
advisory lock, so several processes may run it at once.

Run the tests:

```bash
pytest                           # unit + functional
pytest -m integration            # real browser detonations and the Reading Room
pytest -m postgres               # against real PostgreSQL: RS_TEST_POSTGRES_URL, or a local
                                 # install (initdb); skipped when neither is there
pytest --cov=reddysec --cov-report=term-missing
```

See `docs/` for the Google OAuth setup, Azure deployment and the operations
runbook.

## Status (5 Nov 2026)

What runs today, end to end, in this repository:

- Gmail OAuth sign-in and connector (labels, Hold-mode filter, history
  polling, Pub/Sub push decoding, quarantine/release, dead man's switch).
- IMAP connector for Yahoo, iCloud and Outlook.com (app passwords).
- Full analysis engine: parsing, URL extraction (including QR codes and PDFs),
  lookalike domains, attachment static analysis (macros, PDF JavaScript,
  encrypted archives with the password in the body, HTML smuggling), wire-fraud
  language, triage lanes, scoring, plain-English summaries.
- Detonation chamber on Chromium with three backends: local process (dev),
  Docker (hardened container on a dirty network), Azure Container Instances
  (one hypervisor-isolated container group per detonation).
- Reading Room: pixel-streamed isolated browser with safe-copy downloads.
- Sender trust (`analysis/trust.py`): mail Google verified as coming from a
  mailing-list sender is not accused on wording alone; lookalikes, known-bad
  sites, credential pages, malware and dangerous files always count.
- Learning from the client: "This is safe" / "This is fake" on every report,
  a trusted & blocked senders list per mailbox, and "Check again" /
  "Re-check last 7 days" to re-label mail with today's rules.
- Web app: dashboard, reports with sandbox screenshots, mailbox onboarding,
  concierge queue, audit log, TOTP.
- "Not suspicious?" / "This is fake" on every flagged email, with a quick-pick
  reason and optional note (stored in `feedback_reasons`, shown on the report,
  the audit log and the concierge queue; it never changes the trust math).
- "Ask Secureddy" (`src/reddysec/assistant/`): an in-app chat that answers
  questions about the client's own verdicts with read-only tools. It can only
  *propose* "mark safe / fake / check again"; the client clicks the real
  button. Switch it on with `RS_ASSISTANT_PROVIDER` (anthropic,
  azure_foundry, azure_openai; empty follows `RS_LLM_PROVIDER`) and the
  existing API key settings; optional `RS_ASSISTANT_MODEL`,
  `RS_ASSISTANT_MAX_TURNS` (6), `RS_ASSISTANT_DAILY_MESSAGE_LIMIT` (200).
- Azure infrastructure as Bicep (validated), Dockerfiles, CI/CD, runbooks.

## Status (6 Nov 2026): Microsoft, Yahoo, "Not fake", installable app

- **Sign in with Microsoft** (`mail/oauth_microsoft.py`): personal and work
  accounts, Authorization Code + PKCE, client authentication with a
  certificate (RFC 7523 client assertion, RS256, `x5t` thumbprint) because the
  tenant forbids client secrets. ID tokens are checked against Microsoft's
  published keys, the per-tenant issuer, audience, expiry and nonce. Settings:
  `RS_MICROSOFT_CLIENT_ID`, `RS_MICROSOFT_CLIENT_CERT` (Key Vault
  `rs-microsoft-client-cert`), `RS_MICROSOFT_CERT_THUMBPRINT` (Key Vault
  `rs-microsoft-cert-thumbprint`), `RS_MICROSOFT_AUTHORITY`,
  `RS_MICROSOFT_REDIRECT_PATH`.
- **Outlook / Microsoft 365 mail over Graph** (`mail/outlook_graph.py`):
  folders `Secureddy/Checking` and `Secureddy/Quarantine`, coloured
  categories for verdicts, delta-query polling, immutable message ids,
  Retry-After throttling, token rotation persisted to the vault. Hold mode is
  an inbox rule with no conditions that moves new mail to Checking: **validate
  it on a real mailbox before offering Hold mode on Microsoft accounts.**
- **Sign in with Yahoo** (`mail/oauth_yahoo.py`, sign-in only:
  `RS_YAHOO_CLIENT_ID` / `RS_YAHOO_CLIENT_SECRET`). Yahoo Mail itself connects
  on a "Connect your Yahoo Mail" page with an app password that is tested with
  a real IMAP login before it is saved. The XOAUTH2 path is ready for the day
  Yahoo approves us for its Mail API (see the module docstring).
- **Accounts and linking** (`user_identities` table): one account per person,
  any number of mailboxes. A sign-in is matched to an existing account by
  email only when the provider verified the email (Google; Microsoft work
  accounts with `xms_edov`; Yahoo's `email_verified`) or a Microsoft work
  account already linked in the same tenant. Otherwise: "Already have an
  account? Sign in first, then connect this mailbox." "Connect another
  mailbox" on the Mailboxes page links by the signed-in session (POST + CSRF,
  checked again in the signed state), never by email.
- **"Not fake?"** on quarantined email (reasons: I know this sender, I was
  expecting this, It's from a company I use, Other). **Trust never skips the
  checks**: a sender the client trusts still has its links opened in the
  sandbox. A clean result reads "Confirmed again"; anything serious reads
  "This sender is on your trusted list, but this email looks different" and
  sends a notification. `Verdict.trust_check` carries the outcome; the
  Mailboxes page shows the reason, the date and "last confirmed · N emails
  checked since" (`sender_trust_stats`).
- **Installable web app**: manifest, service worker (shell only; pages are
  network-first and never cached; private paths never touched), offline
  page, install button (Chromium) and a one-time iOS hint. Bottom tab bar and
  action sheet on phones, sidebar on laptops, warm light theme
  (`prefers-color-scheme` or Settings).

Test suite: 1,944 tests (1,911 unit and functional, 33 browser integration,
including an end-to-end scenario that pushes a phishing email through the
real parser, analyzer and Chromium sandbox into quarantine and the
dashboard). Coverage 95.9% (line + branch, both suites).

Not built yet, on purpose: a Windows chamber for Office/executable
detonation (attachments are analysed statically and flattened to safe PDFs
instead), per-session sandbox pods for the Reading Room (v1 runs sessions in
the web process), and Yahoo Mail OAuth (needs Yahoo's partner approval; app
passwords work now). The Gmail Hold-mode filter and the Microsoft Hold-mode
inbox rule must be validated against real mailboxes before anyone relies on
them.

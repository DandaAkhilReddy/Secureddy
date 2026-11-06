# Secureddy

A bodyguard for a private client's inbox. Every email with a link or an
attachment is opened first inside a disposable, isolated environment. The
client sees a verdict in plain English, and when they want to open a link
themselves they open it in the **Reading Room**: a browser that runs on our
servers and streams only pixels to their device.

Built for people who use consumer mailboxes (Gmail, Yahoo, iCloud,
Outlook.com), where enterprise email security products do not reach.

## How it works (one paragraph)

The client signs in with Google (or adds an IMAP mailbox). We ask Gmail for
the minimum access needed to read, label and move mail. New messages are
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
  mail/       Gmail (OAuth + API) and IMAP (Yahoo / iCloud / Outlook.com) connectors
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

Run the tests:

```bash
pytest                           # unit + functional
pytest -m integration            # real browser detonations and the Reading Room
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
- Azure infrastructure as Bicep (validated), Dockerfiles, CI/CD, runbooks.

Test suite: 1,379 tests (unit, functional, browser integration, and an
end-to-end scenario that pushes a phishing email through the real parser,
analyzer and Chromium sandbox into quarantine and the dashboard). Coverage
94.9% (line + branch).

Not built yet, on purpose: a Windows chamber for Office/executable
detonation (attachments are analysed statically and flattened to safe PDFs
instead), per-session sandbox pods for the Reading Room (v1 runs sessions in
the web process), and Yahoo OAuth (needs Yahoo's partner approval; app
passwords work now). The Gmail Hold-mode filter must be validated against a
real mailbox before anyone relies on it.

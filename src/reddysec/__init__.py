"""Secureddy.

Pre-delivery detonation of email links and attachments, plus an isolated
"Reading Room" browser, for private clients who use consumer mailboxes
(Gmail, Yahoo, iCloud, Outlook.com).

Package map
-----------
models/    shared data contracts (Pydantic). Every other package speaks these.
core/      config-free utilities: crypto, ids, artifact store, job queue, logging.
analysis/  static analysis, threat intel, BEC heuristics, triage policy, scoring.
chamber/   the detonation chamber (sandboxed browser) and the Reading Room (RBI).
mail/      mailbox connectors: Gmail API (OAuth), IMAP (Yahoo, iCloud, Outlook.com).
store/     SQLAlchemy persistence (SQLite in dev, PostgreSQL in production).
worker/    the processing loop: poll mailboxes -> parse -> analyze -> act -> notify.
web/       FastAPI application: sign-in, mailbox onboarding, dashboard, reports.
testing/   fakes shared by the test suites.
"""

__version__ = "0.1.0"
ENGINE_VERSION = "rs-engine/0.1.0"

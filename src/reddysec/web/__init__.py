"""FastAPI web application: sign-in, mailbox onboarding, dashboard and reports.

The web layer is the only part of the product the client ever sees, so two
rules shape everything in this package:

* Plain English first. Verdicts, actions and audit entries are written for a
  non-technical reader (or their assistant), never for an analyst.
* Nothing in the browser can hurt the client. Links from scanned email are
  never rendered as clickable anchors; they open only through the isolated
  Reading Room. Every form is CSRF-protected and every response carries a
  strict Content-Security-Policy.

Entry point: :func:`reddysec.web.app.create_app`.
"""

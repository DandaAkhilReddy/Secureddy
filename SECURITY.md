# Security policy

Secureddy reads people's email. We take reports seriously and answer quickly.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private
"Report a vulnerability" button on the Security tab of this repository
(Security → Advisories → Report a vulnerability).

Tell us what you found, how to reproduce it, and what an attacker could do
with it. We will:

- confirm we received it within 3 working days,
- tell you within 10 working days whether we accept it and how we will fix it,
- credit you in the release notes if you would like.

Please give us 90 days to fix it before you talk about it publicly, and do not
access other people's mail or data while testing. Testing your own self-hosted
copy is always fine.

## Supported versions

Only the latest release on `main` gets security fixes. If you self-host,
update regularly.

## How Secureddy protects mail (short version)

The full model is in [docs/security-model.md](docs/security-model.md).

- **Mail bodies are never stored.** We keep metadata and verdicts. The
  "Read email" view fetches the message live and sends it with
  `Cache-Control: no-store`, sanitised, in a sandboxed frame with its own
  strict Content Security Policy.
- **Provider tokens and app passwords** are encrypted (AES-GCM) with a key
  that lives only in Azure Key Vault.
- **No API keys need to exist.** Claude is reached with Workload Identity
  Federation (short-lived tokens from the app's managed identity). Azure
  resources use managed identities too.
- **Sign-in sessions** are server-side and revocable; cookies are HttpOnly,
  SameSite=Lax and Secure. Optional app lock with a PIN, password or passkey.
- **Links** in rendered mail go through a signed warning page that shows our
  verdict; dangerous ones are not opened on the person's device.
- **The assistant** can only read verdicts and metadata for the signed-in
  person, proposes actions the person must confirm, and treats email content
  as untrusted data.
- **Secrets never reach git or logs**: gitleaks runs in CI over the whole
  history and as a pre-commit hook; logs pass through a redaction filter.

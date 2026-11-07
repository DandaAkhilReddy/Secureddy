# Test plan and traceability

Every feature, and the tests that prove it. Paths are under `tests/`.
U = unit, F = functional, P = PostgreSQL, I = integration (real Chromium or
local servers). How to run each suite: [TESTING.md](../TESTING.md).

## 1. Which emails we check (links, buttons, files only)

| Requirement | Tests |
|-------------|-------|
| Actionable = a clickable http(s) link (anchor, button, image map, form action, bare URL), QR code in an image or PDF, link inside an attachment, a real attached file, or a calendar invite with a link | U `unit/analysis/test_actionable.py::TestActionable`; F `functional/analysis/test_text_only_corpus.py::test_actionable_corpus_is_checked` |
| Not actionable: plain text, mailto/tel/sms, cid:, tracking pixels / image src, unsubscribe-only footers, S/MIME and PGP signatures, bounces and read receipts, link-less invites, inline pictures | U `test_actionable.py::TestTextOnly`; F `test_text_only_corpus.py::test_text_only_corpus_is_skipped` |
| An "Unsubscribe" lure to a stranger's domain is still checked; a newsletter with content links is checked | U `test_actionable.py::test_fake_unsubscribe_link_to_a_stranger_is_checked`, `test_newsletter_with_content_links_is_actionable`; F `test_text_only_corpus.py::test_fake_unsubscribe_lure_is_still_analysed_like_any_link` |
| Form actions are extracted as links | U `test_actionable.py::test_form_action_and_button_formaction_are_links` |
| Every corpus email with a link or file is still checked (false-positive corpus stays SAFE, attack corpus stays caught) | F `test_text_only_corpus.py::test_existing_corpus_with_links_or_files_is_still_checked`, `test_false_positives.py`, `test_lure_corpus.py`, `test_corpus.py` |
| Text-only email: no row, no label, no notification, no audit, only the operations counter | F `functional/worker/test_worker_text_only.py::TestScan` |
| HOLD: text-only released at once, Checking label removed, never trapped; provider "not found" tolerated; outage retried | F `test_worker_text_only.py::TestHold`; U `unit/mail/test_mail_text_only_worker.py` (real Gmail, IMAP and Graph connectors); I `integration/test_end_to_end.py` |
| "Also watch text-only emails for money scams": off by default; on = only scam-like text-only mail is checked; trusted senders skipped; heuristic bugs never stop a mailbox | F `test_worker_text_only.py::TestWatchTextScams`; U `test_actionable.py::TestTextScams`; F `test_text_only_corpus.py::test_text_only_money_scams_are_caught_when_watched` |
| Out-of-office replies do not trip the money-scam check (soft tells only count together) | U `test_actionable.py::test_soft_tells_count_only_together`; F `test_text_only_corpus.py` (`out_of_office`) |
| Backfill skips text-only mail without fetching it twice; audit counts only checked email | F `test_worker_text_only.py::test_backfill_skips_text_only_without_looping` |
| Re-check of a stored text-only email forgets it; a quarantined one is re-checked normally | F `test_worker_text_only.py::test_rescore_*` |
| Startup migration and `reddysec purge-text-only` remove old text-only rows (and their notifications, reasons, detonations, "verdict" audit), keep quarantined / waiting / BEC rows, idempotent | U `unit/store/test_people.py::TestPurgeTextOnly`, `unit/worker/test_cli.py::test_purge_text_only`; P `postgres/test_postgres_people.py` |
| Operations counter per mailbox per day, never shown | U `test_people.py::TestCounters`; F `functional/web/test_web_text_only_ui.py::test_account_card_says_plain_text_is_not_checked_without_a_number` |
| Copy: account card line, "We checked N emails with links or files", Email list, assistant prompt and tools | F `test_web_text_only_ui.py`, `test_web_dashboard.py`, `test_web_periods.py`; U `unit/web/test_web_unit_presenters.py::TestSentences` |
| Settings toggle (on/off, audited, CSRF) | F `test_web_text_only_ui.py::test_settings_choice_defaults_off_and_round_trips`; I `integration/test_browser_web.py::test_text_only_scam_choice_saves_itself` |

## 2. Who can use it (invite-only, 5 people, free)

| Requirement | Tests |
|-------------|-------|
| New account only with an open invite for the exact verified email and a free place; calm "invite-only" page otherwise | F `functional/web/test_web_people.py::TestInviteOnlySignIn` (Google, Microsoft, Yahoo); U `unit/store/test_people.py::TestCheckSignup`; P `test_postgres_people.py::test_invite_only_google_sign_in_on_postgres` |
| Existing accounts never locked out, even when full; disabled accounts free a place | F `test_web_people.py::test_full_house_refuses_new_people_but_never_existing_ones` |
| Unverified email never opens an account in invite-only mode | F `test_web_people.py::test_microsoft_needs_a_verified_email`; U `test_people.py` |
| Password sign-in never creates accounts | F `test_web_people.py::test_password_sign_in_never_creates_accounts` |
| Open mode for self-hosters (no invite, still capped) | F `test_web_people.py::test_open_mode_lets_anyone_in_up_to_the_cap`; U `test_people.py::test_open_mode_needs_no_invite_but_keeps_the_cap` |
| First admin = bootstrap email only (at sign-in and by migration); unverified look-alike never promoted | F `test_web_people.py::TestBootstrapAdmin`; U `test_people.py::TestBootstrapAdmin`, `TestPromoteBootstrapAdmin`; P `test_postgres_people.py` |
| People page: admins only; list (methods, mailboxes, last active, places used); invite, withdraw, turn off (sessions revoked, mailboxes paused), turn on (resumes those), change role; guard rails; audit | F `test_web_people.py::TestAdminPage`; I `integration/test_browser_web.py::test_admin_people_page_invites_and_fits_a_phone` |
| CLI `invite`, `make-admin`, `list-users` | U `unit/worker/test_cli.py::TestPeopleCommands` |
| Settings and Bicep parameters (`maxUsers`, `signupMode`, `bootstrapAdminEmail`) | U `test_people.py::TestPolicy`; `bicep build` / `build-params` (see TESTING.md) |
| No payments anywhere | Review: no payment code or dependency; People page states it |

## 3. Mail connectors and the worker

| Feature | Tests |
|---------|-------|
| Gmail (labels, hold filter, history, backfill, release, quarantine, restore, mark safe, watch, search, archive, trash, revoke) | U `unit/mail/test_mail_gmail.py`, `test_mail_actions.py`, `test_mail_client_actions.py` |
| Microsoft Graph (folders, categories, delta, hold, release) | U `unit/mail/test_mail_graph.py`, `test_mail_factory_microsoft.py`, `test_mail_oauth_microsoft.py` |
| IMAP (Yahoo, iCloud, Outlook.com) | U `unit/mail/test_mail_imap.py` |
| OAuth and the credential vault | U `test_mail_oauth.py`, `test_mail_oauth_yahoo.py`, `test_mail_vault.py`, `test_mail_factory.py` |
| Scan and Hold flows, timeouts, crashes fail open, notifications | F `functional/worker/test_worker_flows.py`; I `integration/test_end_to_end.py` |
| Backfill, retries with growing pause, mailbox errors | F `test_worker_backfill_and_retry.py` |
| "This is fake / safe", check again, restore | F `test_worker_client_requests.py` |
| Trusted senders re-checked, "trusted sender sent something unusual" | F `test_worker_trust_recheck.py`, `unit/analysis/test_trust.py` |
| Paused Hold mailbox: hold rule lifted, held mail released, re-armed on resume | F `test_worker_text_only.py::TestPausedHold` |
| Signing out of a Hold mailbox releases first | F `functional/web/test_web_hold_safety.py` |
| Dead man's switch | U `unit/worker/test_worker_deadman.py`; F `test_worker_flows.py` |
| Second-opinion model wiring | F `test_worker_llm_wiring.py`, U `unit/analysis/test_llm_providers.py` |

## 4. Analysis and detonation

| Feature | Tests |
|---------|-------|
| Parsing, auth results, URLs, QR, PDFs, redirects | U `unit/analysis/test_parser*.py`, `test_urls.py`, `test_redirects.py`, `test_headers.py` |
| Attachments, CDR, lures | U `test_attachments*.py`, `unit/chamber/test_cdr.py`, `test_lures.py` |
| BEC, sender trust, scoring, click advice | U `test_bec.py`, `test_trust*.py`, `test_scoring.py`, `test_click_advice.py`, `test_policy.py`, `test_pipeline.py` |
| Sandbox (local Chromium, Docker, ACI) | U `unit/chamber/*`; I `integration/chamber/test_detonate_integration.py`, `test_lures_integration.py` |
| ClickFix / AiTM / tech-support / wallet drainer in a real browser | I `integration/chamber/test_lures_integration.py` |

## 5. Web app

| Feature | Tests |
|---------|-------|
| Sign in with Google / Microsoft / Yahoo / password / developer; identities; account-takeover rules | F `test_web_auth.py`, `test_web_identities.py`, `test_web_people.py` |
| Two-step sign-in (TOTP, recovery codes, remembered devices) | F `test_web_mfa.py`; U `unit/web/test_web_unit_mfa.py`; I `test_browser_web.py::test_two_step_sign_in_in_a_browser` |
| App lock (PIN, password, passkey), sessions and devices | F `test_web_sessions_lock.py`; I `test_browser_web.py::test_pin_lock_on_a_phone` |
| Accounts page, merge/separate inbox views, periods | F `test_web_mailboxes.py`, `test_web_accounts_mail.py`, `test_web_periods.py`, `test_web_dashboard.py` |
| Email list, search (stored and live), report page | F `test_web_messages.py`, `test_web_accounts_mail.py` |
| Read view sanitizer, image proxy, /go interstitial | U `unit/web/test_web_unit_mailview.py`; F `test_web_accounts_mail.py`; I `test_browser_web.py::test_read_email_in_sandboxed_frame` |
| Reading Room | U `unit/chamber/test_readingroom*.py`, `unit/web/test_room_glue.py`; I `integration/chamber/test_readingroom_integration.py` |
| Assistant (fake model, streaming, cards, proposals, daily limit) | U `unit/assistant/*`; F `test_web_assistant.py`, `test_web_accounts_mail.py`; I `test_browser_web.py` |
| Settings, theme | F `test_web_settings.py`, `test_web_theme.py`, `test_web_text_only_ui.py`; I `test_browser_web.py::test_appearance_*` |
| Sender feedback with reasons, concierge, audit log | F `test_web_sender_feedback.py`, `test_web_feedback_reasons.py`, `test_web_concierge_audit.py` |
| PWA, Gmail push hook, JSON API | F `test_web_pwa_and_trust.py`, `test_web_hooks_api.py` |

## 6. Security

| Requirement | Tests |
|-------------|-------|
| Another person gets 404/403 on **every** route that takes an id (routes enumerated from the app; a new id kind fails the test) | F `functional/web/test_web_authz_matrix.py` |
| CSRF on every POST | F `test_web_security.py::test_every_post_route_requires_csrf` (also enumerated from the app) |
| Secrets never in pages, logs or `repr(settings)` | F `test_web_authz_matrix.py::test_secrets_never_reach_pages_or_logs`; U `unit/test_core_secrets.py` |
| Security headers and CSP on pages, errors, health and static files | F `test_web_security.py`, `test_web_authz_matrix.py::test_headers_and_csp_on_every_kind_of_response` |
| Session cookies, tampering, HSTS in prod | F `test_web_security.py`; U `unit/web/test_web_unit_security.py` |
| Reading Room belongs to its owner | U `unit/chamber/test_readingroom_web.py` (`wrong_principal` cases) |

## 7. Database

| Requirement | Tests |
|-------------|-------|
| Column sizes safe on PostgreSQL | U `unit/store/test_column_sizes.py`; P `postgres/test_postgres_schema.py` |
| Upgrades of existing databases (new tables, widened columns, duplicate mailboxes, counters) | U `unit/store/test_migrations.py`, `test_people.py::test_merge_drops_the_twins_counters`; P `test_postgres_accounts.py`, `test_postgres_people.py` |

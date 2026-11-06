"""Installable app (manifest, service worker, offline page, caching rules),
"Not fake?" with a reason, the trusted-sender re-check on reports and lists,
the Mailboxes trust stats, and the appearance setting."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from reddysec.assistant.tools import ToolBox
from reddysec.core.ids import new_id
from reddysec.models import Signal, SignalStage, TriageLane, TrustCheck, Verdict, VerdictLevel
from reddysec.store.models import (
    FeedbackReasonRow,
    MessageRow,
    SenderFeedbackRow,
    SenderTrustStatsRow,
    UserRow,
)
from reddysec.web.routes.pwa import NEVER_CACHE, service_worker_source, shell_urls

NOW = datetime.now(UTC)

# ---------------------------------------------------------------- PWA


def test_manifest_is_valid_and_installable(client):
    r = client.get("/manifest.webmanifest")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/manifest+json")
    m = json.loads(r.text)
    assert (m["name"], m["short_name"], m["start_url"], m["scope"], m["display"]) == (
        "Secureddy", "Secureddy", "/", "/", "standalone")
    assert m["theme_color"] == m["background_color"] == "#0e1318"
    sizes = {(i["sizes"], i["purpose"]) for i in m["icons"]}
    assert {("192x192", "any"), ("512x512", "any"), ("512x512", "maskable")} <= sizes
    for icon in m["icons"]:
        png = client.get(icon["src"])
        assert png.status_code == 200 and png.content[:8] == b"\x89PNG\r\n\x1a\n"


def test_service_worker_headers_scope_and_rules(client):
    r = client.get("/sw.js")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/javascript")
    assert r.headers["service-worker-allowed"] == "/" and r.headers["cache-control"] == "no-cache"
    assert "script-src 'self'" in r.headers["content-security-policy"]
    src = r.text
    assert src == service_worker_source()
    version = re.search(r'var CACHE = "secureddy-shell-([^"]+)"', src).group(1)
    assert version.startswith("0.1.0-") and len(version) > 8  # package version + asset hash
    shell = json.loads(re.search(r"var SHELL = (\[.*?\]);", src).group(1))
    assert shell == shell_urls() and "/offline" in shell
    assert all(u.startswith(("/static/", "/offline")) for u in shell)  # nothing personal is precached
    never = json.loads(re.search(r"var NEVER_CACHE = (\[.*?\]);", src).group(1))
    for private in ("/api/", "/artifacts/", "/auth/", "/room/", "/assistant", "/messages", "/mailboxes"):
        assert private in never
    assert never == list(NEVER_CACHE)
    # pages: network first, offline fallback, and never written to the cache
    assert 'request.mode === "navigate"' in src and "caches.match(OFFLINE_URL)" in src
    assert src.count("cache.put") == 0 and "cache.addAll(SHELL)" in src
    assert "key !== CACHE" in src and "caches.delete" in src  # old versions are removed


def test_offline_page_is_anonymous(client):
    r = client.get("/offline")
    assert r.status_code == 200 and "set-cookie" not in r.headers
    assert "You're offline" in r.text
    assert "Your mail is still protected. We keep checking it on our servers." in r.text
    assert "csrf_token" not in r.text


def test_static_and_redirect_helpers(client):
    assert client.get("/apple-touch-icon.png").headers["location"] == "/static/icons/apple-touch-icon.png"
    assert client.get("/favicon.ico").headers["location"] == "/static/icons/favicon-32.png"
    assert client.get("/static/app.css").headers["cache-control"] == "no-cache"


async def test_pages_are_never_cached_and_shell_is_linked(client, seed, login):
    await seed.user("me@example.com")
    login(client, "me@example.com")
    for path in ("/", "/messages", "/mailboxes", "/settings/security", "/api/me"):
        r = client.get(path)
        assert r.headers["cache-control"] == "no-store", path
    page = client.get("/").text
    assert '<link rel="manifest" href="/manifest.webmanifest">' in page
    assert 'name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"' in page
    assert '<meta name="apple-mobile-web-app-capable" content="yes">' in page
    assert 'rel="apple-touch-icon" sizes="180x180"' in page and 'name="theme-color"' in page
    assert re.search(r'/static/app\.css\?v=[0-9a-f]{10}', page)
    assert 'class="tabbar"' in page and page.count('class="tab-link"') == 4
    assert "data-install hidden" in page and "data-ios-hint hidden" in page
    js = client.get("/static/app.js").text
    assert 'register("/sw.js", { scope: "/" })' in js and "beforeinstallprompt" in js and "Add to Home Screen" not in js


def test_every_shell_url_is_served(client):
    for url in shell_urls():
        assert client.get(url).status_code == 200, url


# ---------------------------------------------------------------- "Not fake?"


def _quarantined_verdict(make_verdict):
    return make_verdict("malicious", signals=[
        Signal(code="auth.dmarc_pass_aligned", stage=SignalStage.STATIC, weight=0, title="ok"),
        Signal(code="url.new_domain", stage=SignalStage.INTEL, weight=40, title="new"),
    ]) | {"verified_domain": "walmart.com"}


async def test_not_fake_with_reason_restores_and_explains(client, seed, login, csrf_of, make_verdict, db):
    user = await seed.user("me@example.com")
    mailbox = await seed.mailbox(user)
    message = await seed.message(mailbox, level="malicious", verdict=_quarantined_verdict(make_verdict),
                                 from_address="orders@walmart.com")
    login(client, "me@example.com")
    page = client.get(f"/messages/{message.id}").text
    assert "Not fake?" in page and "It&#39;s from a company I use" in page and "Not fake, move it back" in page
    assert 'href="#decide"' in page and 'class="card action-bar action-sheet" id="decide"' in page
    r = client.post(f"/messages/{message.id}/safe", data={"csrf_token": csrf_of(client, f"/messages/{message.id}"),
                                                          "reason_code": "company", "reason_text": "Weekly order"})
    assert r.status_code == 303
    flash = client.get(f"/messages/{message.id}").text
    assert ("Done. We moved it back to your inbox. Next time walmart.com writes, we&#39;ll still check it and "
            "tell you if it&#39;s safe.") in flash
    async with db.session() as s:
        row = await s.get(MessageRow, message.id)
        (reason,) = (await s.execute(select(FeedbackReasonRow))).scalars()
    assert row.state == "restore_requested" and (reason.reason_code, reason.reason_text) == ("company", "Weekly order")
    mailboxes = client.get("/mailboxes").text
    assert "Your reason: <q>It&#39;s from a company I use. Weekly order</q>" in mailboxes
    assert "No new email from them yet. We will check the next one." in mailboxes


async def test_list_rows_offer_not_fake_on_quarantine_and_not_suspicious_otherwise(client, seed, login, make_verdict):
    user = await seed.user("me@example.com")
    mailbox = await seed.mailbox(user)
    await seed.message(mailbox, level="malicious", verdict=_quarantined_verdict(make_verdict), subject="Q")
    await seed.message(mailbox, level="suspicious", verdict=make_verdict("suspicious"), subject="S", quarantined=False)
    login(client, "me@example.com")
    page = client.get("/messages").text
    assert page.count("Not fake?") == 1 and page.count("Not suspicious?") == 1


async def test_unknown_reason_code_is_refused(client, seed, login, csrf_of, make_verdict):
    user = await seed.user("me@example.com")
    message = await seed.message(await seed.mailbox(user), verdict=_quarantined_verdict(make_verdict))
    login(client, "me@example.com")
    r = client.post(f"/messages/{message.id}/safe", data={"csrf_token": csrf_of(client, f"/messages/{message.id}"),
                                                          "reason_code": "bribed"})
    assert r.status_code == 400


# ---------------------------------------------------------------- re-check of trusted senders


def _trusted_verdict(outcome: str) -> dict:
    level = VerdictLevel.SAFE if outcome == "confirmed" else VerdictLevel.MALICIOUS
    return Verdict(
        level=level, score=0 if level is VerdictLevel.SAFE else 92, lane=TriageLane.TRUSTED,
        summary=("You told us you trust this sender (reason: I ordered this). We checked this one too. It's safe."
                 if outcome == "confirmed" else
                 "This sender is on your trusted list, but this email looks different. The link opens a fake sign-in page."),
        signals=[Signal(code="dynamic.credential_phish", stage=SignalStage.DYNAMIC, weight=85, title="Fake page")]
        if outcome == "changed" else [Signal(code="history.trust_confirmed", stage=SignalStage.HISTORY, weight=0,
                                             title="Confirmed again")],
        verified_domain="walmart.com",
        trust_check=TrustCheck(trusted_by_client=True, reason="I ordered this", outcome=outcome, scope="domain",
                               value="walmart.com"),
    ).model_dump(mode="json")


async def test_reports_and_list_show_the_trust_check(client, seed, login, db):
    user = await seed.user("me@example.com")
    mailbox = await seed.mailbox(user)
    ok = await seed.message(mailbox, level="safe", verdict=_trusted_verdict("confirmed"), subject="Order shipped")
    bad = await seed.message(mailbox, level="malicious", verdict=_trusted_verdict("changed"), subject="Invoice")
    login(client, "me@example.com")
    page = client.get(f"/messages/{ok.id}").text
    assert 'class="trust-box trust-confirmed"' in page and "Confirmed again" in page
    assert "You told us you trust this sender (reason: I ordered this). We checked this one too. It&#39;s safe." in page
    page = client.get(f"/messages/{bad.id}").text
    assert 'class="trust-box trust-changed"' in page
    assert "This sender is on your trusted list, but this email looks different:" in page
    assert page.count("This sender is on your trusted list") == 1  # not repeated in the summary
    listing = client.get("/messages").text
    assert "Confirmed again" in listing and "Trusted sender, looks different" in listing
    assert "You trust this sender. We checked this one too, and it&#39;s safe." in listing
    assert "A sender you trust, but this email looks different." in listing
    async with db.session() as s:
        me = await s.get(UserRow, user.id)
        report = await ToolBox(s, me).get_message_report(bad.id)
        listed = await ToolBox(s, me).list_messages(days=7)
    assert report["trust_check"]["outcome"] == "changed" and report["trust_check"]["trusted_by_client"] is True
    assert {m["trusted_sender_check"] for m in listed["messages"]} == {"confirmed", "changed"}


async def test_mailboxes_show_reason_date_and_counters(client, seed, login, db):
    user = await seed.user("me@example.com")
    mailbox = await seed.mailbox(user)
    async with db.session() as s:
        s.add(SenderFeedbackRow(id="sfb_w", mailbox_id=mailbox.id, scope="domain", value="walmart.com",
                                decision="trusted", authenticated=True, created_at=datetime(2026, 11, 2, tzinfo=UTC)))
        s.add(SenderFeedbackRow(id="sfb_v", mailbox_id=mailbox.id, scope="domain", value="vendor.com",
                                decision="trusted", authenticated=True))
        s.add(FeedbackReasonRow(id=new_id("frs"), sender_feedback_id="sfb_w", message_id="m", user_id=user.id,
                                decision="safe", reason_code="expected", reason_text=""))
        s.add(SenderTrustStatsRow(id=new_id("sts"), mailbox_id=mailbox.id, scope="domain", value="walmart.com",
                                  emails_checked=5, last_checked_at=NOW - timedelta(days=2), last_outcome="confirmed",
                                  last_confirmed_at=NOW - timedelta(days=2)))
        s.add(SenderTrustStatsRow(id=new_id("sts"), mailbox_id=mailbox.id, scope="domain", value="vendor.com",
                                  emails_checked=1, last_checked_at=NOW - timedelta(hours=1), last_outcome="changed"))
    login(client, "me@example.com")
    page = client.get("/mailboxes").text
    assert "Your reason: <q>I ordered this / expected it</q> &middot; Since 2 Nov" in page
    assert "Last confirmed 2 days ago · 5 emails checked since" in page
    assert "Last email looked different (1 hour ago) · 1 email checked since" in page
    assert page.index("vendor.com") < page.index("walmart.com")
    # removing the entry also forgets its counters
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    client.post(f"/mailboxes/{mailbox.id}/senders/sfb_w/remove", data={"csrf_token": token})
    async with db.session() as s:
        left = [r.value for r in (await s.execute(select(SenderTrustStatsRow))).scalars()]
    assert left == ["vendor.com"]


async def test_trusting_again_resets_counters(client, seed, login, csrf_of, make_verdict, db):
    user = await seed.user("me@example.com")
    mailbox = await seed.mailbox(user)
    message = await seed.message(mailbox, level="suspicious", quarantined=False,
                                 verdict=make_verdict("suspicious") | {"verified_domain": "walmart.com"},
                                 from_address="a@walmart.com")
    async with db.session() as s:
        s.add(SenderTrustStatsRow(id=new_id("sts"), mailbox_id=mailbox.id, scope="domain", value="walmart.com",
                                  emails_checked=9, last_outcome="confirmed"))
    login(client, "me@example.com")
    client.post(f"/messages/{message.id}/safe", data={"csrf_token": csrf_of(client, f"/messages/{message.id}")})
    async with db.session() as s:
        assert list((await s.execute(select(SenderTrustStatsRow))).scalars()) == []


# ---------------------------------------------------------------- appearance


async def test_theme_setting_sets_a_cookie_and_the_page_follows(client, seed, login, csrf_of):
    await seed.user("me@example.com")
    login(client, "me@example.com")
    page = client.get("/settings/security").text
    assert "Appearance" in page and 'value="system" checked' in page and "<html lang=\"en\">" in page
    r = client.post("/settings/theme", data={"csrf_token": csrf_of(client, "/settings/security"), "theme": "light"})
    assert r.status_code == 303 and "rs_theme=light" in r.headers["set-cookie"]
    page = client.get("/settings/security").text
    assert '<html lang="en" data-theme="light">' in page and '<meta name="theme-color" content="#f6f1e7">' in page
    client.post("/settings/theme", data={"csrf_token": csrf_of(client, "/settings/security"), "theme": "dark"})
    assert 'data-theme="dark"' in client.get("/").text
    client.post("/settings/theme", data={"csrf_token": csrf_of(client, "/settings/security"), "theme": "neon"})
    assert "data-theme" not in client.get("/").text.split("<head>")[0]

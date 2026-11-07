"""One main account, many mailboxes: account cards, reconnect, sign out of a
mailbox, the inbox switch, Together / Separately, search (records and live),
reading an email, the /go link check, images, attachments, mail actions,
ways to sign in, and the assistant's streaming endpoint."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from urllib.parse import parse_qs, quote, urlsplit

import httpx
import pytest
from sqlalchemy import select
from starlette.testclient import TestClient

from reddysec.assistant.llm import ChatReply, ToolCall
from reddysec.mail.base import AuthExpired, ConnectorError, SearchHit
from reddysec.store.models import AuditLog, MailboxRow, MailboxSecret, MessageRow, UserIdentityRow, UserRow
from reddysec.web import mailview, search
from reddysec.web.app import create_app

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
SECRET = "functional-test-secret-key-that-is-long"


def tok(client, path="/settings/security") -> str:
    return CSRF_RE.search(client.get(path).text).group(1)


async def actions(db) -> list[str]:
    async with db.session() as s:
        return [a.action for a in (await s.execute(select(AuditLog).order_by(AuditLog.at))).scalars()]


@pytest.fixture
async def world(seed, make_verdict):
    me = await seed.user("me@example.com")
    gmail = await seed.mailbox(me, address="me@gmail.com")
    outlook = await seed.mailbox(me, provider="microsoft", address="me@outlook.com", mode="hold")
    yahoo = await seed.mailbox(me, provider="yahoo", address="me@yahoo.com", status="error",
                               last_error="IMAP login rejected")
    urls = [
        {"url": "https://walmart-deliveries.net/confirm", "level": "malicious", "score": 92,
         "click_advice": "do_not_open", "click_advice_reason": "A fake sign-in page.",
         "downloads_summary": [{"filename": "invoice.exe", "category": "program", "dangerous": True, "why": "an installer"}]},
        {"url": "https://www.walmart.com/help", "level": "safe", "score": 1},
        {"url": "https://unsure.example/x", "level": "suspicious", "score": 50},
    ]
    v = make_verdict("malicious", urls=urls, attachments=[
        {"filename": "receipt.pdf", "sha256": "0" * 64, "level": "safe", "score": 0},
        {"filename": "tool.exe", "sha256": "1" * 64, "level": "malicious", "score": 90, "safe_copy_ref": "cdr:x/y.pdf"},
    ])
    v["links_summary"] = "Links: 1 safe · 1 open only in Reading Room · 1 do not open"
    phish = await seed.message(gmail, level="malicious", verdict=v, subject="Your Walmart order failed",
                               from_address="orders@walmart-deliveries.net", from_name="Walmart")
    paypal = await seed.message(outlook, level="suspicious", quarantined=False, subject="PayPal sign-in",
                                from_address="billing@paypa1.com")
    news = await seed.message(gmail, level="safe", subject="Morning news", from_address="news@nytimes.com")
    gift = await seed.message(yahoo, level="suspicious", quarantined=False, subject="Gift card prize")
    other = await seed.user("other@example.com")
    obox = await seed.mailbox(other, address="other@gmail.com")
    secret = await seed.message(obox, subject="Other person's mail")
    return {"me": me, "gmail": gmail, "outlook": outlook, "yahoo": yahoo, "phish": phish, "paypal": paypal,
            "news": news, "gift": gift, "other": other, "secret": secret}


def email_bytes() -> bytes:
    msg = EmailMessage()
    msg["From"] = "Walmart <orders@walmart-deliveries.net>"
    msg["Subject"] = "Your Walmart order failed"
    msg.set_content("Plain version https://walmart-deliveries.net/confirm")
    msg.add_alternative(
        '<p onclick="x()">Confirm <a href="https://walmart-deliveries.net/confirm">here</a>'
        '<img src="https://track.example/p.gif"><script>alert(1)</script></p>', subtype="html")
    msg.add_attachment(b"%PDF receipt", maintype="application", subtype="pdf", filename="receipt.pdf")
    msg.add_attachment(b"MZ", maintype="application", subtype="octet-stream", filename="tool.exe")
    return msg.as_bytes()


# --------------------------------------------------------------------------- accounts


async def test_account_cards_have_the_same_actions(client, login, world):
    login(client, "me@example.com")
    page = client.get("/mailboxes").text
    assert page.count("Open inbox") == 3 and page.count("Sign out of this mailbox") == 3
    assert page.count("Re-check last 7 days") == 3 and "Needs reconnect" in page
    assert "Yahoo no longer accepts the app password" in page and "IMAP login rejected" in page
    assert "Checked this week" in page and "Add an account" in page


async def test_reconnect_runs_the_right_flow(client, login, world, oauth, connectors):
    login(client, "me@example.com")
    token = tok(client, "/mailboxes")
    r = client.post(f"/mailboxes/{world['gmail'].id}/reconnect", data={"csrf_token": token})
    assert r.status_code == 303 and r.headers["location"].startswith("https://accounts.google.example/")
    assert oauth.links[oauth.started[-1].state] == world["me"].id
    r = client.post(f"/mailboxes/{world['yahoo'].id}/reconnect", data={"csrf_token": token})
    assert r.headers["location"] == "/mailboxes/connect-yahoo?address=me%40yahoo.com"
    r = client.post(f"/mailboxes/{world['outlook'].id}/reconnect", data={"csrf_token": token})
    assert r.headers["location"] == "/mailboxes"  # Microsoft sign-in is not set up in tests
    assert "Microsoft sign-in is not set up" in client.get("/mailboxes").text
    assert client.post(f"/mailboxes/{world['secret'].mailbox_id}/reconnect", data={"csrf_token": token}).status_code == 404


async def test_reconnect_imap_and_unconfigured_google(settings, db, artifact_store, login, seed):
    app = create_app(settings, db=db, artifact_store=artifact_store)
    with TestClient(app, follow_redirects=False) as c:
        me = await seed.user("imap@example.com")
        box = await seed.mailbox(me, provider="icloud", address="imap@icloud.com")
        gm = await seed.mailbox(me, address="imap@gmail.com")
        login(c, "imap@example.com")
        token = tok(c, "/mailboxes")
        r = c.post(f"/mailboxes/{box.id}/reconnect", data={"csrf_token": token})
        assert r.headers["location"] == "/mailboxes/add-imap?address=imap%40icloud.com&provider=icloud"
        c.post(f"/mailboxes/{gm.id}/reconnect", data={"csrf_token": token})
        assert "Google sign-in is not set up" in c.get("/mailboxes").text


async def test_reconnect_passes_login_hint_when_supported(settings, db, artifact_store, login, seed, fake_oauth_cls):
    class HintOAuth(fake_oauth_cls):
        def begin(self, return_to="/", *, link=None, login_hint=None):
            self.hint = login_hint
            return super().begin(return_to, link=link)

    oauth = HintOAuth()
    app = create_app(settings, db=db, artifact_store=artifact_store, oauth=oauth)
    with TestClient(app, follow_redirects=False) as c:
        me = await seed.user("hint@example.com")
        box = await seed.mailbox(me, address="hint@gmail.com")
        login(c, "hint@example.com")
        c.post(f"/mailboxes/{box.id}/reconnect", data={"csrf_token": tok(c, "/mailboxes")})
        assert oauth.hint == "hint@gmail.com"


async def test_sign_out_of_a_mailbox_revokes_and_explains(client, login, world, db, connectors):
    login(client, "me@example.com")
    token = tok(client, "/mailboxes")
    async with db.session() as s:
        s.add(MailboxSecret(mailbox_id=world["gmail"].id, kind="google_oauth", ciphertext="x", key_id="k"))
    r = client.post(f"/mailboxes/{world['gmail'].id}/disconnect", data={"csrf_token": token})
    assert r.status_code == 303
    assert ("revoke", world["gmail"].id, "") in connectors.calls
    page = client.get("/mailboxes").text
    assert "We asked Google to cancel our access" in page and "Signed out" in page and "Sign in again" in page
    async with db.session() as s:
        assert await s.get(MailboxSecret, world["gmail"].id) is None
    # Microsoft: no revoke endpoint, so we say where to remove the app.
    client.post(f"/mailboxes/{world['outlook'].id}/disconnect", data={"csrf_token": token})
    assert "account.live.com/consent/Manage" in client.get("/mailboxes").text
    # Yahoo: delete the app password in Yahoo. The provider failing must not block signing out.
    connectors.fail_with = ConnectorError("down")
    client.post(f"/mailboxes/{world['yahoo'].id}/disconnect", data={"csrf_token": token})
    assert "delete that app password in Yahoo" in client.get("/mailboxes").text
    assert (await actions(db)).count("mailbox_signed_out") == 3


async def test_google_revoke_not_confirmed(client, login, world, connectors):
    connectors.revoke_result = False
    login(client, "me@example.com")
    client.post(f"/mailboxes/{world['gmail'].id}/disconnect", data={"csrf_token": tok(client, "/mailboxes")})
    assert "myaccount.google.com/permissions" in client.get("/mailboxes").text


# --------------------------------------------------------------------------- inbox switch and views


async def test_switch_together_and_separately(client, login, world, db):
    login(client, "me@example.com")
    page = client.get("/messages").text
    assert "All inboxes" in page and page.count('class="inbox-pill"') == 4
    assert page.count('class="acct-tag"') == 4  # Together: a tag on each row
    one = client.get(f"/messages?mailbox={world['outlook'].id}").text
    assert "PayPal sign-in" in one and "Morning news" not in one and 'aria-current="true"' in one
    home = client.get("/").text  # the dashboard follows the same choice
    assert "PayPal sign-in" in home and "Morning news" not in home
    client.get("/?mailbox=all")
    token = tok(client)
    r = client.post("/settings/view", data={"inbox_view": "separate", "next": "/messages", "csrf_token": token})
    assert r.headers["location"] == "/messages"
    page = client.get("/messages").text
    assert page.count('class="card card-flush inbox-section"') == 3 and "me@yahoo.com" in page
    assert "Gift card prize" in page and 'class="acct-tag"' not in page
    filtered = client.get("/messages?level=suspicious").text
    assert "Gift card prize" in filtered and "Morning news" not in filtered
    assert client.post("/settings/view", data={"inbox_view": "sideways", "csrf_token": token}).status_code == 400
    client.post("/settings/view", data={"inbox_view": "together", "csrf_token": token})
    assert "shown together" in client.get("/settings/security").text


async def test_stat_card_links_keep_the_inbox(client, login, world):
    login(client, "me@example.com")
    page = client.get(f"/?mailbox={world['gmail'].id}").text
    assert f"/messages?tab=checked&amp;period=7d&amp;mailbox={world['gmail'].id}" in page


# --------------------------------------------------------------------------- search


async def test_search_records_highlight_and_scope(client, login, world):
    login(client, "me@example.com")
    page = client.get("/messages?q=walmart").text
    assert "<mark>Walmart</mark>" in page and "Morning news" not in page and "1</span> checked email" in page
    assert "Other person" not in client.get("/messages?q=person").text
    sus = client.get("/messages?q=suspicious").text
    assert "PayPal sign-in" in sus and "Gift card prize" in sus and "Morning news" not in sus
    none = client.get("/messages?q=zzzz").text
    assert "Nothing found" in none and 'Search inside emails' in none
    scoped = client.get(f"/messages?q=gift&mailbox={world['gmail'].id}").text
    assert "Gift card prize" not in scoped


async def test_search_reasons_and_pagination(client, login, seed, world):
    for i in range(55):
        await seed.message(world["gmail"], level="safe", subject=f"Invoice {i}", from_address="billing@shop.example")
    login(client, "me@example.com")
    first = client.get("/messages?q=invoice").text
    assert "Page 1 of 2" in first and "q=invoice&amp;page=2" in first
    assert "Invoice" in client.get("/messages?q=invoice&page=2").text


async def test_search_inside_emails_merges_and_check_now(client, login, world, connectors, db):
    connectors.hits[world["gmail"].id] = [
        SearchHit(world["phish"].provider_message_id, "Walmart", "orders@walmart-deliveries.net",
                  "Your Walmart order failed", datetime.now(UTC) - timedelta(hours=1), "Confirm your address"),
        SearchHit("unseen-1", "Walmart", "help@walmart.com", "Old Walmart receipt",
                  datetime.now(UTC) - timedelta(days=40), "Thanks for shopping"),
    ]
    connectors.registry_error = None
    login(client, "me@example.com")
    page = client.get("/messages?q=walmart&inside=1").text
    assert "Inside your emails" in page and "Not checked yet" in page and "Old <mark>Walmart</mark> receipt" in page
    assert f'href="/messages/{world["phish"].id}"' in page
    assert ("search", world["outlook"].id, "walmart") in connectors.calls  # every selected account was asked
    token = re.search(r'name="token" value="([^"]+)"', page).group(1)
    csrf = CSRF_RE.search(page).group(1)
    r = client.post("/messages/check-now", data={"token": token, "next": "/messages?q=walmart", "csrf_token": csrf})
    assert r.status_code == 303 and r.headers["location"] == "/messages?q=walmart"
    async with db.session() as s:
        row = (await s.execute(select(MessageRow).where(MessageRow.provider_message_id == "unseen-1"))).scalar_one()
    assert row.state == "rescore_requested" and row.subject == "Old Walmart receipt" and row.mailbox_id == world["gmail"].id
    # Again: the same row, no duplicate.
    client.post("/messages/check-now", data={"token": token, "csrf_token": csrf})
    async with db.session() as s:
        assert len((await s.execute(select(MessageRow).where(MessageRow.provider_message_id == "unseen-1"))).all()) == 1
    assert "check_now" in await actions(db)
    tampered = token[:-2] + ("AA" if not token.endswith("AA") else "BB")
    assert client.post("/messages/check-now", data={"token": tampered, "csrf_token": csrf}).status_code == 400


async def test_live_search_problems_are_plain(client, login, world, connectors):
    connectors.fail_with = AuthExpired()
    login(client, "me@example.com")
    page = client.get("/messages?q=walmart&inside=1").text
    assert "needs to be reconnected before we can search it" in page
    connectors.fail_with = ConnectorError("x")
    assert "We could not search me@gmail.com just now" in client.get("/messages?q=x&inside=1").text


def test_check_tokens_are_bound_to_the_person_and_expire():
    hit = SearchHit("p1", "A", "a@x.com", "S", None)
    t = search.sign_check("k", "usr_1", "mbx_1", hit, now=1000)
    assert search.read_check("k", t, "usr_1", now=1001)["p"] == "p1"
    assert search.read_check("k", t, "usr_2", now=1001) is None
    assert search.read_check("k", t, "usr_1", now=1000 + 7200) is None
    assert search.read_check("other", t, "usr_1", now=1001) is None
    assert search.read_check("k", "garbage", "usr_1") is None
    assert str(search.highlight("a<b> walmart", "walmart <b>")) == "a<mark>&lt;b&gt;</mark> <mark>walmart</mark>"
    assert str(search.highlight("x suspicious", "suspicious")) == "x suspicious"  # verdict words are filters
    assert str(search.highlight(None, "x")) == ""


async def test_queue_check_now_existing_message_requests_recheck(db, world):
    from reddysec.web import queries

    async with db.session() as s:
        me = await s.get(UserRow, world["me"].id)
        box = await s.get(MailboxRow, world["gmail"].id)
        row = await queries.queue_unchecked_message(s, me, box, {"p": world["news"].provider_message_id, "r": "bad"})
        assert row.id == world["news"].id and row.state == "rescore_requested"
        fresh = await queries.queue_unchecked_message(s, me, box, {"p": "new-1", "r": "not-a-date"})
        assert fresh.received_at is not None


# --------------------------------------------------------------------------- reading email


async def test_read_tab_and_sanitised_body(client, login, world, connectors):
    connectors.raw[world["phish"].provider_message_id] = email_bytes()
    login(client, "me@example.com")
    report = client.get(f"/messages/{world['phish'].id}?tab=read").text
    assert 'sandbox="allow-top-navigation-by-user-activation"' in report and "Load images" in report
    assert f'/messages/{world["phish"].id}/attachments/0' in report  # safe file: original download
    assert "Get safe copy" in report and "Reply in Gmail" in report
    body = client.get(f"/messages/{world['phish'].id}/body")
    assert body.status_code == 200
    assert body.headers["cache-control"] == "no-store, private"
    assert "default-src 'none'" in body.headers["content-security-policy"]
    assert body.headers["x-frame-options"] == "SAMEORIGIN"
    text = body.text
    assert "<script" not in text and "onclick" not in text and "track.example" not in text
    href = re.search(r'href="(/go\?[^"]+)"', text).group(1).replace("&amp;", "&")
    q = parse_qs(urlsplit(href).query)
    assert q["u"] == ["https://walmart-deliveries.net/confirm"]
    images = client.get(f"/messages/{world['phish'].id}/body?images=1").text
    assert f"/messages/{world['phish'].id}/image?u=https%3A%2F%2Ftrack.example" in images
    # Nothing about the body was stored.
    assert "Confirm" not in json.dumps([c for c in connectors.calls])


async def test_body_problems_and_plain_text(client, login, world, connectors, seed):
    login(client, "me@example.com")
    missing = client.get(f"/messages/{world['news'].id}/body")
    assert missing.status_code == 502 and "could not reach your mail provider" in missing.text
    connectors.fail_with = AuthExpired()
    assert client.get(f"/messages/{world['news'].id}/body").status_code == 409
    connectors.fail_with = None
    connectors.raw[world["news"].provider_message_id] = b"Subject: x\r\n\r\nSee https://nytimes.com/a\r\n"
    plain = client.get(f"/messages/{world['news'].id}/body").text
    assert 'class="plain"' in plain and "/go?u=https%3A%2F%2Fnytimes.com%2Fa" in plain
    connectors.raw[world["news"].provider_message_id] = b"Subject: empty\r\n\r\n"
    assert "has no text" in client.get(f"/messages/{world['news'].id}/body").text
    # Other people's mail, and staff, get nothing.
    assert client.get(f"/messages/{world['secret'].id}/body").status_code == 404


async def test_unparseable_email(client, login, world, connectors, monkeypatch):
    connectors.raw[world["news"].provider_message_id] = b"x"
    login(client, "me@example.com")

    def boom(raw):
        raise ValueError("bad")

    monkeypatch.setattr(mailview, "parse_message", boom)
    assert client.get(f"/messages/{world['news'].id}/body").status_code == 422


async def test_staff_cannot_read_mail(client, login, world):
    login(client, "staff@example.com", role="concierge")
    assert client.get(f"/messages/{world['phish'].id}").status_code == 200  # the report, yes
    page = client.get(f"/messages/{world['phish'].id}?tab=read").text
    assert "Read email" not in page
    assert client.get(f"/messages/{world['phish'].id}/body").status_code == 404


async def test_disconnected_mailbox_cannot_be_read(client, login, world, db):
    from sqlalchemy import update

    async with db.session() as s:
        await s.execute(update(MailboxRow).where(MailboxRow.id == world["gmail"].id).values(status="disconnected"))
    login(client, "me@example.com")
    assert "Read email" not in client.get(f"/messages/{world['phish'].id}?tab=read").text
    assert client.get(f"/messages/{world['phish'].id}/body").status_code == 409


async def test_attachments(client, login, world, connectors):
    connectors.raw[world["phish"].provider_message_id] = email_bytes()
    login(client, "me@example.com")
    ok = client.get(f"/messages/{world['phish'].id}/attachments/0")
    assert ok.status_code == 200 and ok.content == b"%PDF receipt"
    assert ok.headers["content-disposition"] == 'attachment; filename="receipt.pdf"'
    assert ok.headers["content-type"] == "application/octet-stream" and ok.headers["cache-control"] == "no-store, private"
    assert client.get(f"/messages/{world['phish'].id}/attachments/1").status_code == 403  # dangerous: safe copy only
    assert client.get(f"/messages/{world['phish'].id}/attachments/7").status_code == 404
    connectors.raw[world["phish"].provider_message_id] = b"Subject: no files\r\n\r\nhi"
    assert client.get(f"/messages/{world['phish'].id}/attachments/0").status_code == 404
    connectors.fail_with = ConnectorError("down")
    assert client.get(f"/messages/{world['phish'].id}/attachments/0").status_code == 502


def test_attachment_helpers():
    from reddysec.web.routes.mailread import attachment_level, attachment_name

    row = MessageRow(verdict={"attachments": [{"filename": "a.pdf", "level": "safe"}, "junk"]})
    assert attachment_name(row, 0) == "a.pdf" and attachment_name(row, 1) is None
    assert attachment_level(row, "a.pdf") == "safe" and attachment_level(row, "b") == ""
    assert attachment_level(MessageRow(verdict=None), "a") == ""


# --------------------------------------------------------------------------- /go


def go(message_id: str, url: str, secret: str = SECRET) -> str:
    return mailview.go_href(secret, message_id, url)


async def test_go_page_follows_click_advice(client, login, world):
    login(client, "me@example.com")
    m = world["phish"].id
    bad = client.get(go(m, "https://walmart-deliveries.net/confirm")).text
    assert "Do not open this link" in bad and "A fake sign-in page." in bad and "I understand the risk" in bad
    assert "invoice.exe (a program), dangerous: an installer" in bad
    assert 'href="https://walmart-deliveries.net/confirm"' not in bad  # no direct link, ever
    safe = client.get(go(m, "https://www.walmart.com/help")).text
    assert "This link looks safe" in safe and 'href="https://www.walmart.com/help"' in safe and "Open in Reading Room" in safe
    unsure = client.get(go(m, "https://unsure.example/x")).text
    assert "Open this link in the Reading Room" in unsure and 'href="https://unsure.example/x"' not in unsure
    unknown = client.get(go(m, "https://not-analysed.example/")).text
    assert "We have not checked this exact link" in unknown and 'href="https://not-analysed.example/"' not in unknown


async def test_go_is_not_an_open_redirect(client, login, world):
    login(client, "me@example.com")
    m = world["phish"].id
    href = go(m, "https://www.walmart.com/help")
    tampered = href.replace("walmart.com", "evil.example")
    assert client.get(tampered).status_code == 404
    assert client.get(go(m, "https://www.walmart.com/help", secret="wrong")).status_code == 404
    other = go(world["secret"].id, "https://x.example/")
    assert client.get(other).status_code == 404  # signed for someone else's message
    moved = go(world["news"].id, "https://www.walmart.com/help").replace(world["news"].id, m)
    assert client.get(moved).status_code == 404
    assert client.get(f"/go?u={quote('https://x.example')}&m={m}&s=x").status_code == 404


async def test_go_without_reading_room(settings, db, artifact_store, login, world, connectors):
    app = create_app(settings, db=db, artifact_store=artifact_store, connector_factory=connectors)
    with TestClient(app, follow_redirects=False) as c:
        login(c, "me@example.com")
        page = c.get(go(world["phish"].id, "https://unsure.example/x")).text
        assert "Reading Room is not switched on" in page


async def test_report_shows_link_advice_and_summary(client, login, world):
    login(client, "me@example.com")
    page = client.get(f"/messages/{world['phish'].id}").text
    assert "Links: 1 safe · 1 open only in Reading Room · 1 do not open" in page
    assert "Do not open this link." in page and "This link looks safe." in page
    assert page.count(">Open link<") == 1


# --------------------------------------------------------------------------- image proxy


async def test_image_proxy(settings, db, artifact_store, login, world, connectors):
    def handler(request):
        if request.url.host == "cdn.example":
            return httpx.Response(200, content=b"GIF89a", headers={"content-type": "image/gif"})
        return httpx.Response(200, content=b"<svg/>", headers={"content-type": "image/svg+xml"})

    async def public(host):
        return True

    app = create_app(settings, db=db, artifact_store=artifact_store, connector_factory=connectors,
                     http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    app.state.image_resolver = public
    with TestClient(app, follow_redirects=False) as c:
        login(c, "me@example.com")
        m = world["phish"].id
        href = mailview.image_href(SECRET, m, "https://cdn.example/a.gif")
        r = c.get(href)
        assert r.status_code == 200 and r.content == b"GIF89a" and r.headers["cache-control"] == "no-store, private"
        assert c.get(mailview.image_href(SECRET, m, "https://other.example/a.svg")).status_code == 404
        assert c.get(href.replace("cdn.example", "evil.example")).status_code == 404
        assert c.get(mailview.image_href(SECRET, world["secret"].id, "https://cdn.example/a.gif")).status_code == 404


# --------------------------------------------------------------------------- mail actions


@pytest.mark.parametrize("action,call,flash_text", [
    ("archive", "archive", "Archived in Gmail."),
    ("read", "read", "Marked as read."),
    ("unread", "unread", "Marked as unread."),
    ("trash", "trash", "Moved to the Trash in Gmail."),
])
async def test_mail_actions(client, login, world, connectors, db, action, call, flash_text):
    login(client, "me@example.com")
    m = world["phish"]
    r = client.post(f"/messages/{m.id}/{action}", data={"csrf_token": tok(client, f"/messages/{m.id}"),
                                                       "next": f"/messages/{m.id}?tab=read"})
    assert r.status_code == 303 and r.headers["location"] == f"/messages/{m.id}?tab=read"
    assert (call, world["gmail"].id, m.provider_message_id) in connectors.calls
    assert flash_text in client.get(f"/messages/{m.id}").text


async def test_mail_action_failures(client, login, world, connectors):
    login(client, "me@example.com")
    token = tok(client, "/messages")
    connectors.fail_with = AuthExpired()
    client.post(f"/messages/{world['phish'].id}/archive", data={"csrf_token": token})
    assert "needs to be reconnected first" in client.get("/messages").text
    connectors.fail_with = ConnectorError("x")
    client.post(f"/messages/{world['paypal'].id}/trash", data={"csrf_token": token})
    assert "We could not reach Outlook just now. Nothing changed." in client.get("/messages").text
    assert client.post(f"/messages/{world['secret'].id}/archive", data={"csrf_token": token}).status_code == 404


async def test_open_in_provider(client, login, world, connectors):
    login(client, "me@example.com")
    r = client.get(f"/messages/{world['phish'].id}/open")
    assert r.status_code == 303 and r.headers["location"] == f"https://mail.example/gmail/{world['phish'].provider_message_id}"
    connectors.fail_with = ConnectorError("x")
    r = client.get(f"/messages/{world['phish'].id}/open")
    assert r.headers["location"] == f"/messages/{world['phish'].id}"


# --------------------------------------------------------------------------- ways to sign in


async def test_add_a_way_to_sign_in_links_the_same_account(client, login, world, oauth, db):
    oauth.claims = {"sub": "g-other", "email": "different@gmail.com", "email_verified": True, "name": "Me"}
    login(client, "me@example.com")
    r = client.post("/auth/google/link", data={"purpose": "signin", "next": "/settings/security#signin",
                                               "csrf_token": tok(client)})
    state = oauth.started[-1].state
    assert oauth.links[state] == world["me"].id
    r = client.get(f"/auth/google/callback?state={state}&code=good-code")
    assert r.status_code == 303 and r.headers["location"] == "/settings/security#signin"
    page = client.get("/settings/security").text
    assert "You can now sign in with Google (different@gmail.com)" in page
    async with db.session() as s:
        ids = list((await s.execute(select(UserIdentityRow))).scalars())
        boxes = [m.address for m in (await s.execute(select(MailboxRow))).scalars()]
    assert [(i.user_id, i.email) for i in ids] == [(world["me"].id, "different@gmail.com")]
    assert "different@gmail.com" not in boxes  # sign-in only: no new mailbox
    assert "identity_linked" in await actions(db)


async def test_add_sign_in_for_a_protected_address_refreshes_its_tokens(client, login, world, oauth, db):
    oauth.claims = {"sub": "g-me", "email": "me@gmail.com", "email_verified": True}
    login(client, "me@example.com")
    client.post("/auth/google/link", data={"purpose": "signin", "csrf_token": tok(client)})
    client.get(f"/auth/google/callback?state={oauth.started[-1].state}&code=good-code")
    async with db.session() as s:
        assert await s.get(MailboxSecret, world["gmail"].id) is not None


async def test_cannot_link_someone_elses_identity(client, login, world, oauth, seed, db):
    await seed.user("victim@example.com", google_sub="g-victim")
    oauth.claims = {"sub": "g-victim", "email": "victim@gmail.com", "email_verified": True}
    login(client, "me@example.com")
    client.post("/auth/google/link", data={"purpose": "signin", "csrf_token": tok(client)})
    r = client.get(f"/auth/google/callback?state={oauth.started[-1].state}&code=good-code")
    assert r.status_code == 409 and "already connected" in r.text


async def test_link_needs_the_same_signed_in_session(app, login, world, oauth):
    with TestClient(app, follow_redirects=False) as me, TestClient(app, follow_redirects=False) as attacker:
        login(me, "me@example.com")
        me.post("/auth/google/link", data={"purpose": "signin", "csrf_token": tok(me)})
        state = oauth.started[-1].state
        login(attacker, "other@example.com")
        # The attacker's browser has no pending flow for this state.
        r = attacker.get(f"/auth/google/callback?state={state}&code=good-code")
        assert r.headers["location"] == "/login"
        # Signing out between start and callback ends the link too.
        me.cookies.delete("rs_sid")
        r = me.get(f"/auth/google/callback?state={state}&code=good-code")
        assert r.headers["location"] == "/login"


async def test_remove_sign_in_keeps_at_least_one(client, login, world, db):
    async with db.session() as s:
        s.add(UserIdentityRow(id="uid_a", user_id=world["me"].id, provider="google", subject="g1", email="me@gmail.com",
                              email_verified=True))
        s.add(UserIdentityRow(id="uid_b", user_id=world["me"].id, provider="microsoft", subject="m1",
                              email="me@outlook.com", email_verified=True))
        me = await s.get(UserRow, world["me"].id)
        me.google_sub = "g1"
    login(client, "me@example.com")
    page = client.get("/settings/security").text
    assert page.count(">Remove<") >= 2 and "me@outlook.com" in page
    client.post("/settings/sign-in/uid_a/remove", data={"csrf_token": tok(client)})
    assert "no longer sign in with Google" in client.get("/settings/security").text
    async with db.session() as s:
        assert (await s.get(UserRow, world["me"].id)).google_sub is None
    client.post("/settings/sign-in/uid_b/remove", data={"csrf_token": tok(client)})
    assert "your only way to sign in" in client.get("/settings/security").text
    async with db.session() as s:
        assert await s.get(UserIdentityRow, "uid_b") is not None
    assert client.post("/settings/sign-in/uid_zzz/remove", data={"csrf_token": tok(client)}).status_code == 404
    assert client.get("/settings").headers["location"] == "/settings/security"


async def test_yahoo_add_sign_in(settings, db, artifact_store, login, seed, fake_oauth_cls):
    yahoo = fake_oauth_cls({"sub": "y-1", "email": "me@yahoo.com", "email_verified": True})
    app = create_app(settings, db=db, artifact_store=artifact_store, yahoo_oauth=yahoo)
    with TestClient(app, follow_redirects=False) as c:
        await seed.user("ya@example.com")
        login(c, "ya@example.com")
        assert "Add Yahoo" in c.get("/settings/security").text
        c.post("/auth/yahoo/link", data={"purpose": "signin", "csrf_token": tok(c)})
        r = c.get(f"/auth/yahoo/callback?state={yahoo.started[-1].state}&code=good-code")
        assert r.headers["location"] == "/settings/security"
        assert "You can now sign in with Yahoo" in c.get("/settings/security").text


# --------------------------------------------------------------------------- assistant streaming


class StreamChat:
    def __init__(self, *replies):
        self.replies = list(replies)
        self.seen = []

    async def complete(self, system, messages, tools):
        self.seen.append(messages)
        return self.replies.pop(0)

    async def stream(self, system, messages, tools):
        reply = await self.complete(system, messages, tools)
        if reply.text:
            yield reply.text
        yield reply


def parse_sse(text: str) -> list[tuple[str, dict]]:
    out = []
    for block in text.strip().split("\n\n"):
        name = re.search(r"^event: (.+)$", block, re.M).group(1)
        data = json.loads(re.search(r"^data: (.+)$", block, re.M).group(1))
        out.append((name, data))
    return out


async def test_assistant_stream_end_to_end(settings, db, artifact_store, login, world, connectors):
    chat = StreamChat(ChatReply("", (ToolCall("t1", "top_suspicious", {}),)), ChatReply("Two need a look."))
    app = create_app(settings, db=db, artifact_store=artifact_store, chat_model=chat, connector_factory=connectors)
    with TestClient(app, follow_redirects=False) as c:
        login(c, "me@example.com")
        page = c.get("/assistant").text
        assert "need a look. Show them" in page
        token = CSRF_RE.search(page).group(1)
        r = c.post("/assistant/stream", data={"message": "most suspicious?", "csrf_token": token},
                   headers={"accept": "text/event-stream"})
        assert r.headers["content-type"].startswith("text/event-stream") and r.headers["cache-control"] == "no-store"
        events = parse_sse(r.text)
        names = [n for n, _ in events]
        assert names[0] == "start" and "status" in names and "cards" in names and names[-1] == "done"
        done = events[-1][1]
        assert done["reply"]["text"] == "Two need a look." and done["reply"]["cards"][0]["kind"] == "ranked"
        rows = done["reply"]["cards"][0]["rows"]
        assert all(r["href"].startswith("/messages/msg_") for r in rows)
        assert world["secret"].id not in r.text
        # The conversation page shows the cards after a reload.
        page = c.get(done["conversation_url"]).text
        assert 'class="ccard ccard-ranked"' in page and "Your Walmart order failed" in page
        # Validation and limits use the normal errors.
        bad = c.post("/assistant/stream", data={"message": " ", "csrf_token": token}, headers={"accept": "application/json"})
        assert bad.status_code == 400


async def test_assistant_stream_respects_daily_limit_and_selected_inbox(settings, db, artifact_store, login, world, connectors):
    chat = StreamChat(ChatReply("", (ToolCall("t1", "list_messages", {"days": 30}),)), ChatReply("ok"))
    app = create_app(settings.model_copy(update={"assistant_daily_message_limit": 1}), db=db,
                     artifact_store=artifact_store, chat_model=chat, connector_factory=connectors)
    with TestClient(app, follow_redirects=False) as c:
        login(c, "me@example.com")
        c.get(f"/messages?mailbox={world['outlook'].id}")
        page = c.get("/assistant").text
        assert "me@outlook.com" in page  # the scope tag
        token = CSRF_RE.search(page).group(1)
        r = c.post("/assistant/stream", data={"message": "list", "csrf_token": token})
        done = parse_sse(r.text)[-1][1]
        tool_result = json.loads(chat.seen[1][-1]["results"][0]["content"])
        assert [m["email"]["untrusted"]["subject"] for m in tool_result["messages"]] == ["PayPal sign-in"]
        assert done["reply"]["text"] == "ok"
        again = c.post("/assistant/stream", data={"message": "more", "csrf_token": token}, headers={"accept": "application/json"})
        assert again.status_code == 429


async def test_assistant_stream_errors_become_events(settings, db, artifact_store, login, world, monkeypatch):
    from reddysec.assistant.agent import Assistant, RateLimited

    app = create_app(settings, db=db, artifact_store=artifact_store, chat_model=StreamChat(ChatReply("x")))
    with TestClient(app, follow_redirects=False) as c:
        login(c, "me@example.com")
        token = CSRF_RE.search(c.get("/assistant").text).group(1)

        async def limited(*a, **k):
            raise RateLimited()
            yield  # pragma: no cover

        monkeypatch.setattr(Assistant, "events", limited)
        assert parse_sse(c.post("/assistant/stream", data={"message": "q", "csrf_token": token}).text)[-1][0] == "error"

        async def crash(*a, **k):
            raise RuntimeError("x")
            yield  # pragma: no cover

        monkeypatch.setattr(Assistant, "events", crash)
        last = parse_sse(c.post("/assistant/stream", data={"message": "q", "csrf_token": token}).text)[-1]
        assert last == ("error", {"text": "Sorry, something went wrong. Please try again."})


async def test_read_email_consent_via_send(settings, db, artifact_store, login, world, connectors):
    connectors.raw[world["phish"].provider_message_id] = email_bytes()
    chat = StreamChat(ChatReply("It wants your address."))
    app = create_app(settings, db=db, artifact_store=artifact_store, chat_model=chat, connector_factory=connectors)
    with TestClient(app, follow_redirects=False) as c:
        login(c, "me@example.com")
        page = c.get(f"/assistant?about={world['phish'].id}").text
        assert "Let the assistant read this email" in page
        token = CSRF_RE.search(page).group(1)
        r = c.post("/assistant/send", data={"message": "What does it say?", "about": world["phish"].id,
                                            "read_email": world["phish"].id, "csrf_token": token},
                   headers={"accept": "application/json"})
        assert r.status_code == 200
        sent = chat.seen[0][-1]["text"]
        assert "email_text" in sent and "Plain version" in sent and "<script" not in sent
        assert "assistant_read_email" in await actions(db)
        conv = r.json()["conversation_url"]
        assert "you let me read it" in c.get(conv).text


async def test_disabled_assistant_shows_admin_hint_to_staff(settings, db, artifact_store, login, seed):
    app = create_app(settings, db=db, artifact_store=artifact_store)
    with TestClient(app, follow_redirects=False) as c:
        login(c, "admin@example.com", role="admin")
        page = c.get("/assistant").text
        assert "RS_ASSISTANT_PROVIDER=anthropic" in page and "RS_ANTHROPIC_FEDERATION_RULE_ID" in page

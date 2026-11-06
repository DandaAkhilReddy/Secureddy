""""Not suspicious?" / "This is fake" with a reason, and the refreshed dashboard."""

from __future__ import annotations

from sqlalchemy import select

from reddysec.store.models import FeedbackReasonRow, SenderFeedbackRow

XSS = '<script>alert("x")</script> I ordered it'


async def _setup(seed, login, client, make_verdict, *, level="suspicious", quarantined=False, verified="walmart.com"):
    user = await seed.user("owner@example.com")
    mailbox = await seed.mailbox(user)
    v = make_verdict(level)
    v["verified_domain"] = verified
    message = await seed.message(mailbox, level=level, quarantined=quarantined, verdict=v,
                                 from_address="help@walmart.com", from_name="Walmart", subject="Order shipped")
    login(client, "owner@example.com")
    return user, mailbox, message


async def _reasons(db):
    async with db.session() as s:
        return list((await s.execute(select(FeedbackReasonRow))).scalars())


async def test_safe_with_reason_is_stored_shown_escaped_and_audited(client, seed, login, csrf_of, make_verdict, db):
    _u, mailbox, message = await _setup(seed, login, client, make_verdict)
    token = csrf_of(client, f"/messages/{message.id}")
    response = client.post(f"/messages/{message.id}/safe",
                           data={"csrf_token": token, "reason_code": "expected", "reason_text": XSS})
    assert response.status_code == 303 and response.headers["location"] == f"/messages/{message.id}"
    (reason,) = await _reasons(db)
    async with db.session() as s:
        (entry,) = (await s.execute(select(SenderFeedbackRow))).scalars()
    assert (reason.decision, reason.reason_code, reason.reason_text) == ("safe", "expected", XSS)
    assert reason.sender_feedback_id == entry.id and reason.message_id == message.id
    assert entry.scope == "domain"  # the trust math is unchanged by the reason

    page = client.get(f"/messages/{message.id}").text
    assert "Done. We marked it Checked. Next time walmart.com writes, we&#39;ll still check it and tell you if it&#39;s safe." in page
    assert "You marked this safe on " in page and "I ordered this / expected it. &lt;script&gt;" in page
    assert XSS not in page
    audit = client.get("/audit").text
    assert "walmart.com · I ordered this / expected it. &lt;script&gt;" in audit and "<script>alert" not in audit


async def test_newsletter_on_verified_sender_trusts_domain(client, seed, login, csrf_of, make_verdict, db):
    _u, _mb, message = await _setup(seed, login, client, make_verdict)
    client.post(f"/messages/{message.id}/safe",
                data={"csrf_token": csrf_of(client, f"/messages/{message.id}"), "reason_code": "newsletter"})
    async with db.session() as s:
        (entry,) = (await s.execute(select(SenderFeedbackRow))).scalars()
    assert (entry.scope, entry.value, entry.authenticated) == ("domain", "walmart.com", True)
    assert "It&#39;s a newsletter I signed up for." in client.get(f"/messages/{message.id}").text


async def test_fake_with_reason_and_list_redirect(client, seed, login, csrf_of, make_verdict, db):
    _u, _mb, message = await _setup(seed, login, client, make_verdict, verified="")
    token = csrf_of(client, "/messages")
    response = client.post(f"/messages/{message.id}/fake", data={
        "csrf_token": token, "reason_code": "money_or_codes", "reason_text": "Wanted gift cards", "next": "/messages?level=suspicious"})
    assert response.headers["location"] == "/messages?level=suspicious"
    (reason,) = await _reasons(db)
    assert (reason.decision, reason.reason_code) == ("fake", "money_or_codes")
    page = client.get(f"/messages/{message.id}").text
    assert "You marked this fake on " in page and "Asks for money or codes. Wanted gift cards." in page


async def test_reason_validation_and_safe_next(client, seed, login, csrf_of, make_verdict, db):
    _u, _mb, message = await _setup(seed, login, client, make_verdict)
    token = csrf_of(client, f"/messages/{message.id}")
    assert client.post(f"/messages/{message.id}/safe",
                       data={"csrf_token": token, "reason_code": "unknown_sender"}).status_code == 400
    assert await _reasons(db) == []
    long = client.post(f"/messages/{message.id}/safe",
                       data={"csrf_token": token, "reason_text": "y" * 900, "next": "//evil.example/"})
    assert long.headers["location"] == f"/messages/{message.id}"  # off-site next is ignored
    (reason,) = await _reasons(db)
    assert reason.reason_code == "other" and len(reason.reason_text) == 500


async def test_no_reason_records_no_reason_row(client, seed, login, csrf_of, make_verdict, db):
    _u, _mb, message = await _setup(seed, login, client, make_verdict)
    client.post(f"/messages/{message.id}/safe", data={"csrf_token": csrf_of(client, f"/messages/{message.id}")})
    assert await _reasons(db) == []
    assert "You marked this safe on" not in client.get(f"/messages/{message.id}").text


async def test_list_rows_offer_reason_forms(client, seed, login, make_verdict):
    user = await seed.user("rows@example.com")
    mailbox = await seed.mailbox(user)
    sus = await seed.message(mailbox, level="suspicious", quarantined=False, subject="Odd one")
    bad = await seed.message(mailbox, level="malicious", subject="Held one")
    safe = await seed.message(mailbox, level="safe", subject="Fine one")
    busy = await seed.message(mailbox, level="suspicious", quarantined=False, state="rescore_requested", subject="Busy")
    login(client, "rows@example.com")
    page = client.get("/messages").text
    assert f'action="/messages/{sus.id}/safe"' in page and f'action="/messages/{sus.id}/fake"' in page
    assert f'action="/messages/{bad.id}/safe"' in page and f'action="/messages/{bad.id}/fake"' not in page
    assert f'/messages/{safe.id}/safe"' not in page and f'/messages/{busy.id}/safe"' not in page
    assert "I know this sender" in page and "It&#39;s a newsletter I signed up for" in page
    assert 'name="next" value="/messages"' in page
    assert "Not suspicious?" in client.get("/").text


async def test_concierge_sees_client_reason(client, seed, login, csrf_of, make_verdict, db):
    user = await seed.user("client@example.com")
    mailbox = await seed.mailbox(user)
    v = make_verdict("suspicious", needs_human_review=True)
    message = await seed.message(mailbox, level="suspicious", quarantined=False, verdict=v)
    login(client, "client@example.com")
    client.post(f"/messages/{message.id}/safe", data={
        "csrf_token": csrf_of(client, f"/messages/{message.id}"), "reason_code": "known_sender", "reason_text": "My dentist"})
    client.post("/auth/logout", data={"csrf_token": csrf_of(client, "/")})
    login(client, "staff@example.com", role="concierge")
    page = client.get("/concierge").text
    assert "Client marked this safe on" in page and "I know this sender. My dentist." in page


async def test_dashboard_hero_sparklines_and_chip_icons(client, seed, login):
    user = await seed.user("dash@example.com")
    mailbox = await seed.mailbox(user)
    await seed.message(mailbox, level="safe", hours_ago=30)
    await seed.message(mailbox, level="suspicious", quarantined=False)
    login(client, "dash@example.com")
    page = client.get("/").text
    assert "1 email needs a look" in page and "hero-warn" in page
    assert page.count('<svg class="spark"') == 3 and 'aria-label="Last 7 days: ' in page
    assert '<polyline class="spark-line" points="' in page
    assert '<span class="chip tone-warn"><svg class="chip-ico"' in page
    assert "Why was my Walmart email flagged?" in page and 'action="/assistant/send"' in page


async def test_dashboard_quiet_hero(client, seed, login):
    user = await seed.user("calm@example.com")
    mailbox = await seed.mailbox(user)
    await seed.message(mailbox, level="safe")
    login(client, "calm@example.com")
    assert "Your inbox is safe" in client.get("/").text

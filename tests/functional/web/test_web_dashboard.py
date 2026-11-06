"""Dashboard and message list pages."""

from __future__ import annotations


async def test_dashboard_empty_state_for_new_user(client, login):
    login(client, "fresh@example.com", name="Fresh Start")
    page = client.get("/")
    assert page.status_code == 200
    assert "Welcome back, Fresh." in page.text
    assert "Connect a mailbox and we start checking your email within a minute." in page.text
    assert "Three steps and you are protected" in page.text
    assert "Connect Gmail" in page.text and "/auth/google/start?next=/mailboxes" in page.text
    assert "Recent email" not in page.text


async def test_dashboard_with_messages_counts_and_rows(client, seed, login):
    user = await seed.user("busy@example.com", name="Busy Bee")
    mailbox = await seed.mailbox(user, labels={})
    await seed.message(mailbox, level="safe", subject="Dinner on Friday")
    await seed.message(mailbox, level="suspicious", subject="Your invoice", quarantined=False)
    bad = await seed.message(mailbox, level="malicious", subject="Reset your password now")
    await seed.message(mailbox, level="safe", hours_ago=24 * 9, subject="Old news")  # outside the week
    await seed.message(mailbox, level=None, state="pending", subject="Still arriving")
    await seed.notification(user, message=bad)
    login(client, "busy@example.com")

    page = client.get("/")
    assert page.status_code == 200
    assert (
        "We checked 3 emails this week. 1 was dangerous and is in Quarantine. 1 looked suspicious, so we marked it for care."
        in page.text
    )
    assert "Setting up" in page.text  # labels == {} means the worker has not run setup yet
    for subject in ("Dinner on Friday", "Your invoice", "Reset your password now", "Still arriving"):
        assert subject in page.text
    assert "Old news" not in page.text or "9 days" not in page.text  # listed in recent, not counted
    assert page.text.count('class="chip tone-bad"') >= 1
    assert "Checking" in page.text
    assert "Sandboxed" in page.text and "detonate" not in page.text.split("<tbody>")[1]
    assert "Needs your attention" in page.text and "A dangerous email was quarantined" in page.text
    assert f"/messages/{bad.id}" in page.text


async def test_dashboard_quiet_week_sentence(client, seed, login):
    user = await seed.user("quiet@example.com")
    await seed.mailbox(user)
    login(client, "quiet@example.com")
    page = client.get("/")
    assert "We have not seen any new email this week. Everything is quiet." in page.text
    assert "No email checked yet" in page.text


async def test_dashboard_only_shows_own_mail(client, seed, login):
    me = await seed.user("me@example.com")
    other = await seed.user("other@example.com")
    await seed.mailbox(me)
    await seed.message(await seed.mailbox(other), subject="Private to other")
    login(client, "me@example.com")
    assert "Private to other" not in client.get("/").text


async def test_assistant_sees_principals_mail(client, seed, login):
    principal = await seed.user("boss@example.com")
    await seed.user("helper@example.com", role="assistant", principal_id=principal.id)
    await seed.message(await seed.mailbox(principal), subject="Board papers")
    login(client, "helper@example.com", role="assistant")
    page = client.get("/")
    assert "Board papers" in page.text


async def test_message_list_filters(client, seed, login):
    user = await seed.user("filters@example.com")
    gmail = await seed.mailbox(user)
    yahoo = await seed.mailbox(user, provider="yahoo", address="filters@yahoo.com")
    await seed.message(gmail, level="safe", subject="Safe one")
    await seed.message(gmail, level="malicious", subject="Bad one")
    await seed.message(yahoo, level="suspicious", subject="Yahoo odd one", quarantined=False)
    login(client, "filters@example.com")

    everything = client.get("/messages")
    assert everything.status_code == 200
    assert all(s in everything.text for s in ("Safe one", "Bad one", "Yahoo odd one"))
    only_bad = client.get("/messages?level=malicious")
    assert "Bad one" in only_bad.text and "Safe one" not in only_bad.text
    only_yahoo = client.get(f"/messages?mailbox={yahoo.id}")
    assert "Yahoo odd one" in only_yahoo.text and "Safe one" not in only_yahoo.text
    quarantine = client.get("/messages?quarantined=1")
    assert "Bad one" in quarantine.text and "Yahoo odd one" not in quarantine.text
    ignored = client.get("/messages?level=bogus&mailbox=mbx_not_mine")
    assert ignored.status_code == 200 and "Safe one" in ignored.text


async def test_message_list_empty_state(client, seed, login):
    await seed.user("none@example.com")
    login(client, "none@example.com")
    page = client.get("/messages?level=safe")
    assert "Nothing to show" in page.text


async def test_dashboard_handles_verdict_summary_in_table(client, seed, login, make_verdict):
    user = await seed.user("summary@example.com")
    mailbox = await seed.mailbox(user)
    await seed.message(
        mailbox, verdict=make_verdict("safe", summary="Nothing to worry about here."), level="safe"
    )
    login(client, "summary@example.com")
    assert "Nothing to worry about here." in client.get("/messages").text

"""Home and Email follow the chosen period: Today, 7 days, 1 month, 1 year."""

from __future__ import annotations

from sqlalchemy import select

from reddysec.store.models import UserPreferenceRow


async def _prefs(db, user_id):
    async with db.session() as s:
        rows = (await s.execute(select(UserPreferenceRow).where(UserPreferenceRow.user_id == user_id))).scalars()
        return {r.key: r.value for r in rows}


async def test_period_switch_changes_cards_sentence_sparklines_and_list(client, seed, login, db):
    user = await seed.user("period@example.com")
    gmail = await seed.mailbox(user)
    yahoo = await seed.mailbox(user, provider="yahoo", address="period@yahoo.com")
    await seed.message(gmail, level="safe", subject="Just now", hours_ago=0.01)
    await seed.message(gmail, level="suspicious", quarantined=False, subject="Two weeks ago", hours_ago=24 * 14)
    await seed.message(gmail, level="malicious", subject="Three months ago", hours_ago=24 * 90)
    await seed.message(yahoo, level="suspicious", quarantined=False, subject="Yahoo today", hours_ago=0.02)
    login(client, "period@example.com")

    week = client.get("/").text
    assert 'aria-current="true">7 days</a>' in week
    assert "We checked 2 emails this week. 1 looked suspicious." in week
    assert "Two weeks ago" not in week and 'aria-label="Last 7 days: ' in week

    today = client.get("/?period=today").text
    assert "We checked 2 emails today." in today and 'aria-label="Today, by hour: ' in today
    assert 'class="stat-period">Today<' in today

    month = client.get("/?period=1m").text
    assert "We checked 3 emails this month. 2 looked suspicious." in month and "Two weeks ago" in month
    assert 'aria-label="Last 30 days: ' in month and "Three months ago" not in month

    year = client.get("/?period=1y").text
    assert "We checked 4 emails this year. 3 looked suspicious. We moved 1 out of your inbox." in year
    assert 'aria-label="Last 12 months: ' in year and "1 moved out of your inbox" in year
    assert '<span class="num">4</span> emails checked' in year
    assert (await _prefs(db, user.id))["period"] == "1y"

    # The choice is remembered, and the inbox switch keeps it.
    again = client.get("/").text
    assert 'aria-current="true">1 year</a>' in again
    only_yahoo = client.get(f"/?mailbox={yahoo.id}").text
    assert "We checked 1 email this year." in only_yahoo
    assert f'href="/?mailbox={yahoo.id}&amp;period=today"' in only_yahoo  # period links keep the inbox
    assert 'href="/?period=1y&amp;mailbox=all"' in only_yahoo  # inbox links keep the period
    assert f"/messages?tab=suspicious&amp;period=1y&amp;mailbox={yahoo.id}" in only_yahoo


async def test_today_uses_the_browser_time_zone(client, seed, login):
    user = await seed.user("tz@example.com")
    mailbox = await seed.mailbox(user)
    await seed.message(mailbox, level="safe", hours_ago=0.01)
    login(client, "tz@example.com")
    client.cookies.set("rs_tz", "Pacific/Kiritimati")  # UTC+14
    page = client.get("/?period=today").text
    assert "We checked 1 email today." in page
    client.cookies.set("rs_tz", "Not/AZone")  # ignored: UTC
    assert client.get("/?period=today").status_code == 200


async def test_messages_period_tabs_and_old_links(client, seed, login):
    user = await seed.user("tabs@example.com")
    mailbox = await seed.mailbox(user)
    await seed.message(mailbox, level="malicious", subject="Moved one")
    await seed.message(mailbox, level="suspicious", quarantined=False, subject="Odd one")
    await seed.message(mailbox, level="safe", subject="Fine one")
    await seed.message(mailbox, level="unknown", subject="Unknown one", quarantined=False)
    login(client, "tabs@example.com")
    sus = client.get("/messages?tab=suspicious&period=7d").text
    assert "Moved one" in sus and "Odd one" in sus and "Fine one" not in sus
    assert sus.count("Moved out of inbox") == 1 and "Not fake?" in sus and "Not suspicious?" in sus
    assert "Secureddy Quarantine folder" in sus
    tabs = sus.split('class="tabs"')[1].split("</nav>")[0]
    assert ">All<" in tabs and ">Checked<" in tabs and ">Suspicious<" in tabs and "Quarantine" not in tabs
    checked = client.get("/messages?tab=checked").text
    assert "Fine one" in checked and "Moved one" not in checked
    unknown = client.get("/messages?level=unknown").text
    assert "Unknown one" in unknown and "Fine one" not in unknown
    for old in ("/messages?filter=quarantined", "/messages?quarantined=1", "/messages?level=malicious"):
        r = client.get(old)
        assert r.status_code == 303 and r.headers["location"] == "/messages?tab=suspicious"
    r = client.get(f"/messages?filter=quarantined&period=1y&mailbox={mailbox.id}")
    assert r.headers["location"] == f"/messages?tab=suspicious&period=1y&mailbox={mailbox.id}"


async def test_messages_sections_keep_period(client, seed, login, csrf_of):
    user = await seed.user("sections@example.com")
    gmail = await seed.mailbox(user)
    await seed.mailbox(user, provider="yahoo", address="sections@yahoo.com")
    await seed.message(gmail, level="suspicious", quarantined=False, subject="Odd")
    login(client, "sections@example.com")
    client.post("/settings/view", data={"inbox_view": "separate", "csrf_token": csrf_of(client, "/settings/security")})
    page = client.get("/messages?tab=suspicious&period=1m").text
    assert f'href="/messages?tab=suspicious&amp;period=1m&amp;mailbox={gmail.id}&amp;page=1"' in page
    everything = client.get("/messages?tab=suspicious&period=all").text
    assert f'href="/messages?tab=suspicious&amp;period=all&amp;mailbox={gmail.id}&amp;page=1"' in everything

"""What the person sees of the "links or files only" rule: one quiet line on
the account card, the Settings choice for text-only money scams, and copy
that says what we count ("We checked N emails with links or files")."""

from __future__ import annotations

import re

from sqlalchemy import select

from reddysec.assistant.agent import SYSTEM_PROMPT
from reddysec.assistant.tools import TOOL_SPECS
from reddysec.store import repo
from reddysec.store.models import AuditLog, UserPreferenceRow, UserRow
from reddysec.web import preferences

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


async def me(db, email: str) -> UserRow:
    async with db.session() as s:
        return (await s.execute(select(UserRow).where(UserRow.login_email == email))).scalar_one()


async def test_settings_choice_defaults_off_and_round_trips(client, login, db):
    login(client, "ann@example.com")
    page = client.get("/settings/security").text
    assert "Also watch text-only emails for money scams (wire transfer, gift cards)" in page
    assert "Scammers sometimes send no links at all and just ask for money. Turn this on to also check those." in page
    assert 'name="text_scams" value="on" data-autosubmit' in page  # not checked
    token = CSRF_RE.search(page).group(1)

    on = client.post("/settings/text-scams", data={"csrf_token": token, "text_scams": ["off", "on"]})
    assert on.status_code == 303 and on.headers["location"] == "/settings/security#scams"
    page = client.get("/settings/security").text
    assert 'value="on" checked data-autosubmit' in page
    assert "We now also check text-only emails for money scams." in page
    user = await me(db, "ann@example.com")
    async with db.session() as s:
        assert await repo.watches_text_scams(s, user.id)

    off = client.post("/settings/text-scams", data={"csrf_token": token, "text_scams": "off"})
    assert off.status_code == 303
    async with db.session() as s:
        assert not await repo.watches_text_scams(s, user.id)
        actions = [a.action for a in (await s.execute(select(AuditLog).where(AuditLog.actor_id == user.id))).scalars()]
    assert "text_scams_on" in actions and "text_scams_off" in actions
    assert "Turned on checks of text-only emails for money scams" in client.get("/audit").text


async def test_only_on_and_off_can_be_stored(db, seed):
    user = await seed.user("p@example.com")
    async with db.session() as s:
        assert not await preferences.set_preference(s, user.id, preferences.TEXT_SCAMS, "maybe")
        assert await preferences.set_preference(s, user.id, preferences.TEXT_SCAMS, "on")
        s.add(UserPreferenceRow(id="prf_bad", user_id=user.id, key="other", value="x"))
    async with db.session() as s:
        assert (await preferences.get_preferences(s, user.id))[preferences.TEXT_SCAMS] == "on"


async def test_account_card_says_plain_text_is_not_checked_without_a_number(client, login, seed, db):
    login(client, "bo@example.com")
    user = await me(db, "bo@example.com")
    mailbox = await seed.mailbox(user, address="bo@gmail.com")
    async with db.session() as s:
        await repo.bump_skipped_text_only(s, mailbox.id, by=9137)
    page = client.get("/mailboxes").text
    assert "Plain text emails are not checked" in page
    assert "9137" not in page and "9,137" not in page
    for path in ("/", "/messages", "/audit"):
        assert "9137" not in client.get(path).text


async def test_dashboard_and_email_list_copy(client, login, seed, db):
    login(client, "cy@example.com")
    user = await me(db, "cy@example.com")
    mailbox = await seed.mailbox(user, address="cy@gmail.com")
    await seed.message(mailbox, level="safe")
    home = client.get("/").text
    assert "We checked 1 email with links or files this week." in home
    assert "Every email with links or files we have checked" in client.get("/messages").text


def test_assistant_knows_what_we_check():
    assert "Plain text emails with nothing to click or open are not checked and not counted" in SYSTEM_PROMPT.replace(
        "\\\n", "")
    described = {t.name: t.description for t in TOOL_SPECS}
    assert "links or files" in described["get_stats"] and "not counted" in described["get_stats"]
    assert "links or files" in described["list_messages"] and "links or files" in described["search_messages"]

"""Mailbox onboarding (IMAP) and protection settings."""

from __future__ import annotations

import json

from sqlalchemy import select

from reddysec.core.crypto import TokenCipher
from reddysec.store.models import AuditLog, MailboxRow, MailboxSecret


def _cipher(settings) -> TokenCipher:
    return TokenCipher.from_settings(
        settings.token_kek.get_secret_value(), settings.secret_key.get_secret_value()
    )


async def _mailbox(db, mailbox_id):
    async with db.session() as s:
        return await s.get(MailboxRow, mailbox_id)


async def _actions(db, mailbox_id):
    async with db.session() as s:
        rows = (
            await s.execute(select(AuditLog).where(AuditLog.mailbox_id == mailbox_id).order_by(AuditLog.at))
        ).scalars()
        return [r.action for r in rows]


async def test_mailboxes_page_renders_chips_and_explanations(client, seed, login):
    user = await seed.user("boxes@example.com")
    await seed.mailbox(user, mode="hold")
    await seed.mailbox(user, provider="yahoo", address="boxes@yahoo.com", status="paused")
    await seed.mailbox(
        user, provider="icloud", address="boxes@icloud.com", status="error", last_error="Password rejected"
    )
    await seed.mailbox(user, provider="outlook", address="boxes@outlook.com", status="disconnected")
    login(client, "boxes@example.com")
    page = client.get("/mailboxes")
    assert page.status_code == 200
    for label in ("Protected", "Paused", "Needs reconnect", "Signed out", "Hold", "Scan"):
        assert label in page.text
    assert "Password rejected" in page.text  # the raw error, under "Details"
    assert "no longer accepts the password we have" in page.text  # in plain words first
    assert "safety switch releases everything within 10 minutes" in page.text
    assert ">Resume<" in page.text and ">Pause<" in page.text and ">Reconnect<" in page.text
    assert "Open inbox" in page.text and "Sign out of this mailbox" in page.text and "Re-check last 7 days" in page.text
    assert "Yahoo Mail" in page.text and "iCloud Mail" in page.text and "Outlook.com" in page.text


async def test_mailboxes_empty_state(client, login):
    login(client, "nobox@example.com")
    page = client.get("/mailboxes")
    assert "No account yet" in page.text and "Connect Gmail" in page.text


async def test_add_imap_page_shows_instructions(client, login):
    login(client, "imap@example.com")
    page = client.get("/mailboxes/add-imap")
    assert page.status_code == 200
    assert "Generate app password" in page.text  # Yahoo
    assert "App-Specific Passwords" in page.text  # iCloud
    assert "Create a new app password" in page.text  # Outlook.com
    assert "IMAP server name and port" in page.text  # Other
    assert 'name="app_password"' in page.text


async def test_add_imap_stores_encrypted_password(client, seed, db, settings, login, csrf_of):
    login(client, "yahoo.person@example.com")
    token = csrf_of(client, "/mailboxes/add-imap")
    response = client.post(
        "/mailboxes/add-imap",
        data={
            "provider": "yahoo",
            "address": "Yahoo.Person@Yahoo.com",
            "app_password": "abcd efgh ijkl mnop",
            "csrf_token": token,
        },
    )
    assert response.status_code == 303 and response.headers["location"] == "/mailboxes"
    async with db.session() as s:
        mailbox = (await s.execute(select(MailboxRow))).scalar_one()
        secret = await s.get(MailboxSecret, mailbox.id)
    assert (mailbox.provider, mailbox.address, mailbox.mode, mailbox.status, mailbox.labels) == (
        "yahoo",
        "yahoo.person@yahoo.com",
        "scan",
        "active",
        {},
    )
    assert secret.kind == "imap_password"
    payload = json.loads(_cipher(settings).decrypt(secret.ciphertext, aad=mailbox.id))
    assert payload == {
        "host": "imap.mail.yahoo.com",
        "port": 993,
        "username": "yahoo.person@yahoo.com",
        "password": "abcd efgh ijkl mnop",
    }
    assert await _actions(db, mailbox.id) == ["mailbox_connected"]
    assert "Yahoo Mail is connected" in client.get("/mailboxes").text


async def test_add_generic_imap_uses_custom_host(client, db, settings, login, csrf_of):
    login(client, "generic@example.com")
    token = csrf_of(client, "/mailboxes/add-imap")
    response = client.post(
        "/mailboxes/add-imap",
        data={
            "provider": "imap",
            "address": "me@fastmail.example",
            "app_password": "pw",
            "host": "IMAP.Fastmail.example",
            "port": "1993",
            "csrf_token": token,
        },
    )
    assert response.status_code == 303
    async with db.session() as s:
        mailbox = (await s.execute(select(MailboxRow))).scalar_one()
        secret = await s.get(MailboxSecret, mailbox.id)
    payload = json.loads(_cipher(settings).decrypt(secret.ciphertext, aad=mailbox.id))
    assert (
        mailbox.provider == "imap" and payload["host"] == "imap.fastmail.example" and payload["port"] == 1993
    )


async def test_add_imap_validation_errors(client, seed, login, csrf_of):
    user = await seed.user("validate@example.com")
    await seed.mailbox(user, provider="yahoo", address="dupe@yahoo.com")
    login(client, "validate@example.com")
    token = csrf_of(client, "/mailboxes/add-imap")
    cases = [
        ({"provider": "aol", "address": "a@b.c", "app_password": "x"}, "choose a mail provider"),
        ({"provider": "yahoo", "address": "not-an-address", "app_password": "x"}, "full email address"),
        ({"provider": "yahoo", "address": "a@b.c", "app_password": "   "}, "paste the app password"),
        (
            {"provider": "imap", "address": "a@b.c", "app_password": "x", "host": "", "port": "993"},
            "IMAP server name",
        ),
        (
            {"provider": "imap", "address": "a@b.c", "app_password": "x", "host": "h.example", "port": "abc"},
            "between 1 and 65535",
        ),
        (
            {
                "provider": "imap",
                "address": "a@b.c",
                "app_password": "x",
                "host": "h.example",
                "port": "70000",
            },
            "between 1 and 65535",
        ),
        ({"provider": "yahoo", "address": "dupe@yahoo.com", "app_password": "x"}, "already connected"),
    ]
    for data, message in cases:
        response = client.post("/mailboxes/add-imap", data={**data, "csrf_token": token})
        assert response.status_code == 400, data
        assert message in response.text, data


async def test_mode_switch_resets_labels_and_audits(client, seed, db, login, csrf_of):
    user = await seed.user("mode@example.com")
    mailbox = await seed.mailbox(user, labels={"Secureddy": "L1", "Secureddy/Checking": "L2"})
    login(client, "mode@example.com")
    token = csrf_of(client, "/mailboxes")
    response = client.post(f"/mailboxes/{mailbox.id}/mode", data={"mode": "hold", "csrf_token": token})
    assert response.status_code == 303
    row = await _mailbox(db, mailbox.id)
    assert row.mode == "hold" and row.labels == {}
    assert "Hold mode is on" in client.get("/mailboxes").text
    # Same mode again: nothing to record.
    client.post(f"/mailboxes/{mailbox.id}/mode", data={"mode": "hold", "csrf_token": token})
    assert await _actions(db, mailbox.id) == ["mode_changed"]
    back = client.post(f"/mailboxes/{mailbox.id}/mode", data={"mode": "scan", "csrf_token": token})
    assert back.status_code == 303 and "Scan mode is on" in client.get("/mailboxes").text
    assert (
        client.post(f"/mailboxes/{mailbox.id}/mode", data={"mode": "turbo", "csrf_token": token}).status_code
        == 400
    )
    async with db.session() as s:
        entry = (await s.execute(select(AuditLog).where(AuditLog.action == "mode_changed"))).scalars().first()
    assert entry.details == {"from": "scan", "to": "hold"} and entry.target == mailbox.address


async def test_pause_resume_disconnect(client, seed, db, login, csrf_of):
    user = await seed.user("lifecycle@example.com")
    mailbox = await seed.mailbox(user, provider="yahoo", address="life@yahoo.com")
    async with db.session() as s:
        s.add(
            MailboxSecret(mailbox_id=mailbox.id, kind="imap_password", ciphertext="v1.dev.xx", key_id="dev")
        )
    login(client, "lifecycle@example.com")
    token = csrf_of(client, "/mailboxes")

    assert client.post(f"/mailboxes/{mailbox.id}/pause", data={"csrf_token": token}).status_code == 303
    assert (await _mailbox(db, mailbox.id)).status == "paused"
    assert "Protection is paused" in client.get("/mailboxes").text
    client.post(
        f"/mailboxes/{mailbox.id}/pause", data={"csrf_token": token}
    )  # already paused: no new audit row

    assert client.post(f"/mailboxes/{mailbox.id}/resume", data={"csrf_token": token}).status_code == 303
    assert (await _mailbox(db, mailbox.id)).status == "active"
    assert "Protection is back on" in client.get("/mailboxes").text

    assert client.post(f"/mailboxes/{mailbox.id}/disconnect", data={"csrf_token": token}).status_code == 303
    row = await _mailbox(db, mailbox.id)
    assert row.status == "disconnected"
    async with db.session() as s:
        assert await s.get(MailboxSecret, mailbox.id) is None
    assert "Signed out of" in client.get("/mailboxes").text
    client.post(f"/mailboxes/{mailbox.id}/disconnect", data={"csrf_token": token})  # idempotent
    assert await _actions(db, mailbox.id) == [
        "mailbox_paused", "mailbox_resumed", "mailbox_disconnected", "mailbox_signed_out"
    ]
    page = client.get("/mailboxes")
    assert "Signed out" in page.text and f"/mailboxes/{mailbox.id}/mode" not in page.text


async def test_resume_from_error_state(client, seed, db, login, csrf_of):
    user = await seed.user("err@example.com")
    mailbox = await seed.mailbox(user, status="error", last_error="token revoked")
    login(client, "err@example.com")
    token = csrf_of(client, "/mailboxes")
    client.post(f"/mailboxes/{mailbox.id}/resume", data={"csrf_token": token})
    row = await _mailbox(db, mailbox.id)
    assert row.status == "active" and row.last_error is None


async def test_other_users_mailbox_is_404_for_every_mutation(client, seed, db, login, csrf_of):
    owner = await seed.user("owner@example.com")
    mailbox = await seed.mailbox(owner)
    await seed.user("other@example.com")
    login(client, "other@example.com")
    token = csrf_of(client, "/mailboxes")
    for action, data in (("mode", {"mode": "hold"}), ("pause", {}), ("resume", {}), ("disconnect", {})):
        response = client.post(f"/mailboxes/{mailbox.id}/{action}", data={**data, "csrf_token": token})
        assert response.status_code == 404, action
    assert client.post("/mailboxes/mbx_missing/pause", data={"csrf_token": token}).status_code == 404
    assert (await _mailbox(db, mailbox.id)).status == "active"


async def test_assistant_can_see_but_not_manage_principal_mailbox(client, seed, db, login, csrf_of):
    principal = await seed.user("principal@example.com")
    mailbox = await seed.mailbox(principal)
    await seed.user("pa@example.com", role="assistant", principal_id=principal.id)
    login(client, "pa@example.com", role="assistant")
    page = client.get("/mailboxes")
    assert mailbox.address in page.text and "Only the account owner can change this mailbox" in page.text
    token = csrf_of(client, "/mailboxes")
    assert client.post(f"/mailboxes/{mailbox.id}/pause", data={"csrf_token": token}).status_code == 404


async def test_mailbox_card_shows_the_workers_plain_error(client, seed, login):
    from reddysec.models.accounts import MAILBOX_ERROR_SAVE_PLACE

    user = await seed.user("owner@example.com")
    await seed.mailbox(user, provider="yahoo", address="me@yahoo.com", status="error",
                       last_error=MAILBOX_ERROR_SAVE_PLACE, labels={})
    await seed.mailbox(user, provider="gmail", address="other@gmail.com", status="error",
                       last_error="mailbox credentials expired or revoked")
    login(client, "owner@example.com")
    page = client.get("/mailboxes").text
    assert "We couldn&#39;t save our place in your mailbox. We&#39;re fixing it." in page
    assert "We hit a problem with this mailbox: We couldn" not in page
    assert "Setting up" not in page and ">Error<" in page and "Needs reconnect" in page
    assert "Google stopped letting us read this mailbox" in page  # plain words for a revoked grant
    assert "mailbox credentials expired or revoked" in page  # the worker's words, under "Details"


async def test_add_imap_rejects_an_overlong_address(client, seed, login, csrf_of):
    await seed.user("owner@example.com")
    login(client, "owner@example.com")
    token = csrf_of(client, "/mailboxes/add-imap")
    response = client.post("/mailboxes/add-imap", data={"csrf_token": token, "provider": "yahoo",
                                                        "address": "a" * 250 + "@yahoo.com", "app_password": "x"})
    assert response.status_code == 400 and "full email address" in response.text

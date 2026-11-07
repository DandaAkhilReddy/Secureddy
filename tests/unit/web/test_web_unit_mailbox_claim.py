"""One mailbox per person and address, whichever connect path is used."""

from __future__ import annotations

from sqlalchemy import select

from reddysec.core.crypto import TokenCipher
from reddysec.store import repo
from reddysec.store.models import MailboxRow, MailboxSecret
from reddysec.web import queries

CIPHER = TokenCipher.from_settings("", "unit-test-secret")


async def _rows(db) -> list[MailboxRow]:
    async with db.session() as s:
        return list((await s.execute(select(MailboxRow))).scalars())


async def test_reconnect_after_disconnect_reuses_the_row(db):
    """The production duplicate: connect, disconnect, connect again."""
    async with db.session() as s:
        user = await repo.create_user(s, email="owner@example.com", display_name="Owner")
        first = await queries.add_imap_mailbox(s, CIPHER, user, provider="yahoo", address="Me@Yahoo.com",
                                               host="imap.mail.yahoo.com", port=993, password="one")
        first.labels = {"Secureddy": "Secureddy"}
        await queries.disconnect_mailbox(s, user, first)
    async with db.session() as s:
        user = await repo.get_user(s, user.id)
        existing = await queries.find_mailbox_by_address(s, user.id, "me@yahoo.com")
        assert not queries.mailbox_is_connected(existing)
        again = await queries.add_imap_mailbox(s, CIPHER, user, provider="yahoo", address="me@yahoo.com",
                                               host="imap.mail.yahoo.com", port=993, password="two")
        assert again.id == first.id and again.status == "active" and again.labels == {}
        assert queries.mailbox_is_connected(again)
    (row,) = await _rows(db)
    async with db.session() as s:
        assert (await queries.read_mailbox_secret(s, CIPHER, row.id))["password"] == "two"


async def test_switching_from_app_password_to_microsoft_keeps_one_row(db):
    async with db.session() as s:
        user = await repo.create_user(s, email="owner@example.com", display_name="Owner")
        imap = await queries.add_imap_mailbox(s, CIPHER, user, provider="outlook", address="me@outlook.com",
                                              host="outlook.office365.com", port=993, password="pw")
        imap.cursor, imap.labels = "1:5", {"Secureddy": "Secureddy"}
        await s.flush()
        graph = await queries.connect_microsoft_mailbox(s, CIPHER, user, "me@outlook.com",
                                                        {"access_token": "a", "refresh_token": "r"})
        assert graph.id == imap.id and graph.provider == "microsoft"
        assert graph.cursor is None and graph.labels == {}  # set up again for the new provider
        secret = await s.get(MailboxSecret, graph.id)
        assert secret.kind == "microsoft_oauth"
    assert len(await _rows(db)) == 1


async def test_racing_inserts_end_with_one_row(db, monkeypatch):
    """Two submits read "no mailbox" at the same time; the unique index makes
    the second insert fail and claim_mailbox falls back to the winner."""
    async with db.session() as s:
        user = await repo.create_user(s, email="owner@example.com", display_name="Owner")
    async with db.session() as s:
        winner = await queries.add_imap_mailbox(s, CIPHER, user, provider="yahoo", address="me@yahoo.com",
                                                host="h", port=993, password="pw")
    real_find = queries.find_mailbox_by_address
    calls = {"n": 0}

    async def stale_first_read(session, user_id, address):
        calls["n"] += 1
        return None if calls["n"] == 1 else await real_find(session, user_id, address)

    monkeypatch.setattr(queries, "find_mailbox_by_address", stale_first_read)
    async with db.session() as s:
        user = await repo.get_user(s, user.id)
        mailbox, created = await queries.claim_mailbox(s, user, provider="yahoo", address="ME@yahoo.com")
        assert not created and mailbox.id == winner.id
    assert len(await _rows(db)) == 1


async def test_request_recent_backfill_widens_an_open_request(db):
    async with db.session() as s:
        user = await repo.create_user(s, email="owner@example.com", display_name="Owner")
        box = await repo.create_mailbox(s, user_id=user.id, provider="gmail", address="me@gmail.com")
        assert await queries.request_recent_backfill(s, user, box, days=2, limit=50) is True
        assert await queries.request_recent_backfill(s, user, box) is False
        task = await repo.open_backfill(s, box.id)
        assert task.max_messages == 200

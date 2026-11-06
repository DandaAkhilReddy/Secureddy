"""Query-layer edge cases that the pages never reach on their own."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from reddysec.core.crypto import TokenCipher
from reddysec.core.ids import new_id
from reddysec.store.models import MailboxRow, MailboxSecret, MessageRow, UserRow
from reddysec.web import queries

CIPHER = TokenCipher.from_settings("", "unit-test-secret")


async def _user(db, email="q@example.com", **kw) -> UserRow:
    async with db.session() as s:
        row = UserRow(
            id=new_id("usr"), display_name="Q", login_email=email, role=kw.pop("role", "principal"), **kw
        )
        s.add(row)
    return row


class TestSecrets:
    async def test_unknown_secret_kind_is_refused(self, db):
        async with db.session() as s:
            with pytest.raises(ValueError):
                queries.write_mailbox_secret(s, CIPHER, "mbx_x", "yahoo_oauth", {"a": 1})

    async def test_read_secret_handles_missing_and_undecryptable_rows(self, db):
        user = await _user(db)
        async with db.session() as s:
            mailbox = MailboxRow(id=new_id("mbx"), user_id=user.id, provider="gmail", address="a@b")
            s.add(mailbox)
            await s.flush()
            s.add(
                MailboxSecret(
                    mailbox_id=mailbox.id, kind="google_oauth", ciphertext="v1.dev.garbage", key_id="dev"
                )
            )
        async with db.session() as s:
            assert await queries.read_mailbox_secret(s, CIPHER, "mbx_missing") is None
            assert await queries.read_mailbox_secret(s, CIPHER, mailbox.id) is None
            # Valid ciphertext that is not a JSON object.
            row = await s.get(MailboxSecret, mailbox.id)
            row.ciphertext = CIPHER.encrypt("[1, 2]", aad=mailbox.id)
        async with db.session() as s:
            assert await queries.read_mailbox_secret(s, CIPHER, mailbox.id) is None
            row = await s.get(MailboxSecret, mailbox.id)
            row.ciphertext = CIPHER.encrypt('{"refresh_token": "r"}', aad=mailbox.id)
        async with db.session() as s:
            assert await queries.read_mailbox_secret(s, CIPHER, mailbox.id) == {"refresh_token": "r"}

    async def test_gmail_reconnect_without_any_refresh_token_stores_what_it_got(self, db):
        user = await _user(db)
        async with db.session() as s:
            await queries.connect_gmail_mailbox(s, CIPHER, user, "q@example.com", {"access_token": "a1"})
        async with db.session() as s:
            mailbox = await queries.connect_gmail_mailbox(
                s, CIPHER, user, "Q@example.com", {"access_token": "a2", "refresh_token": None}
            )
        async with db.session() as s:
            assert len((await s.execute(select(MailboxRow))).scalars().all()) == 1
            assert await queries.read_mailbox_secret(s, CIPHER, mailbox.id) == {
                "access_token": "a2",
                "refresh_token": None,
            }

    async def test_gmail_reconnect_reactivates_disconnected_mailbox(self, db):
        user = await _user(db)
        async with db.session() as s:
            mailbox = await queries.connect_gmail_mailbox(
                s, CIPHER, user, "q@example.com", {"refresh_token": "r1"}
            )
            await queries.disconnect_mailbox(s, user, mailbox)
        async with db.session() as s:
            again = await queries.connect_gmail_mailbox(
                s, CIPHER, user, "q@example.com", {"refresh_token": None}
            )
            assert again.id == mailbox.id and again.status == "active"
        async with db.session() as s:
            # Nothing to inherit: the disconnect deleted the old secret.
            assert (await queries.read_mailbox_secret(s, CIPHER, mailbox.id))["refresh_token"] is None


class TestVerdictMutations:
    async def test_override_rejects_unknown_level(self, db):
        user = await _user(db, role="concierge")
        async with db.session() as s:
            mailbox = MailboxRow(id=new_id("mbx"), user_id=user.id, provider="gmail", address="a@b")
            message = MessageRow(
                id=new_id("msg"),
                mailbox_id=mailbox.id,
                provider_message_id="p",
                received_at=datetime.now(UTC),
                verdict={},
            )
            with pytest.raises(ValueError):
                await queries.override_verdict(s, user, message, mailbox, "terrible", "note")

    async def test_restore_request_requires_quarantine(self, db):
        user = await _user(db)
        async with db.session() as s:
            mailbox = MailboxRow(id=new_id("mbx"), user_id=user.id, provider="gmail", address="a@b")
            message = MessageRow(
                id=new_id("msg"),
                mailbox_id=mailbox.id,
                provider_message_id="p",
                received_at=datetime.now(UTC),
                quarantined=False,
            )
            assert await queries.request_restore(s, user, message, mailbox) is False
            message.quarantined = True
            assert await queries.request_restore(s, user, message, mailbox) is True
            assert await queries.request_restore(s, user, message, mailbox) is False  # already requested


class TestVisibility:
    def test_visible_owner_ids(self):
        principal = UserRow(id="u1", display_name="", login_email="a", role="principal")
        helper = UserRow(id="u2", display_name="", login_email="b", role="assistant", principal_id="u1")
        odd = UserRow(id="u3", display_name="", login_email="c", role="family", principal_id="u3")
        assert queries.visible_owner_ids(principal) == ["u1"]
        assert queries.visible_owner_ids(helper) == ["u2", "u1"]
        assert queries.visible_owner_ids(odd) == ["u3"]
        assert queries.is_staff(UserRow(id="x", display_name="", login_email="d", role="admin"))
        assert not queries.is_staff(principal)

    async def test_list_notifications_without_since(self, db):
        user = await _user(db)
        async with db.session() as s:
            queries.notify(s, user_id=user.id, message_id=None, level="safe", title="t", body="b")
        async with db.session() as s:
            rows = await queries.list_notifications(s, user)
            assert [r.title for r in rows] == ["t"]

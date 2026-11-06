"""build_connector: mailbox row + vault -> connector, with fakes for both providers."""

from __future__ import annotations

import os
from datetime import timedelta

import httpx
import pytest

from reddysec.config import Settings
from reddysec.core.crypto import TokenCipher
from reddysec.mail.base import AuthExpired
from reddysec.mail.factory import build_connector, connector_factory_from_settings, make_google_oauth
from reddysec.mail.gmail import GmailConnector
from reddysec.mail.imap import ImapConnector
from reddysec.mail.vault import KIND_GOOGLE_OAUTH, KIND_IMAP_PASSWORD, CredentialVault
from reddysec.models import ProtectionMode, Provider
from reddysec.store import repo

from .conftest import CLIENT_ID, CLIENT_SECRET, FIXED_NOW, FakeImapServer, GmailEnv, sample_raw


@pytest.fixture
def settings() -> Settings:
    return Settings(
        google_client_id=CLIENT_ID,
        google_client_secret=CLIENT_SECRET,
        secret_key="s",
        base_url="http://localhost:8000",
    )


@pytest.fixture
def vault() -> CredentialVault:
    return CredentialVault(TokenCipher({"k1": os.urandom(32)}, "k1"))


async def _mailbox(
    db, vault, *, provider: str, kind: str, secret: dict, mode: str = "scan", labels: dict | None = None
):
    async with db.session() as s:
        user = await repo.create_user(s, email="c@example.com", display_name="C")
        mbx = await repo.create_mailbox(
            s, user_id=user.id, provider=provider, address="client@example.com", mode=mode
        )
        await vault.store(s, mbx.id, kind, secret)
        if labels:
            await repo.set_mailbox_labels(s, mbx.id, labels)
    async with db.session() as s:
        return await repo.get_mailbox(s, mbx.id)


class TestGmail:
    async def test_builds_gmail_connector_and_persists_refreshed_tokens(
        self, db, vault, settings, gmail_env: GmailEnv
    ):
        secret = {
            "access_token": "stale",
            "refresh_token": "refresh-1",
            "expires_at": (FIXED_NOW - timedelta(hours=2)).isoformat(),
            "sub": "sub-123",
            "email": "client@gmail.com",
        }
        mailbox = await _mailbox(
            db,
            vault,
            provider="gmail",
            kind=KIND_GOOGLE_OAUTH,
            secret=secret,
            mode="hold",
            labels={"Secureddy": "L1", "_mode": "hold"},
        )
        connector = await build_connector(
            mailbox, vault, settings, gmail_env.http, db=db, oauth=gmail_env.oauth
        )
        assert isinstance(connector, GmailConnector)
        assert connector.provider is Provider.GMAIL and connector.mode is ProtectionMode.HOLD
        assert connector.labels == {"Secureddy": "L1"}
        assert connector.credentials.refresh_token == "refresh-1"
        # First call: the stale token triggers a refresh which is written back to the vault.
        mid = gmail_env.server.add_message(sample_raw("m"))
        assert await connector.fetch_raw(mid) == sample_raw("m")
        async with db.session() as s:
            kind, stored = await vault.load(s, mailbox.id)
        assert kind == KIND_GOOGLE_OAUTH
        assert stored["access_token"] == "access-1"
        assert stored["refresh_token"] == "refresh-1"  # carried over: Google does not echo it
        assert stored["sub"] == "sub-123" and stored["email"] == "client@gmail.com"  # identity kept

    async def test_uses_default_oauth_when_none_given(self, db, vault, settings, gmail_env: GmailEnv):
        secret = {
            "access_token": "access-0",
            "refresh_token": "refresh-1",
            "expires_at": (FIXED_NOW + timedelta(hours=2)).isoformat(),
        }
        mailbox = await _mailbox(db, vault, provider="gmail", kind=KIND_GOOGLE_OAUTH, secret=secret)
        connector = await build_connector(
            mailbox, vault, settings, gmail_env.http
        )  # no db: eager-loaded secret
        assert isinstance(connector, GmailConnector)
        assert connector._on_tokens_refreshed is None  # nothing to persist to without a database
        oauth = make_google_oauth(settings)
        assert (
            oauth.client_id == CLIENT_ID
            and oauth.redirect_uri == "http://localhost:8000/auth/google/callback"
        )
        await oauth.aclose()

    async def test_wrong_kind_for_gmail(self, db, vault, settings):
        mailbox = await _mailbox(
            db, vault, provider="gmail", kind=KIND_IMAP_PASSWORD, secret={"username": "u", "password": "p"}
        )
        with pytest.raises(AuthExpired, match="Gmail mailbox"):
            await build_connector(mailbox, vault, settings, db=db)


class TestImap:
    async def test_builds_imap_connector_with_db_resolver(self, db, vault, settings):
        server = FakeImapServer(accept=("client@example.com", "app-pw"))
        mailbox = await _mailbox(
            db,
            vault,
            provider="yahoo",
            kind=KIND_IMAP_PASSWORD,
            secret={"username": "client@example.com", "password": "app-pw"},
        )
        connector = await build_connector(
            mailbox, vault, settings, db=db, imap_session_factory=server.session
        )
        assert isinstance(connector, ImapConnector) and connector.provider is Provider.YAHOO
        await connector.setup(ProtectionMode.SCAN)
        server.deliver("INBOX", sample_raw("m", message_id="<m@example.com>"))
        (raw,), _ = await connector.poll(None)
        # Record the message so the resolver can map the location id to its Message-ID.
        from reddysec.models import ParsedMessage

        parsed = ParsedMessage(
            provider_message_id=raw.provider_message_id,
            mailbox_id=mailbox.id,
            received_at=raw.received_at,
            rfc_message_id="<m@example.com>",
        )
        async with db.session() as s:
            await repo.upsert_message(s, parsed, raw)
        await connector.quarantine(raw.provider_message_id)
        await connector.restore(raw.provider_message_id)  # found via the DB-backed resolver after the move
        assert len(server.folders["INBOX"].messages) == 1
        assert ("search", ('HEADER Message-ID "<m@example.com>"',)) in server.calls

    async def test_resolver_returns_none_for_unknown_message(self, db, vault, settings):
        server = FakeImapServer(accept=("client@example.com", "app-pw"))
        mailbox = await _mailbox(
            db,
            vault,
            provider="yahoo",
            kind=KIND_IMAP_PASSWORD,
            secret={"username": "client@example.com", "password": "app-pw"},
        )
        connector = await build_connector(
            mailbox, vault, settings, db=db, imap_session_factory=server.session
        )
        assert await connector._resolve_message_id("INBOX:1:1") is None

    async def test_unusable_imap_credentials(self, db, vault, settings):
        mailbox = await _mailbox(
            db, vault, provider="yahoo", kind=KIND_IMAP_PASSWORD, secret={"username": "u"}
        )
        with pytest.raises(AuthExpired, match="unusable IMAP credentials"):
            await build_connector(mailbox, vault, settings, db=db)

    async def test_generic_imap_without_host_fails_clearly(self, db, vault, settings):
        mailbox = await _mailbox(
            db, vault, provider="imap", kind=KIND_IMAP_PASSWORD, secret={"username": "u", "password": "p"}
        )
        with pytest.raises(ValueError, match="explicit IMAP host"):
            await build_connector(mailbox, vault, settings, db=db)


class TestSecrets:
    async def test_missing_secret_is_auth_expired(self, db, vault, settings):
        async with db.session() as s:
            user = await repo.create_user(s, email="c@example.com", display_name="C")
            mbx = await repo.create_mailbox(s, user_id=user.id, provider="yahoo", address="c@yahoo.com")
        async with db.session() as s:
            mailbox = await repo.get_mailbox(s, mbx.id)
        with pytest.raises(AuthExpired, match="no credentials"):
            await build_connector(mailbox, vault, settings, db=db)
        with pytest.raises(AuthExpired, match="no credentials"):
            await build_connector(mailbox, vault, settings)  # eager-loaded relationship is None

    async def test_undecryptable_secret_is_auth_expired(self, db, vault, settings):
        mailbox = await _mailbox(
            db, vault, provider="yahoo", kind=KIND_IMAP_PASSWORD, secret={"username": "u", "password": "p"}
        )
        other = CredentialVault(TokenCipher({"k1": os.urandom(32)}, "k1"))
        with pytest.raises(AuthExpired, match="cannot be decrypted"):
            await build_connector(mailbox, other, settings, db=db)

    async def test_unloaded_relationship_without_db(self, db, vault, settings):
        mailbox = await _mailbox(
            db, vault, provider="yahoo", kind=KIND_IMAP_PASSWORD, secret={"username": "u", "password": "p"}
        )
        async with db.session() as s:
            from sqlalchemy import select

            from reddysec.store.models import MailboxRow

            bare = (await s.execute(select(MailboxRow).where(MailboxRow.id == mailbox.id))).scalar_one()
        with pytest.raises(AuthExpired, match="no credentials loaded"):
            await build_connector(bare, vault, settings)


async def test_connector_factory_from_settings(db, settings, gmail_env: GmailEnv):
    vault = CredentialVault(TokenCipher({"k1": os.urandom(32)}, "k1"))
    secret = {
        "access_token": "access-0",
        "refresh_token": "refresh-1",
        "expires_at": (FIXED_NOW + timedelta(hours=2)).isoformat(),
    }
    mailbox = await _mailbox(db, vault, provider="gmail", kind=KIND_GOOGLE_OAUTH, secret=secret)
    factory = connector_factory_from_settings(settings, db, http=gmail_env.http, vault=vault)
    connector = await factory(mailbox)
    assert isinstance(connector, GmailConnector)
    # default vault derived from settings also works (different key -> cannot decrypt our row)
    with pytest.raises(AuthExpired):
        await connector_factory_from_settings(
            settings, db, http=httpx.AsyncClient(transport=gmail_env.server.transport())
        )(mailbox)


async def test_persist_tokens_keeps_previous_refresh_token(db, vault):
    from datetime import UTC, datetime

    from reddysec.mail.factory import _persist_tokens
    from reddysec.mail.oauth_google import TokenSet

    async with db.session() as s:
        user = await repo.create_user(s, email="c@example.com", display_name="C")
        mbx = await repo.create_mailbox(s, user_id=user.id, provider="gmail", address="c@gmail.com")
    previous = {"refresh_token": "keep-me", "access_token": "old", "sub": "sub-1", "email": "c@gmail.com"}
    persist = _persist_tokens(mbx.id, vault, db, previous)
    await persist(
        TokenSet(access_token="new", refresh_token=None, expires_at=datetime(2026, 1, 1, tzinfo=UTC))
    )
    async with db.session() as s:
        _kind, stored = await vault.load(s, mbx.id)
    assert (
        stored["refresh_token"] == "keep-me" and stored["access_token"] == "new" and stored["sub"] == "sub-1"
    )

"""build_connector for Microsoft mailboxes, and the Microsoft/Yahoo OAuth factories."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from reddysec.config import Settings
from reddysec.core.crypto import TokenCipher
from reddysec.mail.base import AuthExpired, ConnectorError
from reddysec.mail.factory import build_connector, make_microsoft_oauth, make_yahoo_oauth
from reddysec.mail.imap import ImapConnector, ImapCredentials
from reddysec.mail.oauth_google import TokenSet
from reddysec.mail.outlook_graph import GraphMailConnector
from reddysec.mail.vault import KIND_IMAP_PASSWORD, KIND_MICROSOFT_OAUTH, CredentialVault
from reddysec.models import Provider
from reddysec.store import repo

from .conftest import FakeImapServer
from .oidc_support import rsa_key, self_signed_bundle, thumbprint

NOW = datetime.now(UTC)


@pytest.fixture(scope="module")
def pem_and_thumb():
    pem, cert = self_signed_bundle(rsa_key())
    return pem, thumbprint(cert)


@pytest.fixture
def settings(pem_and_thumb) -> Settings:
    pem, thumb = pem_and_thumb
    return Settings(
        microsoft_client_id="8cc0907f-7f8e-45ec-9758-102eea8c1a00", microsoft_client_cert=pem,
        microsoft_cert_thumbprint=thumb, yahoo_client_id="y", yahoo_client_secret="ys",
        secret_key="s", base_url="https://rsec.example",
    )


@pytest.fixture
def vault() -> CredentialVault:
    return CredentialVault(TokenCipher({"k1": os.urandom(32)}, "k1"))


async def _mailbox(db, vault, *, kind: str, secret: dict, provider: str = "microsoft"):
    async with db.session() as s:
        user = await repo.create_user(s, email="a@outlook.com", display_name="A")
        mbx = await repo.create_mailbox(s, user_id=user.id, provider=provider, address="a@outlook.com")
        await vault.store(s, mbx.id, kind, secret)
    async with db.session() as s:
        return await repo.get_mailbox(s, mbx.id)


class RefreshingOAuth:
    async def refresh(self, refresh_token: str) -> TokenSet:
        return TokenSet(access_token="new-at", refresh_token="rotated-rt", expires_at=NOW + timedelta(hours=1))


async def test_builds_graph_connector_and_persists_rotated_tokens(db, vault, settings):
    secret = {"access_token": "old", "refresh_token": "rt-1", "expires_at": (NOW - timedelta(hours=1)).isoformat(),
              "sub": "oid-1", "email": "a@outlook.com", "tid": "t"}
    mailbox = await _mailbox(db, vault, kind=KIND_MICROSOFT_OAUTH, secret=secret)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"Subject: x\r\n\r\nbody")

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    conn = await build_connector(mailbox, vault, settings, http, db=db, microsoft_oauth=RefreshingOAuth())
    assert isinstance(conn, GraphMailConnector) and conn.provider is Provider.MICROSOFT
    assert await conn.fetch_raw("m1") == b"Subject: x\r\n\r\nbody"
    async with db.session() as s:
        kind, stored = await vault.load(s, mailbox.id)
    assert kind == KIND_MICROSOFT_OAUTH and stored["refresh_token"] == "rotated-rt"
    assert stored["sub"] == "oid-1" and stored["tid"] == "t"


async def test_default_microsoft_oauth_and_misconfiguration(db, vault, settings):
    mailbox = await _mailbox(db, vault, kind=KIND_MICROSOFT_OAUTH, secret={"access_token": "a"})
    conn = await build_connector(mailbox, vault, settings, db=db)
    assert conn._oauth.client_id == settings.microsoft_client_id
    assert conn._oauth.redirect_uri == "https://rsec.example/auth/microsoft/callback"
    unconfigured = Settings(secret_key="s")
    with pytest.raises(ConnectorError) as exc:
        await build_connector(mailbox, vault, unconfigured, db=db)
    assert not exc.value.retryable
    with pytest.raises(ValueError):
        make_microsoft_oauth(unconfigured)
    with pytest.raises(ValueError):
        make_yahoo_oauth(unconfigured)
    yahoo = make_yahoo_oauth(settings)
    assert yahoo.redirect_uri == "https://rsec.example/auth/yahoo/callback"


async def test_wrong_kind_for_microsoft(db, vault, settings):
    mailbox = await _mailbox(db, vault, kind=KIND_IMAP_PASSWORD, secret={"username": "u", "password": "p"})
    with pytest.raises(AuthExpired, match="Microsoft mailbox"):
        await build_connector(mailbox, vault, settings, db=db)


def test_microsoft_is_not_imap():
    assert not Provider.MICROSOFT.uses_imap and Provider.OUTLOOK.uses_imap and not Provider.GMAIL.uses_imap


async def test_imap_check_login():
    server = FakeImapServer(accept=("a@yahoo.com", "pw"))
    ok = ImapConnector("t", "a@yahoo.com", Provider.YAHOO, ImapCredentials(username="a@yahoo.com", password="pw"),
                       session_factory=server.session)
    assert await ok.check_login() >= 0
    bad = ImapConnector("t", "a@yahoo.com", Provider.YAHOO, ImapCredentials(username="a@yahoo.com", password="no"),
                        session_factory=server.session)
    with pytest.raises(AuthExpired):
        await bad.check_login()


def test_app_builds_providers_only_when_configured(settings):
    from reddysec.web.app import default_microsoft_oauth, default_yahoo_oauth

    assert default_microsoft_oauth(Settings(secret_key="s")) is None
    assert default_yahoo_oauth(Settings(secret_key="s")) is None
    assert default_microsoft_oauth(settings).client_id == settings.microsoft_client_id
    assert default_yahoo_oauth(settings).client_id == "y"
    broken = settings.model_copy(update={"microsoft_cert_thumbprint": "00" * 20})
    assert default_microsoft_oauth(broken) is None  # logged, button hidden, site keeps running

"""Composition root for mailbox connectors.

``build_connector`` turns a mailbox row plus its vaulted secret into a live
``MailboxConnector``. It is the only place that knows which provider maps to
which class, how Google token refreshes are persisted, and how the IMAP
connector finds a message's RFC Message-ID after a move. Everything slow or
external is injectable so the function is unit-testable with fakes.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import httpx
from sqlalchemy import inspect as sa_inspect

from reddysec.config import Settings
from reddysec.core.logging import get_logger
from reddysec.mail.base import AuthExpired, ConnectorError, MailboxConnector
from reddysec.mail.gmail import GmailConnector, GoogleCredentials
from reddysec.mail.imap import ImapConnector, ImapCredentials, ImapSession
from reddysec.mail.oauth_google import GoogleOAuth, TokenSet
from reddysec.mail.oauth_microsoft import MicrosoftOAuth
from reddysec.mail.oauth_yahoo import YahooOAuth
from reddysec.mail.outlook_graph import GraphMailConnector
from reddysec.mail.vault import (
    KIND_GOOGLE_OAUTH,
    KIND_MICROSOFT_OAUTH,
    CredentialVault,
    VaultError,
    cipher_from_settings,
)
from reddysec.models import ProtectionMode, Provider
from reddysec.store import repo
from reddysec.store.db import Database
from reddysec.store.models import MailboxRow

log = get_logger(__name__)

ConnectorFactory = Callable[[MailboxRow], Awaitable[MailboxConnector]]


def make_google_oauth(settings: Settings, http: httpx.AsyncClient | None = None) -> GoogleOAuth:
    return GoogleOAuth(
        settings.google_client_id,
        settings.google_client_secret.get_secret_value(),
        settings.google_redirect_uri,
        state_signer_secret=settings.secret_key.get_secret_value(),
        http=http,
    )


def make_microsoft_oauth(settings: Settings, http: httpx.AsyncClient | None = None) -> MicrosoftOAuth:
    """Raises ``ValueError`` when Microsoft sign-in is not configured or the
    certificate bundle is unusable."""
    if not settings.microsoft_enabled:
        raise ValueError("Microsoft sign-in is not configured (RS_MICROSOFT_CLIENT_ID / RS_MICROSOFT_CLIENT_CERT)")
    return MicrosoftOAuth(
        settings.microsoft_client_id,
        settings.microsoft_client_cert.get_secret_value(),
        settings.microsoft_redirect_uri,
        thumbprint=settings.microsoft_cert_thumbprint,
        authority=settings.microsoft_authority,
        state_signer_secret=settings.secret_key.get_secret_value(),
        http=http,
    )


def make_yahoo_oauth(settings: Settings, http: httpx.AsyncClient | None = None) -> YahooOAuth:
    if not settings.yahoo_enabled:
        raise ValueError("Yahoo sign-in is not configured (RS_YAHOO_CLIENT_ID / RS_YAHOO_CLIENT_SECRET)")
    return YahooOAuth(
        settings.yahoo_client_id,
        settings.yahoo_client_secret.get_secret_value(),
        settings.yahoo_redirect_uri,
        state_signer_secret=settings.secret_key.get_secret_value(),
        http=http,
    )


async def _load_secret(
    mailbox: MailboxRow, vault: CredentialVault, db: Database | None
) -> tuple[str, dict[str, Any]]:
    """Prefer a fresh read when a database is available; otherwise use the
    relationship eagerly loaded by ``repo.list_active_mailboxes``."""
    try:
        if db is not None:
            async with db.session() as session:
                return await vault.load(session, mailbox.id)
        if "secret" not in sa_inspect(mailbox).unloaded and mailbox.secret is not None:
            return vault.open(mailbox.secret)
        raise VaultError(f"no credentials loaded for mailbox {mailbox.id}")
    except VaultError as exc:
        # Missing or undecryptable credentials have the same remedy as a revoked
        # token: the client must reconnect the mailbox.
        raise AuthExpired(str(exc)) from exc


async def build_connector(
    mailbox: MailboxRow,
    vault: CredentialVault,
    settings: Settings,
    http: httpx.AsyncClient | None = None,
    *,
    db: Database | None = None,
    imap_session_factory: Callable[[], ImapSession] | None = None,
    message_id_resolver: Callable[[str], Awaitable[str | None]] | None = None,
    oauth: GoogleOAuth | None = None,
    microsoft_oauth: MicrosoftOAuth | None = None,
) -> MailboxConnector:
    provider = Provider(mailbox.provider)
    mode = ProtectionMode(mailbox.mode)
    kind, secret = await _load_secret(mailbox, vault, db)
    labels: dict[str, str] = dict(mailbox.labels or {})

    if provider is Provider.GMAIL:
        if kind != KIND_GOOGLE_OAUTH:
            raise AuthExpired(f"mailbox {mailbox.id} has {kind!r} credentials but is a Gmail mailbox")
        credentials = GoogleCredentials.from_secret(secret)
        on_refreshed = _persist_tokens(mailbox.id, vault, db, secret, KIND_GOOGLE_OAUTH) if db is not None else None
        return GmailConnector(
            mailbox.id,
            mailbox.address,
            credentials,
            oauth or make_google_oauth(settings, http),
            http=http,
            on_tokens_refreshed=on_refreshed,
            labels=labels,
            mode=mode,
        )

    if provider is Provider.MICROSOFT:
        if kind != KIND_MICROSOFT_OAUTH:
            raise AuthExpired(f"mailbox {mailbox.id} has {kind!r} credentials but is a Microsoft mailbox")
        if microsoft_oauth is None:
            try:
                microsoft_oauth = make_microsoft_oauth(settings, http)
            except ValueError as exc:
                raise ConnectorError(str(exc), retryable=False) from exc
        on_refreshed = (
            _persist_tokens(mailbox.id, vault, db, secret, KIND_MICROSOFT_OAUTH) if db is not None else None
        )
        return GraphMailConnector(
            mailbox.id,
            mailbox.address,
            GoogleCredentials.from_secret(secret),
            microsoft_oauth,
            http=http,
            on_tokens_refreshed=on_refreshed,
            labels=labels,
            mode=mode,
        )

    try:
        credentials = ImapCredentials.from_secret(secret)
    except ValueError as exc:
        raise AuthExpired(f"mailbox {mailbox.id} has unusable IMAP credentials: {exc}") from exc
    resolver = message_id_resolver or (_db_message_id_resolver(mailbox.id, db) if db is not None else None)
    return ImapConnector(
        mailbox.id,
        mailbox.address,
        provider,
        credentials,
        session_factory=imap_session_factory,
        mode=mode,
        folders=labels,
        message_id_resolver=resolver,
    )


def _persist_tokens(
    mailbox_id: str, vault: CredentialVault, db: Database, previous: dict[str, Any], kind: str = KIND_GOOGLE_OAUTH
) -> Callable[[TokenSet], Awaitable[None]]:
    """Google and Microsoft rotate access tokens hourly (Microsoft rotates the
    refresh token too); without persisting them every worker restart would
    start with an expired token and an extra refresh."""

    async def persist(tokens: TokenSet) -> None:
        merged = {**previous, **tokens.to_secret()}
        # A refresh response carries no identity claims; keep the sign-in ones.
        for key in ("sub", "email"):
            if not merged.get(key) and previous.get(key):
                merged[key] = previous[key]
        if not merged.get("refresh_token"):
            merged["refresh_token"] = previous.get("refresh_token")
        async with db.session() as session:
            await vault.store(session, mailbox_id, kind, merged)
        previous.update(merged)
        log.info("mail.tokens_persisted", mailbox_id=mailbox_id, kind=kind)

    return persist


def _db_message_id_resolver(mailbox_id: str, db: Database) -> Callable[[str], Awaitable[str | None]]:
    async def resolve(provider_message_id: str) -> str | None:
        async with db.session() as session:
            row = await repo.get_message_by_provider_id(session, mailbox_id, provider_message_id)
            return row.rfc_message_id if row else None

    return resolve


def connector_factory_from_settings(
    settings: Settings,
    db: Database,
    *,
    http: httpx.AsyncClient | None = None,
    vault: CredentialVault | None = None,
) -> ConnectorFactory:
    """The default wiring used by the worker, the dead man's switch and the CLI."""
    vault = vault or CredentialVault(cipher_from_settings(settings))

    async def factory(mailbox: MailboxRow) -> MailboxConnector:
        return await build_connector(mailbox, vault, settings, http, db=db)

    return factory

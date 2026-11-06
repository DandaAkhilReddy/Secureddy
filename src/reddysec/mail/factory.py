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
from reddysec.mail.base import AuthExpired, MailboxConnector
from reddysec.mail.gmail import GmailConnector, GoogleCredentials
from reddysec.mail.imap import ImapConnector, ImapCredentials, ImapSession
from reddysec.mail.oauth_google import GoogleOAuth, TokenSet
from reddysec.mail.vault import KIND_GOOGLE_OAUTH, CredentialVault, VaultError, cipher_from_settings
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
) -> MailboxConnector:
    provider = Provider(mailbox.provider)
    mode = ProtectionMode(mailbox.mode)
    kind, secret = await _load_secret(mailbox, vault, db)
    labels: dict[str, str] = dict(mailbox.labels or {})

    if provider is Provider.GMAIL:
        if kind != KIND_GOOGLE_OAUTH:
            raise AuthExpired(f"mailbox {mailbox.id} has {kind!r} credentials but is a Gmail mailbox")
        credentials = GoogleCredentials.from_secret(secret)
        on_refreshed = _persist_tokens(mailbox.id, vault, db, secret) if db is not None else None
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
    mailbox_id: str, vault: CredentialVault, db: Database, previous: dict[str, Any]
) -> Callable[[TokenSet], Awaitable[None]]:
    """Google rotates access tokens hourly; without persisting them every
    worker restart would start with an expired token and an extra refresh."""

    async def persist(tokens: TokenSet) -> None:
        merged = {**previous, **tokens.to_secret()}
        # A refresh response carries no identity claims; keep the sign-in ones.
        for key in ("sub", "email"):
            if not merged.get(key) and previous.get(key):
                merged[key] = previous[key]
        if not merged.get("refresh_token"):
            merged["refresh_token"] = previous.get("refresh_token")
        async with db.session() as session:
            await vault.store(session, mailbox_id, KIND_GOOGLE_OAUTH, merged)
        previous.update(merged)
        log.info("gmail.tokens_persisted", mailbox_id=mailbox_id)

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

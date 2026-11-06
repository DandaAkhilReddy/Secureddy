"""Fixtures for the worker-side unit tests: settings, a local SMTP sink, and
database rows for a client with one mailbox."""

from __future__ import annotations

import socket
from collections.abc import Iterator
from dataclasses import dataclass
from email import message_from_bytes
from email.message import Message
from typing import Any

import pytest
from aiosmtpd.controller import Controller

from reddysec.config import Settings
from reddysec.store import repo
from reddysec.store.models import MailboxRow, UserRow


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class RecordingHandler:
    """aiosmtpd handler that keeps every envelope."""

    def __init__(self) -> None:
        self.envelopes: list[Any] = []

    async def handle_DATA(self, server: Any, session: Any, envelope: Any) -> str:
        self.envelopes.append(envelope)
        return "250 OK"

    @property
    def messages(self) -> list[Message]:
        return [message_from_bytes(e.content) for e in self.envelopes]


@dataclass
class SmtpSink:
    host: str
    port: int
    handler: RecordingHandler


@pytest.fixture
def smtp_sink() -> Iterator[SmtpSink]:
    handler = RecordingHandler()
    port = free_port()
    controller = Controller(handler, hostname="127.0.0.1", port=port)
    controller.start()
    try:
        yield SmtpSink("127.0.0.1", port, handler)
    finally:
        controller.stop()


@pytest.fixture
def make_settings():
    def factory(**overrides: Any) -> Settings:
        base: dict[str, Any] = dict(
            env="test",
            base_url="https://rs.example",
            secret_key="unit-test-secret",
            gmail_poll_seconds=1,
            imap_poll_seconds=1,
            hold_dead_man_minutes=10,
            detonation_timeout_s=5,
        )
        base.update(overrides)
        return Settings(**base)

    return factory


@dataclass
class ClientRows:
    user: UserRow
    mailbox: MailboxRow


@pytest.fixture
async def client_rows(db) -> ClientRows:
    async with db.session() as s:
        user = await repo.create_user(s, email="client@example.com", display_name="The Client")
        mailbox = await repo.create_mailbox(
            s, user_id=user.id, provider="gmail", address="client@gmail.com", mode="hold"
        )
    return ClientRows(user=user, mailbox=mailbox)

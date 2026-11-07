"""The real worker driving the real Gmail and IMAP connectors (against their
in-memory servers) on text-only email in HOLD mode: released into the inbox
at once, the Checking label/folder emptied, no Secureddy verdict label, and
nothing stored. An email with a link next to it is checked as usual."""

from __future__ import annotations

from types import SimpleNamespace

from reddysec.config import Settings
from reddysec.mail.base import LABEL_PENDING, LABEL_SAFE
from reddysec.mail.imap import KEYWORD_SAFE
from reddysec.models import ProtectionMode, TriageLane, Verdict, VerdictLevel
from reddysec.store import repo
from reddysec.worker.engine import Worker
from reddysec.worker.notify import Notifier

from .conftest import FakeImapServer, GmailEnv
from .test_mail_imap import checking, connector

TEXT_ONLY = (
    b"From: Ann <ann@example.org>\r\nTo: client@gmail.com\r\nSubject: Dinner\r\nMessage-ID: <dinner@example.org>\r\n"
    b"Date: Thu, 05 Nov 2026 10:00:00 +0000\r\n\r\nAre we still on for Saturday at 7?\r\n"
)
WITH_LINK = (
    b"From: Bo <bo@example.org>\r\nTo: client@gmail.com\r\nSubject: Agenda\r\nMessage-ID: <agenda@example.org>\r\n"
    b"Date: Thu, 05 Nov 2026 10:05:00 +0000\r\n\r\nAgenda: https://docs.example/agenda\r\n"
)


async def analyze_safe(parsed, ctx) -> Verdict:
    return Verdict(level=VerdictLevel.SAFE, score=0, summary="fine", lane=TriageLane.DETONATE)


def worker_for(db, connector_obj) -> Worker:
    settings = Settings(env="test", initial_backfill_days=0)

    async def factory(mailbox):
        return connector_obj

    return Worker(db, settings, connector_factory=factory, analyzer=analyze_safe,
                  context_factory=lambda **kw: SimpleNamespace(**kw), detonator=object(), intel=object(),
                  notifier=Notifier(db, settings))


async def hold_mailbox(db, address: str, provider: str):
    async with db.session() as s:
        user = await repo.create_user(s, email=f"owner-{provider}@example.com", display_name="Owner")
        return await repo.create_mailbox(s, user_id=user.id, provider=provider, address=address, mode="hold")


async def stored(db, mailbox_id: str) -> list[str]:
    async with db.session() as s:
        return [r.subject for r in await repo.list_recent_messages(s, [mailbox_id], limit=10)]


async def test_gmail_hold_releases_text_only_without_a_label(db, gmail_env: GmailEnv):
    mailbox = await hold_mailbox(db, "client@gmail.com", "gmail")
    gmail = gmail_env.new_connector(mode=ProtectionMode.HOLD)
    worker = worker_for(db, gmail)
    await worker.run_cycle()  # labels + hold filter, first poll seeds the cursor
    server = gmail_env.server
    pending, safe = server.label_id(LABEL_PENDING), server.label_id(LABEL_SAFE)
    text_id = server.add_message(TEXT_ONLY, labels=(pending, "UNREAD"))  # what the hold filter does
    link_id = server.add_message(WITH_LINK, labels=(pending, "UNREAD"))

    stats = await worker.run_cycle()

    assert stats.text_only == 1 and stats.messages == 1
    text_labels = set(server.messages[text_id]["labelIds"])
    assert "INBOX" in text_labels and pending not in text_labels and safe not in text_labels
    link_labels = set(server.messages[link_id]["labelIds"])
    assert "INBOX" in link_labels and safe in link_labels
    assert await stored(db, mailbox.id) == ["Agenda"]


async def test_imap_hold_moves_text_only_back_to_the_inbox_unmarked(db):
    server = FakeImapServer()
    imap = connector(server, ProtectionMode.HOLD)
    mailbox = await hold_mailbox(db, "client@yahoo.com", "yahoo")
    worker = worker_for(db, imap)
    await worker.run_cycle()
    held = checking(server)
    server.deliver(held, TEXT_ONLY)
    server.deliver(held, WITH_LINK)

    stats = await worker.run_cycle()

    assert stats.text_only == 1 and stats.messages == 1
    assert server.folders[held].messages == {}
    inbox = list(server.folders["INBOX"].messages.values())
    assert len(inbox) == 2
    by_subject = {(b"Dinner" in m["raw"]): m for m in inbox}
    assert KEYWORD_SAFE not in by_subject[True]["flags"]
    assert KEYWORD_SAFE in by_subject[False]["flags"]
    assert await stored(db, mailbox.id) == ["Agenda"]


async def test_graph_hold_moves_text_only_back_to_the_inbox_uncategorised(db, monkeypatch):
    from . import test_mail_graph as g

    def mime(subject: str) -> bytes:
        body = "Agenda: https://docs.example/agenda" if subject == "agenda" else "Are we still on for Saturday?"
        return f"From: a@contoso.com\r\nTo: avery@outlook.com\r\nSubject: {subject}\r\n\r\n{body}\r\n".encode()

    monkeypatch.setattr(g, "raw_mime", mime)
    graph = g.FakeGraph()
    conn = g.connector(graph, mode=ProtectionMode.HOLD)
    mailbox = await hold_mailbox(db, "avery@outlook.com", "microsoft")
    worker = worker_for(db, conn)
    await worker.run_cycle()
    pending = conn.labels[LABEL_PENDING] if hasattr(conn, "labels") else None
    assert pending
    text_id = graph.deliver("dinner", folder=pending, minutes_ago=1)
    link_id = graph.deliver("agenda", folder=pending, minutes_ago=1)

    stats = await worker.run_cycle()

    assert stats.text_only == 1 and stats.messages == 1
    assert graph.messages[text_id]["folder"] == "inbox-id" and graph.messages[text_id]["categories"] == []
    assert graph.messages[link_id]["folder"] == "inbox-id" and graph.messages[link_id]["categories"] == [g.SAFE]
    assert await stored(db, mailbox.id) == ["agenda"]

"""Connector support for the client's "This is safe" and "Check again":
``mark_safe`` and ``apply_verdict(..., relabel=True)`` on Gmail, IMAP and the
in-memory fake."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from reddysec.mail.base import (
    LABEL_PENDING,
    LABEL_QUARANTINE,
    LABEL_RELEASED,
    LABEL_SAFE,
    LABEL_SUSPICIOUS,
    ConnectorError,
)
from reddysec.mail.gmail import verdict_label_plan
from reddysec.mail.imap import KEYWORD_SAFE, KEYWORD_SUSPICIOUS, ImapConnector, ImapCredentials
from reddysec.models import (
    PolicyConfig,
    ProtectionMode,
    Provider,
    RawMessage,
    TriageLane,
    Verdict,
    VerdictLevel,
)
from reddysec.testing.fakes import FakeMailbox

from .conftest import FakeImapServer, GmailEnv, sample_raw

LABELS = {LABEL_PENDING: "Lp", LABEL_SAFE: "Ls", LABEL_SUSPICIOUS: "Lsu", LABEL_QUARANTINE: "Lq", LABEL_RELEASED: "Lr"}


def verdict(level: VerdictLevel) -> Verdict:
    return Verdict(level=level, score=50, summary="s", lane=TriageLane.DETONATE)


class TestRelabelPlan:
    def test_relabel_removes_the_other_verdict_word_only(self):
        add, remove = verdict_label_plan(VerdictLevel.SUSPICIOUS, PolicyConfig(), LABELS, hold=False, relabel=True)
        assert add == ["Lsu"] and remove == ["Lp", "Ls"]
        add, remove = verdict_label_plan(VerdictLevel.SAFE, PolicyConfig(), LABELS, hold=False, relabel=True)
        assert add == ["Ls"] and remove == ["Lp", "Lsu"]
        # Quarantine and "Released by you" describe where the message is; they stay.
        add, remove = verdict_label_plan(VerdictLevel.MALICIOUS, PolicyConfig(), LABELS, hold=False, relabel=True)
        assert add == ["Lq"] and set(remove) == {"Lp", "INBOX", "Ls", "Lsu"} and "Lr" not in remove

    def test_without_relabel_nothing_changes(self):
        assert verdict_label_plan(VerdictLevel.SAFE, PolicyConfig(), LABELS, hold=False) == (["Ls"], ["Lp"])


class TestGmail:
    async def test_mark_safe_swaps_labels_and_returns_to_inbox(self, gmail_env: GmailEnv):
        server = gmail_env.server
        labels = await gmail_env.connector.setup(ProtectionMode.SCAN)
        mid = server.add_message(sample_raw("q"), labels=(labels[LABEL_QUARANTINE], labels[LABEL_SUSPICIOUS]))
        await gmail_env.connector.mark_safe(mid)
        (call,) = server.calls_to("POST", f"messages/{mid}/modify")
        assert call.json == {
            "addLabelIds": [labels[LABEL_SAFE], "INBOX"],
            "removeLabelIds": [labels[LABEL_SUSPICIOUS], labels[LABEL_QUARANTINE], labels[LABEL_PENDING]],
        }
        assert set(server.messages[mid]["labelIds"]) == {labels[LABEL_SAFE], "INBOX"}

    async def test_apply_verdict_relabel(self, gmail_env: GmailEnv):
        server = gmail_env.server
        labels = await gmail_env.connector.setup(ProtectionMode.SCAN)
        mid = server.add_message(sample_raw("r"), labels=("INBOX", labels[LABEL_SAFE]))
        raw = RawMessage(provider_message_id=mid, mailbox_id="mbx_1", received_at=datetime.now(UTC), raw=b"x")
        await gmail_env.connector.apply_verdict(raw, verdict(VerdictLevel.SUSPICIOUS), PolicyConfig(), relabel=True)
        assert set(server.messages[mid]["labelIds"]) == {"INBOX", labels[LABEL_SUSPICIOUS]}


def _imap(server: FakeImapServer) -> ImapConnector:
    creds = ImapCredentials(username="client@yahoo.com", password="app-password")
    return ImapConnector("mbx_1", "client@yahoo.com", Provider.YAHOO, creds, session_factory=server.session)


class TestImap:
    async def test_mark_safe_brings_back_from_quarantine(self, imap_server: FakeImapServer):
        c = _imap(imap_server)
        await c.setup(ProtectionMode.SCAN)
        imap_server.deliver("INBOX", sample_raw("m"), flags={KEYWORD_SUSPICIOUS})
        await c.quarantine("INBOX:111:1")
        q = imap_server.folder_path(LABEL_QUARANTINE)
        assert len(imap_server.folders[q].messages) == 1
        qid = f"{q}:{imap_server.folders[q].uidvalidity}:1"
        await c.mark_safe(qid)
        assert imap_server.folders[q].messages == {}
        (back,) = imap_server.folders["INBOX"].messages.values()
        assert KEYWORD_SAFE in back["flags"] and KEYWORD_SUSPICIOUS not in back["flags"]

    async def test_mark_safe_in_inbox_only_swaps_keyword(self, imap_server: FakeImapServer):
        c = _imap(imap_server)
        await c.setup(ProtectionMode.SCAN)
        imap_server.deliver("INBOX", sample_raw("m"), flags={KEYWORD_SUSPICIOUS})
        imap_server.calls.clear()
        await c.mark_safe("INBOX:111:1")
        assert imap_server.folders["INBOX"].messages[1]["flags"] == {KEYWORD_SAFE}
        assert not [1 for name, _ in imap_server.calls if name == "move"]

    async def test_mark_safe_missing_message_is_permanent_error(self, imap_server: FakeImapServer):
        c = _imap(imap_server)
        await c.setup(ProtectionMode.SCAN)
        with pytest.raises(ConnectorError) as info:
            await c.mark_safe("INBOX:111:42")
        assert not info.value.retryable

    async def test_apply_verdict_relabel_swaps_keyword(self, imap_server: FakeImapServer):
        c = _imap(imap_server)
        await c.setup(ProtectionMode.SCAN)
        imap_server.deliver("INBOX", sample_raw("m"), flags={KEYWORD_SAFE})
        messages, _ = await c.poll(None)
        await c.apply_verdict(messages[0], verdict(VerdictLevel.SUSPICIOUS), PolicyConfig(), relabel=True)
        assert imap_server.folders["INBOX"].messages[1]["flags"] == {KEYWORD_SUSPICIOUS}


class TestFakeMailbox:
    async def test_mark_safe_and_relabel(self):
        fake = FakeMailbox()
        msg = fake.deliver(b"raw")
        await fake.quarantine(msg.provider_message_id)
        await fake.mark_safe(msg.provider_message_id)
        assert fake.labels[msg.provider_message_id] == {"Secureddy/Checked"}
        assert fake.in_inbox[msg.provider_message_id]
        await fake.apply_verdict(msg, verdict(VerdictLevel.SUSPICIOUS), PolicyConfig(), relabel=True)
        assert fake.labels[msg.provider_message_id] == {"Secureddy/Suspicious"}
        assert ("relabel", msg.provider_message_id) in fake.actions

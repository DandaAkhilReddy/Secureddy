"""Repository support for sender feedback and client requests."""

from __future__ import annotations

from datetime import UTC, datetime

from reddysec.core.ids import new_id
from reddysec.models import TriageLane, Verdict, VerdictLevel
from reddysec.store import repo
from reddysec.store.models import MessageRow, SenderFeedbackRow


async def _mailbox(db):
    async with db.session() as s:
        user = await repo.create_user(s, email="c@example.com", display_name="C")
        return await repo.create_mailbox(s, user_id=user.id, provider="gmail", address="c@gmail.com")


async def test_load_client_feedback_sorts_entries(db):
    mailbox = await _mailbox(db)
    rows = [
        ("domain", "walmart.com", "trusted", True),
        ("address", "friend@gmail.com", "trusted", True),
        ("address", "shop@small.example", "trusted", False),
        ("domain", "bad.example", "blocked", True),
        ("address", "x@bad.example", "blocked", True),
        ("address", "boss@co.example", "blocked", False),
    ]
    async with db.session() as s:
        for scope, value, decision, auth in rows:
            s.add(SenderFeedbackRow(id=new_id("sfb"), mailbox_id=mailbox.id, scope=scope, value=value,
                                    decision=decision, authenticated=auth))
    async with db.session() as s:
        fb = await repo.load_client_feedback(s, mailbox.id)
        empty = await repo.load_client_feedback(s, "mbx_other")
    assert fb.trusted_domains == ["walmart.com"]
    assert fb.verified_addresses == ["friend@gmail.com"]
    assert fb.trusted_addresses == ["shop@small.example"]
    assert fb.blocked_domains == ["bad.example"]
    assert fb.blocked_addresses == ["x@bad.example"]
    assert fb.blocked_unverified_addresses == ["boss@co.example"]
    assert empty.is_empty and not fb.is_empty


async def test_record_rescore_keeps_one_previous_and_client_fields(db):
    mailbox = await _mailbox(db)
    async with db.session() as s:
        row = MessageRow(id="msg_1", mailbox_id=mailbox.id, provider_message_id="p", received_at=datetime.now(UTC),
                         state=repo.STATE_RESCORE_REQUESTED, level="suspicious",
                         verdict={"level": "suspicious", "client_decision": {"decision": "safe"},
                                  "previous": {"level": "malicious"}})
        s.add(row)
    new = Verdict(level=VerdictLevel.SAFE, score=0, summary="ok", lane=TriageLane.DETONATE)
    async with db.session() as s:
        row = await repo.get_message(s, "msg_1")
        await repo.record_rescore(s, row, new, quarantined=False)
    async with db.session() as s:
        row = await repo.get_message(s, "msg_1")
        assert row.state == "done" and row.level == "safe"
        assert row.verdict["previous"] == {"level": "suspicious", "client_decision": {"decision": "safe"}}
        assert row.verdict["client_decision"] == {"decision": "safe"}
        assert repo.client_decision(row) == "safe"
        assert await repo.list_requests(s, mailbox.id, repo.STATE_RESCORE_REQUESTED) == []


async def test_client_decision_reader():
    assert repo.client_decision(MessageRow(verdict=None)) is None
    assert repo.client_decision(MessageRow(verdict={"client_decision": "safe"})) is None
    assert repo.client_decision(MessageRow(verdict={"client_decision": {"decision": "fake"}})) == "fake"


async def test_mark_restored_with_safe_decision_sets_level(db):
    mailbox = await _mailbox(db)
    async with db.session() as s:
        s.add(MessageRow(id="msg_2", mailbox_id=mailbox.id, provider_message_id="p2", received_at=datetime.now(UTC),
                         state=repo.STATE_RESTORE_REQUESTED, level="malicious", quarantined=True,
                         verdict={"client_decision": {"decision": "safe"}}))
    async with db.session() as s:
        row = await repo.get_message(s, "msg_2")
        await repo.mark_restored(s, row)
        assert row.level == "safe" and not row.quarantined and row.state == "done"

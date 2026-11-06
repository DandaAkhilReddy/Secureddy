"""Senders the client trusts are re-checked and confirmed: stats and the
"A sender you trust sent something unusual" notification."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from reddysec.core.ids import new_id
from reddysec.models import TrustCheck, VerdictLevel
from reddysec.store import repo
from reddysec.store.models import FeedbackReasonRow, SenderFeedbackRow, SenderTrustStatsRow

from .test_worker_flows import NOW, Harness, email_bytes, verdict


@pytest.fixture
def harness(db, settings) -> Harness:
    return Harness(db, settings)


@pytest.fixture
def settings():
    from reddysec.config import Settings

    return Settings(env="test", base_url="https://rs.example", secret_key="functional", detonation_timeout_s=2)


def check(outcome: str, *, by_client: bool = True) -> TrustCheck:
    return TrustCheck(trusted_by_client=by_client, reason="I ordered this", outcome=outcome, scope="domain",
                      value="walmart.com")


async def _stats(db) -> list[SenderTrustStatsRow]:
    async with db.session() as s:
        return list((await s.execute(select(SenderTrustStatsRow))).scalars())


async def test_confirmed_updates_stats_without_alerting(harness: Harness, db):
    user, mailbox, fake = await harness.add_client()
    async with db.session() as s:
        s.add(SenderFeedbackRow(id="sfb_w", mailbox_id=mailbox.id, scope="domain", value="walmart.com",
                                decision="trusted", authenticated=True))
        s.add(FeedbackReasonRow(id=new_id("frs"), sender_feedback_id="sfb_w", message_id="m", user_id=user.id,
                                decision="safe", reason_code="expected", reason_text="new shoes"))
    harness.analyzer.scripts = {
        "Order 1": verdict(VerdictLevel.SAFE, trust_check=check("confirmed")),
        "Order 2": verdict(VerdictLevel.SAFE, trust_check=check("confirmed")),
    }
    fake.deliver(email_bytes("Order 1", sender="Walmart <orders@walmart.com>"))
    fake.deliver(email_bytes("Order 2", sender="Walmart <orders@walmart.com>"))
    await harness.worker().run_cycle()
    # the client's reason travels to the engine with the feedback
    assert harness.contexts[0]["feedback"].reasons == {"walmart.com": "I ordered this / expected it. new shoes"}
    (stats,) = await _stats(db)
    assert (stats.scope, stats.value, stats.emails_checked, stats.last_outcome) == ("domain", "walmart.com", 2, "confirmed")
    assert repo.aware(stats.last_confirmed_at) == NOW and repo.aware(stats.last_checked_at) == NOW
    assert await harness.notifications(user.id) == []


async def test_changed_alerts_once_and_records_outcome(harness: Harness, db):
    user, mailbox, fake = await harness.add_client()
    harness.analyzer.scripts = {"Invoice": verdict(VerdictLevel.MALICIOUS, trust_check=check("changed"))}
    fake.deliver(email_bytes("Invoice", sender="Billing <billing@walmart.com>"))
    await harness.worker().run_cycle()
    (stats,) = await _stats(db)
    assert stats.last_outcome == "changed" and stats.emails_checked == 1 and stats.last_confirmed_at is None
    notes = await harness.notifications(user.id)
    assert [n.title for n in notes] == ["A sender you trust sent something unusual"]
    assert "You told us you trust walmart.com" in notes[0].body and "put it in Quarantine" in notes[0].body
    assert notes[0].level == "alert" and notes[0].message_id


async def test_changed_but_suspicious_says_marked(harness: Harness):
    user, _mailbox, fake = await harness.add_client()
    harness.analyzer.scripts = {"Hm": verdict(VerdictLevel.SUSPICIOUS, trust_check=check("changed"))}
    fake.deliver(email_bytes("Hm", sender="b@walmart.com"))
    await harness.worker().run_cycle()
    (note,) = await harness.notifications(user.id)
    assert "marked it Suspicious" in note.body


async def test_policy_trust_is_not_counted(harness: Harness, db):
    _user, _mailbox, fake = await harness.add_client()
    harness.analyzer.scripts = {"Hi": verdict(VerdictLevel.SAFE, trust_check=check("confirmed", by_client=False))}
    fake.deliver(email_bytes("Hi"))
    await harness.worker().run_cycle()
    assert await _stats(db) == []

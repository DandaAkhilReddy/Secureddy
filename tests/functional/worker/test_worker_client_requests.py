"""Worker handling of the client's requests: "This is fake"
(quarantine_requested), "This is safe" (relabel_safe_requested, or a restore
with a safe decision) and "Check again" (rescore_requested)."""

from __future__ import annotations

from typing import Any

import pytest

from reddysec.config import Settings
from reddysec.core.ids import new_id
from reddysec.mail.base import ConnectorError
from reddysec.models import VerdictLevel
from reddysec.store import repo
from reddysec.store.models import SenderFeedbackRow

from .test_worker_flows import Harness, email_bytes, verdict


@pytest.fixture
def harness(db) -> Harness:
    settings = Settings(
        env="test",
        base_url="https://rs.example",
        secret_key="functional",
        gmail_poll_seconds=1,
        imap_poll_seconds=1,
        detonation_timeout_s=2,
        hold_dead_man_minutes=10,
    )
    return Harness(db, settings)

SUBJ = "Weekly deals"


async def _deliver_and_process(harness: Harness, level: VerdictLevel = VerdictLevel.SUSPICIOUS, **policy: Any):
    user, mailbox, fake = await harness.add_client(policy=policy or None)
    harness.analyzer.scripts = {SUBJ: verdict(level)}
    raw = fake.deliver(email_bytes(SUBJ, sender="Shop <news@shop.example>"))
    await harness.worker().run_cycle()
    msgs = await harness.messages(mailbox.id)
    return user, mailbox, fake, raw, msgs[raw.provider_message_id]


async def _set_state(harness: Harness, row, state: str, **verdict_extra: Any) -> None:
    async with harness.db.session() as s:
        fresh = await repo.get_message(s, row.id)
        fresh.state = state
        if verdict_extra:
            fresh.verdict = {**(fresh.verdict or {}), **verdict_extra}


async def _row(harness: Harness, mailbox_id: str, pid: str):
    return (await harness.messages(mailbox_id))[pid]


class TestFakeAndSafe:
    async def test_quarantine_requested(self, harness: Harness):
        _u, mailbox, fake, raw, row = await _deliver_and_process(harness)
        await _set_state(harness, row, repo.STATE_QUARANTINE_REQUESTED, client_decision={"decision": "fake"})
        stats = await harness.worker().run_cycle()
        assert stats.client_requests == 1
        assert ("quarantine", raw.provider_message_id) in fake.actions
        after = await _row(harness, mailbox.id, raw.provider_message_id)
        assert after.state == "done" and after.quarantined and after.level == "malicious"
        assert "client_quarantine" in await harness.audit_actions(mailbox.id)

    async def test_relabel_safe_requested(self, harness: Harness):
        _u, mailbox, fake, raw, row = await _deliver_and_process(harness)
        await _set_state(harness, row, repo.STATE_RELABEL_SAFE_REQUESTED)
        await harness.worker().run_cycle()
        assert fake.labels[raw.provider_message_id] == {"Secureddy/Checked"}
        after = await _row(harness, mailbox.id, raw.provider_message_id)
        assert after.state == "done" and after.level == "safe" and not after.quarantined
        assert "client_mark_safe" in await harness.audit_actions(mailbox.id)

    async def test_restore_with_safe_decision_also_relabels(self, harness: Harness):
        _u, mailbox, fake, raw, row = await _deliver_and_process(harness, VerdictLevel.MALICIOUS)
        assert row.quarantined
        await _set_state(harness, row, repo.STATE_RESTORE_REQUESTED, client_decision={"decision": "safe"})
        await harness.worker().run_cycle()
        assert ("restore", raw.provider_message_id) in fake.actions
        assert ("mark_safe", raw.provider_message_id) in fake.actions
        after = await _row(harness, mailbox.id, raw.provider_message_id)
        assert after.level == "safe" and not after.quarantined and after.restored_by_client

    async def test_permanent_connector_error_resets_state(self, harness: Harness):
        _u, mailbox, fake, raw, row = await _deliver_and_process(harness)
        await _set_state(harness, row, repo.STATE_RELABEL_SAFE_REQUESTED)

        async def broken(pid: str) -> None:
            raise ConnectorError("gone", retryable=False)

        fake.mark_safe = broken  # type: ignore[method-assign]
        await harness.worker().run_cycle()
        after = await _row(harness, mailbox.id, raw.provider_message_id)
        assert after.state == "done" and after.level == "suspicious"
        assert "client_mark_safe_failed" in await harness.audit_actions(mailbox.id)

    async def test_retryable_error_keeps_request_for_next_cycle(self, harness: Harness):
        _u, mailbox, fake, raw, row = await _deliver_and_process(harness)
        await _set_state(harness, row, repo.STATE_QUARANTINE_REQUESTED)

        async def flaky(pid: str) -> None:
            raise ConnectorError("429", retryable=True)

        fake.quarantine = flaky  # type: ignore[method-assign]
        stats = await harness.worker().run_cycle()
        assert mailbox.id in stats.mailbox_errors
        assert (await _row(harness, mailbox.id, raw.provider_message_id)).state == repo.STATE_QUARANTINE_REQUESTED


class TestRescore:
    async def test_rescore_to_safe_relabels_and_keeps_previous(self, harness: Harness):
        _u, mailbox, fake, raw, row = await _deliver_and_process(harness)
        await _set_state(harness, row, repo.STATE_RESCORE_REQUESTED, client_decision={"decision": "safe"})
        harness.analyzer.scripts = {SUBJ: verdict(VerdictLevel.SAFE)}
        await harness.worker().run_cycle()
        after = await _row(harness, mailbox.id, raw.provider_message_id)
        assert after.state == "done" and after.level == "safe"
        assert after.verdict["previous"]["level"] == "suspicious"
        assert after.verdict["client_decision"] == {"decision": "safe"}  # kept across re-checks
        assert ("mark_safe", raw.provider_message_id) in fake.actions
        assert "rescore" in await harness.audit_actions(mailbox.id)

    async def test_rescore_records_new_detonations(self, harness: Harness):
        from reddysec.models import UrlVerdict

        _u, mailbox, _fake, raw, row = await _deliver_and_process(harness)
        await _set_state(harness, row, repo.STATE_RESCORE_REQUESTED)
        harness.analyzer.scripts = {SUBJ: verdict(VerdictLevel.SAFE, urls=[
            UrlVerdict(url="https://shop.example/x", level=VerdictLevel.SAFE, score=0, detonation_job_id="det_new",
                       detonated=True)])}
        await harness.worker().run_cycle()
        async with harness.db.session() as s:
            (det,) = await repo.list_detonations(s, row.id)
        assert det.job_id == "det_new"

    async def test_rescore_retryable_fetch_error_waits(self, harness: Harness):
        _u, mailbox, fake, raw, row = await _deliver_and_process(harness)
        await _set_state(harness, row, repo.STATE_RESCORE_REQUESTED)

        async def busy(pid: str) -> bytes:
            raise ConnectorError("503", retryable=True)

        fake.fetch_raw = busy  # type: ignore[method-assign]
        await harness.worker().run_cycle()
        assert (await _row(harness, mailbox.id, raw.provider_message_id)).state == repo.STATE_RESCORE_REQUESTED

    async def test_rescore_passes_feedback_to_analysis(self, harness: Harness):
        _u, mailbox, _fake, _raw, row = await _deliver_and_process(harness)
        async with harness.db.session() as s:
            s.add(SenderFeedbackRow(id=new_id("sfb"), mailbox_id=mailbox.id, scope="domain", value="shop.example",
                                    decision="trusted", authenticated=True))
        await _set_state(harness, row, repo.STATE_RESCORE_REQUESTED)
        await harness.worker().run_cycle()
        feedback = harness.contexts[-1]["feedback"]
        assert feedback.trusted_domains == ["shop.example"]

    async def test_new_mail_gets_feedback_too(self, harness: Harness):
        user, mailbox, fake = await harness.add_client()
        async with harness.db.session() as s:
            s.add(SenderFeedbackRow(id=new_id("sfb"), mailbox_id=mailbox.id, scope="address", value="x@y.example",
                                    decision="blocked", authenticated=False))
        fake.deliver(email_bytes("Hi"))
        await harness.worker().run_cycle()
        assert harness.contexts[-1]["feedback"].blocked_unverified_addresses == ["x@y.example"]

    async def test_rescore_to_suspicious_relabels(self, harness: Harness):
        _u, mailbox, fake, raw, row = await _deliver_and_process(harness, VerdictLevel.SAFE)
        await _set_state(harness, row, repo.STATE_RESCORE_REQUESTED)
        harness.analyzer.scripts = {SUBJ: verdict(VerdictLevel.SUSPICIOUS)}
        await harness.worker().run_cycle()
        assert ("relabel", raw.provider_message_id) in fake.actions
        assert fake.labels[raw.provider_message_id] == {"Secureddy/Suspicious"}
        assert (await _row(harness, mailbox.id, raw.provider_message_id)).level == "suspicious"

    async def test_quarantined_message_only_leaves_when_safe(self, harness: Harness):
        _u, mailbox, fake, raw, row = await _deliver_and_process(harness, VerdictLevel.MALICIOUS)
        await _set_state(harness, row, repo.STATE_RESCORE_REQUESTED)
        harness.analyzer.scripts = {SUBJ: verdict(VerdictLevel.SUSPICIOUS)}
        await harness.worker().run_cycle()
        after = await _row(harness, mailbox.id, raw.provider_message_id)
        assert after.quarantined and after.level == "suspicious"
        assert fake.in_inbox[raw.provider_message_id] is False

    async def test_rescore_failure_keeps_old_verdict(self, harness: Harness):
        _u, mailbox, fake, raw, row = await _deliver_and_process(harness)
        await _set_state(harness, row, repo.STATE_RESCORE_REQUESTED)
        harness.analyzer.scripts = {SUBJ: RuntimeError("engine down")}
        await harness.worker().run_cycle()
        after = await _row(harness, mailbox.id, raw.provider_message_id)
        assert after.state == "done" and after.level == "suspicious" and "previous" not in (after.verdict or {})
        assert "rescore_failed" in await harness.audit_actions(mailbox.id)

    async def test_rescore_fetch_failure(self, harness: Harness):
        _u, mailbox, fake, raw, row = await _deliver_and_process(harness)
        await _set_state(harness, row, repo.STATE_RESCORE_REQUESTED)

        async def gone(pid: str) -> bytes:
            raise ConnectorError("deleted", retryable=False)

        fake.fetch_raw = gone  # type: ignore[method-assign]
        await harness.worker().run_cycle()
        assert (await _row(harness, mailbox.id, raw.provider_message_id)).state == "done"
        assert "rescore_failed" in await harness.audit_actions(mailbox.id)

    async def test_rescore_parse_failure(self, harness: Harness):
        _u, mailbox, _fake, raw, row = await _deliver_and_process(harness)
        await _set_state(harness, row, repo.STATE_RESCORE_REQUESTED)

        def explode(*a: Any, **kw: Any):
            raise ValueError("bad mime")

        await harness.worker(parser=explode).run_cycle()
        assert (await _row(harness, mailbox.id, raw.provider_message_id)).state == "done"

    async def test_rescore_label_failure(self, harness: Harness):
        _u, mailbox, fake, raw, row = await _deliver_and_process(harness)
        await _set_state(harness, row, repo.STATE_RESCORE_REQUESTED)
        harness.analyzer.scripts = {SUBJ: verdict(VerdictLevel.SAFE)}

        async def broken(pid: str) -> None:
            raise ConnectorError("label gone", retryable=False)

        fake.mark_safe = broken  # type: ignore[method-assign]
        await harness.worker().run_cycle()
        after = await _row(harness, mailbox.id, raw.provider_message_id)
        assert after.state == "done" and after.level == "suspicious"

    async def test_rescores_are_rationed_per_cycle(self, harness: Harness, monkeypatch):
        import reddysec.worker.engine as engine

        monkeypatch.setattr(engine, "RESCORES_PER_CYCLE", 2)
        user, mailbox, fake = await harness.add_client()
        for i in range(3):
            fake.deliver(email_bytes(f"m{i}"))
        await harness.worker().run_cycle()
        for row in (await harness.messages(mailbox.id)).values():
            await _set_state(harness, row, repo.STATE_RESCORE_REQUESTED)
        await harness.worker().run_cycle()
        states = [r.state for r in (await harness.messages(mailbox.id)).values()]
        assert states.count(repo.STATE_RESCORE_REQUESTED) == 1

    async def test_polling_never_reprocesses_requested_messages(self, harness: Harness):
        _u, mailbox, fake, raw, row = await _deliver_and_process(harness)
        await _set_state(harness, row, repo.STATE_RESCORE_REQUESTED)
        harness.analyzer.calls.clear()
        await harness.worker().run_cycle()
        # one analysis: the rescore itself, not a second pass from polling
        assert len(harness.analyzer.calls) == 1

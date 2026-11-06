"""Repository functions against SQLite (the ``db`` fixture)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from reddysec.models import (
    AttachmentVerdict,
    DetonationResult,
    DetonationStatus,
    ExtractedUrl,
    ParsedMessage,
    RawMessage,
    TriageLane,
    UrlSource,
    UrlVerdict,
    Verdict,
    VerdictLevel,
)
from reddysec.store import repo
from reddysec.store.models import MailboxRow, MessageRow

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)


def parsed(
    pid: str, mailbox_id: str, *, from_address: str = "alice@example.com", subject: str = "Hi", urls: int = 0
) -> ParsedMessage:
    return ParsedMessage(
        provider_message_id=pid,
        mailbox_id=mailbox_id,
        rfc_message_id=f"<{pid}@example.com>",
        from_address=from_address,
        from_name="Alice",
        subject=subject,
        received_at=NOW,
        urls=[
            ExtractedUrl(
                raw=f"https://x.example/{i}", normalized=f"https://x.example/{i}", source=UrlSource.HTML_HREF
            )
            for i in range(urls)
        ],
    )


def raw(
    pid: str, mailbox_id: str, *, received_at: datetime = NOW, thread_id: str | None = "t1"
) -> RawMessage:
    return RawMessage(
        provider_message_id=pid, mailbox_id=mailbox_id, received_at=received_at, raw=b"x", thread_id=thread_id
    )


def verdict(level: VerdictLevel = VerdictLevel.SAFE, **kw) -> Verdict:
    return Verdict(level=level, score=10, summary="fine", lane=TriageLane.RELEASE_FAST, analyzed_at=NOW, **kw)


@pytest.fixture
async def mailbox(db) -> MailboxRow:
    async with db.session() as s:
        user = await repo.create_user(
            s, email="Client@Example.com", display_name=" The Client ", google_sub="sub-1"
        )
        return await repo.create_mailbox(
            s,
            user_id=user.id,
            provider="gmail",
            address="Client@Gmail.com",
            mode="hold",
            policy={"notify_at": "safe"},
        )


class TestUsers:
    async def test_create_and_lookups(self, db, mailbox):
        async with db.session() as s:
            user = await repo.get_user(s, mailbox.user_id)
            assert user.login_email == "client@example.com" and user.display_name == "The Client"
            assert (await repo.get_user_by_email(s, " CLIENT@example.com ")).id == user.id
            assert (await repo.get_user_by_google_sub(s, "sub-1")).id == user.id
            assert await repo.get_user_by_google_sub(s, "nope") is None
            assert await repo.get_user_by_email(s, "nobody@example.com") is None
            assert await repo.get_user(s, "usr_missing") is None

    async def test_list_users_by_role_excludes_disabled(self, db, mailbox):
        async with db.session() as s:
            c1 = await repo.create_user(s, email="c1@rs.local", display_name="C1", role="concierge")
            c2 = await repo.create_user(s, email="c2@rs.local", display_name="C2", role="admin")
            c2.disabled = True
            await repo.create_user(
                s, email="fam@rs.local", display_name="F", role="family", principal_id=mailbox.user_id
            )
        async with db.session() as s:
            assert [u.id for u in await repo.list_users(s, roles=("concierge", "admin"))] == [c1.id]
            assert len(await repo.list_users(s)) == 3


class TestMailboxes:
    async def test_create_follows_setup_convention(self, db, mailbox):
        assert mailbox.labels == {} and mailbox.status == "active" and mailbox.address == "client@gmail.com"
        assert mailbox.policy == {"notify_at": "safe"}

    async def test_active_listing_and_updates(self, db, mailbox):
        async with db.session() as s:
            other = await repo.create_mailbox(
                s, user_id=mailbox.user_id, provider="yahoo", address="c@yahoo.com"
            )
            await repo.set_mailbox_status(s, other.id, "error", error="boom")
        async with db.session() as s:
            active = await repo.list_active_mailboxes(s)
            assert [m.id for m in active] == [mailbox.id]
            assert active[0].secret is None  # eagerly loaded, no lazy load needed
            everything = await repo.list_mailboxes(s)
            assert [m.id for m in everything] == [mailbox.id, other.id]
            assert everything[1].status == "error" and everything[1].last_error == "boom"
            assert [m.id for m in await repo.list_mailboxes(s, user_id="nobody")] == []
            await repo.update_cursor(s, mailbox.id, "12345")
            await repo.set_mailbox_labels(s, mailbox.id, {"Secureddy": "L1"})
            await repo.set_mode(s, mailbox.id, "scan")
            await repo.set_policy(s, mailbox.id, {"quarantine_at": "suspicious"})
        async with db.session() as s:
            fresh = await repo.get_mailbox(s, mailbox.id)
            assert fresh.cursor == "12345" and fresh.last_sync_at is not None
            assert fresh.labels == {"Secureddy": "L1"} and fresh.mode == "scan"
            assert fresh.policy == {"quarantine_at": "suspicious"}
            assert await repo.get_mailbox(s, "mbx_missing") is None
            assert await repo.get_secret_row(s, mailbox.id) is None
            await repo.set_mailbox_status(s, mailbox.id, "active")
        async with db.session() as s:
            assert (await repo.get_mailbox(s, mailbox.id)).last_error is None


class TestMessages:
    async def test_upsert_is_unique_per_provider_id(self, db, mailbox):
        async with db.session() as s:
            row = await repo.upsert_message(
                s, parsed("p1", mailbox.id, urls=2), raw("p1", mailbox.id), state="analyzing"
            )
            assert row.state == "analyzing" and row.url_count == 2 and row.thread_id == "t1"
            assert row.rfc_message_id == "<p1@example.com>" and row.from_name == "Alice"
            again = await repo.upsert_message(
                s, parsed("p1", mailbox.id, subject="Changed"), raw("p1", mailbox.id, thread_id=None)
            )
            assert (
                again.id == row.id
                and again.subject == "Changed"
                and again.state == "pending"
                and again.thread_id is None
            )
            assert await repo.count_messages(s, mailbox.id) == 1
            found = await repo.get_message_by_provider_id(s, mailbox.id, "p1")
            assert found.id == row.id
            assert await repo.get_message_by_provider_id(s, mailbox.id, "p2") is None
            assert (await repo.get_message(s, row.id)).id == row.id

    async def test_long_fields_are_truncated(self, db, mailbox):
        p = parsed("p1", mailbox.id, subject="s" * 2000)
        p.rfc_message_id = "<" + "x" * 600 + ">"
        async with db.session() as s:
            row = await repo.upsert_message(s, p, raw("p1", mailbox.id))
            assert len(row.subject) == 1000 and len(row.rfc_message_id) == 500

    async def test_record_verdict_and_recent_listing(self, db, mailbox):
        async with db.session() as s:
            rows = []
            for i, level in enumerate([VerdictLevel.SAFE, VerdictLevel.MALICIOUS, VerdictLevel.SUSPICIOUS]):
                row = await repo.upsert_message(
                    s,
                    parsed(f"p{i}", mailbox.id),
                    raw(f"p{i}", mailbox.id, received_at=NOW + timedelta(minutes=i)),
                )
                await repo.record_verdict(s, row, verdict(level), quarantined=level is VerdictLevel.MALICIOUS)
                rows.append(row)
            assert rows[1].level == "malicious" and rows[1].quarantined and rows[1].state == "done"
            assert rows[1].verdict["summary"] == "fine" and rows[1].lane == "release_fast"
            assert rows[1].analyzed_at is not None
            recent = await repo.list_recent_messages(s, [mailbox.id], limit=2)
            assert [r.provider_message_id for r in recent] == ["p2", "p1"]
            assert [
                r.provider_message_id
                for r in await repo.list_recent_messages(s, [mailbox.id], level="malicious")
            ] == ["p1"]
            assert await repo.list_recent_messages(s, [], limit=5) == []
            held = await repo.record_verdict(
                s, rows[0], verdict(VerdictLevel.UNKNOWN), quarantined=False, state=repo.STATE_HELD_FOR_REVIEW
            )
            assert held.state == "held_for_review"

    async def test_restore_flow_and_failures(self, db, mailbox):
        async with db.session() as s:
            row = await repo.upsert_message(s, parsed("p1", mailbox.id), raw("p1", mailbox.id))
            await repo.record_verdict(s, row, verdict(VerdictLevel.MALICIOUS), quarantined=True)
            assert await repo.request_restore(s, "msg_missing") is None
            requested = await repo.request_restore(s, row.id)
            assert requested.state == repo.STATE_RESTORE_REQUESTED
            assert [r.id for r in await repo.list_restore_requests(s)] == [row.id]
            assert [r.id for r in await repo.list_restore_requests(s, mailbox.id)] == [row.id]
            assert await repo.list_restore_requests(s, "mbx_other") == []
            await repo.mark_restored(s, row)
            assert row.state == "done" and not row.quarantined and row.restored_by_client
            await repo.set_message_state(s, row, repo.STATE_RESTORE_FAILED)
            assert row.state == "restore_failed"
            await repo.mark_failed(s, row, "boom")
            assert row.state == "failed" and row.verdict["summary"] == "fine"  # existing verdict is kept
            bare = await repo.upsert_message(s, parsed("p2", mailbox.id), raw("p2", mailbox.id))
            await repo.mark_failed(s, bare, "parse error")
            assert bare.verdict == {"error": "parse error"}

    async def test_mark_released_by_deadman(self, db, mailbox):
        async with db.session() as s:
            a = await repo.upsert_message(s, parsed("a", mailbox.id), raw("a", mailbox.id), state="pending")
            b = await repo.upsert_message(s, parsed("b", mailbox.id), raw("b", mailbox.id), state="analyzing")
            c = await repo.upsert_message(s, parsed("c", mailbox.id), raw("c", mailbox.id), state="done")
            assert await repo.mark_released_by_deadman(s, mailbox.id) == 2
        async with db.session() as s:
            states = {
                r.provider_message_id: r.state for r in await repo.list_recent_messages(s, [mailbox.id])
            }
            assert states == {"a": "released_by_deadman", "b": "released_by_deadman", "c": "done"}
            assert await repo.count_messages(s, mailbox.id, state="done") == 1
            del a, b, c


class TestContacts:
    async def test_touch_and_history(self, db, mailbox):
        async with db.session() as s:
            assert await repo.sender_history(s, mailbox.id, "alice@example.com") is None
            first = await repo.touch_contact(
                s, mailbox.id, "Alice@Example.com", "Alice", seen_at=NOW - timedelta(days=2)
            )
            assert first.message_count == 1 and first.display_names == ["Alice"]
            second = await repo.touch_contact(
                s, mailbox.id, "alice@example.com", "Alice A.", replied_to=True, seen_at=NOW
            )
            assert second.id == first.id and second.message_count == 2 and second.replied_to
            # an older sighting never moves last_seen backwards
            await repo.touch_contact(
                s, mailbox.id, "alice@example.com", None, seen_at=NOW - timedelta(days=5)
            )
            for i in range(6):
                await repo.touch_contact(s, mailbox.id, "alice@example.com", f"Name{i}")
        async with db.session() as s:
            history = await repo.sender_history(s, mailbox.id, "ALICE@example.com")
            assert history.message_count == 9 and history.replied_to
            assert len(history.display_names) == 5 and history.display_names[-1] == "Name5"
            assert history.first_seen == NOW - timedelta(days=2) and history.last_seen >= NOW
            assert history.first_seen.tzinfo is not None and history.last_seen.tzinfo is not None
            assert await repo.sender_history(s, "mbx_other", "alice@example.com") is None


class TestDetonations:
    async def test_save_and_reference(self, db, mailbox):
        async with db.session() as s:
            row = await repo.upsert_message(s, parsed("p1", mailbox.id), raw("p1", mailbox.id))
            result = DetonationResult(
                job_id="det_1", status=DetonationStatus.OK, duration_ms=321, sandbox_backend="local"
            )
            saved = await repo.save_detonation(s, row.id, "url", "https://x.example/", result)
            assert saved.status == "ok" and saved.duration_ms == 321 and saved.result["job_id"] == "det_1"
            # the pipeline saved the result without a message link; the worker fills it in
            orphan = await repo.save_detonation(
                s, None, "file", "evil.pdf", DetonationResult(job_id="det_2", status=DetonationStatus.TIMEOUT)
            )
            assert orphan.message_id is None
            linked = await repo.record_detonation_ref(s, row.id, "det_2", "file", "evil.pdf")
            assert linked.message_id == row.id and linked.status == "timeout"  # status untouched
            fresh = await repo.record_detonation_ref(s, row.id, "det_3", "url", "https://y.example/")
            assert fresh.status == "unknown" and fresh.result is None
            again = await repo.record_detonation_ref(s, "msg_other", "det_3", "url", "https://y.example/")
            assert again.message_id == row.id  # first link wins
            resaved = await repo.save_detonation(
                s, None, "url", "https://x.example/", result.model_copy(update={"duration_ms": 1})
            )
            assert resaved.message_id == row.id and resaved.duration_ms == 1
            assert [d.job_id for d in await repo.list_detonations(s, row.id)] == ["det_1", "det_2", "det_3"]


class TestNotificationsAndAudit:
    async def test_notifications(self, db, mailbox):
        async with db.session() as s:
            n1 = await repo.create_notification(
                s, user_id=mailbox.user_id, channel="email", level="suspicious", title="t" * 400, body="b"
            )
            n2 = await repo.create_notification(
                s,
                user_id=mailbox.user_id,
                channel="dashboard",
                level="safe",
                title="t",
                body="b",
                message_id="msg_1",
            )
            n3 = await repo.create_notification(
                s, user_id=mailbox.user_id, channel="email", level="safe", title="t", body="b"
            )
            assert len(n1.title) == 300
            await repo.mark_notification_sent(s, n2.id)
            await repo.mark_notification_sent(s, n3.id, error="smtp down")
        async with db.session() as s:
            assert [n.id for n in await repo.list_unsent(s)] == [n1.id]
            assert [n.id for n in await repo.list_unsent(s, channel="dashboard")] == []
            all_rows = await repo.list_notifications(s, mailbox.user_id)
            by_id = {n.id: n for n in all_rows}
            assert (
                by_id[n2.id].sent_at is not None
                and by_id[n3.id].error == "smtp down"
                and by_id[n3.id].sent_at is None
            )
            assert by_id[n2.id].message_id == "msg_1"

    async def test_audit(self, db, mailbox):
        async with db.session() as s:
            await repo.audit(s, None, "system", "verdict", mailbox.id, "msg_1", {"level": "safe"})
            await repo.audit(s, mailbox.user_id, "principal", "restore_requested", mailbox.id, "msg_1")
            await repo.audit(s, None, "system", "deadman_release", "mbx_other")
        async with db.session() as s:
            rows = await repo.list_audit(s, mailbox.id)
            assert [r.action for r in rows] == ["restore_requested", "verdict"]
            assert rows[1].details == {"level": "safe"} and rows[0].actor_id == mailbox.user_id
            assert len(await repo.list_audit(s)) == 3


class TestHeartbeat:
    async def test_beat_and_release_flags(self, db, mailbox):
        async with db.session() as s:
            assert await repo.get_heartbeat(s, mailbox.id) is None
            first = await repo.beat(s, mailbox.id, at=NOW)
            assert first.beat_at == NOW
            marked = await repo.mark_deadman_release(s, mailbox.id, at=NOW + timedelta(minutes=1))
            assert marked.released_by_deadman_at is not None
            again = await repo.beat(s, mailbox.id, at=NOW + timedelta(minutes=2))
            assert again.released_by_deadman_at is None  # a live worker clears the alarm
            other = await repo.create_mailbox(
                s, user_id=mailbox.user_id, provider="yahoo", address="o@yahoo.com", mode="hold"
            )
            created = await repo.mark_deadman_release(s, other.id)  # creates the row when missing
            assert created.mailbox_id == other.id

    async def test_stale_detection(self, db, mailbox):
        threshold = timedelta(minutes=10)
        async with db.session() as s:
            await repo.set_mailbox_labels(s, mailbox.id, {"Secureddy": "L1", "_mode": "hold"})
            await repo.beat(s, mailbox.id, at=NOW - timedelta(minutes=11))
            fresh = await repo.create_mailbox(
                s, user_id=mailbox.user_id, provider="gmail", address="fresh@gmail.com", mode="hold"
            )
            await repo.beat(s, fresh.id, at=NOW - timedelta(minutes=1))
            scan = await repo.create_mailbox(
                s, user_id=mailbox.user_id, provider="gmail", address="scan@gmail.com", mode="scan"
            )
            await repo.beat(s, scan.id, at=NOW - timedelta(days=1))
            errored = await repo.create_mailbox(
                s, user_id=mailbox.user_id, provider="gmail", address="err@gmail.com", mode="hold"
            )
            await repo.beat(s, errored.id, at=NOW - timedelta(days=1))
            await repo.set_mailbox_status(s, errored.id, "error", "x")
            never_setup = await repo.create_mailbox(
                s, user_id=mailbox.user_id, provider="gmail", address="new@gmail.com", mode="hold"
            )
            setup_no_beat = await repo.create_mailbox(
                s, user_id=mailbox.user_id, provider="gmail", address="half@gmail.com", mode="hold"
            )
            await repo.set_mailbox_labels(s, setup_no_beat.id, {"Secureddy": "L1"})
            setup_no_beat.created_at = NOW - timedelta(hours=1)
            never_setup.created_at = NOW - timedelta(hours=1)
        async with db.session() as s:
            stale = await repo.stale_hold_mailboxes(s, threshold, now=NOW)
            assert sorted(m.address for m in stale) == ["client@gmail.com", "half@gmail.com"]
            assert all(m.secret is None for m in stale)  # relationship eagerly loaded
            none = await repo.stale_hold_mailboxes(s, timedelta(days=30), now=NOW)
            assert none == []


def test_aware_helper():
    assert repo.aware(None) is None
    naive = datetime(2026, 1, 1, 12, 0)
    assert repo.aware(naive) == datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    from datetime import timezone

    plus_one = datetime(2026, 1, 1, 13, 0, tzinfo=timezone(timedelta(hours=1)))
    assert repo.aware(plus_one) == datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def test_detonation_models_imported_for_schema_parity():
    # Guard: the verdict shapes we persist carry detonation job ids the worker links.
    assert (
        UrlVerdict(url="u", level=VerdictLevel.SAFE, score=0, detonation_job_id="det_1").detonation_job_id
        == "det_1"
    )
    assert (
        AttachmentVerdict(filename="f", sha256="0" * 64, level=VerdictLevel.SAFE, score=0).detonation_job_id
        is None
    )
    assert MessageRow.__tablename__ == "messages"

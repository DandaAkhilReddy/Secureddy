"""Invites, the user cap and the first admin (``store.people``), and the two
new startup migration steps: forgetting stored text-only email and promoting
the bootstrap admin (``store.migrations``)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select

from reddysec.config import Settings
from reddysec.core.ids import new_id
from reddysec.store import migrations, people, repo
from reddysec.store.models import (
    AuditLog,
    DetonationRow,
    FeedbackReasonRow,
    MailboxDailyCounterRow,
    MessageRow,
    NotificationRow,
    UserRow,
)

POLICY = people.SignupPolicy(mode="invite_only", max_users=3, bootstrap_admin_email="owner@gmail.com")


async def make_users(db, n: int, *, role: str = "principal", disabled: bool = False) -> list[UserRow]:
    out = []
    async with db.session() as s:
        for _ in range(n):
            user = await repo.create_user(s, email=f"{new_id('u').lower()}@example.com", display_name="U", role=role)
            user.disabled = disabled
            out.append(user)
    return out


class TestPolicy:
    def test_from_settings(self):
        policy = people.SignupPolicy.from_settings(
            Settings(env="test", max_users=7, signup_mode="open", bootstrap_admin_email=" Owner@Gmail.com ")
        )
        assert (policy.mode, policy.max_users, policy.bootstrap_admin_email, policy.invite_only) == (
            "open", 7, "owner@gmail.com", False
        )
        default = people.SignupPolicy.from_settings(Settings(env="test"))
        assert default.invite_only and default.max_users == 5 and default.bootstrap_admin_email == ""

    def test_settings_validate_mode(self):
        with pytest.raises(ValueError):
            Settings(env="test", signup_mode="everyone")

    @pytest.mark.parametrize(
        "email, ok",
        [("a@b.co", True), ("  Ann@Example.COM ", True), ("", False), ("no-at", False), ("a@b", False),
         ("a@@b.com", False), ("a b@c.com", False), ("a@.com", False), ("a@com.", False), ("x" * 320 + "@a.com", False)],
    )
    def test_looks_like_email(self, email, ok):
        assert people.looks_like_email(email) is ok


class TestInvites:
    async def test_create_is_idempotent_and_lowercases(self, db):
        async with db.session() as s:
            first, created = await people.create_invite(s, " Friend@Gmail.com ", invited_by="usr_1")
            again, created_again = await people.create_invite(s, "friend@gmail.com", invited_by="usr_2")
        assert created and not created_again and first.id == again.id and first.email == "friend@gmail.com"

    async def test_create_refuses_garbage(self, db):
        async with db.session() as s:
            with pytest.raises(ValueError):
                await people.create_invite(s, "not an email", invited_by=None)

    async def test_revoke_and_reinvite(self, db):
        async with db.session() as s:
            invite, _ = await people.create_invite(s, "a@b.co", invited_by=None)
            assert await people.revoke_invite(s, invite)
            assert not await people.revoke_invite(s, invite)  # already revoked
            assert await people.open_invite_for(s, "a@b.co") is None
            fresh, created = await people.create_invite(s, "a@b.co", invited_by=None)
            assert created and fresh.id != invite.id
            assert [i.id for i in await people.list_invites(s)] == [fresh.id]
            assert len(await people.list_invites(s, open_only=False)) == 2

    async def test_accept_marks_the_invite(self, db):
        async with db.session() as s:
            await people.create_invite(s, "new@b.co", invited_by=None)
            user = await repo.create_user(s, email="new@b.co", display_name="New")
            invite = await people.accept_invite(s, user)
            assert invite is not None and invite.accepted_by == user.id and invite.accepted_at is not None
            assert not await people.revoke_invite(s, invite)  # used
            assert await people.accept_invite(s, user) is None


class TestCheckSignup:
    async def test_invite_only_needs_invite_and_verified_email(self, db):
        async with db.session() as s:
            with pytest.raises(people.SignupRefused) as refused:
                await people.check_signup(s, POLICY, "stranger@gmail.com", email_verified=True)
            assert refused.value.reason == "invite_needed" and refused.value.email == "stranger@gmail.com"
            await people.create_invite(s, "friend@gmail.com", invited_by=None)
            await people.check_signup(s, POLICY, "Friend@Gmail.com", email_verified=True)
            with pytest.raises(people.SignupRefused):
                await people.check_signup(s, POLICY, "friend@gmail.com", email_verified=False)

    async def test_revoked_invite_does_not_count(self, db):
        async with db.session() as s:
            invite, _ = await people.create_invite(s, "friend@gmail.com", invited_by=None)
            await people.revoke_invite(s, invite)
            with pytest.raises(people.SignupRefused):
                await people.check_signup(s, POLICY, "friend@gmail.com", email_verified=True)

    async def test_cap_counts_active_users_only(self, db):
        await make_users(db, 2)
        await make_users(db, 4, disabled=True)
        async with db.session() as s:
            await people.create_invite(s, "friend@gmail.com", invited_by=None)
            await people.check_signup(s, POLICY, "friend@gmail.com", email_verified=True)  # 2 < 3
        await make_users(db, 1, role="admin")
        async with db.session() as s:
            assert await people.active_user_count(s) == 3
            with pytest.raises(people.SignupRefused) as refused:
                await people.check_signup(s, POLICY, "friend@gmail.com", email_verified=True)
        assert refused.value.reason == "full"

    async def test_open_mode_needs_no_invite_but_keeps_the_cap(self, db):
        open_policy = people.SignupPolicy(mode="open", max_users=1)
        async with db.session() as s:
            await people.check_signup(s, open_policy, "anyone@x.com", email_verified=False)
        await make_users(db, 1)
        async with db.session() as s:
            with pytest.raises(people.SignupRefused):
                await people.check_signup(s, open_policy, "anyone@x.com", email_verified=True)

    async def test_bootstrap_email_is_invited_and_may_exceed_the_cap_while_no_admin(self, db):
        await make_users(db, 3)
        async with db.session() as s:
            await people.check_signup(s, POLICY, "owner@gmail.com", email_verified=True)
            with pytest.raises(people.SignupRefused):  # unverified never
                await people.check_signup(s, POLICY, "owner@gmail.com", email_verified=False)
        await make_users(db, 1, role="admin")
        async with db.session() as s:
            with pytest.raises(people.SignupRefused) as refused:
                await people.check_signup(s, POLICY, "owner@gmail.com", email_verified=True)
        assert refused.value.reason == "full"


class TestBootstrapAdmin:
    async def test_promotes_only_the_bootstrap_email_while_no_admin(self, db):
        async with db.session() as s:
            other = await repo.create_user(s, email="other@gmail.com", display_name="O")
            owner = await repo.create_user(s, email="Owner@Gmail.com", display_name="Owner")
            assert not await people.maybe_bootstrap_admin(s, POLICY, other, trusted=True)
            assert not await people.maybe_bootstrap_admin(s, POLICY, owner, trusted=False)
            assert await people.maybe_bootstrap_admin(s, POLICY, owner, trusted=True)
            assert owner.role == "admin"
            assert not await people.maybe_bootstrap_admin(s, POLICY, owner, trusted=True)  # already
            again = await repo.create_user(s, email="owner2@gmail.com", display_name="x")
            assert not await people.maybe_bootstrap_admin(
                s, people.SignupPolicy(bootstrap_admin_email="owner2@gmail.com"), again, trusted=True
            )  # an admin exists now
            disabled = await repo.create_user(s, email="d@gmail.com", display_name="d")
            disabled.disabled = True
            assert not await people.maybe_bootstrap_admin(
                s, people.SignupPolicy(bootstrap_admin_email="d@gmail.com"), disabled, trusted=True
            )
            assert not await people.maybe_bootstrap_admin(s, people.SignupPolicy(), other, trusted=True)


# --------------------------------------------------------------------- migrations


async def seed_message(db, mailbox_id: str, **kw) -> str:
    mid = new_id("msg")
    async with db.session() as s:
        s.add(MessageRow(id=mid, mailbox_id=mailbox_id, provider_message_id=new_id("p"),
                         received_at=datetime.now(UTC), **kw))
    return mid


class TestPurgeTextOnly:
    async def test_purges_only_analysed_text_only_rows_and_their_trail(self, db):
        async with db.session() as s:
            user = await repo.create_user(s, email="c@x.com", display_name="C")
            mbx = await repo.create_mailbox(s, user_id=user.id, provider="gmail", address="c@x.com")
        plain = {"level": "safe", "signals": [{"code": "sender.first_time", "weight": 5}]}
        gone = await seed_message(db, mbx.id, state="done", level="safe", verdict=plain)
        reviewed = await seed_message(db, mbx.id, state="reviewed", level="safe", verdict=plain)
        keep_bec = await seed_message(db, mbx.id, state="done", level="suspicious",
                                      verdict={"signals": [{"code": "bec.gift_card", "weight": 50}]})
        keep_links = await seed_message(db, mbx.id, state="done", url_count=2, verdict=plain)
        keep_files = await seed_message(db, mbx.id, state="done", attachment_count=1, verdict=plain)
        keep_quarantined = await seed_message(db, mbx.id, state="done", quarantined=True, verdict=plain)
        keep_held = await seed_message(db, mbx.id, state="held_for_review", verdict=plain)
        keep_request = await seed_message(db, mbx.id, state="restore_requested", verdict=plain)
        keep_unchecked = await seed_message(db, mbx.id, state="rescore_requested")
        keep_none = await seed_message(db, mbx.id, state="done")
        keep_url_signal = await seed_message(db, mbx.id, state="done",
                                             verdict={"signals": [{"code": "url.credential_form"}]})
        async with db.session() as s:
            await repo.create_notification(s, user_id=user.id, channel="dashboard", level="safe", title="t",
                                           body="b", message_id=gone)
            s.add(FeedbackReasonRow(id=new_id("frs"), message_id=gone, user_id=user.id, decision="safe"))
            s.add(DetonationRow(job_id=new_id("det"), message_id=gone, kind="url", target="x", status="ok"))
            await repo.audit(s, None, "system", "verdict", mbx.id, gone, {})
            await repo.audit(s, None, "system", "restore", mbx.id, gone, {})

        async with db.engine.begin() as conn:
            assert await conn.run_sync(lambda c: migrations.purge_text_only_messages(c, dry_run=True)) == 2
        changes = await db.create_all()
        assert any("removed 2 stored text-only emails" in c for c in changes)

        async with db.session() as s:
            left = set((await s.execute(select(MessageRow.id))).scalars())
            assert left == {keep_bec, keep_links, keep_files, keep_quarantined, keep_held, keep_request,
                            keep_unchecked, keep_none, keep_url_signal}
            assert gone not in left and reviewed not in left
            for model, column in ((NotificationRow, NotificationRow.message_id),
                                  (FeedbackReasonRow, FeedbackReasonRow.message_id),
                                  (DetonationRow, DetonationRow.message_id)):
                assert (await s.execute(select(func.count()).select_from(model).where(column == gone))).scalar_one() == 0
            actions = [a.action for a in (await s.execute(select(AuditLog).where(AuditLog.target == gone))).scalars()]
            assert actions == ["restore"]  # only the "verdict" (counted) entry goes
        assert not any("text-only" in c for c in await db.create_all())  # idempotent

    async def test_merge_drops_the_twins_counters(self, db):
        from sqlalchemy import text

        async with db.session() as s:
            user = await repo.create_user(s, email="c@x.com", display_name="C")
            keep = await repo.create_mailbox(s, user_id=user.id, provider="gmail", address="c@x.com")
            await repo.bump_skipped_text_only(s, keep.id)
        async with db.engine.begin() as conn:
            await conn.execute(text(f"DROP INDEX {migrations.MAILBOX_UNIQUE_INDEX}"))
            await conn.execute(text(
                "INSERT INTO mailboxes (id, user_id, provider, address, mode, status, labels, policy, created_at) "
                f"VALUES ('mbx_twin', '{user.id}', 'imap', 'C@X.com', 'scan', 'paused', '{{}}', '{{}}', '2020-01-01')"
            ))
            await conn.execute(text(
                "INSERT INTO mailbox_daily_counters (id, mailbox_id, day, skipped_text_only, updated_at) "
                "VALUES ('cnt_twin', 'mbx_twin', '2026-01-01', 4, '2026-01-01')"
            ))
        changes = await db.create_all()
        assert any("merged duplicate mailbox mbx_twin" in c for c in changes)
        async with db.session() as s:
            rows = (await s.execute(select(MailboxDailyCounterRow))).scalars().all()
        assert [r.mailbox_id for r in rows] == [keep.id]


class TestPromoteBootstrapAdmin:
    async def test_existing_account_becomes_admin_once(self, db):
        async with db.session() as s:
            owner = await repo.create_user(s, email="owner@gmail.com", display_name="Owner")
            await repo.create_user(s, email="friend@gmail.com", display_name="Friend")
        assert migrations.promote_bootstrap_admin  # exported
        changes = await migrations.migrate(db.engine, bootstrap_admin_email=" OWNER@gmail.com")
        assert "made owner@gmail.com an admin (bootstrap admin email)" in changes
        async with db.session() as s:
            assert (await s.get(UserRow, owner.id)).role == "admin"
            roles = sorted(u.role for u in (await s.execute(select(UserRow))).scalars())
        assert roles == ["admin", "principal"]
        assert not any("admin" in c for c in await migrations.migrate(db.engine, bootstrap_admin_email="owner@gmail.com"))

    async def test_no_email_or_existing_admin_changes_nothing(self, db):
        async with db.session() as s:
            await repo.create_user(s, email="owner@gmail.com", display_name="Owner")
        assert not any("admin" in c for c in await migrations.migrate(db.engine, bootstrap_admin_email=""))
        assert not any("admin" in c for c in await migrations.migrate(db.engine, bootstrap_admin_email="nobody@x.com"))
        async with db.session() as s:
            await repo.create_user(s, email="boss@x.com", display_name="Boss", role="admin")
        assert not any("admin" in c for c in await migrations.migrate(db.engine, bootstrap_admin_email="owner@gmail.com"))

    async def test_default_reads_settings(self, db, monkeypatch):
        from reddysec.config import reset_settings_cache

        async with db.session() as s:
            await repo.create_user(s, email="owner@gmail.com", display_name="Owner")
        monkeypatch.setenv("RS_BOOTSTRAP_ADMIN_EMAIL", "owner@gmail.com")
        reset_settings_cache()
        try:
            assert any("admin" in c for c in await db.create_all())
        finally:
            reset_settings_cache()


class TestCounters:
    async def test_bump_and_sum(self, db):
        async with db.session() as s:
            user = await repo.create_user(s, email="c@x.com", display_name="C")
            mbx = await repo.create_mailbox(s, user_id=user.id, provider="gmail", address="c@x.com")
            await repo.bump_skipped_text_only(s, mbx.id, at=datetime(2026, 11, 1, 23, 0, tzinfo=UTC))
            await repo.bump_skipped_text_only(s, mbx.id, at=datetime(2026, 11, 1, 23, 30, tzinfo=UTC), by=2)
            await repo.bump_skipped_text_only(s, mbx.id, at=datetime(2026, 11, 2, 0, 1, tzinfo=UTC))
            assert await repo.skipped_text_only(s, mbx.id) == 4
            assert await repo.skipped_text_only(s, mbx.id, since_day="2026-11-02") == 1
            assert repo.utc_day(datetime(2026, 11, 2, 0, 1)) == "2026-11-02"
        async with db.session() as s:
            assert (await s.execute(select(func.count()).select_from(MailboxDailyCounterRow))).scalar_one() == 2
            assert await repo.get_user_preference(s, user.id, "text_scams") == ""
            assert not await repo.watches_text_scams(s, user.id)

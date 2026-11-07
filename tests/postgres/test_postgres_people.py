"""Invites, text-only counters, the text-only purge and the bootstrap admin on
a real PostgreSQL, reached through the migration path (an existing database
that lacks the new tables), plus the invite-only sign-in end to end."""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

import pytest
from pydantic import SecretStr
from sqlalchemy import func, select, text
from starlette.testclient import TestClient

from reddysec.config import Settings
from reddysec.core.ids import new_id
from reddysec.store import migrations, people, repo
from reddysec.store.models import Base, InviteRow, MailboxDailyCounterRow, MessageRow, UserRow

pytestmark = pytest.mark.postgres


async def test_new_tables_appear_on_an_existing_database(pg_db):
    async with pg_db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("DROP TABLE invites"))
        await conn.execute(text("DROP TABLE mailbox_daily_counters"))
    await pg_db.create_all()
    async with pg_db.engine.begin() as conn:
        names = {r[0] for r in (await conn.execute(text(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()"))).all()}
        assert {"invites", "mailbox_daily_counters"} <= names
        assert await conn.run_sync(migrations.pending_column_changes) == []


async def test_invites_counters_purge_and_bootstrap(pg_db):
    await pg_db.create_all()
    async with pg_db.session() as s:
        owner = await repo.create_user(s, email="owner@gmail.com", display_name="Owner")
        mbx = await repo.create_mailbox(s, user_id=owner.id, provider="gmail", address="owner@gmail.com")
        invite, created = await people.create_invite(s, "Friend@Gmail.com", invited_by=owner.id)
        assert created and invite.email == "friend@gmail.com"
        await repo.bump_skipped_text_only(s, mbx.id)
        await repo.bump_skipped_text_only(s, mbx.id, by=4)
        for i, verdict in enumerate(({"signals": []}, {"signals": [{"code": "bec.gift_card"}]}, None)):
            s.add(MessageRow(id=new_id("msg"), mailbox_id=mbx.id, provider_message_id="p" + "x" * 300 + str(i),
                             received_at=datetime.now(UTC), state="done", verdict=verdict))
    policy = people.SignupPolicy(max_users=2)
    async with pg_db.session() as s:
        await people.check_signup(s, policy, "friend@gmail.com", email_verified=True)
        assert await repo.skipped_text_only(s, mbx.id) == 5
        assert (await s.execute(select(func.count()).select_from(MailboxDailyCounterRow))).scalar_one() == 1

    changes = await migrations.migrate(pg_db.engine, bootstrap_admin_email="owner@gmail.com")
    assert "removed 1 stored text-only email (nothing to click or open)" in changes
    assert "made owner@gmail.com an admin (bootstrap admin email)" in changes
    assert await migrations.migrate(pg_db.engine, bootstrap_admin_email="owner@gmail.com") == []
    async with pg_db.session() as s:
        assert (await s.get(UserRow, owner.id)).role == "admin"
        assert (await s.execute(select(func.count()).select_from(MessageRow))).scalar_one() == 2
        assert (await s.execute(select(InviteRow))).scalar_one().email == "friend@gmail.com"


async def test_invite_only_google_sign_in_on_postgres(pg_url, tmp_path):
    from sqlalchemy.pool import NullPool

    from reddysec.store.db import Database
    from reddysec.web.app import create_app
    from tests.functional.web.conftest import FakeOAuthProvider

    pg_db = Database(pg_url, poolclass=NullPool)  # the app's loop and the test's loop share it
    await pg_db.create_all()
    settings = Settings(env="test", dev_login_enabled=True, artifacts_dir=str(tmp_path / "a"),
                        secret_key=SecretStr("postgres-people-secret-key-long-enough"), token_kek=SecretStr(""),
                        bootstrap_admin_email="owner@gmail.com")
    oauth = FakeOAuthProvider({"sub": "s-friend", "email": "friend@gmail.com", "email_verified": True, "name": "F"})
    app = create_app(settings, db=pg_db, oauth=oauth)

    def sign_in(client: TestClient):
        start = client.get("/auth/google/start")
        state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
        return client.get("/auth/google/callback", params={"state": state, "code": "good-code"})

    with TestClient(app, follow_redirects=False) as c:
        assert sign_in(c).status_code == 403
        async with pg_db.session() as s:
            await people.create_invite(s, "friend@gmail.com", invited_by=None)
        assert sign_in(c).status_code == 303
    with TestClient(app, follow_redirects=False) as c:
        oauth.claims = {"sub": "s-owner", "email": "owner@gmail.com", "email_verified": True, "name": "Owner"}
        assert sign_in(c).status_code == 303
        assert c.get("/admin/users").status_code == 200
    async with pg_db.session() as s:
        roles = {u.login_email: u.role for u in (await s.execute(select(UserRow))).scalars()}
    await pg_db.dispose()
    assert roles == {"friend@gmail.com": "principal", "owner@gmail.com": "admin"}

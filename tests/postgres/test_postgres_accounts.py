"""Sessions, app lock, passkeys and preferences on a real PostgreSQL, created
by the migration path (an existing database without the new tables)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text

from reddysec.core.ids import new_id
from reddysec.store.migrations import pending_column_changes
from reddysec.store.models import AppLockRow, Base, PasskeyRow, UserPreferenceRow, UserRow, UserSessionRow
from reddysec.web import applock, preferences
from reddysec.web.sessions import create_session, find_session, list_sessions, revoke_user_sessions

pytestmark = pytest.mark.postgres

NEW_TABLES = ("user_preferences", "user_sessions", "app_locks", "user_passkeys")


async def test_migration_creates_the_new_tables(pg_db):
    async with pg_db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        for table in NEW_TABLES:
            await conn.execute(text(f"DROP TABLE {table}"))
    await pg_db.create_all()
    async with pg_db.engine.begin() as conn:
        names = {r[0] for r in (await conn.execute(text(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()"))).all()}
        assert set(NEW_TABLES) <= names
        assert await conn.run_sync(pending_column_changes) == []
    assert await pg_db.create_all() == []  # idempotent


async def test_sessions_lock_passkeys_preferences_round_trip(pg_db):
    await pg_db.create_all()
    async with pg_db.session() as s:
        user = UserRow(id=new_id("usr"), display_name="P", login_email="p@example.com")
        s.add(user)
    long_ua = "Mozilla/5.0 " + "x" * 500
    token, row = await create_session(pg_db, user.id, user_agent=long_ua, ip="2001:db8::1", method="google" * 5)
    async with pg_db.session() as s:
        found = await find_session(s, token, datetime.now(UTC))
        assert found is not None and found[0].handle == row.handle and found[1] is None
        assert len(await list_sessions(s, user.id)) == 1
        s.add(AppLockRow(user_id=user.id, kind="pin", secret_hash=applock.hash_secret("482913"), timeout_s=300))
        s.add(PasskeyRow(id=new_id("pky"), user_id=user.id, credential_id="c" * 900, public_key="k" * 900, name="n" * 100))
        assert await preferences.set_preference(s, user.id, preferences.INBOX_VIEW, "separate")
        assert await preferences.set_preference(s, user.id, preferences.SELECTED_MAILBOX, "mbx_" + "A" * 26)
    async with pg_db.session() as s:
        found = await find_session(s, token, datetime.now(UTC))
        assert found[1] is not None and found[1].kind == "pin"
        prefs = await preferences.get_preferences(s, user.id)
        assert prefs == {"inbox_view": "separate", "selected_mailbox": "mbx_" + "A" * 26, "period": "7d", "theme": "", "text_scams": "off"}
        result = await applock.try_unlock(s, user.id, row.id, "000000")
        assert result.outcome == "wrong"
        assert await revoke_user_sessions(s, user.id, "test") == 1
    async with pg_db.session() as s:
        assert await find_session(s, token, datetime.now(UTC)) is None
        assert (await s.execute(select(UserPreferenceRow))).scalars().all()
        assert (await s.execute(select(UserSessionRow))).scalar_one().revoked_reason == "test"
        assert await find_session(s, token, datetime.now(UTC) + timedelta(days=400)) is None

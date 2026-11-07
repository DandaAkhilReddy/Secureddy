"""web.mfa: code windows, replay, rate limit, recovery codes, remembered devices, QR."""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from sqlalchemy import select

from reddysec.core.ids import new_id
from reddysec.store.db import Database
from reddysec.store.models import MfaStateRow, RecoveryCodeRow, TrustedDeviceRow, UserRow
from reddysec.web import mfa

SECRET = pyotp.random_base32()
T0 = 1_800_000_000.0  # a fixed instant, the start of a 30 s step
STEP0 = int(T0 // 30)


def code_at(t: float) -> str:
    return pyotp.TOTP(SECRET).at(t)


class TestMatchingStep:
    def test_current_and_one_step_drift(self):
        assert mfa.matching_step(SECRET, code_at(T0), now=T0) == STEP0
        assert mfa.matching_step(SECRET, code_at(T0 - 30), now=T0) == STEP0 - 1  # phone a little slow
        assert mfa.matching_step(SECRET, code_at(T0 + 30), now=T0) == STEP0 + 1  # phone a little fast

    def test_outside_the_window(self):
        assert mfa.matching_step(SECRET, code_at(T0 - 60), now=T0) is None
        assert mfa.matching_step(SECRET, code_at(T0 + 60), now=T0) is None

    def test_edges_of_a_step(self):
        last_second = T0 + 29.999
        assert mfa.matching_step(SECRET, code_at(T0), now=last_second) == STEP0
        assert mfa.matching_step(SECRET, code_at(T0), now=T0 + 30) == STEP0  # previous step, still fine
        assert mfa.matching_step(SECRET, code_at(T0), now=T0 + 60) is None

    @pytest.mark.parametrize("bad", ["", None, "12345", "1234567", "abcdef", "12 34 56 78 90 12 34"])
    def test_malformed(self, bad):
        assert mfa.matching_step(SECRET, bad, now=T0) is None

    def test_spaces_are_fine(self):
        c = code_at(T0)
        assert mfa.matching_step(SECRET, f"{c[:3]} {c[3:]}", now=T0) == STEP0
        assert mfa.matching_step("", c, now=T0) is None


def test_uri_key_and_qr():
    uri = mfa.otpauth_uri(SECRET, "me@example.com")
    assert uri.startswith("otpauth://totp/Secureddy:me%40example.com?") and "issuer=Secureddy" in uri
    assert mfa.grouped("ABCDEFGHIJ") == "ABCD EFGH IJ"
    svg = mfa.qr_svg(uri, label='Scan "me"')
    assert svg.startswith('<svg class="qr"') and "<path" in svg and "style" not in svg and "<script" not in svg
    assert 'aria-label="Scan &#34;me&#34;"' in svg
    size = int(re.search(r'viewBox="0 0 (\d+) ', svg).group(1))
    assert size >= 29  # version 3+ plus the quiet zone


def test_recovery_code_format():
    codes = mfa.new_recovery_codes()
    assert len(codes) == 10 and len(set(codes)) == 10
    assert all(re.fullmatch(r"[a-z2-9]{5}-[a-z2-9]{5}", c) for c in codes)
    assert mfa.normalize_recovery(" ABCDE fghjk ") == "abcde-fghjk"
    assert mfa.normalize_recovery("abcde-fghj") == "" and mfa.normalize_recovery("abcde-fghi0") == ""
    assert mfa.normalize_recovery(None) == ""
    text = mfa.recovery_text(codes, "me@example.com")
    assert "me@example.com" in text and all(c in text for c in codes)


def test_messages():
    assert "2 tries left" in mfa.result_message(mfa.CheckResult("wrong", left=2))
    assert "1 try left" in mfa.result_message(mfa.CheckResult("reused", left=1))
    assert "already used" in mfa.result_message(mfa.CheckResult("reused", left=1))
    soon = datetime.now(UTC) + timedelta(minutes=3)
    assert "wait 3 minutes" in mfa.result_message(mfa.CheckResult("limited", until=soon))
    assert "wait 15 minutes" in mfa.result_message(mfa.CheckResult("limited"))


def test_pending_in_the_flow_cookie():
    flow: dict = {}
    assert mfa.pending_of(flow) is None
    mfa.remember_pending(flow, "usr_1", "google", "/messages")
    assert mfa.pending_of(flow)["uid"] == "usr_1"
    flow[mfa.SESSION_KEY]["exp"] = int(time.time()) - 1
    assert mfa.pending_of(flow) is None
    assert mfa.pending_of({mfa.SESSION_KEY: "junk"}) is None


@pytest.fixture
async def store(tmp_path):
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'mfa.db'}")
    await db.create_all()
    user = UserRow(id=new_id("usr"), display_name="M", login_email="m@example.com")
    async with db.session() as s:
        s.add(user)
    yield db, user
    await db.dispose()


def at(t: float) -> datetime:
    return datetime.fromtimestamp(t, UTC)


class TestCheckCode:
    async def test_accepts_once_then_refuses_replay(self, store):
        db, user = store
        async with db.session() as s:
            assert (await mfa.check_code(s, user, SECRET, code_at(T0), now=at(T0))).outcome == "ok"
        async with db.session() as s:
            again = await mfa.check_code(s, user, SECRET, code_at(T0), now=at(T0 + 5))
            assert again.outcome == "reused" and again.left == 4
            older = await mfa.check_code(s, user, SECRET, code_at(T0 - 30), now=at(T0 + 5))
            assert older.outcome == "reused"
        async with db.session() as s:
            assert (await mfa.check_code(s, user, SECRET, code_at(T0 + 30), now=at(T0 + 31))).ok
            assert (await s.get(MfaStateRow, user.id)).failed_attempts == 0  # success clears the count

    async def test_five_wrong_codes_pause_for_fifteen_minutes(self, store):
        db, user = store
        async with db.session() as s:
            results = [await mfa.check_code(s, user, SECRET, "000000", now=at(T0 + i)) for i in range(5)]
        assert [r.outcome for r in results] == ["wrong"] * 4 + ["limited"]
        assert [r.left for r in results[:4]] == [4, 3, 2, 1]
        async with db.session() as s:
            right = await mfa.check_code(s, user, SECRET, code_at(T0 + 600), now=at(T0 + 600))
            assert right.outcome == "limited"  # even the right code waits
        async with db.session() as s:
            later = T0 + 15 * 60 + 1
            assert (await mfa.check_code(s, user, SECRET, code_at(later), now=at(later))).ok

    async def test_the_window_starts_over_after_fifteen_minutes(self, store):
        db, user = store
        async with db.session() as s:
            for i in range(4):
                await mfa.check_code(s, user, SECRET, "000000", now=at(T0 + i))
            fresh = await mfa.check_code(s, user, SECRET, "000000", now=at(T0 + 16 * 60))
        assert fresh.outcome == "wrong" and fresh.left == 4

    async def test_recovery_codes_work_once(self, store):
        db, user = store
        codes = mfa.new_recovery_codes()
        async with db.session() as s:
            await mfa.replace_recovery_codes(s, user.id, codes)
        async with db.session() as s:
            hashes = [r.code_hash for r in (await s.execute(select(RecoveryCodeRow))).scalars()]
            assert len(hashes) == 10 and all(h.startswith("$argon2id$") for h in hashes)
            assert not any(c in h for c in codes for h in hashes)
        async with db.session() as s:
            used = await mfa.check_code(s, user, SECRET, codes[3].upper().replace("-", " "))
            assert used.outcome == "recovery" and used.recovery_left == 9
        async with db.session() as s:
            assert (await mfa.check_code(s, user, SECRET, codes[3])).outcome == "wrong"
            assert (await mfa.check_code(s, user, SECRET, codes[4], allow_recovery=False)).outcome == "wrong"
            assert await mfa.recovery_codes_left(s, user.id) == 9

    async def test_remembered_devices(self, store):
        db, user = store
        now = datetime.now(UTC)
        async with db.session() as s:
            token = await mfa.trust_device(s, user.id, session_id="sid1", user_agent="Safari on iPhone", now=now)
        async with db.session() as s:
            assert await mfa.device_is_trusted(s, user.id, token)
            assert not await mfa.device_is_trusted(s, "usr_other", token)
            assert not await mfa.device_is_trusted(s, user.id, "nope")
            assert not await mfa.device_is_trusted(s, user.id, None)
            assert not await mfa.device_is_trusted(s, user.id, "x" * 300)
            assert not await mfa.device_is_trusted(s, user.id, token, now=now + timedelta(days=31))
            assert await mfa.remembered_devices(s, user.id) == 1
            assert (await s.get(TrustedDeviceRow, mfa.hash_token(token))).session_id == "sid1"
            assert await mfa.forget_devices(s, user.id, session_id="other") == 0
            assert await mfa.forget_devices(s, user.id, session_id="sid1") == 1

"""Staying signed in (server-side sessions), devices, the app lock and passkeys."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
from datetime import UTC, datetime, timedelta

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select, update
from starlette.testclient import TestClient

from reddysec.store.models import AppLockRow, AuditLog, PasskeyRow, UserSessionRow
from reddysec.web import applock
from reddysec.web.app import create_app
from reddysec.web.sessions import (
    AuthSessionMiddleware,
    device_name,
    hash_token,
    ip_prefix,
    lock_state,
    wants_json_scope,
)

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


async def sessions(db, user_id=None) -> list[UserSessionRow]:
    async with db.session() as s:
        stmt = select(UserSessionRow)
        if user_id:
            stmt = stmt.where(UserSessionRow.user_id == user_id)
        return list((await s.execute(stmt)).scalars())


def token_of(client) -> str:
    return CSRF_RE.search(client.get("/settings/security").text).group(1)


# --------------------------------------------------------------------------- pure helpers


def test_device_names_and_networks():
    assert device_name("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit Version/18.0 Mobile Safari/604.1") == "Safari on iPhone"
    assert device_name("Mozilla/5.0 (Windows NT 10.0) Chrome/130.0 Safari/537.36 Edg/130.0") == "Edge on Windows"
    assert device_name("curl/8") == "Unknown device" and device_name(None) == "Unknown device"
    assert device_name("Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0") == "Firefox on Linux"
    assert ip_prefix("203.0.113.77") == "203.0.113.0/24"
    assert ip_prefix("2001:db8:1234:5678::1") == "2001:db8:1234::/48"
    assert ip_prefix("testclient") == "" and ip_prefix(None) == ""


def test_lock_state_rules():
    now = datetime.now(UTC)
    row = UserSessionRow(unlocked_at=now, last_active_at=now - timedelta(seconds=30))
    assert lock_state(row, None, now) == (False, False)
    lock = AppLockRow(timeout_s=60)
    assert lock_state(row, lock, now) == (True, False)
    row.last_active_at = now - timedelta(seconds=61)
    assert lock_state(row, lock, now) == (True, True)
    row.unlocked_at = None
    assert lock_state(row, lock, now) == (True, True)


def test_wants_json_scope():
    assert wants_json_scope({"path": "/api/me", "headers": []})
    assert wants_json_scope({"path": "/x", "headers": [(b"accept", b"text/event-stream")]})
    assert wants_json_scope({"path": "/x", "headers": [(b"accept", b"application/json")]})
    assert not wants_json_scope({"path": "/x", "headers": [(b"accept", b"text/html,application/json")]})


async def test_middleware_passes_lifespan_through():
    seen = []

    async def app(scope, receive, send):
        seen.append(scope["type"])

    await AuthSessionMiddleware(app)({"type": "lifespan"}, None, None)
    assert seen == ["lifespan"]


# --------------------------------------------------------------------------- sessions


async def test_sign_in_creates_a_server_session_with_a_long_lived_cookie(client, login, db):
    login(client, "me@example.com")
    (row,) = await sessions(db)
    raw = client.cookies.get("rs_sid")
    assert row.id == hash_token(raw) and raw not in row.id  # only the hash is stored
    assert len(raw) >= 40 and row.handle.startswith("dev_") and row.auth_method == "dev"
    expires = row.expires_at.replace(tzinfo=UTC) if row.expires_at.tzinfo is None else row.expires_at
    created = row.created_at.replace(tzinfo=UTC) if row.created_at.tzinfo is None else row.created_at
    assert (expires - created).days == 90
    page = client.get("/")
    assert page.status_code == 200


async def test_cookie_attributes(settings, db, login):
    prod = settings.model_copy(update={"env": "prod", "dev_login_enabled": False})
    app = create_app(prod, db=db)
    from reddysec.web.auth import (
        start_session,  # noqa: F401 - prod has no dev login; check the header shape instead
    )

    with TestClient(app, follow_redirects=False, base_url="https://testserver") as c:
        r = c.get("/login")
        assert "Secure" in r.headers["set-cookie"]


async def test_dev_cookie_header(client, login):
    token = CSRF_RE.search(client.get("/login").text).group(1)
    r = client.post("/auth/dev-login", data={"email": "c@example.com", "csrf_token": token})
    cookies = r.headers.get_list("set-cookie")
    sid = next(c for c in cookies if c.startswith("rs_sid="))
    assert "HttpOnly" in sid and "SameSite=Lax" in sid and "Path=/" in sid and f"Max-Age={90 * 86400}" in sid


async def test_sliding_renewal_at_most_hourly_and_absolute_cap(client, login, db):
    login(client, "slide@example.com")
    (row,) = await sessions(db)
    # 30 minutes later: nothing written.
    async with db.session() as s:
        await s.execute(update(UserSessionRow).values(last_seen_at=datetime.now(UTC) - timedelta(minutes=30)))
    r = client.get("/")
    assert "rs_sid=" not in r.headers.get("set-cookie", "")
    # Two hours later: slid forward and the cookie renewed.
    async with db.session() as s:
        await s.execute(update(UserSessionRow).values(
            last_seen_at=datetime.now(UTC) - timedelta(hours=2), expires_at=datetime.now(UTC) + timedelta(days=1)))
    r = client.get("/")
    assert "rs_sid=" in r.headers.get("set-cookie", "")
    (row,) = await sessions(db)
    exp = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=UTC)
    assert exp > datetime.now(UTC) + timedelta(days=89)
    # Near the absolute end: the slide stops at it.
    cap = datetime.now(UTC) + timedelta(days=2)
    async with db.session() as s:
        await s.execute(update(UserSessionRow).values(absolute_expires_at=cap,
                                                      last_seen_at=datetime.now(UTC) - timedelta(hours=2)))
    client.get("/")
    (row,) = await sessions(db)
    exp = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=UTC)
    assert exp <= cap + timedelta(seconds=1)
    # Past the absolute end: signed out.
    async with db.session() as s:
        await s.execute(update(UserSessionRow).values(absolute_expires_at=datetime.now(UTC) - timedelta(seconds=1)))
    r = client.get("/")
    assert r.status_code == 303 and r.headers["location"] == "/login"


async def test_idle_expiry_signs_out(client, login, db):
    login(client, "idle@example.com")
    async with db.session() as s:
        await s.execute(update(UserSessionRow).values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
    assert client.get("/").status_code == 303


async def test_logout_revokes_the_row(client, login, db, csrf_of):
    login(client, "out@example.com")
    raw = client.cookies.get("rs_sid")
    client.post("/auth/logout", data={"csrf_token": csrf_of(client, "/")})
    (row,) = await sessions(db)
    assert row.revoked_at is not None and row.revoked_reason == "signed_out"
    client.cookies.set("rs_sid", raw)  # a stolen copy of the cookie is now worthless
    assert client.get("/").status_code == 303


async def test_signing_in_again_replaces_the_device_session(client, login, db):
    login(client, "again@example.com")
    token = CSRF_RE.search(client.get("/settings/security").text).group(1)
    r = client.post("/auth/dev-login", data={"email": "again@example.com", "csrf_token": token})
    assert r.status_code == 303
    rows = await sessions(db)
    assert len(rows) == 2 and sum(r.revoked_at is None for r in rows) == 1
    assert {r.revoked_reason for r in rows if r.revoked_at} == {"replaced"}


async def test_devices_list_sign_out_one_and_everywhere(app, db, login):
    phone = TestClient(app, follow_redirects=False, headers={"user-agent": "Mozilla/5.0 (iPhone) Version/18 Mobile Safari/604"})
    laptop = TestClient(app, follow_redirects=False, headers={"user-agent": "Mozilla/5.0 (Macintosh) Chrome/130 Safari/537"})
    with phone, laptop:
        login(phone, "dev@example.com")
        login(laptop, "dev@example.com")
        page = laptop.get("/settings/security").text
        assert "Safari on iPhone" in page and "Chrome on Mac" in page and "This device" in page
        rows = await sessions(db)
        phone_row = next(r for r in rows if "iPhone" in r.user_agent)
        token = token_of(laptop)
        r = laptop.post(f"/settings/devices/{phone_row.handle}/sign-out", data={"csrf_token": token})
        assert r.status_code == 303 and phone.get("/").status_code == 303
        assert laptop.get("/").status_code == 200
        assert laptop.post("/settings/devices/dev_nope/sign-out", data={"csrf_token": token}).status_code == 404
        # Signing out this device from the list
        laptop_row = next(r for r in await sessions(db) if "Mac" in r.user_agent)
        r = laptop.post(f"/settings/devices/{laptop_row.handle}/sign-out", data={"csrf_token": token})
        assert r.headers["location"] == "/login" and laptop.get("/").status_code == 303
        login(laptop, "dev@example.com")
        login(phone, "dev@example.com")
        r = laptop.post("/settings/devices/sign-out-everywhere", data={"csrf_token": token_of(laptop)})
        assert r.headers["location"] == "/login"
        assert laptop.get("/").status_code == 303 and phone.get("/").status_code == 303
        async with db.session() as s:
            actions = [a.action for a in (await s.execute(select(AuditLog))).scalars()]
        assert "device_signed_out" in actions and "signed_out_everywhere" in actions


async def test_other_users_device_cannot_be_signed_out(app, db, login):
    with TestClient(app, follow_redirects=False) as a, TestClient(app, follow_redirects=False) as b:
        login(a, "a@example.com")
        login(b, "b@example.com")
        (row_b,) = [r for r in await sessions(db) if r.revoked_at is None and "b" in r.user_id or False] or [None]
        b_rows = [r for r in await sessions(db) if r.revoked_at is None]
        target = next(r for r in b_rows if r.id == hash_token(b.cookies.get("rs_sid")))
        assert a.post(f"/settings/devices/{target.handle}/sign-out", data={"csrf_token": token_of(a)}).status_code == 404
        assert b.get("/").status_code == 200


async def test_password_change_signs_out_other_devices(app, db, login):
    with TestClient(app, follow_redirects=False) as one, TestClient(app, follow_redirects=False) as two:
        login(one, "pw@example.com")
        login(two, "pw@example.com")
        pw = "correct horse battery staple"
        r = one.post("/settings/security/password", data={"password": pw, "confirm": pw, "csrf_token": token_of(one)})
        assert r.status_code == 303
        assert "signed out 1 other device" in one.get("/settings/security").text
        assert one.get("/").status_code == 200 and two.get("/").status_code == 303
        one.post("/settings/security/password", data={"password": pw, "confirm": pw, "csrf_token": token_of(one)})
        assert "Your password is changed" in one.get("/settings/security").text


async def test_disabled_account_session_is_ended(client, login, db):
    login(client, "closed@example.com")
    from reddysec.store.models import UserRow

    async with db.session() as s:
        await s.execute(update(UserRow).values(disabled=True))
    assert client.get("/").status_code == 303
    (row,) = await sessions(db)
    assert row.revoked_reason == "account_closed"


# --------------------------------------------------------------------------- app lock


def set_pin(client, pin="482913", timeout="5m", current=""):
    return client.post("/settings/lock", data={"kind": "pin", "secret": pin, "confirm": pin, "timeout": timeout,
                                               "current": current, "csrf_token": token_of(client)})


async def lock_now(client):
    return client.post("/lock/now", data={"csrf_token": token_of(client)})


async def test_turning_the_lock_on_validates_and_signs_out_other_devices(app, db, login):
    with TestClient(app, follow_redirects=False) as me, TestClient(app, follow_redirects=False) as other:
        login(me, "lock@example.com")
        login(other, "lock@example.com")
        for pin, confirm, message in (("12345", "12345", "exactly 6 digits"), ("111111", "111111", "too easy"),
                                      ("482913", "482914", "did not match")):
            me.post("/settings/lock", data={"kind": "pin", "secret": pin, "confirm": confirm, "csrf_token": token_of(me)})
            assert message in me.get("/settings/security").text
        me.post("/settings/lock", data={"kind": "password", "secret": "short", "confirm": "short", "csrf_token": token_of(me)})
        assert "at least 8" in me.get("/settings/security").text
        me.post("/settings/lock", data={"kind": "weird", "secret": "x", "confirm": "x", "csrf_token": token_of(me)})
        assert "Please choose a PIN" in me.get("/settings/security").text
        me.post("/settings/lock", data={"kind": "passkey", "csrf_token": token_of(me)})
        assert "Add a passkey first" in me.get("/settings/security").text
        assert set_pin(me, timeout="bogus").status_code == 303
        async with db.session() as s:
            lock = await s.get(AppLockRow, (await sessions(db))[0].user_id)
        assert lock.kind == "pin" and lock.timeout_s == 300 and lock.secret_hash.startswith("$argon2id$")
        assert "App lock is on" in me.get("/settings/security").text
        assert other.get("/").status_code == 303 and me.get("/").status_code == 200


async def test_locked_session_shows_lock_screen_and_423_for_json(client, login, db):
    login(client, "locked@example.com")
    set_pin(client)
    await lock_now(client)
    r = client.get("/messages?level=safe")
    assert r.status_code == 303 and r.headers["location"] == "/lock?next=/messages?level=safe"
    assert client.get("/").headers["location"] == "/lock"
    api = client.get("/api/me")
    assert api.status_code == 423 and api.json()["error"] == "locked"
    fetch = client.post("/assistant/stream", headers={"accept": "text/event-stream"}, data={"message": "x"})
    assert fetch.status_code == 423
    post = client.post("/mailboxes/x/pause", data={})
    assert post.status_code == 303 and post.headers["location"] == "/lock"
    page = client.get("/lock?next=/messages")
    assert page.status_code == 200 and "Secureddy is locked" in page.text and 'class="nav"' not in page.text
    assert "Forgot PIN?" in page.text and client.get("/static/app.css").status_code == 200
    assert client.get("/manifest.webmanifest").status_code == 200


async def test_unlock_with_pin_and_wrong_pin_counts(client, login, db):
    login(client, "pin@example.com")
    set_pin(client)
    await lock_now(client)
    token = CSRF_RE.search(client.get("/lock").text).group(1)
    wrong = client.post("/lock", data={"secret": "000000", "next": "/messages", "csrf_token": token})
    assert wrong.status_code == 401 and "4 tries left" in wrong.text
    ok = client.post("/lock", data={"secret": "482913", "next": "/messages", "csrf_token": token})
    assert ok.status_code == 303 and ok.headers["location"] == "/messages"
    assert client.get("/messages").status_code == 200
    assert client.get("/lock").headers["location"] == "/"  # not locked: the lock page sends you on
    assert client.post("/lock", data={"secret": "x", "csrf_token": token}).status_code == 303


async def test_five_wrong_pins_pause_ten_sign_out_everywhere(app, db, login):
    with TestClient(app, follow_redirects=False) as client, TestClient(app, follow_redirects=False) as other:
        login(client, "brute@example.com")
        set_pin(client)
        login(other, "brute@example.com")
        await lock_now(client)
        token = CSRF_RE.search(client.get("/lock").text).group(1)
        for _ in range(4):
            assert client.post("/lock", data={"secret": "000000", "csrf_token": token}).status_code == 401
        fifth = client.post("/lock", data={"secret": "000000", "csrf_token": token})
        assert "wait 15 minutes" in fifth.text
        # Even the right PIN waits during the pause.
        right = client.post("/lock", data={"secret": "482913", "csrf_token": token})
        assert right.status_code == 401 and "wait 15 minutes" in right.text
        assert "try again in" in client.get("/lock").text
        async with db.session() as s:
            await s.execute(update(AppLockRow).values(locked_until=datetime.now(UTC) - timedelta(seconds=1)))
        for _ in range(4):
            client.post("/lock", data={"secret": "000000", "csrf_token": token})
        tenth = client.post("/lock", data={"secret": "000000", "csrf_token": token})
        assert tenth.status_code == 303 and tenth.headers["location"] == "/login"
        assert client.get("/").status_code == 303 and other.get("/").status_code == 303
        # A full sign-in resets the count and opens the app.
        login(client, "brute@example.com")
        assert client.get("/").status_code == 200
        async with db.session() as s:
            lock = (await s.execute(select(AppLockRow))).scalar_one()
        assert lock.failed_attempts == 0


async def test_inactivity_timeout_locks(client, login, db):
    login(client, "idle-lock@example.com")
    set_pin(client, timeout="open")
    assert client.get("/").status_code == 200
    async with db.session() as s:
        await s.execute(update(UserSessionRow).values(last_active_at=datetime.now(UTC) - timedelta(seconds=90)))
    assert client.get("/").headers["location"] == "/lock"
    async with db.session() as s:
        (row,) = [r for r in (await s.execute(select(UserSessionRow))).scalars() if r.revoked_at is None]
    assert row.unlocked_at is None  # stays locked on the server


async def test_activity_is_recorded_while_unlocked(client, login, db):
    login(client, "act@example.com")
    set_pin(client)
    async with db.session() as s:
        await s.execute(update(UserSessionRow).values(last_active_at=datetime.now(UTC) - timedelta(seconds=60)))
    client.get("/")
    async with db.session() as s:
        (row,) = [r for r in (await s.execute(select(UserSessionRow))).scalars() if r.revoked_at is None]
    last = row.last_active_at if row.last_active_at.tzinfo else row.last_active_at.replace(tzinfo=UTC)
    assert datetime.now(UTC) - last < timedelta(seconds=10)


async def test_forgot_pin_signs_this_device_out(client, login, db):
    login(client, "forgot@example.com")
    set_pin(client)
    await lock_now(client)
    token = CSRF_RE.search(client.get("/lock").text).group(1)
    r = client.post("/lock/forgot", data={"next": "/messages", "csrf_token": token})
    assert r.headers["location"] == "/login?next=/messages"
    assert client.get("/").status_code == 303
    fresh = CSRF_RE.search(client.get("/login").text).group(1)
    r2 = client.post("/lock/forgot", data={"csrf_token": fresh})
    assert r2.headers["location"] == "/login"


async def test_lock_page_without_session_and_lock_now_without_lock(client, login):
    assert client.get("/lock").headers["location"] == "/login"
    token = CSRF_RE.search(client.get("/login").text).group(1)
    assert client.post("/lock", data={"csrf_token": token}).headers["location"] == "/login"
    login(client, "nolock@example.com")
    r = client.post("/lock/now", data={"csrf_token": token_of(client)})
    assert r.headers["location"] == "/settings/security#lock"


async def test_change_timeout_change_pin_and_remove(client, login, db):
    login(client, "change@example.com")
    assert client.post("/settings/lock/timeout", data={"timeout": "1h", "csrf_token": token_of(client)}).status_code == 303
    assert "Turn on the app lock first" in client.get("/settings/security").text
    set_pin(client)
    assert client.post("/settings/lock/timeout", data={"timeout": "nope", "csrf_token": token_of(client)}).status_code == 400
    client.post("/settings/lock/timeout", data={"timeout": "1d", "csrf_token": token_of(client)})
    async with db.session() as s:
        assert (await s.execute(select(AppLockRow))).scalar_one().timeout_s == 86400
    # Changing needs the current PIN.
    set_pin(client, pin="739154")
    assert "did not match, so nothing changed" in client.get("/settings/security").text
    set_pin(client, pin="739154", current="482913")
    async with db.session() as s:
        lock = (await s.execute(select(AppLockRow))).scalar_one()
    assert applock.verify_secret(lock.secret_hash, "739154")
    client.post("/settings/lock/remove", data={"current": "000000", "csrf_token": token_of(client)})
    assert "the lock stays on" in client.get("/settings/security").text
    client.post("/settings/lock/remove", data={"current": "739154", "csrf_token": token_of(client)})
    async with db.session() as s:
        assert (await s.execute(select(AppLockRow))).scalar_one_or_none() is None
    assert client.post("/settings/lock/remove", data={"csrf_token": token_of(client)}).status_code == 303


async def test_lock_json_responses(client, login):
    login(client, "json@example.com")
    r = client.post("/settings/lock", headers={"accept": "application/json"},
                    data={"kind": "pin", "secret": "1", "confirm": "1", "csrf_token": token_of(client)})
    assert r.status_code == 400 and r.json()["ok"] is False


async def test_unit_try_unlock_without_lock(db, seed):
    user = await seed.user("u@example.com")
    async with db.session() as s:
        result = await applock.try_unlock(s, user.id, "nope", "123456")
    assert result.outcome == "not_locked"
    assert applock.timeout_key(42) == "5m" and applock.verify_secret("not-a-hash", "x") is False
    assert applock.take_challenge({"webauthn": {"c": "AA", "p": "x", "exp": 1}}, "x") is None  # expired
    assert applock.take_challenge({"webauthn": {"c": "AA", "p": "y", "exp": 9e12}}, "x") is None  # other purpose
    assert applock.take_challenge({}, "x") is None


# --------------------------------------------------------------------------- passkeys


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64u(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class Authenticator:
    """A software passkey: ES256, 'none' attestation, user verified."""

    def __init__(self, rp_id: str = "localhost", origin: str = "http://localhost:8000") -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = b"cred-" + bytes(range(16))
        self.rp_id = rp_id
        self.origin = origin
        self.count = 0

    def _client_data(self, kind: str, challenge: str) -> bytes:
        return json.dumps({"type": kind, "challenge": challenge, "origin": self.origin, "crossOrigin": False}).encode()

    def create(self, options: dict) -> str:
        nums = self.key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        auth = (hashlib.sha256(self.rp_id.encode()).digest() + bytes([0x45]) + struct.pack(">I", 0) + bytes(16)
                + struct.pack(">H", len(self.cred_id)) + self.cred_id + cose)
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
        return json.dumps({"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                           "response": {"clientDataJSON": b64u(self._client_data("webauthn.create", options["challenge"])),
                                        "attestationObject": b64u(att)}})

    def get(self, options: dict, *, tamper: bool = False) -> str:
        self.count += 1
        auth = hashlib.sha256(self.rp_id.encode()).digest() + bytes([0x05]) + struct.pack(">I", self.count)
        cdata = self._client_data("webauthn.get", options["challenge"])
        signature = self.key.sign(auth + hashlib.sha256(cdata).digest(), ec.ECDSA(hashes.SHA256()))
        if tamper:
            signature = signature[:-1] + bytes([signature[-1] ^ 1])
        return json.dumps({"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                           "response": {"clientDataJSON": b64u(cdata), "authenticatorData": b64u(auth),
                                        "signature": b64u(signature), "userHandle": None}})


async def add_passkey(client, device: Authenticator) -> None:
    token = token_of(client)
    options = client.post("/settings/passkeys/options", data={"csrf_token": token}).json()
    assert options["rp"]["id"] == "localhost" and options["authenticatorSelection"]["userVerification"] == "required"
    r = client.post("/settings/passkeys", data={"credential": device.create(options), "name": "", "csrf_token": token})
    assert r.status_code == 200 and r.json()["ok"], r.text


async def test_passkey_register_unlock_and_remove(client, login, db):
    login(client, "pk@example.com")
    device = Authenticator()
    await add_passkey(client, device)
    page = client.get("/settings/security").text
    assert "Passkey on" in page and "Passkey only" in page
    # Same passkey twice is refused; a stale challenge too.
    token = token_of(client)
    options = client.post("/settings/passkeys/options", data={"csrf_token": token}).json()
    assert len(options["excludeCredentials"]) == 1
    dup = client.post("/settings/passkeys", data={"credential": device.create(options), "csrf_token": token})
    assert dup.status_code == 400 and "already added" in dup.json()["error"]
    stale = client.post("/settings/passkeys", data={"credential": device.create(options), "csrf_token": token})
    assert stale.status_code == 400 and "too long" in stale.json()["error"]
    # Passkey-only lock.
    r = client.post("/settings/lock", data={"kind": "passkey", "timeout": "5m", "csrf_token": token})
    assert r.status_code == 303
    await lock_now(client)
    lock_page = client.get("/lock").text
    assert "Unlock with passkey" in lock_page and 'name="secret"' not in lock_page
    token = CSRF_RE.search(lock_page).group(1)
    opts = client.post("/lock/passkey/options", data={"csrf_token": token}).json()
    bad = client.post("/lock/passkey", data={"credential": device.get(opts, tamper=True), "csrf_token": token})
    assert bad.status_code == 400 and client.get("/").status_code == 303
    opts = client.post("/lock/passkey/options", data={"csrf_token": token}).json()
    ok = client.post("/lock/passkey", data={"credential": device.get(opts), "next": "/messages", "csrf_token": token})
    assert ok.status_code == 200 and ok.json() == {"ok": True, "next": "/messages"}
    assert client.get("/").status_code == 200
    async with db.session() as s:
        pk = (await s.execute(select(PasskeyRow))).scalar_one()
    assert pk.sign_count == 2 and pk.last_used_at is not None
    # Removing the last passkey of a passkey-only lock removes the lock.
    r = client.post(f"/settings/passkeys/{pk.id}/remove", data={"csrf_token": token_of(client)})
    assert r.status_code == 303
    async with db.session() as s:
        assert (await s.execute(select(AppLockRow))).scalar_one_or_none() is None
    assert client.post("/settings/passkeys/pky_nope/remove", data={"csrf_token": token_of(client)}).status_code == 404


async def test_passkey_errors(client, login):
    login(client, "pkerr@example.com")
    token = token_of(client)
    bad = client.post("/settings/passkeys/options", data={"csrf_token": token}).json()
    r = client.post("/settings/passkeys", data={"credential": "{}", "csrf_token": token})
    assert r.status_code == 400 and bad
    assert client.post("/lock/passkey/options", data={"csrf_token": token}).status_code == 400
    r = client.post("/lock/passkey", data={"credential": "not json", "csrf_token": token})
    assert r.status_code == 400
    client.cookies.delete("rs_sid")
    assert client.post("/lock/passkey", data={"credential": "{}", "csrf_token": token}).status_code == 401


async def test_unknown_passkey_cannot_unlock(client, login):
    login(client, "pk2@example.com")
    mine = Authenticator()
    await add_passkey(client, mine)
    set_pin(client)
    await lock_now(client)
    token = CSRF_RE.search(client.get("/lock").text).group(1)
    opts = client.post("/lock/passkey/options", data={"csrf_token": token}).json()
    stranger = Authenticator()
    stranger.cred_id = b"someone-else"
    r = client.post("/lock/passkey", data={"credential": stranger.get(opts), "csrf_token": token})
    assert r.status_code == 400 and "not set up" in r.json()["error"]


@pytest.mark.parametrize("path", ["/lock", "/lock/forgot", "/lock/passkey", "/settings/lock", "/settings/devices/sign-out-everywhere"])
async def test_lock_and_device_posts_need_csrf(client, login, path):
    login(client, "csrf@example.com")
    assert client.post(path, data={}).status_code == 403

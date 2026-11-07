"""Two-step sign-in, end to end: setup with a QR code for Microsoft
Authenticator (or any TOTP app), recovery codes, the code step after every
sign-in, remembered devices, turning it off, and unlocking the app lock."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from urllib.parse import unquote

from sqlalchemy import select

from reddysec.store.models import AuditLog, MfaStateRow, RecoveryCodeRow, TrustedDeviceRow, UserRow
from reddysec.web.auth import hash_password

KEY_RE = re.compile(r'<code class="manual-key"[^>]*>([^<]+)</code>')
CODES_RE = re.compile(r"<li><code>([a-z2-9]{5}-[a-z2-9]{5})</code></li>")
PASSWORD = "a long enough password"


async def _user(db, email: str) -> UserRow:
    async with db.session() as s:
        return (await s.execute(select(UserRow).where(UserRow.login_email == email))).scalar_one()


async def _rows(db, model, **where):
    async with db.session() as s:
        stmt = select(model)
        for k, v in where.items():
            stmt = stmt.where(getattr(model, k) == v)
        return list((await s.execute(stmt)).scalars())


async def _time_passes(db, user_id: str) -> None:
    """Pretend a few minutes went by: the last accepted code is long past."""
    async with db.session() as s:
        (await s.get(MfaStateRow, user_id)).last_step = 0


def _password_sign_in(client, csrf_of, email: str, **extra):
    return client.post(
        "/auth/login", data={"email": email, "password": PASSWORD, "csrf_token": csrf_of(client, "/login"), **extra}
    )


def _set_up(client, csrf_of, totp_code) -> tuple[str, list[str]]:
    """Settings → Two-step sign-in, the way a person does it."""
    page = client.get("/settings/security").text
    key = KEY_RE.search(page).group(1).replace(" ", "")
    done = client.post(
        "/settings/security/totp/enable", data={"code": totp_code(key), "csrf_token": csrf_of(client, "/settings/security")}
    )
    assert done.status_code == 200
    return key, CODES_RE.findall(done.text)


async def test_setup_page_has_qr_key_and_microsoft_authenticator_steps(client, login):
    login(client, "setup@example.com")
    page = client.get("/settings/security").text
    section = page.split('id="two-step"')[1].split("</section>")[0]
    assert '<svg class="qr"' in section and '<path class="qr-fg" d="M' in section
    assert 'href="otpauth://totp/Secureddy:setup%40example.com?secret=' in section and "issuer=Secureddy" in section
    key = KEY_RE.search(section).group(1)
    assert re.fullmatch(r"([A-Z2-7]{4} )*[A-Z2-7]{1,4}", key)  # groups of four
    assert f'data-copy="{key.replace(" ", "")}"' in section
    assert "Microsoft Authenticator" in section and "Other account (Google, Facebook, etc.)" in section
    assert "Scan QR code" in section and "Google Authenticator" in section and "Authy" in section
    assert 'href="#two-step">Two-step sign-in</a>' in page


async def test_enable_shows_ten_recovery_codes_once_and_stores_hashes(client, db, login, csrf_of, totp_code):
    login(client, "codes@example.com")
    key, codes = _set_up(client, csrf_of, totp_code)
    assert len(codes) == 10 and len(set(codes)) == 10
    user = await _user(db, "codes@example.com")
    rows = await _rows(db, RecoveryCodeRow, user_id=user.id)
    assert len(rows) == 10 and all(r.code_hash.startswith("$argon2id$") for r in rows)
    assert not any(c in r.code_hash for c in codes for r in rows)
    # Downloadable as a .txt without the server keeping them.
    again = client.post(
        "/settings/security/totp/enable", data={"code": "123456", "csrf_token": csrf_of(client, "/settings/security")}
    )
    assert again.status_code == 303  # nothing pending any more: no second page of codes
    page = client.get("/settings/security").text
    assert "10 of 10 left" in page and not CODES_RE.search(page)
    state = (await _rows(db, MfaStateRow, user_id=user.id))[0]
    assert state.last_step > 0  # the setup code cannot be replayed at sign-in


async def test_recovery_page_download_and_no_store(client, login, csrf_of, totp_code):
    login(client, "dl@example.com")
    key = KEY_RE.search(client.get("/settings/security").text).group(1).replace(" ", "")
    done = client.post(
        "/settings/security/totp/enable", data={"code": totp_code(key), "csrf_token": csrf_of(client, "/settings/security")}
    )
    assert done.headers["cache-control"] == "no-store, private"
    href = re.search(r'href="(data:text/plain;charset=utf-8,[^"]+)" download="secureddy-recovery-codes.txt"', done.text)
    text = unquote(href.group(1).split(",", 1)[1])
    assert "Secureddy recovery codes" in text and "dl@example.com" in text
    assert all(c in text for c in CODES_RE.findall(done.text))


async def test_every_sign_in_method_needs_the_code(client, db, seed, login, csrf_of, totp_code, pass_mfa, oauth):
    user = await seed.user("client@gmail.com", password_hash=hash_password(PASSWORD))
    login(client, "client@gmail.com")
    key, _codes = _set_up(client, csrf_of, totp_code)
    client.post("/auth/logout", data={"csrf_token": csrf_of(client, "/settings/security")})

    # Developer sign-in
    login(client, "client@gmail.com")
    assert client.get("/").status_code == 303 and client.get("/").headers["location"].startswith("/login")
    assert "Enter your code" in client.get("/auth/mfa").text
    pass_mfa(client, key, steps=1)
    assert client.get("/").status_code == 200
    client.post("/auth/logout", data={"csrf_token": csrf_of(client, "/")})

    # Password
    r = _password_sign_in(client, csrf_of, "client@gmail.com")
    assert r.headers["location"] == "/auth/mfa"
    assert client.get("/").status_code == 303

    # Google, while the password sign-in is still waiting: the newest sign-in wins.
    start = client.get("/auth/google/start?next=/messages")
    assert start.status_code == 303
    cb = client.get(f"/auth/google/callback?state={oauth.started[-1].state}&code=good-code")
    assert cb.status_code == 303 and cb.headers["location"] == "/auth/mfa"
    assert "Google" in client.get("/auth/mfa").text
    assert client.get("/").status_code == 303
    await _time_passes(db, user.id)
    done = pass_mfa(client, key, steps=-1)  # a phone 30 s slow still works
    assert done.headers["location"] == "/messages"
    assert client.get("/").status_code == 200
    audit = [a.details for a in await _rows(db, AuditLog, action="mfa_passed")]
    assert {"method": "google", "with": "ok"} in audit and {"method": "dev", "with": "ok"} in audit
    sessions = [s.auth_method for s in await _sessions(db, user.id)]
    assert "google+2fa" in sessions


async def _sessions(db, user_id):
    from reddysec.store.models import UserSessionRow

    return await _rows(db, UserSessionRow, user_id=user_id)


async def test_same_code_cannot_be_used_twice(client, seed, login, csrf_of, enable_totp, totp_code, pass_mfa):
    user = await seed.user("replay@example.com")
    key = await enable_totp(user.id)
    login(client, "replay@example.com")
    pass_mfa(client, key)
    client.post("/auth/logout", data={"csrf_token": csrf_of(client, "/")})
    login(client, "replay@example.com")
    replay = client.post("/auth/mfa", data={"code": totp_code(key), "csrf_token": csrf_of(client, "/auth/mfa")})
    assert replay.status_code == 401 and "already used" in replay.text
    old = client.post("/auth/mfa", data={"code": totp_code(key, -1), "csrf_token": csrf_of(client, "/auth/mfa")})
    assert old.status_code == 401 and "already used" in old.text
    too_old = client.post("/auth/mfa", data={"code": totp_code(key, -3), "csrf_token": csrf_of(client, "/auth/mfa")})
    assert too_old.status_code == 401 and "did not match" in too_old.text
    pass_mfa(client, key, steps=1)
    assert client.get("/").status_code == 200


async def test_recovery_code_signs_in_once(client, db, login, csrf_of, totp_code):
    login(client, "lost@example.com")
    _key, codes = _set_up(client, csrf_of, totp_code)
    client.post("/auth/logout", data={"csrf_token": csrf_of(client, "/settings/security")})
    login(client, "lost@example.com")
    used = client.post("/auth/mfa", data={"code": codes[0].upper(), "csrf_token": csrf_of(client, "/auth/mfa")})
    assert used.status_code == 303
    assert "You used a recovery code. 9 left." in client.get("/").text
    client.post("/auth/logout", data={"csrf_token": csrf_of(client, "/")})
    login(client, "lost@example.com")
    again = client.post("/auth/mfa", data={"code": codes[0], "csrf_token": csrf_of(client, "/auth/mfa")})
    assert again.status_code == 401 and client.get("/").status_code == 303
    user = await _user(db, "lost@example.com")
    assert len([r for r in await _rows(db, RecoveryCodeRow, user_id=user.id) if r.used_at is None]) == 9


async def test_five_wrong_codes_pause_sign_in(client, db, seed, login, csrf_of, enable_totp, totp_code):
    user = await seed.user("brute@example.com")
    key = await enable_totp(user.id)
    login(client, "brute@example.com")
    token = csrf_of(client, "/auth/mfa")
    statuses = [client.post("/auth/mfa", data={"code": "000000", "csrf_token": token}).status_code for _ in range(5)]
    assert statuses == [401, 401, 401, 401, 429]
    right = client.post("/auth/mfa", data={"code": totp_code(key), "csrf_token": token})
    assert right.status_code == 429 and "Too many wrong codes" in right.text
    # The pause is per person: a new device gets no fresh tries.
    async with db.session() as s:
        state = await s.get(MfaStateRow, user.id)
        state.locked_until = datetime.now(UTC) - timedelta(seconds=1)
    assert client.post("/auth/mfa", data={"code": totp_code(key), "csrf_token": token}).status_code == 303
    assert len(await _rows(db, AuditLog, action="mfa_failed")) == 6


async def test_remember_this_device_for_30_days(app, client, db, seed, login, csrf_of, enable_totp, pass_mfa):
    from starlette.testclient import TestClient

    user = await seed.user("phone@example.com")
    key = await enable_totp(user.id)
    login(client, "phone@example.com")
    r = pass_mfa(client, key, remember=True)
    cookie = r.headers["set-cookie"]
    assert "rs_mfa_dev=" in cookie and "Max-Age=2592000" in cookie and "HttpOnly" in cookie
    (device,) = await _rows(db, TrustedDeviceRow, user_id=user.id)
    assert device.session_id and device.id not in cookie  # only the hash is stored
    client.post("/auth/logout", data={"csrf_token": csrf_of(client, "/")})
    login(client, "phone@example.com")
    assert client.get("/").status_code == 200  # remembered: no code this time
    assert any(s.auth_method == "dev+trusted" for s in await _sessions(db, user.id))
    assert "1 device skip the code" in client.get("/settings/security").text

    with TestClient(app, follow_redirects=False) as other:  # another browser is not remembered
        login(other, "phone@example.com")
        assert other.get("/").status_code == 303

    client.post("/settings/security/totp/forget-devices", data={"csrf_token": csrf_of(client, "/settings/security")})
    assert await _rows(db, TrustedDeviceRow, user_id=user.id) == []
    client.post("/auth/logout", data={"csrf_token": csrf_of(client, "/")})
    login(client, "phone@example.com")
    assert client.get("/").status_code == 303  # asked again


async def test_signing_out_everywhere_forgets_remembered_devices(client, db, seed, login, csrf_of, enable_totp, pass_mfa):
    user = await seed.user("all@example.com")
    key = await enable_totp(user.id)
    login(client, "all@example.com")
    pass_mfa(client, key, remember=True)
    client.post("/settings/devices/sign-out-everywhere", data={"csrf_token": csrf_of(client, "/settings/security")})
    assert await _rows(db, TrustedDeviceRow, user_id=user.id) == []


async def test_signing_out_one_device_forgets_it(app, client, db, seed, login, csrf_of, enable_totp, pass_mfa):
    from starlette.testclient import TestClient

    user = await seed.user("one@example.com")
    key = await enable_totp(user.id)
    login(client, "one@example.com")
    pass_mfa(client, key)
    with TestClient(app, follow_redirects=False) as laptop:
        login(laptop, "one@example.com")
        pass_mfa(laptop, key, steps=1, remember=True)
        (device,) = await _rows(db, TrustedDeviceRow, user_id=user.id)
        page = client.get("/settings/security").text
        handles = re.findall(r'action="/settings/devices/(dev_[^/]+)/sign-out"', page)
        from reddysec.store.models import UserSessionRow

        async with db.session() as s:
            row = await s.get(UserSessionRow, device.session_id)
        assert row.handle in handles
        client.post(f"/settings/devices/{row.handle}/sign-out", data={"csrf_token": csrf_of(client, "/settings/security")})
    assert await _rows(db, TrustedDeviceRow, user_id=user.id) == []


async def test_turn_off_needs_a_code_and_clears_everything(client, db, seed, login, csrf_of, enable_totp, totp_code, pass_mfa):
    user = await seed.user("off2@example.com")
    login(client, "off2@example.com")
    key, codes = _set_up(client, csrf_of, totp_code)
    client.post("/settings/security/totp/forget-devices", data={"csrf_token": csrf_of(client, "/settings/security")})
    client.post("/auth/logout", data={"csrf_token": csrf_of(client, "/settings/security")})
    login(client, "off2@example.com")
    pass_mfa(client, key, steps=1, remember=True)
    token = csrf_of(client, "/settings/security")
    refused = client.post("/settings/security/totp/disable", data={"code": "", "csrf_token": token})
    assert refused.status_code == 303 and (await _user(db, "off2@example.com")).totp_secret_enc
    # A recovery code also proves it is them (the phone may be the thing that is lost).
    off = client.post("/settings/security/totp/disable", data={"code": codes[1], "csrf_token": token})
    assert 'rs_mfa_dev=""' in off.headers["set-cookie"] or "rs_mfa_dev=;" in off.headers["set-cookie"]
    assert (await _user(db, "off2@example.com")).totp_secret_enc is None
    assert await _rows(db, RecoveryCodeRow, user_id=user.id) == []
    assert await _rows(db, TrustedDeviceRow, user_id=user.id) == []
    assert await _rows(db, MfaStateRow, user_id=user.id) == []
    client.post("/auth/logout", data={"csrf_token": csrf_of(client, "/settings/security")})
    login(client, "off2@example.com")
    assert client.get("/").status_code == 200  # no code any more


async def test_new_recovery_codes_replace_the_old_ones(client, db, login, csrf_of, totp_code):
    login(client, "renew@example.com")
    key, old = _set_up(client, csrf_of, totp_code)
    token = csrf_of(client, "/settings/security")
    wrong = client.post("/settings/security/totp/recovery", data={"code": "000000", "csrf_token": token})
    assert wrong.status_code == 303 and "did not match" in client.get("/settings/security").text
    fresh = client.post("/settings/security/totp/recovery", data={"code": totp_code(key, 1), "csrf_token": token})
    assert fresh.status_code == 200 and "Your new recovery codes" in fresh.text
    new = CODES_RE.findall(fresh.text)
    assert len(new) == 10 and not set(new) & set(old)
    client.post("/auth/logout", data={"csrf_token": csrf_of(client, "/settings/security")})
    login(client, "renew@example.com")
    assert client.post("/auth/mfa", data={"code": old[0], "csrf_token": csrf_of(client, "/auth/mfa")}).status_code == 401
    assert client.post("/auth/mfa", data={"code": new[0], "csrf_token": csrf_of(client, "/auth/mfa")}).status_code == 303


async def test_settings_routes_without_two_step_are_harmless(client, login, csrf_of):
    login(client, "plain@example.com")
    token = csrf_of(client, "/settings/security")
    for path in ("/settings/security/totp/recovery", "/settings/security/totp/disable"):
        r = client.post(path, data={"code": "123456", "csrf_token": token})
        assert r.status_code == 303 and r.headers["location"] == "/settings/security#two-step"


async def test_pending_sign_in_expires_and_can_be_cancelled(client, seed, login, csrf_of, enable_totp, totp_code,
                                                            monkeypatch):
    from reddysec.web import mfa

    user = await seed.user("wait@example.com")
    key = await enable_totp(user.id)
    login(client, "wait@example.com")
    token = csrf_of(client, "/auth/mfa")
    cancel = client.post("/auth/mfa/cancel", data={"csrf_token": token})
    assert cancel.headers["location"] == "/login"
    assert client.get("/auth/mfa").headers["location"] == "/login"
    login(client, "wait@example.com")
    token = csrf_of(client, "/auth/mfa")
    monkeypatch.setattr(mfa, "_clock", lambda: 9_999_999_999.0)  # ten minutes are long gone
    late = client.post("/auth/mfa", data={"code": totp_code(key), "csrf_token": token})
    assert late.status_code == 303 and late.headers["location"] == "/login"


async def test_unlock_the_app_lock_with_the_authenticator(client, db, seed, login, csrf_of, enable_totp, totp_code,
                                                          pass_mfa):
    user = await seed.user("locky@example.com")
    key = await enable_totp(user.id)
    login(client, "locky@example.com")
    pass_mfa(client, key)
    token = csrf_of(client, "/settings/security")
    client.post("/settings/lock", data={"csrf_token": token, "kind": "pin", "secret": "482913", "confirm": "482913",
                                        "timeout": "5m"})
    client.post("/lock/now", data={"csrf_token": csrf_of(client, "/settings/security")})
    page = client.get("/lock")
    assert "Use your authenticator app" in page.text and 'action="/lock/totp"' in page.text
    token = csrf_of(client, "/lock")
    replay = client.post("/lock/totp", data={"code": totp_code(key), "csrf_token": token, "next": "/messages"})
    assert replay.status_code == 401 and "already used" in replay.text
    ok = client.post("/lock/totp", data={"code": totp_code(key, 1), "csrf_token": token, "next": "/messages"})
    assert ok.status_code == 303 and ok.headers["location"] == "/messages"
    assert client.get("/messages").status_code == 200
    assert client.post("/lock/totp", data={"code": "1", "csrf_token": token}).status_code == 303  # not locked
    unlocks = [a.details for a in await _rows(db, AuditLog, action="app_unlocked")]
    assert {"method": "authenticator"} in unlocks


async def test_lock_page_without_two_step_has_no_code_option(client, login, csrf_of):
    login(client, "nocode@example.com")
    client.post("/settings/lock", data={"csrf_token": csrf_of(client, "/settings/security"), "kind": "pin",
                                        "secret": "482913", "confirm": "482913", "timeout": "5m"})
    client.post("/lock/now", data={"csrf_token": csrf_of(client, "/settings/security")})
    page = client.get("/lock").text
    assert "Use your authenticator app" not in page
    r = client.post("/lock/totp", data={"code": "123456", "csrf_token": csrf_of(client, "/lock")})
    assert r.status_code == 400 and "not on" in r.text


async def test_lock_code_attempts_are_rate_limited(client, seed, login, csrf_of, enable_totp, totp_code, pass_mfa):
    user = await seed.user("lockrate@example.com")
    key = await enable_totp(user.id)
    login(client, "lockrate@example.com")
    pass_mfa(client, key)
    client.post("/settings/lock", data={"csrf_token": csrf_of(client, "/settings/security"), "kind": "pin",
                                        "secret": "482913", "confirm": "482913", "timeout": "5m"})
    client.post("/lock/now", data={"csrf_token": csrf_of(client, "/settings/security")})
    token = csrf_of(client, "/lock")
    codes = [client.post("/lock/totp", data={"code": "000000", "csrf_token": token}).status_code for _ in range(5)]
    assert codes[-1] == 429
    assert client.post("/lock/totp", data={"code": totp_code(key, 1), "csrf_token": token}).status_code == 429
    # The PIN still works.
    assert client.post("/lock", data={"secret": "482913", "csrf_token": token}).status_code == 303

"""Account security settings: TOTP enrolment and local password."""

from __future__ import annotations

import re

import pyotp
from sqlalchemy import select

from reddysec.core.crypto import TokenCipher
from reddysec.store.models import AuditLog, UserRow

KEY_RE = re.compile(r'<code class="manual-key">([^<]+)</code>')


def _cipher(settings) -> TokenCipher:
    return TokenCipher.from_settings(
        settings.token_kek.get_secret_value(), settings.secret_key.get_secret_value()
    )


async def _user(db, email):
    async with db.session() as s:
        return (await s.execute(select(UserRow).where(UserRow.login_email == email))).scalar_one()


async def _actions(db):
    async with db.session() as s:
        return [a.action for a in (await s.execute(select(AuditLog).order_by(AuditLog.at))).scalars()]


async def test_totp_enrolment_then_login_with_code(client, db, settings, login, csrf_of):
    login(client, "secure@example.com")
    page = client.get("/settings/security")
    assert page.status_code == 200 and "Off" in page.text and "Not set" in page.text
    key = KEY_RE.search(page.text).group(1).replace(" ", "")
    assert "otpauth://totp/Secureddy:secure%40example.com" in page.text
    # The pending key is stable across reloads until confirmed.
    assert KEY_RE.search(client.get("/settings/security").text).group(1).replace(" ", "") == key

    token = csrf_of(client, "/settings/security")
    wrong = client.post("/settings/security/totp/enable", data={"code": "000000", "csrf_token": token})
    assert wrong.status_code == 303
    assert "did not match" in client.get("/settings/security").text
    assert (await _user(db, "secure@example.com")).totp_secret_enc is None

    good = client.post(
        "/settings/security/totp/enable", data={"code": pyotp.TOTP(key).now(), "csrf_token": token}
    )
    assert good.status_code == 303
    user = await _user(db, "secure@example.com")
    assert user.totp_secret_enc and _cipher(settings).decrypt(user.totp_secret_enc, aad=user.id) == key
    page = client.get("/settings/security")
    assert "2-step sign-in is on" in page.text and ">On<" in page.text and "manual-key" not in page.text

    # Set a password, sign out, and sign back in with password + code.
    client.post(
        "/settings/security/password",
        data={
            "password": "a reasonably long passphrase",
            "confirm": "a reasonably long passphrase",
            "csrf_token": token,
        },
    )
    assert "Your password is set" in client.get("/settings/security").text
    client.post("/auth/logout", data={"csrf_token": token})
    login_token = csrf_of(client, "/login")
    step1 = client.post(
        "/auth/login",
        data={
            "email": "secure@example.com",
            "password": "a reasonably long passphrase",
            "csrf_token": login_token,
        },
    )
    assert step1.status_code == 200 and 'name="code"' in step1.text
    step2 = client.post("/auth/login", data={"code": pyotp.TOTP(key).now(), "csrf_token": login_token})
    assert step2.status_code == 303 and client.get("/").status_code == 200
    assert "totp_enabled" in await _actions(db) and "password_set" in await _actions(db)


async def test_totp_disable_requires_current_code(client, db, settings, seed, login, csrf_of):
    secret = pyotp.random_base32()
    user = await seed.user("off@example.com")
    async with db.session() as s:
        (await s.get(UserRow, user.id)).totp_secret_enc = _cipher(settings).encrypt(secret, aad=user.id)
    login(client, "off@example.com")
    token = csrf_of(client, "/settings/security")
    client.post("/settings/security/totp/disable", data={"code": "123456", "csrf_token": token})
    assert (await _user(db, "off@example.com")).totp_secret_enc is not None
    assert "stays on" in client.get("/settings/security").text
    client.post(
        "/settings/security/totp/disable", data={"code": pyotp.TOTP(secret).now(), "csrf_token": token}
    )
    assert (await _user(db, "off@example.com")).totp_secret_enc is None
    assert "2-step sign-in is off" in client.get("/settings/security").text
    # Disabling twice is a harmless no-op.
    assert (
        client.post("/settings/security/totp/disable", data={"code": "1", "csrf_token": token}).status_code
        == 303
    )
    assert "totp_disabled" in await _actions(db)


async def test_password_validation(client, db, login, csrf_of):
    login(client, "pw@example.com")
    token = csrf_of(client, "/settings/security")
    client.post(
        "/settings/security/password", data={"password": "short", "confirm": "short", "csrf_token": token}
    )
    assert "at least 12 characters" in client.get("/settings/security").text
    client.post(
        "/settings/security/password",
        data={"password": "long enough passphrase", "confirm": "different one", "csrf_token": token},
    )
    assert "did not match" in client.get("/settings/security").text
    assert (await _user(db, "pw@example.com")).password_hash is None

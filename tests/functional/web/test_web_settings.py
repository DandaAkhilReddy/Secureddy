"""Account security settings: TOTP enrolment and local password."""

from __future__ import annotations

import re

from sqlalchemy import select

from reddysec.core.crypto import TokenCipher
from reddysec.store.models import AuditLog, UserRow

KEY_RE = re.compile(r'<code class="manual-key"[^>]*>([^<]+)</code>')


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


async def test_totp_enrolment_then_login_with_code(client, db, settings, login, csrf_of, totp_code, pass_mfa):
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

    good = client.post("/settings/security/totp/enable", data={"code": totp_code(key), "csrf_token": token})
    assert good.status_code == 200 and "Recovery codes" in good.text and "Two-step sign-in is on" in good.text
    user = await _user(db, "secure@example.com")
    assert user.totp_secret_enc and _cipher(settings).decrypt(user.totp_secret_enc, aad=user.id) == key
    page = client.get("/settings/security")
    assert "Every sign-in, with Google" in page.text and ">On<" in page.text and "manual-key" not in page.text

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
    assert step1.status_code == 303 and step1.headers["location"] == "/auth/mfa"
    pass_mfa(client, key, steps=1)  # the code used to turn it on cannot be used again
    assert client.get("/").status_code == 200
    assert "totp_enabled" in await _actions(db) and "password_set" in await _actions(db)


async def test_totp_disable_requires_current_code(client, db, seed, login, csrf_of, enable_totp, totp_code, pass_mfa):
    user = await seed.user("off@example.com")
    secret = await enable_totp(user.id)
    login(client, "off@example.com")
    pass_mfa(client, secret)
    token = csrf_of(client, "/settings/security")
    client.post("/settings/security/totp/disable", data={"code": "123456", "csrf_token": token})
    assert (await _user(db, "off@example.com")).totp_secret_enc is not None
    assert "stays on" in client.get("/settings/security").text
    # The code used to sign in moments ago is refused: each code works once.
    client.post("/settings/security/totp/disable", data={"code": totp_code(secret), "csrf_token": token})
    assert (await _user(db, "off@example.com")).totp_secret_enc is not None
    assert "already used" in client.get("/settings/security").text
    client.post("/settings/security/totp/disable", data={"code": totp_code(secret, 1), "csrf_token": token})
    assert (await _user(db, "off@example.com")).totp_secret_enc is None
    assert "Two-step sign-in is off" in client.get("/settings/security").text
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

"""Sign-in flows: Google, password (+TOTP), developer login, logout, limits."""

from __future__ import annotations

import json
from datetime import datetime

import pyotp
from sqlalchemy import select
from starlette.testclient import TestClient

from reddysec.core.crypto import TokenCipher
from reddysec.store.models import AuditLog, MailboxRow, MailboxSecret, UserRow
from reddysec.web.app import create_app
from reddysec.web.auth import hash_password


def _cipher(settings) -> TokenCipher:
    return TokenCipher.from_settings(
        settings.token_kek.get_secret_value(), settings.secret_key.get_secret_value()
    )


async def _one(db, model, **where):
    async with db.session() as s:
        stmt = select(model)
        for key, value in where.items():
            stmt = stmt.where(getattr(model, key) == value)
        return (await s.execute(stmt)).scalars().first()


async def _all(db, model, **where):
    async with db.session() as s:
        stmt = select(model)
        for key, value in where.items():
            stmt = stmt.where(getattr(model, key) == value)
        return list((await s.execute(stmt)).scalars())


# --------------------------------------------------------------------------
# Login page and developer sign-in
# --------------------------------------------------------------------------


async def test_login_page_renders_all_three_ways_in(client):
    response = client.get("/login")
    assert response.status_code == 200
    assert "Sign in with Google" in response.text
    assert 'action="/auth/login"' in response.text
    assert "Developer sign-in" in response.text
    assert "rs_session" in response.headers.get("set-cookie", "")  # anonymous session carries the CSRF token


async def test_anonymous_html_request_redirects_to_login_with_next(client):
    response = client.get("/mailboxes?x=1")
    assert response.status_code == 303
    assert response.headers["location"] == "/login?next=/mailboxes?x=1"


async def test_dev_login_creates_user_and_session(client, db, login):
    login(client, "new.person@example.com", name="New Person")
    user = await _one(db, UserRow, login_email="new.person@example.com")
    assert user is not None and user.display_name == "New Person" and user.role == "principal"
    home = client.get("/")
    assert home.status_code == 200
    assert "Welcome back, New." in home.text
    entries = await _all(db, AuditLog, action="login")
    assert entries and entries[0].details == {"method": "dev"} and entries[0].actor_id == user.id


async def test_dev_login_rotates_session_cookie(client, login):
    before = client.get("/login").cookies.get("rs_session")
    login(client, "rotate@example.com")
    after = client.cookies.get("rs_session")
    assert before and after and before != after


async def test_login_page_redirects_when_already_signed_in(client, login):
    login(client, "already@example.com")
    response = client.get("/login?next=/audit")
    assert response.status_code == 303 and response.headers["location"] == "/audit"


async def test_dev_login_rejects_bad_role_and_bad_email(client, csrf_of):
    token = csrf_of(client)
    assert (
        client.post(
            "/auth/dev-login", data={"email": "a@b.c", "role": "root", "csrf_token": token}
        ).status_code
        == 400
    )
    bad = client.post("/auth/dev-login", data={"email": "not-an-email", "csrf_token": token})
    assert bad.status_code == 400 and "Please enter an email address" in bad.text


async def test_dev_login_is_404_when_disabled(settings, db, oauth, csrf_of):
    settings = settings.model_copy(update={"dev_login_enabled": False})
    app = create_app(settings, db=db, oauth=oauth)
    with TestClient(app, follow_redirects=False) as c:
        page = c.get("/login")
        assert page.status_code == 200 and "Developer sign-in" not in page.text
        assert c.get("/auth/dev-login").status_code == 404
        token = csrf_of(c)
        assert c.post("/auth/dev-login", data={"email": "x@y.z", "csrf_token": token}).status_code == 404


async def test_dev_login_is_forced_off_in_prod(db, settings):
    prod = settings.model_copy(update={"env": "prod", "dev_login_enabled": True})
    app = create_app(prod, db=db)
    assert app.state.dev_login_enabled is False


# --------------------------------------------------------------------------
# Google
# --------------------------------------------------------------------------


async def test_google_start_stores_state_and_redirects_to_provider(client, oauth):
    response = client.get("/auth/google/start?next=/mailboxes")
    assert response.status_code == 303
    start = oauth.started[0]
    assert response.headers["location"] == start.url
    assert "accounts.google.example" in start.url and "rt=/mailboxes" in start.url


async def test_google_start_404_without_provider(settings, db):
    app = create_app(settings, db=db, oauth=None)
    with TestClient(app, follow_redirects=False) as c:
        page = c.get("/login")
        assert "Sign in with Google" not in page.text
        assert c.get("/auth/google/start").status_code == 404


async def test_google_callback_happy_path_creates_user_mailbox_and_secret(client, oauth, db, settings):
    client.get("/auth/google/start?next=/mailboxes")
    state = oauth.started[0].state
    response = client.get(f"/auth/google/callback?state={state}&code=good-code")
    assert response.status_code == 303 and response.headers["location"] == "/mailboxes"
    assert oauth.finished == [(state, "good-code", "verifier-1")]

    user = await _one(db, UserRow, google_sub="google-sub-1")
    assert user is not None and user.login_email == "client@gmail.com" and user.display_name == "Avery Client"
    mailbox = await _one(db, MailboxRow, user_id=user.id)
    assert mailbox is not None
    assert (mailbox.provider, mailbox.mode, mailbox.status, mailbox.labels, mailbox.policy) == (
        "gmail",
        "scan",
        "active",
        {},
        {},
    )
    secret = await _one(db, MailboxSecret, mailbox_id=mailbox.id)
    assert secret is not None and secret.kind == "google_oauth" and secret.key_id == "dev"
    payload = json.loads(_cipher(settings).decrypt(secret.ciphertext, aad=mailbox.id))
    assert payload["refresh_token"] == "refresh-abc"
    assert payload["access_token"] == "access-xyz"
    assert payload["scopes"][-1].endswith("gmail.modify")
    assert datetime.fromisoformat(payload["expires_at"]).tzinfo is not None

    actions = {e.action for e in await _all(db, AuditLog)}
    assert {"login", "mailbox_connected"} <= actions
    home = client.get("/")
    assert home.status_code == 200 and "Welcome back, Avery." in home.text
    assert "Your Gmail is connected" in home.text


async def test_google_callback_rejects_unverified_email(settings, db, fake_oauth_cls):
    oauth = fake_oauth_cls(claims={"sub": "s2", "email": "unverified@gmail.com", "email_verified": False})
    app = create_app(settings, db=db, oauth=oauth)
    with TestClient(app, follow_redirects=False) as c:
        c.get("/auth/google/start")
        response = c.get(f"/auth/google/callback?state={oauth.started[0].state}&code=good-code")
        assert response.status_code == 403
        assert "could not confirm your email address" in response.text
    assert await _one(db, UserRow, login_email="unverified@gmail.com") is None
    assert c.get("/").status_code == 303  # still anonymous


async def test_google_callback_rejects_state_mismatch(client, oauth, db):
    client.get("/auth/google/start")
    response = client.get("/auth/google/callback?state=forged-state&code=good-code")
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert oauth.finished == []
    assert await _all(db, UserRow) == []
    page = client.get("/login")
    assert "was not valid" in page.text


async def test_google_callback_without_pending_flow_or_with_error(client, oauth):
    response = client.get("/auth/google/callback?state=x&code=y")
    assert response.status_code == 303 and response.headers["location"] == "/login"
    client.get("/auth/google/start")
    response = client.get(f"/auth/google/callback?state={oauth.started[0].state}&error=access_denied")
    assert response.status_code == 303 and oauth.finished == []
    assert "did not complete" in client.get("/login").text


async def test_google_callback_provider_failure_is_retryable(client, oauth, db):
    oauth.fail_with = RuntimeError("token endpoint down")
    client.get("/auth/google/start")
    response = client.get(f"/auth/google/callback?state={oauth.started[0].state}&code=good-code")
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert await _all(db, UserRow) == []


async def test_google_reconnect_keeps_refresh_token_when_google_omits_it(client, oauth, db, settings):
    client.get("/auth/google/start")
    client.get(f"/auth/google/callback?state={oauth.started[0].state}&code=good-code")
    # Second consent: Google returns no refresh token.
    oauth.refresh_token = None
    client.get("/auth/google/start")
    client.get(f"/auth/google/callback?state={oauth.started[1].state}&code=good-code")
    mailboxes = await _all(db, MailboxRow)
    assert len(mailboxes) == 1
    secret = await _one(db, MailboxSecret, mailbox_id=mailboxes[0].id)
    payload = json.loads(_cipher(settings).decrypt(secret.ciphertext, aad=mailboxes[0].id))
    assert payload["refresh_token"] == "refresh-abc"
    assert len(await _all(db, UserRow)) == 1


async def test_google_callback_links_existing_email_account(client, oauth, db, seed):
    existing = await seed.user("client@gmail.com", name="Pre Provisioned")
    client.get("/auth/google/start")
    client.get(f"/auth/google/callback?state={oauth.started[0].state}&code=good-code")
    user = await _one(db, UserRow, id=existing.id)
    assert user.google_sub == "google-sub-1" and user.display_name == "Pre Provisioned"


async def test_google_callback_refuses_disabled_account(client, oauth, db, seed):
    await seed.user("client@gmail.com", disabled=True)
    client.get("/auth/google/start")
    response = client.get(f"/auth/google/callback?state={oauth.started[0].state}&code=good-code")
    assert response.status_code == 403 and "account is closed" in response.text


# --------------------------------------------------------------------------
# Password and TOTP
# --------------------------------------------------------------------------


async def test_password_login_good_and_bad(client, seed, db, csrf_of):
    await seed.user("pw@example.com", password_hash=hash_password("correct horse battery"))
    token = csrf_of(client)
    bad = client.post(
        "/auth/login", data={"email": "pw@example.com", "password": "wrong", "csrf_token": token}
    )
    assert bad.status_code == 401 and "did not match" in bad.text
    unknown = client.post(
        "/auth/login", data={"email": "nobody@example.com", "password": "x", "csrf_token": token}
    )
    assert unknown.status_code == 401
    empty = client.post("/auth/login", data={"email": "pw@example.com", "csrf_token": token})
    assert empty.status_code == 401
    good = client.post(
        "/auth/login",
        data={
            "email": "PW@example.com",
            "password": "correct horse battery",
            "next": "/audit",
            "csrf_token": token,
        },
    )
    assert good.status_code == 303 and good.headers["location"] == "/audit"
    assert client.get("/").status_code == 200
    entries = await _all(db, AuditLog, action="login")
    assert entries[0].details == {"method": "password"}


async def test_password_login_with_totp_second_step(client, seed, settings, csrf_of):
    secret = pyotp.random_base32()
    user = await seed.user("totp@example.com", password_hash=hash_password("a long enough password"))
    async with seed.db.session() as s:
        row = await s.get(UserRow, user.id)
        row.totp_secret_enc = _cipher(settings).encrypt(secret, aad=user.id)
    token = csrf_of(client)
    step1 = client.post(
        "/auth/login",
        data={"email": "totp@example.com", "password": "a long enough password", "csrf_token": token},
    )
    assert step1.status_code == 200 and 'name="code"' in step1.text and "authenticator app" in step1.text
    wrong = client.post("/auth/login", data={"code": "000000", "csrf_token": token})
    assert wrong.status_code == 401
    good = client.post("/auth/login", data={"code": pyotp.TOTP(secret).now(), "csrf_token": token})
    assert good.status_code == 303 and good.headers["location"] == "/"
    assert client.get("/").status_code == 200


async def test_totp_code_alone_without_recent_password_is_refused(client, seed, csrf_of):
    await seed.user("solo@example.com", password_hash=hash_password("a long enough password"))
    token = csrf_of(client)
    response = client.post("/auth/login", data={"code": "123456", "csrf_token": token})
    assert response.status_code == 401


async def test_password_and_code_in_one_step(client, seed, settings, csrf_of):
    secret = pyotp.random_base32()
    user = await seed.user("onestep@example.com", password_hash=hash_password("a long enough password"))
    async with seed.db.session() as s:
        (await s.get(UserRow, user.id)).totp_secret_enc = _cipher(settings).encrypt(secret, aad=user.id)
    token = csrf_of(client)
    wrong = client.post(
        "/auth/login",
        data={
            "email": "onestep@example.com",
            "password": "a long enough password",
            "code": "111111",
            "csrf_token": token,
        },
    )
    assert wrong.status_code == 401
    # A wrong code still counts as a passed password step: retry with the code alone.
    retry = client.post("/auth/login", data={"code": pyotp.TOTP(secret).now(), "csrf_token": token})
    assert retry.status_code == 303
    client.post("/auth/logout", data={"csrf_token": csrf_of(client, "/")})
    good = client.post(
        "/auth/login",
        data={
            "email": "onestep@example.com",
            "password": "a long enough password",
            "code": pyotp.TOTP(secret).now(),
            "csrf_token": csrf_of(client, "/login"),
        },
    )
    assert good.status_code == 303


async def test_disabled_account_cannot_sign_in_and_is_logged_out(client, seed, db, login, csrf_of):
    user = await seed.user("gone@example.com", password_hash=hash_password("a long enough password"))
    login(client, "gone@example.com")
    assert client.get("/").status_code == 200
    async with db.session() as s:
        (await s.get(UserRow, user.id)).disabled = True
    assert client.get("/").status_code == 303
    token = csrf_of(client)
    response = client.post(
        "/auth/login",
        data={"email": "gone@example.com", "password": "a long enough password", "csrf_token": token},
    )
    assert response.status_code == 401


async def test_auth_routes_are_rate_limited(client, csrf_of):
    token = csrf_of(client)
    statuses = []
    for _ in range(25):
        r = client.post("/auth/login", data={"email": "x@y.z", "password": "nope", "csrf_token": token})
        statuses.append(r.status_code)
    assert 429 in statuses
    assert statuses[-1] == 429
    limited = client.post("/auth/login", data={"email": "x@y.z", "password": "nope", "csrf_token": token})
    assert limited.headers.get("retry-after") and "Too many attempts" in limited.text
    assert limited.headers.get("content-security-policy")  # headers even on the fast path


async def test_logout_clears_session_and_audits(client, db, login, csrf_of):
    login(client, "bye@example.com")
    token = csrf_of(client, "/")
    response = client.post("/auth/logout", data={"csrf_token": token})
    assert response.status_code == 303 and response.headers["location"] == "/login"
    assert client.get("/").status_code == 303
    assert "You are signed out" in client.get("/login").text
    assert await _all(db, AuditLog, action="logout")


async def test_logout_when_anonymous_is_harmless(client, csrf_of):
    token = csrf_of(client)
    assert client.post("/auth/logout", data={"csrf_token": token}).status_code == 303


async def test_open_redirects_are_neutralised(client, oauth):
    page = client.get("/login?next=//evil.example/steal")
    assert 'value="/"' in page.text and "evil.example" not in page.text
    client.get("/auth/google/start?next=https://evil.example")
    assert "rt=/" in oauth.started[0].url and "evil" not in oauth.started[0].url


async def test_api_requires_session_with_json_401(client):
    response = client.get("/api/me")
    assert response.status_code == 401 and response.json() == {"error": "sign_in_required"}

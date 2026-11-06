"""Edge cases: integrator hooks, defensive branches and failure fallbacks."""

from __future__ import annotations

import pyotp
from fastapi import Depends
from sqlalchemy import delete, select
from starlette.testclient import TestClient

from reddysec.core.crypto import TokenCipher
from reddysec.store.models import AuditLog, UserRow
from reddysec.web.app import create_app
from reddysec.web.auth import get_principal_id, hash_password


def _cipher(settings) -> TokenCipher:
    return TokenCipher.from_settings(
        settings.token_kek.get_secret_value(), settings.secret_key.get_secret_value()
    )


async def test_get_principal_id_dependency_for_the_reading_room(settings, db, login):
    """The integrator passes ``get_principal_id`` to ``make_room_router``; it
    must yield the signed-in account id and redirect anonymous visitors."""
    app = create_app(settings, db=db)

    @app.get("/whoami")
    async def whoami(principal_id: str = Depends(get_principal_id)) -> dict:
        return {"principal_id": principal_id}

    with TestClient(app, follow_redirects=False) as c:
        assert c.get("/whoami").status_code == 303
        login(c, "room.user@example.com")
        async with db.session() as s:
            user = (await s.execute(select(UserRow))).scalar_one()
        assert c.get("/whoami").json() == {"principal_id": user.id}


async def test_totp_second_step_fails_if_totp_was_removed_meanwhile(client, seed, db, settings, csrf_of):
    secret = pyotp.random_base32()
    user = await seed.user("race@example.com", password_hash=hash_password("a long enough password"))
    async with db.session() as s:
        (await s.get(UserRow, user.id)).totp_secret_enc = _cipher(settings).encrypt(secret, aad=user.id)
    token = csrf_of(client)
    step1 = client.post(
        "/auth/login",
        data={"email": "race@example.com", "password": "a long enough password", "csrf_token": token},
    )
    assert step1.status_code == 200
    async with db.session() as s:
        (await s.get(UserRow, user.id)).totp_secret_enc = None
    step2 = client.post("/auth/login", data={"code": pyotp.TOTP(secret).now(), "csrf_token": token})
    assert step2.status_code == 401


async def test_logout_with_vanished_account(client, db, login, csrf_of):
    login(client, "vanish@example.com")
    token = csrf_of(client, "/")
    async with db.session() as s:
        await s.execute(delete(AuditLog))
        await s.execute(delete(UserRow))
    response = client.post("/auth/logout", data={"csrf_token": token})
    assert response.status_code == 303 and client.get("/").status_code == 303


async def test_dev_login_page_get(client):
    page = client.get("/auth/dev-login?next=/audit")
    assert page.status_code == 200 and 'value="/audit"' in page.text


async def test_resume_when_already_active_records_nothing(client, seed, db, login, csrf_of):
    user = await seed.user("active@example.com")
    mailbox = await seed.mailbox(user)
    login(client, "active@example.com")
    token = csrf_of(client, "/mailboxes")
    assert client.post(f"/mailboxes/{mailbox.id}/resume", data={"csrf_token": token}).status_code == 303
    async with db.session() as s:
        actions = [
            a.action
            for a in (await s.execute(select(AuditLog).where(AuditLog.mailbox_id == mailbox.id))).scalars()
        ]
    assert actions == []


async def test_readyz_reports_template_failure(client, app):
    original = app.state.templates.env.get_template

    def broken(name):
        raise RuntimeError("templates missing")

    app.state.templates.env.get_template = broken
    try:
        response = client.get("/readyz")
    finally:
        app.state.templates.env.get_template = original
    assert response.status_code == 503 and response.json()["templates"] == "error"


async def test_error_page_falls_back_to_plain_text_if_rendering_fails(client, app):
    templates = app.state.templates
    app.state.templates = None  # anything that makes render() blow up
    try:
        response = client.get("/no-such-page")
    finally:
        app.state.templates = templates
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/plain")
    assert "could not find" in response.text.lower() or "not found" in response.text.lower()


async def test_create_app_builds_google_provider_from_settings(settings, db):
    from pydantic import SecretStr

    from reddysec.mail.oauth_google import GoogleOAuth
    from reddysec.web.auth import OAuthProvider

    configured = settings.model_copy(
        update={
            "google_client_id": "cid.apps.googleusercontent.com",
            "google_client_secret": SecretStr("shh"),
        }
    )
    app = create_app(configured, db=db)
    assert isinstance(app.state.oauth, GoogleOAuth) and isinstance(app.state.oauth, OAuthProvider)
    with TestClient(app, follow_redirects=False) as c:
        assert "Sign in with Google" in c.get("/login").text
        start = c.get("/auth/google/start?next=/mailboxes")
        assert start.status_code == 303
        assert start.headers["location"].startswith("https://accounts.google.com/o/oauth2/v2/auth?")
        assert "redirect_uri=" in start.headers["location"]
    assert create_app(settings, db=db).state.oauth is None  # no client id: button hidden

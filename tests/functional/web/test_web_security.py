"""CSRF enforcement, security headers, health endpoints and error pages."""

from __future__ import annotations

import re

from starlette.testclient import TestClient

from reddysec.store.db import Database
from reddysec.web.app import create_app
from reddysec.web.security import CONTENT_SECURITY_POLICY

# Routes that take a POST without a browser session, by design.
CSRF_EXEMPT_POSTS = {"/hooks/gmail/pubsub", "/room/start"}


async def test_post_without_csrf_token_is_forbidden(client):
    client.get("/login")  # establishes a session
    response = client.post("/auth/dev-login", data={"email": "x@y.z"})
    assert response.status_code == 403
    assert "form has expired" in response.text
    wrong = client.post("/auth/dev-login", data={"email": "x@y.z", "csrf_token": "not-the-token"})
    assert wrong.status_code == 403


async def test_every_post_route_requires_csrf(client, app, seed, login):
    """Behavioural guard: walk the OpenAPI document and post to every route
    without a token. Anything that is not 403 is a hole (or on the allowlist)."""
    user = await seed.user("walker@example.com", role="admin")
    login(client, user.login_email, role="admin")
    paths = app.openapi()["paths"]
    posts = [path for path, ops in paths.items() if "post" in ops]
    assert len(posts) >= 12, posts
    unprotected = []
    for path in posts:
        if path in CSRF_EXEMPT_POSTS:
            continue
        concrete = re.sub(r"\{[^}]+\}", "x", path)
        response = client.post(concrete, data={"note": "n"})
        if response.status_code != 403:
            unprotected.append((path, response.status_code))
    assert unprotected == []


async def test_security_headers_on_pages_and_errors(client):
    for path, expected in (("/login", 200), ("/does-not-exist", 404), ("/static/app.css", 200)):
        response = client.get(path)
        assert response.status_code == expected
        assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert "clipboard-write=()" in response.headers["permissions-policy"]
        assert "strict-transport-security" not in response.headers
    assert "frame-ancestors 'none'" in CONTENT_SECURITY_POLICY
    assert "script-src 'self'" in CONTENT_SECURITY_POLICY


async def test_prod_adds_hsts_and_secure_cookie(settings, db):
    prod = settings.model_copy(update={"env": "prod", "dev_login_enabled": False})
    app = create_app(prod, db=db)
    with TestClient(app, follow_redirects=False) as c:
        response = c.get("/login")
        assert response.status_code == 200
        assert response.headers["strict-transport-security"].startswith("max-age=")
        cookie = response.headers["set-cookie"]
        assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=Lax" in cookie
        assert c.get("/openapi.json").status_code == 404


async def test_session_cookie_attributes(client):
    cookie = client.get("/login").headers["set-cookie"]
    assert cookie.startswith("rs_session=")
    assert (
        "HttpOnly" in cookie
        and "SameSite=Lax" in cookie
        and "Max-Age=43200" in cookie
        and "Secure" not in cookie
    )


async def test_tampered_session_cookie_is_ignored(client, login):
    login(client, "tamper@example.com")
    value = client.cookies.get("rs_session")
    client.cookies.set("rs_session", value[:-3] + "abc")
    assert client.get("/").status_code == 303


async def test_healthz_and_readyz(client):
    assert client.get("/healthz").json() == {"status": "ok", "db": "ok"}
    ready = client.get("/readyz")
    assert ready.status_code == 200 and ready.json()["status"] == "ready"


async def test_healthz_reports_database_failure(settings, tmp_path):
    broken = Database(f"sqlite+aiosqlite:///{tmp_path}/missing-dir/nope/x.db")
    app = create_app(settings.model_copy(update={"env": "staging"}), db=broken)
    with TestClient(app, follow_redirects=False) as c:
        health = c.get("/healthz")
        assert health.status_code == 503 and health.json()["db"] == "error"
        ready = c.get("/readyz")
        assert ready.status_code == 503 and ready.json()["db"] == "error"


async def test_error_pages_are_html_for_browsers_and_json_for_api(client, login):
    login(client, "errors@example.com")
    missing = client.get("/messages/msg_nope")
    assert missing.status_code == 404 and "could not find" in missing.text and "<html" in missing.text
    api = client.get("/api/nope")
    assert api.status_code == 404 and api.json()["status"] == 404
    bad_query = client.get("/audit?page=0")
    assert bad_query.status_code == 400 and "missing or not valid" in bad_query.text
    bad_api = client.get("/api/messages?limit=0")
    assert bad_api.status_code == 422 and bad_api.json()["error"] == "invalid_request"
    accept_json = client.get("/messages/msg_nope", headers={"Accept": "application/json"})
    assert accept_json.status_code == 404 and accept_json.json()["status"] == 404


async def test_create_app_defaults_to_shared_database(settings, db):
    """Without ``db`` the app uses ``store.db.get_database()`` (the test fixture
    registered one) and owns its lifecycle."""
    app = create_app(settings)
    assert app.state.db is db
    with TestClient(app) as c:
        assert c.get("/healthz").status_code == 200

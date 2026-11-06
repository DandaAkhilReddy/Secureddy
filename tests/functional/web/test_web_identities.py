"""Sign in with Microsoft / Yahoo, "Connect another mailbox", and account-takeover rules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import select
from starlette.testclient import TestClient

from reddysec.core.ids import new_id
from reddysec.store.models import MailboxRow, MailboxSecret, UserIdentityRow, UserRow
from reddysec.web import queries
from reddysec.web.app import create_app

PERSONAL = "9188040d-6c67-4c5b-b112-36a304b66dad"
WORK = "72f988bf-86f1-41af-91ab-2d7cd011db47"


@dataclass
class Start:
    url: str
    state: str
    code_verifier: str


@dataclass
class Tokens:
    access_token: str
    refresh_token: str | None
    expires_at: datetime | None
    id_claims: dict[str, Any]
    scopes: list[str]


class FakeOidc:
    """Shape of MicrosoftOAuth / YahooOAuth: begin(link=...), link_of(state), finish."""

    def __init__(self, name: str, claims: dict[str, Any]) -> None:
        self.name = name
        self.claims = dict(claims)
        self.links: dict[str, str | None] = {}
        self.n = 0
        self.fail = False

    def begin(self, return_to: str = "/", *, link: str | None = None) -> Start:
        self.n += 1
        state = f"{self.name}-state-{self.n}"
        self.links[state] = link
        return Start(f"https://{self.name}.example/authorize?state={state}&r={return_to}", state, f"v{self.n}")

    def link_of(self, state: str) -> str | None:
        if state not in self.links:
            raise ValueError("bad state")
        return self.links[state]

    async def finish(self, state: str, code: str, verifier: str) -> Tokens:
        if self.fail or code != "good":
            raise RuntimeError("invalid_grant")
        return Tokens("at", "rt", datetime.now(UTC) + timedelta(hours=1), dict(self.claims), ["Mail.ReadWrite"])


def ms_claims(**kw: Any) -> dict[str, Any]:
    base = {"sub": "oid-1", "oid": "oid-1", "tid": PERSONAL, "email": "avery@outlook.com", "email_verified": False,
            "name": "Avery Lawson"}
    return {**base, **kw}


@pytest.fixture
def microsoft() -> FakeOidc:
    return FakeOidc("microsoft", ms_claims())


@pytest.fixture
def yahoo() -> FakeOidc:
    return FakeOidc("yahoo", {"sub": "ysub", "email": "avery.l@yahoo.com", "email_verified": True, "name": "Avery"})


@pytest.fixture
def tested() -> list[tuple]:
    return []


@pytest.fixture
def app(settings, db, oauth, artifact_store, microsoft, yahoo, tested):
    from reddysec.mail.base import AuthExpired, ConnectorError

    async def imap_tester(host: str, port: int, username: str, password: str) -> None:
        tested.append((host, port, username, password))
        if password == "wrongwrongwrongw":
            raise AuthExpired("no")
        if password == "unreachableaaaaa":
            raise ConnectorError("down")

    return create_app(settings, db=db, oauth=oauth, artifact_store=artifact_store, microsoft_oauth=microsoft,
                      yahoo_oauth=yahoo, imap_tester=imap_tester)


def _callback(client: TestClient, provider: str, start_response, code: str = "good"):
    assert start_response.status_code == 303, start_response.text
    state = parse_qs(urlsplit(start_response.headers["location"]).query)["state"][0]
    return client.get(f"/auth/{provider}/callback", params={"state": state, "code": code})


async def _users(db) -> list[UserRow]:
    async with db.session() as s:
        return list((await s.execute(select(UserRow))).scalars())


async def _identities(db) -> list[UserIdentityRow]:
    async with db.session() as s:
        return list((await s.execute(select(UserIdentityRow))).scalars())


async def _mailboxes(db) -> list[MailboxRow]:
    async with db.session() as s:
        return list((await s.execute(select(MailboxRow))).scalars())


# ------------------------------------------------------------------ login page


def test_login_page_shows_three_providers_and_collapses_password(client):
    page = client.get("/login").text
    for name in ("Google", "Microsoft", "Yahoo"):
        assert f"Sign in with {name}" in page
    assert "We never store your emails. Links open on our servers, not your phone." in page
    assert '<details class="signin-other">' in page and "Sign in with a password" in page
    assert page.index("Sign in with Microsoft") < page.index("Other ways to sign in")


def test_unconfigured_providers_are_hidden(settings, db, artifact_store):
    app = create_app(settings, db=db, oauth=None, artifact_store=artifact_store)
    with TestClient(app, follow_redirects=False) as c:
        page = c.get("/login").text
        assert "Sign in with Microsoft" not in page and "Sign in with Yahoo" not in page
        assert '<details class="signin-other" open>' in page  # nothing else to offer
        assert c.get("/auth/microsoft/start").status_code == 404
        assert c.get("/auth/yahoo/start").status_code == 404


# ------------------------------------------------------------------ Microsoft


async def test_microsoft_sign_in_creates_account_identity_and_mailbox(client, db):
    response = _callback(client, "microsoft", client.get("/auth/microsoft/start?next=/mailboxes"))
    assert response.status_code == 303 and response.headers["location"] == "/mailboxes"
    (user,) = await _users(db)
    assert user.login_email == "avery@outlook.com" and user.display_name == "Avery Lawson"
    (identity,) = await _identities(db)
    assert (identity.provider, identity.subject, identity.tenant, identity.email_verified) == (
        "microsoft", "oid-1", PERSONAL, False)
    (mailbox,) = await _mailboxes(db)
    assert (mailbox.provider, mailbox.address, mailbox.labels, mailbox.user_id) == (
        "microsoft", "avery@outlook.com", {}, user.id)
    async with db.session() as s:
        secret = await s.get(MailboxSecret, mailbox.id)
    assert secret.kind == "microsoft_oauth"
    page = client.get("/mailboxes").text
    assert "Welcome. Your Outlook mailbox avery@outlook.com is connected." in page
    assert "Outlook / Microsoft 365" in page
    # a second sign-in finds the same account and the same mailbox
    client.post("/auth/logout", data={"csrf_token": queries_csrf(client)})
    _callback(client, "microsoft", client.get("/auth/microsoft/start"))
    assert len(await _users(db)) == 1 and len(await _mailboxes(db)) == 1


def queries_csrf(client: TestClient) -> str:
    import re

    return re.search(r'name="csrf_token" value="([^"]+)"', client.get("/mailboxes").text).group(1)


async def test_unverified_microsoft_email_never_takes_over_an_account(client, seed, db):
    victim = await seed.user("avery@outlook.com", google_sub="g-victim")
    response = _callback(client, "microsoft", client.get("/auth/microsoft/start"))
    assert response.status_code == 409
    assert "Already have an account?" in response.text and "Sign in first, then connect this mailbox." in response.text
    assert client.get("/").status_code == 303  # not signed in
    assert await _identities(db) == [] and await _mailboxes(db) == []
    assert [u.id for u in await _users(db)] == [victim.id]


async def test_verified_work_account_links_by_email(client, seed, db, microsoft):
    owner = await seed.user("avery@contoso.com", google_sub="g-1")
    microsoft.claims = ms_claims(tid=WORK, email="avery@contoso.com", email_verified=True)
    assert _callback(client, "microsoft", client.get("/auth/microsoft/start")).status_code == 303
    (identity,) = await _identities(db)
    assert identity.user_id == owner.id


async def test_same_tenant_work_account_links_by_email(client, seed, db, microsoft):
    owner = await seed.user("avery@contoso.com")
    async with db.session() as s:
        s.add(UserIdentityRow(id=new_id("uid"), user_id=owner.id, provider="microsoft", subject="old-oid",
                              email="avery@contoso.com", email_verified=False, tenant=WORK))
    microsoft.claims = ms_claims(oid="new-oid", sub="new-oid", tid=WORK, email="avery@contoso.com")
    assert _callback(client, "microsoft", client.get("/auth/microsoft/start")).status_code == 303
    assert {i.subject: i.user_id for i in await _identities(db)} == {"old-oid": owner.id, "new-oid": owner.id}


async def test_pre_account_takeover_via_unverified_identity_is_blocked(client, db, oauth):
    # An attacker signs up first with an unverified Microsoft email equal to the client's Gmail ...
    _callback(client, "microsoft", client.get("/auth/microsoft/start"))
    client.cookies.clear()
    # ... the real owner then signs in with Google (verified email): no linking to the attacker's account.
    oauth.claims = {"sub": "g-real", "email": "avery@outlook.com", "email_verified": True, "name": "Real"}
    start = client.get("/auth/google/start")
    state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
    response = client.get("/auth/google/callback", params={"state": state, "code": "good-code"})
    assert response.status_code == 409 and "Already have an account?" in response.text
    assert [i.provider for i in await _identities(db)] == ["microsoft"]


async def test_google_sign_in_records_identity_and_keeps_legacy_column(client, db, oauth):
    start = client.get("/auth/google/start")
    state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
    client.get("/auth/google/callback", params={"state": state, "code": "good-code"})
    (user,) = await _users(db)
    (identity,) = await _identities(db)
    assert user.google_sub == identity.subject == "google-sub-1" and identity.email_verified
    # a legacy account (google_sub only) gets its identity row on next sign-in
    async with db.session() as s:
        await s.delete(await s.get(UserIdentityRow, identity.id))
    client.cookies.clear()
    start = client.get("/auth/google/start")
    state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
    client.get("/auth/google/callback", params={"state": state, "code": "good-code"})
    assert [i.user_id for i in await _identities(db)] == [user.id]


async def test_microsoft_without_email_and_failures(client, microsoft):
    microsoft.claims = ms_claims(email="")
    response = _callback(client, "microsoft", client.get("/auth/microsoft/start"))
    assert response.status_code == 400 and "could not read your email address" in response.text
    microsoft.fail = True
    response = _callback(client, "microsoft", client.get("/auth/microsoft/start"))
    assert response.headers["location"] == "/login"
    # a Google callback cannot finish a Microsoft flow
    start = client.get("/auth/microsoft/start")
    state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
    assert client.get("/auth/google/callback", params={"state": state, "code": "good"}).headers["location"] == "/login"
    assert client.get("/auth/microsoft/callback?error=access_denied").headers["location"] == "/login"


async def test_disabled_account_cannot_sign_in(client, db, microsoft, seed):
    user = await seed.user("avery@outlook.com", disabled=True)
    async with db.session() as s:
        s.add(UserIdentityRow(id=new_id("uid"), user_id=user.id, provider="microsoft", subject="oid-1",
                              email="avery@outlook.com", email_verified=False, tenant=PERSONAL))
    assert _callback(client, "microsoft", client.get("/auth/microsoft/start")).status_code == 403


# ------------------------------------------------------------------ link mode


async def test_connect_another_mailbox_links_to_the_signed_in_account(client, seed, login, csrf_of, db, microsoft):
    owner = await seed.user("avery@gmail.com", google_sub="g-1")
    login(client, "avery@gmail.com")
    microsoft.claims = ms_claims(email="avery.work@outlook.com")
    page = client.get("/mailboxes").text
    assert 'action="/auth/microsoft/link"' in page and 'action="/auth/google/link"' in page
    assert 'href="/mailboxes/connect-yahoo"' in page
    start = client.post("/auth/microsoft/link", data={"csrf_token": csrf_of(client, "/mailboxes"), "next": "/mailboxes"})
    response = _callback(client, "microsoft", start)
    assert response.headers["location"] == "/mailboxes"
    (mailbox,) = await _mailboxes(db)
    assert mailbox.user_id == owner.id and mailbox.address == "avery.work@outlook.com"
    (identity,) = await _identities(db)
    assert identity.user_id == owner.id
    assert len(await _users(db)) == 1  # no second account, no switch
    assert "avery.work@outlook.com is connected" in client.get("/mailboxes").text


async def test_link_requires_csrf_and_sign_in(client, csrf_of):
    assert client.post("/auth/microsoft/link", data={}).status_code == 403
    token = csrf_of(client, "/login")
    assert client.post("/auth/microsoft/link", data={"csrf_token": token}).status_code == 303  # to /login
    assert client.post("/auth/nope/link", data={"csrf_token": token}).status_code == 404


async def test_link_finished_in_another_session_is_refused(client, seed, login, csrf_of, db, microsoft):
    a = await seed.user("a@example.com")
    await seed.user("b@example.com")
    login(client, "a@example.com")
    start = client.post("/auth/microsoft/link", data={"csrf_token": csrf_of(client, "/mailboxes")})
    state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
    assert microsoft.links[state] == a.id
    client.cookies.clear()
    login(client, "b@example.com")  # someone else is signed in when the callback arrives
    response = client.get("/auth/microsoft/callback", params={"state": state, "code": "good"})
    assert response.headers["location"] == "/login"
    assert await _mailboxes(db) == []


async def test_link_with_tampered_state_link_is_refused(client, seed, login, csrf_of, microsoft, db):
    await seed.user("a@example.com")
    login(client, "a@example.com")
    start = client.post("/auth/microsoft/link", data={"csrf_token": csrf_of(client, "/mailboxes")})
    state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
    microsoft.links[state] = "usr_someone_else"
    assert _callback(client, "microsoft", start).headers["location"] == "/login"
    assert await _mailboxes(db) == []


async def test_link_identity_owned_by_someone_else(client, seed, login, csrf_of, db):
    other = await seed.user("other@example.com")
    async with db.session() as s:
        s.add(UserIdentityRow(id=new_id("uid"), user_id=other.id, provider="microsoft", subject="oid-1",
                              email="avery@outlook.com", email_verified=False, tenant=PERSONAL))
    await seed.user("me@example.com")
    login(client, "me@example.com")
    start = client.post("/auth/microsoft/link", data={"csrf_token": csrf_of(client, "/mailboxes")})
    response = _callback(client, "microsoft", start)
    assert response.status_code == 409 and "already connected" in response.text
    assert await _mailboxes(db) == []


async def test_google_link_mode_connects_gmail_without_switching(client, seed, login, csrf_of, db, oauth):
    me = await seed.user("me@example.com")
    login(client, "me@example.com")
    oauth.claims = {"sub": "g-2", "email": "second@gmail.com", "email_verified": True, "name": "X"}
    start = client.post("/auth/google/link", data={"csrf_token": csrf_of(client, "/mailboxes")})
    state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
    response = client.get("/auth/google/callback", params={"state": state, "code": "good-code"})
    assert response.headers["location"] == "/mailboxes"
    (mailbox,) = await _mailboxes(db)
    assert mailbox.user_id == me.id and mailbox.provider == "gmail" and mailbox.address == "second@gmail.com"
    assert "Gmail second@gmail.com is connected" in client.get("/mailboxes").text
    # linking the same Google account again is fine; a Google sub owned by another account is not
    async with db.session() as s:
        other = await queries.get_or_create_user(s, email="x@example.com")
        other[0].google_sub = "g-3"
    oauth.claims = {"sub": "g-3", "email": "third@gmail.com", "email_verified": True}
    start = client.post("/auth/google/link", data={"csrf_token": csrf_of(client, "/mailboxes")})
    state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
    assert client.get("/auth/google/callback", params={"state": state, "code": "good-code"}).status_code == 409


async def test_relinking_known_identity_is_idempotent(db, seed):
    me = await seed.user("me@example.com")
    async with db.session() as s:
        user = await s.get(UserRow, me.id)
        first = await queries.link_identity(s, user, provider="yahoo", subject="y1", email="a@yahoo.com",
                                            email_verified=True)
        again = await queries.link_identity(s, user, provider="yahoo", subject="y1", email="a@yahoo.com",
                                            email_verified=True)
        assert first.id == again.id
        with pytest.raises(queries.IdentityConflict):
            await queries.resolve_identity(s, provider="yahoo", subject="new", email="", email_verified=True)


# ------------------------------------------------------------------ Yahoo


async def test_yahoo_sign_in_goes_to_connect_step(client, db):
    response = _callback(client, "yahoo", client.get("/auth/yahoo/start"))
    assert response.headers["location"] == "/mailboxes/connect-yahoo?address=avery.l%40yahoo.com"
    page = client.get(response.headers["location"]).text
    assert "Connect your Yahoo Mail" in page and 'value="avery.l@yahoo.com"' in page
    assert "Generate app password" in page and "Test connection" in page
    (identity,) = await _identities(db)
    assert identity.provider == "yahoo" and identity.email_verified
    assert await _mailboxes(db) == []  # mail is connected on the next step


async def test_yahoo_link_mode_keeps_the_account(client, seed, login, csrf_of, db):
    me = await seed.user("me@example.com")
    login(client, "me@example.com")
    start = client.post("/auth/yahoo/link", data={"csrf_token": csrf_of(client, "/mailboxes")})
    response = _callback(client, "yahoo", start)
    assert response.headers["location"].startswith("/mailboxes/connect-yahoo")
    assert [i.user_id for i in await _identities(db)] == [me.id]


async def test_yahoo_conflicts(client, seed, db, yahoo):
    await seed.user("avery.l@yahoo.com", google_sub="g")
    yahoo.claims["email_verified"] = False
    assert _callback(client, "yahoo", client.get("/auth/yahoo/start")).status_code == 409
    yahoo.claims["email"] = ""
    assert _callback(client, "yahoo", client.get("/auth/yahoo/start")).status_code == 400


async def test_connect_yahoo_tests_then_saves(client, seed, login, csrf_of, db, tested):
    me = await seed.user("me@example.com")
    login(client, "me@example.com")
    token = csrf_of(client, "/mailboxes/connect-yahoo")
    bad = client.post("/mailboxes/connect-yahoo", data={"csrf_token": token, "address": "Me@Yahoo.com",
                                                        "app_password": "wron gwro ngwr ongw"})
    assert bad.status_code == 400 and "Yahoo did not accept that app password" in bad.text
    down = client.post("/mailboxes/connect-yahoo", data={"csrf_token": token, "address": "me@yahoo.com",
                                                         "app_password": "unre acha blea aaaa"})
    assert down.status_code == 502 and "could not reach Yahoo Mail" in down.text
    assert await _mailboxes(db) == []
    ok = client.post("/mailboxes/connect-yahoo", data={"csrf_token": token, "address": "me@yahoo.com",
                                                       "app_password": "abcd efgh ijkl mnop"})
    assert ok.status_code == 303 and ok.headers["location"] == "/mailboxes"
    assert tested[-1] == ("imap.mail.yahoo.com", 993, "me@yahoo.com", "abcdefghijklmnop")
    (mailbox,) = await _mailboxes(db)
    assert (mailbox.provider, mailbox.address, mailbox.user_id) == ("yahoo", "me@yahoo.com", me.id)
    assert "Yahoo accepted the app password" in client.get("/mailboxes").text
    again = client.post("/mailboxes/connect-yahoo", data={"csrf_token": token, "address": "me@yahoo.com",
                                                          "app_password": "abcdefghijklmnop"})
    assert again.status_code == 400 and "already connected" in again.text
    client.post("/mailboxes/connect-yahoo", data={"csrf_token": token, "address": "me@aol.com", "app_password": "x"})
    assert tested[-1][0] == "imap.aol.com"


async def test_connect_yahoo_validation(client, seed, login, csrf_of):
    await seed.user("me@yahoo.com")
    login(client, "me@yahoo.com")
    page = client.get("/mailboxes/connect-yahoo").text
    assert 'value="me@yahoo.com"' in page  # prefilled from the account
    token = csrf_of(client, "/mailboxes/connect-yahoo")
    assert client.post("/mailboxes/connect-yahoo", data={"csrf_token": token, "address": "nope",
                                                         "app_password": "x"}).status_code == 400
    assert client.post("/mailboxes/connect-yahoo", data={"csrf_token": token, "address": "a@yahoo.com",
                                                         "app_password": "  "}).status_code == 400


async def test_default_imap_tester_maps_errors(monkeypatch):
    from reddysec.mail.base import AuthExpired
    from reddysec.mail.imap import ImapConnector
    from reddysec.web.app import test_imap_login

    async def fake_check(self):
        assert (self.credentials.host, self.credentials.port) == ("imap.mail.yahoo.com", 993)
        raise AuthExpired("x")

    monkeypatch.setattr(ImapConnector, "check_login", fake_check)
    with pytest.raises(AuthExpired):
        await test_imap_login("imap.mail.yahoo.com", 993, "a@yahoo.com", "pw")


# ------------------------------------------------------------------ IMAP form detection


async def test_imap_form_uses_the_address_to_pick_the_provider(client, seed, login, csrf_of, db):
    await seed.user("me@example.com")
    login(client, "me@example.com")
    token = csrf_of(client, "/mailboxes/add-imap")
    client.post("/mailboxes/add-imap", data={"csrf_token": token, "provider": "icloud", "address": "me@ymail.com",
                                             "app_password": "pw"})
    (mailbox,) = await _mailboxes(db)
    assert mailbox.provider == "yahoo"
    page = client.get("/mailboxes/add-imap?address=me@icloud.com").text
    assert '<option value="icloud" data-host="imap.mail.me.com" data-port="993" selected>' in page
    assert 'id="provider-domains"' in page and "rocketmail.com" in page


async def test_outlook_addresses_are_offered_microsoft_sign_in(client, seed, login, csrf_of, db):
    await seed.user("me@example.com")
    login(client, "me@example.com")
    page = client.get("/mailboxes/add-imap?address=me@hotmail.com").text
    assert "Use Sign in with Microsoft instead" in page and 'action="/auth/microsoft/link"' in page
    token = csrf_of(client, "/mailboxes/add-imap")
    suggest = client.post("/mailboxes/add-imap", data={"csrf_token": token, "provider": "outlook",
                                                       "address": "me@live.com", "app_password": "pw"})
    assert suggest.status_code == 200 and "Use an app password anyway" in suggest.text
    assert await _mailboxes(db) == []
    client.post("/mailboxes/add-imap", data={"csrf_token": token, "provider": "outlook", "address": "me@live.com",
                                             "app_password": "pw", "use_imap": "1"})
    assert [m.provider for m in await _mailboxes(db)] == ["outlook"]


async def test_outlook_without_microsoft_configured_uses_imap(settings, db, artifact_store, seed, login, csrf_of):
    app = create_app(settings, db=db, oauth=None, artifact_store=artifact_store)
    await seed.user("me@example.com")
    with TestClient(app, follow_redirects=False) as c:
        login(c, "me@example.com")
        assert "Use Sign in with Microsoft instead" not in c.get("/mailboxes/add-imap?address=a@outlook.com").text
        page = c.get("/mailboxes").text
        assert 'href="/mailboxes/add-imap?provider=outlook"' in page and "/auth/google/link" not in page

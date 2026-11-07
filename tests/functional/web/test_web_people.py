"""Invite-only sign-up (max 5 people, free), the first admin, and the admin
People page. Runs the real app with the default ``signup_mode=invite_only``
and fake Google / Microsoft / Yahoo providers."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import select
from starlette.testclient import TestClient

from reddysec.core.ids import new_id
from reddysec.store import people
from reddysec.store.models import (
    AuditLog,
    InviteRow,
    MailboxRow,
    MailboxSecret,
    UserIdentityRow,
    UserRow,
    UserSessionRow,
)
from reddysec.web.app import create_app

from .test_web_identities import FakeOidc, ms_claims

CSRF = 'name="csrf_token" value="'
OWNER = "akhilreddydanda3@gmail.com"


def csrf(client: TestClient, path: str = "/login") -> str:
    page = client.get(path).text
    start = page.index(CSRF) + len(CSRF)
    return page[start: page.index('"', start)]


def callback(client: TestClient, provider: str, code: str = "good-code"):
    start = client.get(f"/auth/{provider}/start")
    assert start.status_code == 303, start.text
    state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
    return client.get(f"/auth/{provider}/callback", params={"state": state, "code": code})


@pytest.fixture
def invite_settings(settings):
    return settings.model_copy(update={"signup_mode": "invite_only", "max_users": 5, "bootstrap_admin_email": OWNER})


@pytest.fixture
def microsoft():
    return FakeOidc("microsoft", ms_claims(email="friend@outlook.com", email_verified=True))


@pytest.fixture
def yahoo():
    return FakeOidc("yahoo", {"sub": "ysub", "email": "pal@yahoo.com", "email_verified": True, "name": "Pal"})


@pytest.fixture
def people_app(invite_settings, db, oauth, artifact_store, microsoft, yahoo, connectors):
    return create_app(invite_settings, db=db, oauth=oauth, artifact_store=artifact_store, microsoft_oauth=microsoft,
                      yahoo_oauth=yahoo, connector_factory=connectors)


@pytest.fixture
def pclient(people_app):
    with TestClient(people_app, follow_redirects=False) as c:
        yield c


async def users(db) -> list[UserRow]:
    async with db.session() as s:
        return list((await s.execute(select(UserRow).order_by(UserRow.created_at))).scalars())


async def invite(db, email: str) -> InviteRow:
    async with db.session() as s:
        row, _ = await people.create_invite(s, email, invited_by=None)
    return row


async def audits(db, action: str) -> list[AuditLog]:
    async with db.session() as s:
        return list((await s.execute(select(AuditLog).where(AuditLog.action == action))).scalars())


# ----------------------------------------------------------------- sign-up rules


class TestInviteOnlySignIn:
    async def test_google_without_invite_gets_the_calm_page_and_nothing_is_stored(self, pclient, db, oauth):
        oauth.claims["email"] = "stranger@gmail.com"
        response = callback(pclient, "google")
        assert response.status_code == 403
        assert "Secureddy is invite-only right now" in response.text
        assert "Ask the person who invited you to add stranger@gmail.com." in response.text
        assert await users(db) == []
        async with db.session() as s:
            assert (await s.execute(select(MailboxSecret))).first() is None  # tokens thrown away
        assert pclient.get("/").status_code == 303  # not signed in

    async def test_google_with_invite_creates_the_account_and_uses_the_invite(self, pclient, db, oauth):
        oauth.claims["email"] = "Client@Gmail.com"
        row = await invite(db, "client@gmail.com")
        response = callback(pclient, "google")
        assert response.status_code == 303 and response.headers["location"] == "/"
        (user,) = await users(db)
        assert user.login_email == "client@gmail.com" and user.role == "principal"
        async with db.session() as s:
            used = await s.get(InviteRow, row.id)
            mailbox = (await s.execute(select(MailboxRow))).scalar_one()
        assert used.accepted_by == user.id and used.accepted_at is not None
        assert mailbox.address == "client@gmail.com"
        # Second time: an existing account, no invite needed any more.
        pclient.post("/auth/logout", data={"csrf_token": csrf(pclient, "/")})
        assert callback(pclient, "google").status_code == 303
        assert len(await users(db)) == 1

    async def test_revoked_invite_is_refused(self, pclient, db, oauth):
        oauth.claims["email"] = "client@gmail.com"
        row = await invite(db, "client@gmail.com")
        async with db.session() as s:
            await people.revoke_invite(s, await s.get(InviteRow, row.id))
        assert callback(pclient, "google").status_code == 403

    async def test_microsoft_needs_a_verified_email(self, pclient, db, microsoft):
        await invite(db, "friend@outlook.com")
        microsoft.claims["email_verified"] = False
        refused = callback(pclient, "microsoft", "good")
        assert refused.status_code == 403 and "friend@outlook.com" in refused.text
        microsoft.claims["email_verified"] = True
        assert callback(pclient, "microsoft", "good").status_code == 303
        async with db.session() as s:
            ident = (await s.execute(select(UserIdentityRow))).scalar_one()
        assert ident.provider == "microsoft" and ident.email == "friend@outlook.com"

    async def test_yahoo_with_invite_goes_to_connect_step(self, pclient, db):
        refused = callback(pclient, "yahoo", "good")
        assert refused.status_code == 403
        await invite(db, "pal@yahoo.com")
        ok = callback(pclient, "yahoo", "good")
        assert ok.status_code == 303 and ok.headers["location"].startswith("/mailboxes/connect-yahoo")

    async def test_full_house_refuses_new_people_but_never_existing_ones(self, pclient, db, oauth, seed):
        existing = [await seed.user(f"member{i}@example.com") for i in range(5)]
        await invite(db, "sixth@gmail.com")
        oauth.claims.update(email="sixth@gmail.com", sub="sub-sixth")
        full = callback(pclient, "google")
        assert full.status_code == 403 and "Every place is taken" in full.text
        # An existing member signs in fine even though 5 of 5 places are used.
        oauth.claims.update(email=existing[0].login_email, sub="sub-member0")
        assert callback(pclient, "google").status_code == 303
        # A disabled account frees its place.
        async with db.session() as s:
            (await s.get(UserRow, existing[4].id)).disabled = True
        pclient.post("/auth/logout", data={"csrf_token": csrf(pclient, "/")})
        oauth.claims.update(email="sixth@gmail.com", sub="sub-sixth")
        assert callback(pclient, "google").status_code == 303

    async def test_password_sign_in_never_creates_accounts(self, pclient, db):
        token = csrf(pclient)
        response = pclient.post("/auth/login", data={"email": "nobody@x.com", "password": "x" * 14, "csrf_token": token})
        assert response.status_code == 401 and await users(db) == []

    async def test_open_mode_lets_anyone_in_up_to_the_cap(self, invite_settings, db, oauth, artifact_store, seed):
        settings = invite_settings.model_copy(update={"signup_mode": "open", "max_users": 2})
        app = create_app(settings, db=db, oauth=oauth, artifact_store=artifact_store)
        with TestClient(app, follow_redirects=False) as c:
            oauth.claims.update(email="first@gmail.com", sub="s1")
            assert callback(c, "google").status_code == 303
            await seed.user("other@example.com")
            c.post("/auth/logout", data={"csrf_token": csrf(c, "/")})
            oauth.claims.update(email="third@gmail.com", sub="s3")
            assert callback(c, "google").status_code == 403


class TestBootstrapAdmin:
    async def test_owner_signs_in_first_and_becomes_admin(self, pclient, db, oauth):
        oauth.claims.update(email=OWNER, sub="owner-sub")
        response = callback(pclient, "google")  # no invite needed for the bootstrap email
        assert response.status_code == 303
        (owner,) = await users(db)
        assert owner.role == "admin"
        assert len(await audits(db, "admin_bootstrapped")) == 1
        page = pclient.get("/").text
        assert 'href="/admin/users"' in page

    async def test_nobody_else_becomes_admin(self, pclient, db, oauth):
        await invite(db, "friend@gmail.com")
        oauth.claims.update(email="friend@gmail.com", sub="f")
        callback(pclient, "google")
        (friend,) = await users(db)
        assert friend.role == "principal"
        assert 'href="/admin/users"' not in pclient.get("/").text

    async def test_existing_owner_account_is_promoted_at_sign_in(self, pclient, db, oauth, seed):
        await seed.user(OWNER)
        oauth.claims.update(email=OWNER, sub="owner-sub")
        assert callback(pclient, "google").status_code == 303
        (owner,) = await users(db)
        assert owner.role == "admin"

    async def test_unverified_owner_lookalike_is_not_promoted(self, invite_settings, db, oauth, artifact_store, microsoft):
        """In open mode an unverified Microsoft email could create the owner's
        address first; it must not get admin."""
        settings = invite_settings.model_copy(update={"signup_mode": "open"})
        microsoft.claims.update(email=OWNER, email_verified=False, oid="attacker", sub="attacker")
        app = create_app(settings, db=db, oauth=oauth, artifact_store=artifact_store, microsoft_oauth=microsoft)
        with TestClient(app, follow_redirects=False) as c:
            assert callback(c, "microsoft", "good").status_code == 303
        (user,) = await users(db)
        assert user.role == "principal"


# ----------------------------------------------------------------- admin page


@pytest.fixture
async def admin(seed):
    return await seed.user("boss@example.com", role="admin", name="Boss")


def as_admin(client: TestClient, login, admin_row: UserRow) -> str:
    login(client, admin_row.login_email, role="admin")
    return csrf(client, "/admin/users")


class TestAdminPage:
    @pytest.mark.parametrize("role", ["principal", "concierge", "family"])
    async def test_only_admins(self, client, login, role):
        login(client, f"{role}@example.com", role=role)
        response = client.get("/admin/users")
        assert response.status_code == 403
        assert client.post("/admin/invites", data={"email": "x@y.co", "csrf_token": csrf(client, "/")}).status_code == 403

    async def test_signed_out_goes_to_sign_in(self, client):
        response = client.get("/admin/users")
        assert response.status_code == 303 and response.headers["location"].startswith("/login")

    async def test_lists_people_with_methods_mailboxes_and_places(self, pclient, login, admin, seed, db):
        client = pclient
        member = await seed.user("member@example.com", name="Member", password_hash="x")
        await seed.mailbox(member, address="member@gmail.com")
        async with db.session() as s:
            s.add(UserIdentityRow(id=new_id("uid"), user_id=member.id, provider="google", subject="g", email="member@gmail.com",
                                  email_verified=True))
        await invite(db, "waiting@gmail.com")
        as_admin(client, login, admin)
        page = client.get("/admin/users").text
        assert '<span class="num">2</span> of 5 places used' in page and "invite-only" in page
        assert "member@example.com" in page and "Google, Password" in page and "member@gmail.com" in page
        assert "waiting@gmail.com" in page and "Withdraw" in page
        assert "boss@example.com" in page and "(you)" in page
        assert "No payments" in page

    async def test_invite_flow_and_audit(self, client, login, admin, db):
        token = as_admin(client, login, admin)
        bad = client.post("/admin/invites", data={"email": "not-an-email", "csrf_token": token})
        assert bad.status_code == 303 and "Please enter one email address" in client.get("/admin/users").text
        ok = client.post("/admin/invites", data={"email": " New@Gmail.com ", "csrf_token": token})
        assert ok.status_code == 303
        page = client.get("/admin/users").text
        assert "new@gmail.com is invited" in page
        again = client.post("/admin/invites", data={"email": "new@gmail.com", "csrf_token": token})
        assert again.status_code == 303 and "already invited" in client.get("/admin/users").text
        existing = client.post("/admin/invites", data={"email": "boss@example.com", "csrf_token": token})
        assert existing.status_code == 303 and "already has an account" in client.get("/admin/users").text
        (row,) = await audits(db, "invite_created")
        assert row.actor_id == admin.id and row.details == {"email": "new@gmail.com"}
        async with db.session() as s:
            inv = (await s.execute(select(InviteRow))).scalar_one()
        assert client.post(f"/admin/invites/{inv.id}/revoke", data={"csrf_token": token}).status_code == 303
        assert "withdrawn" in client.get("/admin/users").text
        assert client.post(f"/admin/invites/{inv.id}/revoke", data={"csrf_token": token}).status_code == 303
        assert "already used or withdrawn" in client.get("/admin/users").text
        assert len(await audits(db, "invite_revoked")) == 1
        assert client.post("/admin/invites/inv_missing/revoke", data={"csrf_token": token}).status_code == 404

    async def test_cannot_invite_when_full(self, pclient, login, admin, seed):
        client = pclient
        for i in range(4):
            await seed.user(f"m{i}@example.com")
        token = as_admin(client, login, admin)
        page = client.get("/admin/users").text
        assert "All 5 places are used" in page and 'action="/admin/invites"' not in page
        client.post("/admin/invites", data={"email": "x@gmail.com", "csrf_token": token})
        assert "Turn an account off first" in client.get("/admin/users").text

    async def test_disable_signs_out_and_pauses_then_enable_resumes(self, client, login, admin, seed, db, settings,
                                                                      artifact_store, oauth):
        member = await seed.user("member@example.com")
        active = await seed.mailbox(member, address="member@gmail.com")
        paused_by_them = await seed.mailbox(member, address="old@gmail.com", status="paused")
        member_app = create_app(settings, db=db, oauth=oauth, artifact_store=artifact_store)
        with TestClient(member_app, follow_redirects=False) as member_client:
            login(member_client, "member@example.com")
            assert member_client.get("/").status_code == 200

            token = as_admin(client, login, admin)
            assert client.post(f"/admin/users/{member.id}/disable", data={"csrf_token": token}).status_code == 303
            assert "Their devices are signed out" in client.get("/admin/users").text

            assert member_client.get("/").status_code == 303  # signed out at once
        async with db.session() as s:
            assert (await s.get(UserRow, member.id)).disabled
            sessions = (await s.execute(select(UserSessionRow).where(UserSessionRow.user_id == member.id))).scalars()
            assert all(row.revoked_at is not None for row in sessions)
            assert (await s.get(MailboxRow, active.id)).status == "paused"
        (row,) = await audits(db, "user_disabled")
        assert row.details["paused"] == [active.id] and row.details["email"] == "member@example.com"

        assert client.post(f"/admin/users/{member.id}/enable", data={"csrf_token": token}).status_code == 303
        async with db.session() as s:
            assert not (await s.get(UserRow, member.id)).disabled
            assert (await s.get(MailboxRow, active.id)).status == "active"
            assert (await s.get(MailboxRow, paused_by_them.id)).status == "paused"  # theirs stays paused
        assert len(await audits(db, "user_enabled")) == 1
        # Enabling an enabled account changes nothing.
        assert client.post(f"/admin/users/{member.id}/enable", data={"csrf_token": token}).status_code == 303
        assert len(await audits(db, "user_enabled")) == 1

    async def test_guard_rails(self, client, login, admin, seed, db):
        token = as_admin(client, login, admin)
        me = admin.id
        assert client.post(f"/admin/users/{me}/disable", data={"csrf_token": token}).status_code == 303
        assert "cannot turn off your own account" in client.get("/admin/users").text
        member = await seed.user("member@example.com")
        assert client.post(f"/admin/users/{me}/role", data={"role": "principal", "csrf_token": token}).status_code == 303
        assert "cannot change your own role" in client.get("/admin/users").text
        bad = client.post(f"/admin/users/{member.id}/role", data={"role": "family", "csrf_token": token})
        assert bad.status_code == 400
        assert client.post("/admin/users/usr_missing/disable", data={"csrf_token": token}).status_code == 404
        assert client.post("/admin/users/usr_missing/enable", data={"csrf_token": token}).status_code == 404
        assert client.post("/admin/users/usr_missing/role", data={"role": "admin", "csrf_token": token}).status_code == 404
        async with db.session() as s:
            assert not (await s.get(UserRow, me)).disabled

    async def test_role_changes_are_audited(self, client, login, admin, seed, db):
        member = await seed.user("member@example.com")
        token = as_admin(client, login, admin)
        assert client.post(f"/admin/users/{member.id}/role", data={"role": "admin", "csrf_token": token}).status_code == 303
        assert "member@example.com is now Admin" in client.get("/admin/users").text
        # Same role again: nothing to do, nothing audited.
        assert client.post(f"/admin/users/{member.id}/role", data={"role": "admin", "csrf_token": token}).status_code == 303
        assert client.post(f"/admin/users/{member.id}/role", data={"role": "concierge", "csrf_token": token}).status_code == 303
        rows = await audits(db, "role_changed")
        assert [(r.details["from"], r.details["to"]) for r in rows] == [("principal", "admin"), ("admin", "concierge")]
        assert all(r.actor_id == admin.id for r in rows)
        page = client.get("/audit").text
        assert "Changed what an account can do" in page and "member@example.com · Member to Admin" in page

    async def test_last_admin_guard(self, db, seed):
        """Defence in depth: the routes refuse to remove the last active admin
        (only reachable for one's own account, which is refused first)."""
        from reddysec.web.routes.admin import _is_last_admin

        boss = await seed.user("boss2@example.com", role="admin")
        async with db.session() as s:
            assert await _is_last_admin(s, await s.get(UserRow, boss.id))
        other = await seed.user("other@example.com", role="admin")
        async with db.session() as s:
            assert not await _is_last_admin(s, await s.get(UserRow, boss.id))
            assert not await _is_last_admin(s, await s.get(UserRow, other.id)) or False

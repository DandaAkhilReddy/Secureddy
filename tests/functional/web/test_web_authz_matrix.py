"""Authorisation across people, on every route that takes an id.

The routes are enumerated from the app itself (its OpenAPI document), so a
new route with a path parameter is covered automatically; a new *kind* of
parameter fails ``test_every_id_parameter_is_known`` until it is added to
:data:`OWNER_IDS`. A second signed-in person must get 404 (or 403 for staff
areas) for every one of them, and the owner's data must be unchanged.

Also here: no secret ever reaches a page or a log line, and the security
headers and CSP are on every kind of response.
"""

from __future__ import annotations

import logging
import re

import pytest
from sqlalchemy import select

from reddysec.core.ids import new_id
from reddysec.store import people
from reddysec.store.models import (
    AssistantConversationRow,
    MailboxRow,
    MessageRow,
    PasskeyRow,
    SenderFeedbackRow,
    UserIdentityRow,
    UserRow,
    UserSessionRow,
)
from reddysec.web.security import CONTENT_SECURITY_POLICY
from reddysec.web.sessions import create_session

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
# Path parameters that are not someone's data (the provider name of a sign-in).
NOT_OWNED = {"provider"}
# What each id parameter is, mapped to the owner's object in ``world``.
OWNER_IDS = {
    "message_id", "mailbox_id", "entry_id", "conversation_id", "passkey_id", "handle", "identity_id",
    "invite_id", "user_id", "ref", "index",
}


# The functional app mounts a stand-in Reading Room router; the real one checks
# the room's owner itself (tests/unit/chamber/test_readingroom_web.py,
# "wrong_principal" cases).
FAKE_ROUTERS = ("/room/",)


def id_routes(app) -> list[tuple[str, str]]:
    out = []
    for path, ops in app.openapi()["paths"].items():
        if "{" not in path or path.startswith(FAKE_ROUTERS):
            continue
        for method in ops:
            out.append((method.upper(), path))
    return sorted(out)


def params_of(path: str) -> list[str]:
    return [p.split(":")[0] for p in re.findall(r"\{([^}]+)\}", path)]


@pytest.fixture
async def world(seed, db, make_verdict):
    """Avery owns a mailbox, an email (with a screenshot), a sender entry, a
    chat, a passkey, a signed-in device and a sign-in identity."""
    owner = await seed.user("avery@example.com", name="Avery")
    mailbox = await seed.mailbox(owner, address="avery@gmail.com")
    verdict = make_verdict("malicious", urls=[{"url": "https://evil.example/x", "screenshot_ref": "shots/a.png"}])
    message = await seed.message(mailbox, verdict=verdict, subject="Owner's secret subject")
    async with db.session() as s:
        entry = SenderFeedbackRow(id=new_id("sfb"), mailbox_id=mailbox.id, scope="address", value="x@y.com",
                                  decision="trusted")
        conv = AssistantConversationRow(id=new_id("cnv"), user_id=owner.id, title="Avery's chat")
        passkey = PasskeyRow(id=new_id("pky"), user_id=owner.id, credential_id="cred", public_key="pk")
        ident = UserIdentityRow(id=new_id("uid"), user_id=owner.id, provider="google", subject="g-avery",
                                email="avery@gmail.com", email_verified=True)
        s.add_all([entry, conv, passkey, ident])
        invite, _ = await people.create_invite(s, "someone@gmail.com", invited_by=owner.id)
    _token, session_row = await create_session(db, owner.id, user_agent="Avery's phone")
    return {
        "owner": owner,
        "message_id": message.id,
        "mailbox_id": mailbox.id,
        "entry_id": entry.id,
        "conversation_id": conv.id,
        "passkey_id": passkey.id,
        "handle": session_row.handle,
        "identity_id": ident.id,
        "invite_id": invite.id,
        "user_id": owner.id,
        "ref": "shots/a.png",
        "index": "0",
        "provider": "google",
    }


async def snapshot(db, owner_id: str) -> dict:
    async with db.session() as s:
        return {
            "messages": [(m.id, m.state, m.level, m.quarantined)
                         for m in (await s.execute(select(MessageRow))).scalars()],
            "mailboxes": [(m.id, m.status, m.mode) for m in (await s.execute(select(MailboxRow))).scalars()],
            "entries": [e.id for e in (await s.execute(select(SenderFeedbackRow))).scalars()],
            "passkeys": [p.id for p in (await s.execute(select(PasskeyRow))).scalars()],
            "identities": [i.id for i in (await s.execute(select(UserIdentityRow))).scalars()],
            "sessions": [(r.handle, r.revoked_at is None) for r in (await s.execute(
                select(UserSessionRow).where(UserSessionRow.user_id == owner_id))).scalars()],
            "user": [(u.id, u.role, u.disabled) for u in (await s.execute(
                select(UserRow).where(UserRow.id == owner_id))).scalars()],
        }


def test_every_id_parameter_is_known(app):
    unknown = {p for _m, path in id_routes(app) for p in params_of(path)} - OWNER_IDS - NOT_OWNED
    assert unknown == set(), f"new id parameter(s) {unknown}: add them to OWNER_IDS and the world fixture"
    assert len(id_routes(app)) >= 30


async def test_second_person_gets_404_or_403_on_every_id_route(client, app, login, world, db):
    before = await snapshot(db, world["owner"].id)
    login(client, "intruder@example.com", name="Intruder")
    token = CSRF_RE.search(client.get("/").text).group(1)
    leaks: list[tuple[str, str, int]] = []
    checked = 0
    for method, path in id_routes(app):
        names = params_of(path)
        if not names or set(names) <= NOT_OWNED:
            continue
        concrete = path
        for name in names:
            concrete = re.sub(r"\{" + name + r"(:[^}]+)?\}", str(world[name]), concrete)
        if "{ref" in path:
            concrete += f"?m={world['message_id']}"
        if path.endswith("/image"):
            concrete += "?u=https%3A%2F%2Fimg.example%2Fa.png&s=sig"
        if method == "GET":
            response = client.get(concrete)
        else:
            data = {"csrf_token": token, "role": "admin", "mode": "hold", "level": "safe", "email": "x@y.co",
                    "reason_code": "other", "reason": "x", "feedback": "fine", "note": "n", "verdict": "fine",
                    "reply_id": "r1", "index": "0"}
            response = client.post(concrete, data=data)
        checked += 1
        if response.status_code not in (403, 404):
            leaks.append((method, path, response.status_code))
        assert "Owner's secret subject" not in response.text, (method, path)
    assert leaks == [], leaks
    assert checked >= 30
    assert await snapshot(db, world["owner"].id) == before


async def test_owner_reaches_their_own_report(client, login, world):
    """The matrix above is only meaningful if the owner gets through."""
    login(client, "avery@example.com")
    page = client.get(f"/messages/{world['message_id']}")
    assert page.status_code == 200 and "Owner&#39;s secret subject" in page.text


async def test_family_member_sees_principal_mail_but_not_strangers(client, login, world, seed, db):
    family = await seed.user("kid@example.com", role="family", principal_id=world["owner"].id)
    login(client, family.login_email, role="family")
    assert client.get(f"/messages/{world['message_id']}").status_code == 200
    stranger = await seed.user("other@example.com")
    other_mbx = await seed.mailbox(stranger, address="other@gmail.com")
    other_msg = await seed.message(other_mbx)
    assert client.get(f"/messages/{other_msg.id}").status_code == 404


async def test_secrets_never_reach_pages_or_logs(client, login, world, settings, caplog, db):
    """The flow cookie key, token key and stored ciphertext must never be
    printed: not in HTML, not in a log line."""
    from reddysec.core.crypto import TokenCipher
    from reddysec.store.models import MailboxSecret

    cipher = TokenCipher.from_settings(settings.token_kek.get_secret_value(), settings.secret_key.get_secret_value())
    ciphertext = cipher.encrypt('{"refresh_token": "rt-super-secret-123"}', aad=world["mailbox_id"])
    async with db.session() as s:
        s.add(MailboxSecret(mailbox_id=world["mailbox_id"], kind="google_oauth", ciphertext=ciphertext, key_id="k1"))
    caplog.set_level(logging.DEBUG)
    login(client, "avery@example.com")
    secret_key = settings.secret_key.get_secret_value()
    pages = [client.get(p).text for p in ("/", "/mailboxes", "/messages", f"/messages/{world['message_id']}",
                                           "/settings/security", "/audit", "/assistant", "/notifications")]
    for text in pages + [caplog.text]:
        assert secret_key not in text
        assert "rt-super-secret-123" not in text and ciphertext not in text
    assert "rt-super-secret-123" not in repr(settings) and secret_key not in repr(settings)


@pytest.mark.parametrize("path", ["/login", "/", "/admin/users", "/messages/msg_missing", "/healthz", "/static/app.css"])
async def test_headers_and_csp_on_every_kind_of_response(client, login, path):
    login(client, "header@example.com")
    response = client.get(path)
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "unsafe-inline" not in CONTENT_SECURITY_POLICY.split("script-src", 1)[1].split(";", 1)[0]

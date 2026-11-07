"""The web app's key flows against PostgreSQL, including the exact sequence
that left the owner with two Yahoo mailboxes in production:

Sign in with Yahoo -> connect with an app password -> (mailbox stuck) ->
Disconnect -> Sign in with Yahoo again -> connect again.

The app runs in TestClient's own event loop, so it gets its own ``Database``
with ``NullPool`` (no connection outlives a request's loop); the test reads
the results through a second ``Database``.
"""

from __future__ import annotations

import re

import pytest
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.pool import NullPool
from starlette.testclient import TestClient

from reddysec.config import Settings
from reddysec.store.db import Database
from reddysec.store.models import AuditLog, MailboxRow, MailboxSecret, MailboxTaskRow, UserIdentityRow
from reddysec.web.app import create_app
from tests.functional.web.test_web_identities import FakeOidc, _callback

pytestmark = pytest.mark.postgres

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
ADDRESS = "danda.akhil@yahoo.com"


def csrf(client: TestClient, path: str) -> str:
    match = CSRF_RE.search(client.get(path).text)
    assert match, path
    return match.group(1)


@pytest.fixture
def app(pg_url, tmp_path):
    settings = Settings(
        env="test",
        dev_login_enabled=True,
        artifacts_dir=str(tmp_path / "artifacts"),
        secret_key=SecretStr("postgres-functional-secret-key-long-enough"),
        token_kek=SecretStr(""),
    )
    yahoo = FakeOidc("yahoo", {"sub": "y" * 300, "email": ADDRESS, "email_verified": True, "name": "Akhil"})

    async def imap_tester(host: str, port: int, username: str, password: str) -> None:
        return None

    return create_app(
        settings, db=Database(pg_url, poolclass=NullPool), yahoo_oauth=yahoo, imap_tester=imap_tester
    )


async def rows(pg_url: str, model):
    db = Database(pg_url)
    try:
        async with db.session() as s:
            return list((await s.execute(select(model))).scalars())
    finally:
        await db.dispose()


async def test_yahoo_reconnect_flow_keeps_one_mailbox(app, pg_url):
    with TestClient(app, follow_redirects=False) as client:  # lifespan: create_all + migrations on Postgres
        signed_in = _callback(client, "yahoo", client.get("/auth/yahoo/start"))
        assert signed_in.headers["location"].startswith("/mailboxes/connect-yahoo")
        assert await rows(pg_url, MailboxRow) == []  # signing in never creates a mailbox

        def connect(password: str = "abcd efgh ijkl mnop"):
            token = csrf(client, "/mailboxes/connect-yahoo")
            return client.post(
                "/mailboxes/connect-yahoo", data={"csrf_token": token, "address": ADDRESS, "app_password": password}
            )

        assert connect().status_code == 303
        (first,) = await rows(pg_url, MailboxRow)
        again = connect()
        assert again.status_code == 400 and "already connected" in again.text
        token = csrf(client, "/mailboxes/add-imap")
        other_form = client.post(
            "/mailboxes/add-imap",
            data={"csrf_token": token, "provider": "yahoo", "address": ADDRESS.upper(), "app_password": "x"},
        )
        assert other_form.status_code == 400 and "already connected" in other_form.text

        token = csrf(client, "/mailboxes")
        assert client.post(f"/mailboxes/{first.id}/disconnect", data={"csrf_token": token}).status_code == 303
        assert await rows(pg_url, MailboxSecret) == []
        _callback(client, "yahoo", client.get("/auth/yahoo/start"))  # sign in again
        assert connect("ponm lkji hgfe dcba").status_code == 303

        (mailbox,) = await rows(pg_url, MailboxRow)
        assert mailbox.id == first.id and mailbox.status == "active" and mailbox.labels == {}
        assert [s.mailbox_id for s in await rows(pg_url, MailboxSecret)] == [first.id]
        page = client.get("/mailboxes").text
        assert page.count(f"<h2>{ADDRESS}</h2>") == 1

        token = csrf(client, "/mailboxes")
        assert client.post(f"/mailboxes/{first.id}/recheck", data={"csrf_token": token}).status_code == 303
        assert "checking your email from the last 7 days" in client.get("/mailboxes").text
    (task,) = await rows(pg_url, MailboxTaskRow)
    assert task.mailbox_id == first.id and task.state == "backfill_requested" and task.max_messages == 200
    (identity,) = await rows(pg_url, UserIdentityRow)
    assert len(identity.subject) == 300
    actions = [a.action for a in await rows(pg_url, AuditLog)]
    assert actions.count("mailbox_connected") == 2 and "mailbox_disconnected" in actions

"""Hold mode must never trap mail, also when the person lets go of a mailbox.

"Sign out of this mailbox" on a HOLD mailbox deletes our credential, after
which nobody could release what the hold rule parks. So the route lifts the
rule and releases held mail first, best effort, then signs out."""

from __future__ import annotations

import re

from starlette.testclient import TestClient

from reddysec.store.models import MailboxRow, UserRow
from reddysec.web.app import create_app

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


class HoldConnector:
    def __init__(self, calls: list[str], *, fail: bool = False) -> None:
        self.calls = calls
        self.fail = fail

    async def teardown(self) -> None:
        self.calls.append("teardown")
        if self.fail:
            raise RuntimeError("provider down")

    async def release_all_pending(self) -> int:
        self.calls.append("release_all_pending")
        return 2

    async def revoke(self) -> bool:
        self.calls.append("revoke")
        return True


async def _setup(settings, db, artifact_store, login, *, mode: str, labels: dict, fail: bool = False):
    calls: list[str] = []

    async def factory(mailbox):
        return HoldConnector(calls, fail=fail)

    app = create_app(settings, db=db, artifact_store=artifact_store, connector_factory=factory)
    client = TestClient(app, follow_redirects=False)
    client.__enter__()
    login(client, "holder@example.com")
    async with db.session() as s:
        from sqlalchemy import select

        user = (await s.execute(select(UserRow).where(UserRow.login_email == "holder@example.com"))).scalar_one()
        row = MailboxRow(id="mbx_hold1", user_id=user.id, provider="gmail", address="holder@gmail.com", mode=mode,
                         status="active", labels=labels, policy={})
        s.add(row)
    return client, calls


async def test_signing_out_of_a_hold_mailbox_releases_first(settings, db, artifact_store, login):
    client, calls = await _setup(settings, db, artifact_store, login, mode="hold", labels={"_mode": "hold", "x": "1"})
    try:
        token = CSRF_RE.search(client.get("/mailboxes").text).group(1)
        response = client.post("/mailboxes/mbx_hold1/disconnect", data={"csrf_token": token})
        assert response.status_code == 303
        assert calls == ["teardown", "release_all_pending", "revoke"]
        async with db.session() as s:
            assert (await s.get(MailboxRow, "mbx_hold1")).status == "disconnected"
    finally:
        client.__exit__(None, None, None)


async def test_release_failure_does_not_block_signing_out(settings, db, artifact_store, login):
    client, calls = await _setup(settings, db, artifact_store, login, mode="hold", labels={"_mode": "hold"}, fail=True)
    try:
        token = CSRF_RE.search(client.get("/mailboxes").text).group(1)
        assert client.post("/mailboxes/mbx_hold1/disconnect", data={"csrf_token": token}).status_code == 303
        assert calls == ["teardown", "revoke"]
        async with db.session() as s:
            assert (await s.get(MailboxRow, "mbx_hold1")).status == "disconnected"
    finally:
        client.__exit__(None, None, None)


async def test_scan_mailbox_signs_out_without_touching_hold(settings, db, artifact_store, login):
    client, calls = await _setup(settings, db, artifact_store, login, mode="scan", labels={"_mode": "scan"})
    try:
        token = CSRF_RE.search(client.get("/mailboxes").text).group(1)
        assert client.post("/mailboxes/mbx_hold1/disconnect", data={"csrf_token": token}).status_code == 303
        assert calls == ["revoke"]
    finally:
        client.__exit__(None, None, None)

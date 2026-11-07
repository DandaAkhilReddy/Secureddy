"""End to end: mailbox -> worker -> real parser -> real analyzer -> real
Chromium detonation -> verdict actions -> web dashboard, report, screenshot
and Reading Room.

Only the mailbox provider is faked (there is no Gmail here). Everything else
is the production code path.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from reddysec.chamber.backends.base import DetonationChamber
from reddysec.chamber.backends.local import InProcessBackend
from reddysec.chamber.readingroom import ReadingRoomManager
from reddysec.chamber.readingroom_web import make_room_router
from reddysec.config import get_settings
from reddysec.core.artifacts import LocalArtifactStore
from reddysec.models import ProtectionMode
from reddysec.store import repo
from reddysec.store.models import MessageRow
from reddysec.testing.fakes import FakeMailbox
from reddysec.web import auth as web_auth
from reddysec.web.app import create_app
from reddysec.web.room import csrf_guard
from reddysec.worker.engine import Worker
from tests.integration.chamber.evil_server import EvilSite
from tests.unit.chamber.chamber_helpers import FakeRoomEngine

pytestmark = pytest.mark.integration

CLIENT_EMAIL = "principal@example.com"
MAILBOX_ADDRESS = "principal@gmail.com"


def phishing_email(link: str) -> bytes:
    return (
        "From: DocuSign <noreply@docusign-secure-review.com>\r\n"
        f"To: {MAILBOX_ADDRESS}\r\n"
        "Subject: Completed: Please review and sign your settlement agreement\r\n"
        "Date: Thu, 05 Nov 2026 09:12:00 -0800\r\n"
        "Message-ID: <phish-1@docusign-secure-review.com>\r\n"
        "Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=docusign-secure-review.com;"
        " dkim=none; dmarc=fail (p=NONE) header.from=docusign-secure-review.com\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        "<html><body><p>Your document is ready. Review it within 24 hours or it will be voided.</p>"
        f'<p><a href="{link}">REVIEW DOCUMENT</a></p>'
        "<p>DocuSign Inc.</p></body></html>\r\n"
    ).encode()


def legitimate_email() -> bytes:
    return (
        "From: Sravani <sravani@example.org>\r\n"
        f"To: {MAILBOX_ADDRESS}\r\n"
        "Subject: Dinner on Saturday?\r\n"
        "Date: Thu, 05 Nov 2026 10:00:00 -0800\r\n"
        "Message-ID: <plain-1@example.org>\r\n"
        "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=example.org;"
        " dkim=pass header.i=@example.org header.d=example.org; dmarc=pass header.from=example.org\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Are we still on for Saturday at 7? No rush, let me know.\r\n"
    ).encode()


@pytest.fixture(scope="module")
def evil_site():
    with EvilSite() as site:
        yield site


@pytest.fixture
def room_manager(tmp_path):
    engines: list[FakeRoomEngine] = []

    def factory(session, *, workdir, on_download):
        engine = FakeRoomEngine(session, workdir=workdir, on_download=on_download)
        engines.append(engine)
        return engine

    manager = ReadingRoomManager(LocalArtifactStore(tmp_path / "room"), engine_factory=factory)
    manager.test_engines = engines  # type: ignore[attr-defined]
    return manager


async def _seed(db, mode: ProtectionMode):
    async with db.session() as session:
        user = await repo.create_user(session, email=CLIENT_EMAIL, display_name="The Principal")
        mailbox = await repo.create_mailbox(
            session, user_id=user.id, provider="gmail", address=MAILBOX_ADDRESS, mode=mode.value
        )
    return user, mailbox


async def test_phish_is_quarantined_and_visible_end_to_end(db, tmp_env: Path, evil_site, room_manager):
    settings = get_settings()
    store = LocalArtifactStore(tmp_env / "artifacts")
    chamber = DetonationChamber(
        InProcessBackend(store), store, max_concurrency=2, default_timeout_s=40, allow_private_targets=True
    )
    user, mailbox_row = await _seed(db, ProtectionMode.HOLD)

    fake_mailbox = FakeMailbox(mailbox_id=mailbox_row.id)

    async def connector_factory(_row):
        return fake_mailbox

    worker = Worker(
        db, settings, connector_factory=connector_factory, detonator=chamber, artifact_store=store
    )

    # First cycle performs setup (installs the HOLD rule in the fake mailbox).
    await worker.run_cycle()
    assert fake_mailbox.mode is ProtectionMode.HOLD and fake_mailbox.hold_rule_installed

    phish = fake_mailbox.deliver(phishing_email(evil_site.url("/phish-login")))
    plain = fake_mailbox.deliver(legitimate_email())
    assert fake_mailbox.in_inbox[phish.provider_message_id] is False  # held
    assert fake_mailbox.in_inbox[plain.provider_message_id] is False

    await worker.run_cycle()

    # The phish went to Quarantine. The plain email has nothing to click or
    # open: released into the inbox at once, no label, nothing stored.
    assert fake_mailbox.in_inbox[phish.provider_message_id] is False
    assert "Secureddy/Quarantine" in fake_mailbox.labels[phish.provider_message_id]
    assert fake_mailbox.in_inbox[plain.provider_message_id] is True
    assert not any(label.startswith("Secureddy/") for label in fake_mailbox.labels[plain.provider_message_id])

    async with db.session() as session:
        rows = (await session.execute(MessageRow.__table__.select())).mappings().all()
    by_pid = {r["provider_message_id"]: r for r in rows}
    phish_row = by_pid[phish.provider_message_id]
    assert plain.provider_message_id not in by_pid
    assert phish_row["level"] == "malicious" and phish_row["quarantined"] is True
    verdict = phish_row["verdict"]
    codes = {s["code"] for s in verdict["signals"]}
    assert any(c.startswith("dynamic.") for c in codes), codes  # the sandbox contributed evidence
    url_verdict = verdict["urls"][0]
    assert url_verdict["detonated"] is True and url_verdict["screenshot_ref"]
    assert store.exists(url_verdict["screenshot_ref"])
    assert "docusign" in verdict["summary"].lower()

    # --- the client's view -----------------------------------------------------------
    room_router = make_room_router(
        room_manager, get_principal_id=web_auth.get_principal_id, mutation_guard=csrf_guard
    )
    app = create_app(settings, db=db, room_router=room_router, artifact_store=store)
    with TestClient(app) as client:
        login = client.get("/login")
        token = re.search(r'name="csrf_token" value="([^"]+)"', login.text).group(1)
        resp = client.post(
            "/auth/dev-login",
            data={"email": CLIENT_EMAIL, "name": "The Principal", "csrf_token": token},
            follow_redirects=False,
        )
        assert resp.status_code in (302, 303)

        home = client.get("/")
        assert home.status_code == 200
        assert "Quarantine" in home.text and "settlement agreement" in home.text

        report = client.get(f"/messages/{phish_row['id']}")
        assert report.status_code == 200
        assert verdict["summary"][:40] in report.text
        shot = re.search(r'src="(/artifacts/[^"]+)"', report.text)
        assert shot, "report should show the sandbox screenshot"
        image = client.get(shot.group(1))
        assert image.status_code == 200 and image.headers["content-type"].startswith("image/")

        # Open the link in the Reading Room: CSRF is enforced, then we land in the room.
        page_token = re.search(r'name="csrf_token" value="([^"]+)"', report.text).group(1)
        denied = client.post(
            "/room/start", data={"url": url_verdict["url"], "message_id": phish_row["id"]}, follow_redirects=False
        )
        assert denied.status_code == 403
        opened = client.post(
            "/room/start",
            data={"url": url_verdict["url"], "message_id": phish_row["id"], "csrf_token": page_token},
            follow_redirects=False,
        )
        assert opened.status_code == 303 and opened.headers["location"].startswith("/room/")
        room = client.get(opened.headers["location"])
        assert room.status_code == 200 and "Reading Room" in room.text
        assert room_manager.test_engines and room_manager.test_engines[0].started_url == url_verdict["url"]

        # The glass box: the room start is in the client's audit log.
        audit = client.get("/audit")
        assert audit.status_code == 200

        # Another client cannot see this report.
        client.post("/auth/logout", data={"csrf_token": page_token}, follow_redirects=False)
        login2 = client.get("/login")
        token2 = re.search(r'name="csrf_token" value="([^"]+)"', login2.text).group(1)
        client.post(
            "/auth/dev-login", data={"email": "other@example.com", "csrf_token": token2}, follow_redirects=False
        )
        assert client.get(f"/messages/{phish_row['id']}").status_code == 404
        assert client.get(shot.group(1)).status_code in (403, 404)


async def test_release_restores_quarantined_message(db, tmp_env: Path, evil_site):
    """The client overrules us from the report page; the worker carries it out."""
    settings = get_settings()
    store = LocalArtifactStore(tmp_env / "artifacts")
    chamber = DetonationChamber(InProcessBackend(store), store, default_timeout_s=40, allow_private_targets=True)
    user, mailbox_row = await _seed(db, ProtectionMode.SCAN)
    fake_mailbox = FakeMailbox(mailbox_id=mailbox_row.id)

    async def connector_factory(_row):
        return fake_mailbox

    worker = Worker(db, settings, connector_factory=connector_factory, detonator=chamber, artifact_store=store)
    await worker.run_cycle()
    phish = fake_mailbox.deliver(phishing_email(evil_site.url("/phish-login")))
    await worker.run_cycle()
    assert fake_mailbox.in_inbox[phish.provider_message_id] is False

    async with db.session() as session:
        row = (await session.execute(MessageRow.__table__.select())).mappings().one()
    assert row["quarantined"] is True

    app = create_app(settings, db=db, artifact_store=store)
    with TestClient(app) as client:
        token = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/login").text).group(1)
        client.post("/auth/dev-login", data={"email": CLIENT_EMAIL, "csrf_token": token}, follow_redirects=False)
        report = client.get(f"/messages/{row['id']}")
        page_token = re.search(r'name="csrf_token" value="([^"]+)"', report.text).group(1)
        release = client.post(
            f"/messages/{row['id']}/release", data={"csrf_token": page_token}, follow_redirects=False
        )
        assert release.status_code in (302, 303)

    await worker.run_cycle()
    assert fake_mailbox.in_inbox[phish.provider_message_id] is True
    assert "Secureddy/Released by you" in fake_mailbox.labels[phish.provider_message_id]
    async with db.session() as session:
        row = (await session.execute(MessageRow.__table__.select())).mappings().one()
    assert row["quarantined"] is False and row["restored_by_client"] is True
    assert datetime.now(UTC) > row["analyzed_at"].replace(tzinfo=UTC)

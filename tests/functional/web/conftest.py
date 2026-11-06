"""Fixtures for the web functional tests.

The whole app runs offline: a fake Google OAuth provider, a fake Reading Room
router, a recording Pub/Sub handler and the shared sqlite ``db`` fixture.
Rows are seeded straight through SQLAlchemy so each test states its world.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

import pytest
from fastapi import APIRouter, Form
from pydantic import SecretStr
from starlette.responses import PlainTextResponse, RedirectResponse
from starlette.testclient import TestClient

from reddysec.config import Settings
from reddysec.core.ids import new_id
from reddysec.models import Signal, SignalStage, TriageLane, Verdict, VerdictLevel
from reddysec.store.models import AuditLog, MailboxRow, MessageRow, NotificationRow, UserRow
from reddysec.web.app import create_app

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
GOOGLE_SCOPES = ["openid", "email", "https://www.googleapis.com/auth/gmail.modify"]


# --------------------------------------------------------------------------
# Fakes
# --------------------------------------------------------------------------


@dataclass
class AuthStart:
    url: str
    state: str
    code_verifier: str


@dataclass
class TokenSet:
    access_token: str
    refresh_token: str | None
    expires_at: datetime | None
    id_claims: dict[str, Any]
    scopes: list[str]


class FakeOAuthProvider:
    """Structurally matches ``reddysec.web.auth.OAuthProvider``. ``code`` must be
    ``good-code``; anything else raises like a rejected authorization code."""

    def __init__(
        self, claims: dict[str, Any] | None = None, *, refresh_token: str | None = "refresh-abc"
    ) -> None:
        self.claims = claims or {
            "sub": "google-sub-1",
            "email": "client@gmail.com",
            "email_verified": True,
            "name": "Avery Client",
            "picture": None,
        }
        self.refresh_token = refresh_token
        self.fail_with: Exception | None = None
        self.started: list[AuthStart] = []
        self.finished: list[tuple[str, str, str]] = []

    def begin(self, return_to: str = "/") -> AuthStart:
        state = f"state-{len(self.started) + 1}-{new_id('st')[-6:]}"
        start = AuthStart(
            url=f"https://accounts.google.example/o/oauth2/v2/auth?state={state}&rt={quote(return_to)}",
            state=state,
            code_verifier=f"verifier-{len(self.started) + 1}",
        )
        self.started.append(start)
        return start

    async def finish(self, state: str, code: str, code_verifier: str) -> TokenSet:
        self.finished.append((state, code, code_verifier))
        if self.fail_with is not None:
            raise self.fail_with
        if code != "good-code":
            raise ValueError("invalid_grant")
        return TokenSet(
            access_token="access-xyz",
            refresh_token=self.refresh_token,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            id_claims=dict(self.claims),
            scopes=list(GOOGLE_SCOPES),
        )


class PushRecorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.fail_with: Exception | None = None

    async def __call__(self, email_address: str, history_id: str) -> None:
        self.calls.append((email_address, history_id))
        if self.fail_with is not None:
            raise self.fail_with


def make_room_router(record: list[dict[str, str]]) -> APIRouter:
    """Shape of ``chamber.readingroom_web.make_room_router``: a form POST that
    redirects to the session page."""
    router = APIRouter()

    @router.post("/room/start")
    async def start(url: str = Form(...), message_id: str = Form("")) -> RedirectResponse:
        record.append({"url": url, "message_id": message_id})
        return RedirectResponse(f"/room/room_{len(record)}", status_code=303)

    @router.get("/room/{session_id}")
    async def room(session_id: str) -> PlainTextResponse:
        return PlainTextResponse(f"room {session_id}")

    return router


# --------------------------------------------------------------------------
# App and client
# --------------------------------------------------------------------------


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        env="test",
        dev_login_enabled=True,
        artifacts_dir=str(tmp_path / "artifacts"),
        secret_key=SecretStr("functional-test-secret-key-that-is-long"),
        token_kek=SecretStr(""),
        hold_dead_man_minutes=10,
    )


@pytest.fixture
def oauth() -> FakeOAuthProvider:
    return FakeOAuthProvider()


@pytest.fixture
def push() -> PushRecorder:
    return PushRecorder()


@pytest.fixture
def room_calls() -> list[dict[str, str]]:
    return []


@pytest.fixture
def app(settings, db, oauth, push, room_calls, artifact_store):
    return create_app(
        settings,
        db=db,
        oauth=oauth,
        room_router=make_room_router(room_calls),
        on_gmail_push=push,
        pubsub_token="pubsub-shared-token",
        artifact_store=artifact_store,
    )


@pytest.fixture
def client(app):
    with TestClient(app, follow_redirects=False) as c:
        yield c


def _csrf_of(client: TestClient, path: str = "/login") -> str:
    """Fetch a page and read the CSRF token out of its form."""
    response = client.get(path)
    assert response.status_code == 200, (path, response.status_code)
    match = CSRF_RE.search(response.text)
    assert match, f"no csrf token on {path}"
    return match.group(1)


def _login(client: TestClient, email: str, *, role: str = "principal", name: str = "") -> None:
    """Sign in through the developer form; creates the account if needed."""
    token = _csrf_of(client, "/login")
    response = client.post(
        "/auth/dev-login", data={"email": email, "name": name, "role": role, "csrf_token": token}
    )
    assert response.status_code == 303, response.text


# Helpers are handed to tests as fixtures (pytest's supported way to share
# code from a conftest) so no test module needs to import this file.


@pytest.fixture
def csrf_of():
    return _csrf_of


@pytest.fixture
def login():
    return _login


@pytest.fixture
def fake_oauth_cls():
    return FakeOAuthProvider


# --------------------------------------------------------------------------
# Seeding
# --------------------------------------------------------------------------


def _make_verdict(
    level: str = "malicious",
    *,
    score: int | None = None,
    summary: str | None = None,
    lane: str = "detonate",
    signals: list[Signal] | None = None,
    urls: list[dict[str, Any]] | None = None,
    attachments: list[dict[str, Any]] | None = None,
    needs_human_review: bool = False,
) -> dict[str, Any]:
    default_scores = {"safe": 5, "suspicious": 48, "malicious": 91, "unknown": 0}
    verdict = Verdict(
        level=VerdictLevel(level),
        score=default_scores[level] if score is None else score,
        summary=summary or f"Test summary for a {level} email.",
        lane=TriageLane(lane),
        signals=signals
        or [
            Signal(
                code="url.credential_form",
                stage=SignalStage.DYNAMIC,
                weight=60,
                title="The page asked for a password",
                detail="A sign-in form sent its answers to a server unrelated to the sender.",
            ),
            Signal(
                code="sender.known",
                stage=SignalStage.HISTORY,
                weight=-20,
                title="You have written to this sender before",
            ),
        ],
        urls=[
            {"url": u["url"], "level": u.get("level", level), "score": u.get("score", 80), **u}
            for u in (urls or [])
        ],
        attachments=attachments or [],
        needs_human_review=needs_human_review,
        engine_version="rs-engine/0.1.0-test",
    )
    return verdict.model_dump(mode="json")


@dataclass
class Seeder:
    db: Any
    counter: int = field(default=0)

    def _next(self) -> int:
        self.counter += 1
        return self.counter

    async def user(self, email: str, *, role: str = "principal", name: str | None = None, **kw) -> UserRow:
        async with self.db.session() as s:
            row = UserRow(
                id=new_id("usr"),
                display_name=name or email.split("@")[0].title(),
                login_email=email.lower(),
                role=role,
                **kw,
            )
            s.add(row)
        return row

    async def mailbox(
        self, user: UserRow, *, provider: str = "gmail", address: str | None = None, **kw
    ) -> MailboxRow:
        async with self.db.session() as s:
            row = MailboxRow(
                id=new_id("mbx"),
                user_id=user.id,
                provider=provider,
                address=address or user.login_email,
                mode=kw.pop("mode", "scan"),
                status=kw.pop("status", "active"),
                labels=kw.pop("labels", {"Secureddy": "L1"}),
                policy=kw.pop("policy", {}),
                **kw,
            )
            s.add(row)
        return row

    async def message(
        self,
        mailbox: MailboxRow,
        *,
        level: str | None = "malicious",
        verdict: dict[str, Any] | None = None,
        state: str = "done",
        quarantined: bool | None = None,
        hours_ago: float = 1.0,
        subject: str | None = None,
        **kw,
    ) -> MessageRow:
        n = self._next()
        if verdict is None and level is not None:
            verdict = _make_verdict(level)
        if quarantined is None:
            quarantined = level == "malicious"
        async with self.db.session() as s:
            row = MessageRow(
                id=new_id("msg"),
                mailbox_id=mailbox.id,
                provider_message_id=f"prov-{n}",
                from_address=kw.pop("from_address", f"sender{n}@example.net"),
                from_name=kw.pop("from_name", f"Sender {n}"),
                subject=subject or f"Test message {n}",
                received_at=datetime.now(UTC) - timedelta(hours=hours_ago),
                url_count=len((verdict or {}).get("urls", [])),
                attachment_count=len((verdict or {}).get("attachments", [])),
                state=state,
                lane=(verdict or {}).get("lane"),
                level=level,
                score=(verdict or {}).get("score"),
                verdict=verdict,
                quarantined=quarantined,
                analyzed_at=datetime.now(UTC) - timedelta(hours=hours_ago) if verdict else None,
                **kw,
            )
            s.add(row)
        return row

    async def notification(
        self, user: UserRow, *, message: MessageRow | None = None, **kw
    ) -> NotificationRow:
        async with self.db.session() as s:
            row = NotificationRow(
                id=new_id("ntf"),
                user_id=user.id,
                message_id=message.id if message else None,
                channel=kw.pop("channel", "dashboard"),
                level=kw.pop("level", "malicious"),
                title=kw.pop("title", "A dangerous email was quarantined"),
                body=kw.pop("body", "We moved it out of your inbox."),
                **kw,
            )
            s.add(row)
        return row

    async def audit(self, **kw) -> AuditLog:
        async with self.db.session() as s:
            row = AuditLog(id=new_id("aud"), details=kw.pop("details", {}), **kw)
            s.add(row)
        return row


@pytest.fixture
def make_verdict():
    return _make_verdict


@pytest.fixture
def seed(db) -> Seeder:
    return Seeder(db)

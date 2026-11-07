"""Fakes for the mail connectors: an in-memory Gmail + Google OAuth server
behind ``httpx.MockTransport`` and an in-memory IMAP server behind the
``ImapSession`` protocol. Everything is deterministic and offline."""

from __future__ import annotations

import base64
import imaplib
import json
import re
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from reddysec.mail.gmail import GmailConnector, GoogleCredentials
from reddysec.mail.imap import FetchedMessage, FolderInfo, ImapAuthError, SelectInfo
from reddysec.mail.oauth_google import GoogleOAuth
from reddysec.models import ProtectionMode

GMAIL_HOST = "gmail.googleapis.com"
OAUTH_HOST = "oauth2.googleapis.com"
CLIENT_ID = "client-id.apps.googleusercontent.com"
CLIENT_SECRET = "client-secret"
REDIRECT_URI = "http://localhost:8000/auth/google/callback"
STATE_SECRET = "state-secret"
FIXED_NOW = datetime(2026, 11, 5, 12, 0, 0, tzinfo=UTC)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_id_token(claims: dict[str, Any]) -> str:
    header = b64url(json.dumps({"alg": "RS256", "kid": "k"}).encode())
    payload = b64url(json.dumps(claims).encode())
    return f"{header}.{payload}.{b64url(b'not-a-real-signature')}"


def sample_raw(
    subject: str = "Hello", from_addr: str = "alice@example.com", message_id: str | None = None
) -> bytes:
    mid = message_id or f"<{subject.replace(' ', '-').lower()}@example.com>"
    return (
        f"From: Alice <{from_addr}>\r\nTo: client@gmail.com\r\nSubject: {subject}\r\n"
        f"Message-ID: {mid}\r\nDate: Thu, 05 Nov 2026 10:00:00 +0000\r\n\r\nBody text\r\n"
    ).encode()


@dataclass
class Call:
    method: str
    path: str
    params: dict[str, list[str]]
    json: Any = None
    token: str = ""


class FakeGoogleAuthServer:
    """oauth2.googleapis.com: token exchange, refresh, tokeninfo, revoke."""

    def __init__(self) -> None:
        self.calls: list[Call] = []
        self.valid_codes: dict[str, str] = {"good-code": "sub-123"}
        self.refresh_tokens: set[str] = {"refresh-1"}
        self.access_token_seq = 0
        self.id_claims: dict[str, Any] = {
            "iss": "https://accounts.google.com",
            "aud": CLIENT_ID,
            "sub": "sub-123",
            "email": "Client@Gmail.com",
            "email_verified": "true",
            "name": "The Client",
            "picture": "https://example.com/p.png",
            "exp": str(int((FIXED_NOW + timedelta(hours=1)).timestamp())),
        }
        self.tokeninfo_override: dict[str, Any] | None = None
        self.tokeninfo_status = 200
        self.tokeninfo_raise: Exception | None = None
        self.tokeninfo_text: str | None = None  # a raw (non-JSON) body
        self.fail_next: deque[Exception | httpx.Response] = deque()
        self.refresh_error: str | None = None  # e.g. "invalid_grant"
        self.revoke_status = 200
        self.token_status = 200
        self.token_extra: dict[str, Any] = {}

    def next_access_token(self) -> str:
        self.access_token_seq += 1
        return f"access-{self.access_token_seq}"

    def handle(self, request: httpx.Request) -> httpx.Response:
        form = parse_qs(request.content.decode()) if request.content else {}
        params: dict[str, list[str]] = {}
        for k, v in request.url.params.multi_items():
            params.setdefault(k, []).append(v)
        self.calls.append(Call(request.method, request.url.path, params, form))
        if self.fail_next:
            item = self.fail_next.popleft()
            if isinstance(item, Exception):
                raise item
            return item
        if request.url.path == "/token":
            return self._token(form)
        if request.url.path == "/tokeninfo":
            if self.tokeninfo_raise is not None:
                raise self.tokeninfo_raise
            if self.tokeninfo_text is not None:
                return httpx.Response(200, text=self.tokeninfo_text)
            if self.tokeninfo_status != 200:
                return httpx.Response(self.tokeninfo_status, json={"error": "invalid_token"})
            return httpx.Response(200, json=self.tokeninfo_override or self.id_claims)
        if request.url.path == "/revoke":
            return httpx.Response(
                self.revoke_status, json={} if self.revoke_status == 200 else {"error": "invalid_token"}
            )
        return httpx.Response(404, json={"error": "no such endpoint"})

    def _token(self, form: dict[str, list[str]]) -> httpx.Response:
        if self.token_status != 200:
            return httpx.Response(self.token_status, json={"error": "server_error"})
        grant = form.get("grant_type", [""])[0]
        if grant == "authorization_code":
            code = form.get("code", [""])[0]
            if code not in self.valid_codes:
                return httpx.Response(
                    400, json={"error": "invalid_grant", "error_description": "Bad Request"}
                )
            if form.get("client_secret", [""])[0] != CLIENT_SECRET:
                return httpx.Response(401, json={"error": "invalid_client"})
            body = {
                "access_token": self.next_access_token(),
                "expires_in": 3599,
                "refresh_token": "refresh-1",
                "scope": "openid email https://www.googleapis.com/auth/gmail.modify",
                "token_type": "Bearer",
                "id_token": make_id_token(self.id_claims),
                **self.token_extra,
            }
            return httpx.Response(200, json=body)
        if grant == "refresh_token":
            if self.refresh_error:
                return httpx.Response(
                    400, json={"error": self.refresh_error, "error_description": "Token has been revoked."}
                )
            if form.get("refresh_token", [""])[0] not in self.refresh_tokens:
                return httpx.Response(
                    400, json={"error": "invalid_grant", "error_description": "Bad Request"}
                )
            body = {
                "access_token": self.next_access_token(),
                "expires_in": 3599,
                "scope": "openid email https://www.googleapis.com/auth/gmail.modify",
                "token_type": "Bearer",
                **self.token_extra,
            }
            return httpx.Response(200, json=body)
        return httpx.Response(400, json={"error": "unsupported_grant_type"})


class FakeGmailServer:
    """Enough of the Gmail REST API for the connector, plus hooks to force
    failures. Routes by path, records every call."""

    SYSTEM_LABELS = ("INBOX", "SENT", "DRAFT", "SPAM", "TRASH", "UNREAD", "IMPORTANT")

    def __init__(self, auth: FakeGoogleAuthServer, *, address: str = "client@gmail.com") -> None:
        self.auth = auth
        self.address = address
        self.valid_tokens: set[str] = {"access-0"}
        self.labels: dict[str, dict[str, Any]] = {
            name: {"id": name, "name": name, "type": "system"} for name in self.SYSTEM_LABELS
        }
        self.messages: dict[str, dict[str, Any]] = {}
        self.history: list[dict[str, Any]] = []
        self.history_id = 1000
        self.oldest_history_id = 1000
        self.history_page_size = 100
        self.list_page_size = 100
        self.filters: dict[str, dict[str, Any]] = {}
        self.calls: list[Call] = []
        self.fail_next: deque[Exception | httpx.Response] = deque()
        self.watch_expiration_ms = int((FIXED_NOW + timedelta(days=7)).timestamp() * 1000)
        self._seq = 0
        self.now = FIXED_NOW

    # ---------------------------------------------------------- helpers
    def _next(self, prefix: str) -> str:
        self._seq += 1
        return f"{prefix}{self._seq}"

    def label_id(self, name: str) -> str | None:
        for lbl in self.labels.values():
            if lbl["name"] == name:
                return lbl["id"]
        return None

    def add_message(
        self,
        raw: bytes,
        labels: tuple[str, ...] | list[str] = ("INBOX", "UNREAD"),
        *,
        internal_ms: int | None = None,
        thread_id: str | None = None,
        record_history: bool = True,
    ) -> str:
        mid = self._next("m")
        self.messages[mid] = {
            "id": mid,
            "threadId": thread_id or f"t{mid}",
            "labelIds": list(labels),
            "internalDate": str(internal_ms if internal_ms is not None else int(self.now.timestamp() * 1000)),
            "raw": b64url(raw),
        }
        if record_history:
            self.history_id += 1
            self.history.append(
                {
                    "id": str(self.history_id),
                    "messagesAdded": [
                        {
                            "message": {
                                "id": mid,
                                "threadId": self.messages[mid]["threadId"],
                                "labelIds": list(labels),
                            }
                        }
                    ],
                }
            )
        return mid

    def calls_to(self, method: str, path_suffix: str) -> list[Call]:
        return [c for c in self.calls if c.method == method and c.path.endswith(path_suffix)]

    def force(self, status: int, body: dict[str, Any] | None = None, *, times: int = 1) -> None:
        for _ in range(times):
            self.fail_next.append(
                httpx.Response(status, json=body or {"error": {"code": status, "message": "forced"}})
            )

    def force_exception(self, exc: Exception, *, times: int = 1) -> None:
        for _ in range(times):
            self.fail_next.append(exc)

    def transport(self) -> httpx.MockTransport:
        def route(request: httpx.Request) -> httpx.Response:
            if request.url.host == OAUTH_HOST:
                return self.auth.handle(request)
            if request.url.host == GMAIL_HOST:
                return self.handle(request)
            return httpx.Response(502, json={"error": f"unexpected host {request.url.host}"})

        return httpx.MockTransport(route)

    # ---------------------------------------------------------- routing
    def handle(self, request: httpx.Request) -> httpx.Response:
        params: dict[str, list[str]] = {}
        for k, v in request.url.params.multi_items():
            params.setdefault(k, []).append(v)
        body = json.loads(request.content) if request.content else None
        path = request.url.path.removeprefix("/gmail/v1/users/me").lstrip("/")
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        self.calls.append(Call(request.method, path, params, body, token))

        if self.fail_next:
            item = self.fail_next.popleft()
            if isinstance(item, Exception):
                raise item
            return item

        if token not in self.valid_tokens:
            return self._error(401, "Invalid Credentials", "authError")

        method = request.method
        if path == "profile" and method == "GET":
            return httpx.Response(
                200,
                json={
                    "emailAddress": self.address,
                    "historyId": str(self.history_id),
                    "messagesTotal": len(self.messages),
                },
            )
        if path == "labels" and method == "GET":
            return httpx.Response(200, json={"labels": list(self.labels.values())})
        if path == "labels" and method == "POST":
            if self.label_id(body["name"]):
                return self._error(409, "Label name exists or conflicts", "aborted")
            lid = self._next("Label_")
            self.labels[lid] = {
                "id": lid,
                "name": body["name"],
                "type": "user",
                **{k: v for k, v in body.items() if k != "name"},
            }
            return httpx.Response(200, json=self.labels[lid])
        if path == "messages" and method == "GET":
            return self._list_messages(params)
        if path == "messages/batchModify" and method == "POST":
            for mid in body.get("ids", []):
                if mid in self.messages:
                    self._apply_modify(mid, body)
            return httpx.Response(204)
        m = re.fullmatch(r"messages/([^/]+)", path)
        if m and method == "GET":
            msg = self.messages.get(m.group(1))
            if msg is None:
                return self._error(404, "Requested entity was not found.", "notFound")
            return httpx.Response(200, json=msg)
        m = re.fullmatch(r"messages/([^/]+)/modify", path)
        if m and method == "POST":
            msg = self.messages.get(m.group(1))
            if msg is None:
                return self._error(404, "Requested entity was not found.", "notFound")
            self._apply_modify(m.group(1), body)
            return httpx.Response(200, json=msg)
        if path == "history" and method == "GET":
            return self._history(params)
        if path == "settings/filters" and method == "GET":
            return httpx.Response(200, json={"filter": list(self.filters.values())})
        if path == "settings/filters" and method == "POST":
            fid = self._next("filter")
            self.filters[fid] = {"id": fid, **body}
            return httpx.Response(200, json=self.filters[fid])
        m = re.fullmatch(r"settings/filters/([^/]+)", path)
        if m and method == "DELETE":
            if self.filters.pop(m.group(1), None) is None:
                return self._error(404, "Filter not found", "notFound")
            return httpx.Response(204)
        if path == "watch" and method == "POST":
            return httpx.Response(
                200, json={"historyId": str(self.history_id), "expiration": str(self.watch_expiration_ms)}
            )
        if path == "stop" and method == "POST":
            return httpx.Response(204)
        return self._error(404, f"no route for {method} {path}", "notFound")

    def _apply_modify(self, mid: str, body: dict[str, Any]) -> None:
        labels = set(self.messages[mid]["labelIds"])
        labels -= set(body.get("removeLabelIds", []))
        labels |= set(body.get("addLabelIds", []))
        self.messages[mid]["labelIds"] = sorted(labels)

    def _list_messages(self, params: dict[str, list[str]]) -> httpx.Response:
        wanted = set(params.get("labelIds", []))
        q = params.get("q", [""])[0]
        items = []
        for msg in sorted(self.messages.values(), key=lambda m: -int(m["internalDate"])):
            labels = set(msg["labelIds"])
            if labels & {"SPAM", "TRASH"}:
                continue
            if wanted and not wanted <= labels:
                continue
            if "newer_than:1d" in q and int(msg["internalDate"]) < int(
                (self.now - timedelta(days=1)).timestamp() * 1000
            ):
                continue
            after = re.search(r"\bafter:(\d+)", q)
            if after and int(msg["internalDate"]) < int(after.group(1)) * 1000:
                continue
            if "in:inbox" in q.split() and "INBOX" not in labels:
                continue
            if ("-in:sent" in q and "SENT" in labels) or ("-in:drafts" in q and "DRAFT" in labels):
                continue
            items.append({"id": msg["id"], "threadId": msg["threadId"]})
        size = min(int(params.get("maxResults", ["100"])[0]), self.list_page_size)
        start = int(params.get("pageToken", ["0"])[0])
        page = items[start : start + size]
        out: dict[str, Any] = {"messages": page, "resultSizeEstimate": len(items)}
        if start + size < len(items):
            out["nextPageToken"] = str(start + size)
        return httpx.Response(200, json=out)

    def _history(self, params: dict[str, list[str]]) -> httpx.Response:
        start = int(params["startHistoryId"][0])
        if start < self.oldest_history_id:
            return self._error(404, "Requested entity was not found.", "notFound")
        records = [h for h in self.history if int(h["id"]) > start]
        offset = int(params.get("pageToken", ["0"])[0])
        page = records[offset : offset + self.history_page_size]
        out: dict[str, Any] = {"historyId": str(self.history_id)}
        if page:
            out["history"] = page
        if offset + self.history_page_size < len(records):
            out["nextPageToken"] = str(offset + self.history_page_size)
        return httpx.Response(200, json=out)

    @staticmethod
    def _error(status: int, message: str, reason: str) -> httpx.Response:
        return httpx.Response(
            status, json={"error": {"code": status, "message": message, "errors": [{"reason": reason}]}}
        )


@dataclass
class GmailEnv:
    auth: FakeGoogleAuthServer
    server: FakeGmailServer
    http: httpx.AsyncClient
    oauth: GoogleOAuth
    connector: GmailConnector
    sleeps: list[float] = field(default_factory=list)
    refreshed: list[Any] = field(default_factory=list)

    def new_connector(self, **overrides: Any) -> GmailConnector:
        async def on_refreshed(tokens: Any) -> None:
            self.refreshed.append(tokens)

        async def fake_sleep(seconds: float) -> None:
            self.sleeps.append(seconds)

        kwargs: dict[str, Any] = dict(
            http=self.http,
            on_tokens_refreshed=on_refreshed,
            mode=ProtectionMode.SCAN,
            sleep=fake_sleep,
            rng=lambda: 0.5,
            clock=lambda: self.server.now,
        )
        kwargs.update(overrides)
        credentials = kwargs.pop(
            "credentials",
            GoogleCredentials(
                access_token="access-0", refresh_token="refresh-1", expires_at=FIXED_NOW + timedelta(hours=1)
            ),
        )
        return GmailConnector("mbx_1", self.server.address, credentials, self.oauth, **kwargs)


@pytest.fixture
def google_auth() -> FakeGoogleAuthServer:
    return FakeGoogleAuthServer()


@pytest.fixture
async def gmail_env(google_auth: FakeGoogleAuthServer) -> GmailEnv:
    server = FakeGmailServer(google_auth)
    http = httpx.AsyncClient(transport=server.transport())
    oauth = GoogleOAuth(
        CLIENT_ID,
        CLIENT_SECRET,
        REDIRECT_URI,
        state_signer_secret=STATE_SECRET,
        http=http,
        clock=lambda: FIXED_NOW,
    )
    env = GmailEnv(auth=google_auth, server=server, http=http, oauth=oauth, connector=None)  # type: ignore[arg-type]
    env.connector = env.new_connector()

    # Every refreshed access token the auth server hands out becomes valid on the Gmail side.
    original_next = google_auth.next_access_token

    def tracked_next() -> str:
        token = original_next()
        server.valid_tokens.add(token)
        return token

    google_auth.next_access_token = tracked_next  # type: ignore[method-assign]
    yield env
    await http.aclose()


# ------------------------------------------------------------------ IMAP fake
@dataclass
class FakeFolder:
    uidvalidity: int
    uidnext: int = 1
    messages: dict[int, dict[str, Any]] = field(default_factory=dict)

    def append(self, raw: bytes, date: datetime | None = None, flags: set[str] | None = None) -> int:
        uid = self.uidnext
        self.uidnext += 1
        self.messages[uid] = {"raw": raw, "date": date or FIXED_NOW, "flags": set(flags or ())}
        return uid


class FakeImapServer:
    """In-memory IMAP state shared by every FakeImapSession the connector opens."""

    def __init__(
        self,
        *,
        delimiter: str = "/",
        capabilities: set[str] | None = None,
        permanent_flags: set[str] | None = None,
        accept: tuple[str, str] = ("client@yahoo.com", "app-password"),
    ) -> None:
        self.delimiter = delimiter
        self.capabilities = set(
            capabilities if capabilities is not None else {"IMAP4REV1", "MOVE", "UIDPLUS"}
        )
        self.permanent_flags = set(
            permanent_flags if permanent_flags is not None else {"\\Seen", "\\Deleted", "\\Flagged", "\\*"}
        )
        self.accept = accept
        self.folders: dict[str, FakeFolder] = {"INBOX": FakeFolder(uidvalidity=111)}
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.auth_log: list[tuple[str, ...]] = []
        self.fail_auth = False
        self.sessions_opened = 0
        self.logouts = 0
        self.raise_on: dict[str, Exception] = {}
        self.factory_error: Exception | None = None
        self.fail_logout = False
        self._uv_seq = 1000

    def session(self) -> FakeImapSession:
        if self.factory_error is not None:
            raise self.factory_error
        self.sessions_opened += 1
        return FakeImapSession(self)

    def deliver(
        self, folder: str, raw: bytes, *, date: datetime | None = None, flags: set[str] | None = None
    ) -> int:
        return self.folders[folder].append(raw, date, flags)

    def folder_path(self, label: str) -> str:
        return label.replace("/", self.delimiter)

    def new_uidvalidity(self) -> int:
        self._uv_seq += 1
        return self._uv_seq


class FakeImapSession:
    def __init__(self, server: FakeImapServer) -> None:
        self.server = server
        self.selected: str | None = None
        self.logged_out = False

    def _record(self, name: str, *args: Any) -> None:
        self.server.calls.append((name, args))
        exc = self.server.raise_on.get(name)
        if exc is not None:
            raise exc

    def _folder(self) -> FakeFolder:
        assert self.selected is not None, "no folder selected"
        return self.server.folders[self.selected]

    def login(self, username: str, password: str) -> None:
        self._record("login", username)
        self.server.auth_log.append(("login", username, password))
        if self.server.fail_auth or (username, password) != self.server.accept:
            raise ImapAuthError("[AUTHENTICATIONFAILED] Invalid credentials")

    def authenticate_xoauth2(self, username: str, access_token: str) -> None:
        self._record("xoauth2", username)
        self.server.auth_log.append(("xoauth2", username, access_token))
        if self.server.fail_auth:
            raise ImapAuthError("[AUTHENTICATIONFAILED] Invalid token")

    def capabilities(self) -> frozenset[str]:
        return frozenset(self.server.capabilities)

    def list_folders(self) -> list[FolderInfo]:
        self._record("list")
        return [FolderInfo(name=n, delimiter=self.server.delimiter) for n in self.server.folders]

    def create_folder(self, name: str) -> None:
        self._record("create", name)
        if name in self.server.folders:
            raise imaplib.IMAP4.error("CREATE failed: NO [ALREADYEXISTS]")
        self.server.folders[name] = FakeFolder(uidvalidity=self.server.new_uidvalidity())

    def select(self, folder: str) -> SelectInfo:
        self._record("select", folder)
        if folder not in self.server.folders:
            raise imaplib.IMAP4.error(f"SELECT failed: NO [NONEXISTENT] {folder}")
        self.selected = folder
        f = self.server.folders[folder]
        return SelectInfo(
            uidvalidity=f.uidvalidity,
            uidnext=f.uidnext,
            exists=len(f.messages),
            permanent_flags=frozenset(self.server.permanent_flags),
        )

    def uid_search(self, criteria: str) -> list[int]:
        self._record("search", criteria)
        folder = self._folder()
        uids = sorted(folder.messages)
        if criteria == "ALL":
            return uids
        m = re.fullmatch(r"UID (\d+):\*", criteria)
        if m:
            start = int(m.group(1))
            found = [u for u in uids if u >= start]
            # RFC 3501: "n:*" always includes the highest UID, even if n is past the end.
            return found or (uids[-1:] if uids else [])
        m = re.fullmatch(r"UID (\d+)", criteria)
        if m:
            return [int(m.group(1))] if int(m.group(1)) in folder.messages else []
        m = re.fullmatch(r"SINCE (\d{2})-([A-Z][a-z]{2})-(\d{4})", criteria)
        if m:
            day = datetime.strptime(f"{m.group(1)}-{m.group(2)}-{m.group(3)}", "%d-%b-%Y").date()
            return [u for u in uids if folder.messages[u]["date"].date() >= day]
        m = re.fullmatch(r'HEADER Message-ID "([^"]+)"', criteria)
        if m:
            needle = m.group(1).encode()
            return [u for u in uids if needle in folder.messages[u]["raw"]]
        raise imaplib.IMAP4.error(f"unsupported search {criteria!r}")

    def uid_fetch(self, uids: list[int]) -> list[FetchedMessage]:
        self._record("fetch", tuple(uids))
        folder = self._folder()
        return [
            FetchedMessage(
                uid=u,
                raw=folder.messages[u]["raw"],
                internal_date=folder.messages[u]["date"],
                flags=frozenset(folder.messages[u]["flags"]),
            )
            for u in uids
            if u in folder.messages
        ]

    def uid_store(self, uid: int, op: str, flags: list[str]) -> None:
        self._record("store", uid, op, tuple(flags))
        msg = self._folder().messages[uid]
        if op == "+FLAGS":
            msg["flags"] |= set(flags)
        elif op == "-FLAGS":
            msg["flags"] -= set(flags)

    def uid_copy(self, uid: int, folder: str) -> None:
        self._record("copy", uid, folder)
        msg = self._folder().messages[uid]
        self.server.folders[folder].append(msg["raw"], msg["date"], set(msg["flags"]))

    def uid_move(self, uid: int, folder: str) -> None:
        self._record("move", uid, folder)
        if "MOVE" not in self.server.capabilities:
            raise imaplib.IMAP4.error("UID MOVE failed: BAD unknown command")
        msg = self._folder().messages.pop(uid)
        self.server.folders[folder].append(msg["raw"], msg["date"], set(msg["flags"]))

    def uid_expunge(self, uid: int) -> None:
        self._record("uid_expunge", uid)
        folder = self._folder()
        if uid in folder.messages and "\\Deleted" in folder.messages[uid]["flags"]:
            del folder.messages[uid]

    def expunge(self) -> None:
        self._record("expunge")
        folder = self._folder()
        for uid in [u for u, m in folder.messages.items() if "\\Deleted" in m["flags"]]:
            del folder.messages[uid]

    def logout(self) -> None:
        self.logged_out = True
        self.server.logouts += 1
        if self.server.fail_logout:
            raise OSError("connection already closed")


@pytest.fixture
def imap_server() -> FakeImapServer:
    return FakeImapServer()


SessionFactory = Callable[[], FakeImapSession]

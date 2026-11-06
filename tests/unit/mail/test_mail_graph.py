"""GraphMailConnector against an in-memory Microsoft Graph (httpx.MockTransport)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from reddysec.mail.base import LABEL_PENDING, LABEL_QUARANTINE, LABEL_ROOT, AuthExpired, ConnectorError
from reddysec.mail.gmail import GoogleCredentials
from reddysec.mail.oauth_google import TokenSet
from reddysec.mail.outlook_graph import (
    CATEGORIES_KEY,
    CATEGORY,
    HOLD_RULE_KEY,
    HOLD_RULE_NAME,
    INBOX_KEY,
    GraphApiError,
    GraphMailConnector,
    verdict_category_plan,
)
from reddysec.models import PolicyConfig, ProtectionMode, RawMessage, TriageLane, Verdict, VerdictLevel

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
ME = "https://graph.microsoft.com/v1.0/me/"
SAFE, SUSP, QUAR, REL = (CATEGORY[k] for k in ("Secureddy/Checked", "Secureddy/Suspicious",
                                                "Secureddy/Quarantine", "Secureddy/Released by you"))


def raw_mime(subject: str) -> bytes:
    return f"From: a@contoso.com\r\nTo: avery@outlook.com\r\nSubject: {subject}\r\n\r\nhi\r\n".encode()


class FakeGraph:
    PAGE = 2

    def __init__(self) -> None:
        self.folders: dict[str, dict[str, Any]] = {"inbox-id": {"displayName": "Inbox", "parent": None}}
        self.messages: dict[str, dict[str, Any]] = {}
        self.categories: list[dict[str, Any]] = [{"displayName": "Family", "color": "preset9"}]
        self.rules: dict[str, dict[str, Any]] = {}
        self.seq = 0
        self.ids = 0
        self.calls: list[tuple[str, str]] = []
        self.tokens: list[str] = []
        self.fail: list[tuple[str, str, httpx.Response]] = []  # (method, path-substring, response)
        self.reject_token: set[str] = set()
        self.reject_filter = False

    # ---- helpers for tests
    def new_id(self, prefix: str) -> str:
        self.ids += 1
        return f"{prefix}-{self.ids}"

    def deliver(self, subject: str, *, folder: str = "inbox-id", minutes_ago: int = 5, categories=None,
                draft: bool = False) -> str:
        mid = self.new_id("msg")
        self.seq += 1
        self.messages[mid] = {
            "folder": folder, "categories": list(categories or []), "draft": draft, "subject": subject,
            "received": NOW - timedelta(minutes=minutes_ago), "changed": self.seq,
        }
        return mid

    def folder_id(self, name: str) -> str | None:
        return next((k for k, v in self.folders.items() if v["displayName"] == name), None)

    def touch(self, mid: str) -> None:
        self.seq += 1
        self.messages[mid]["changed"] = self.seq

    # ---- the HTTP surface
    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        assert url.startswith(ME), url
        path = urlsplit(url).path.split("/v1.0/me/", 1)[1]
        q = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
        method = request.method
        self.calls.append((method, path))
        token = request.headers["authorization"].removeprefix("Bearer ")
        self.tokens.append(token)
        assert 'IdType="ImmutableId"' in request.headers["prefer"]
        if token in self.reject_token:
            return httpx.Response(401, json={"error": {"code": "InvalidAuthenticationToken"}})
        for i, (m, frag, resp) in enumerate(self.fail):
            if m == method and frag in path:
                del self.fail[i]
                return resp
        body = json.loads(request.content) if request.content else None
        parts = path.split("/")

        if path == "mailFolders/inbox":
            return httpx.Response(200, json={"id": "inbox-id"})
        if path == "mailFolders":
            if method == "POST":
                fid = self.new_id("fld")
                self.folders[fid] = {"displayName": body["displayName"], "parent": None}
                return httpx.Response(201, json={"id": fid})
            return self._page([{"id": k, "displayName": v["displayName"]} for k, v in self.folders.items()
                               if v["parent"] is None], q, url)
        if parts[0] == "mailFolders" and len(parts) == 3 and parts[2] == "childFolders":
            parent = parts[1]
            if method == "POST":
                fid = self.new_id("fld")
                self.folders[fid] = {"displayName": body["displayName"], "parent": parent}
                return httpx.Response(201, json={"id": fid})
            return self._page([{"id": k, "displayName": v["displayName"]} for k, v in self.folders.items()
                               if v["parent"] == parent], q, url)
        if path == "outlook/masterCategories":
            if method == "POST":
                self.categories.append(body)
                return httpx.Response(201, json=body)
            return httpx.Response(200, json={"value": self.categories})
        if path.startswith("mailFolders/inbox/messageRules"):
            if method == "POST":
                rid = self.new_id("rule")
                self.rules[rid] = {**body, "id": rid}
                return httpx.Response(201, json=self.rules[rid])
            if method == "DELETE":
                self.rules.pop(parts[-1])
                return httpx.Response(204)
            return httpx.Response(200, json={"value": list(self.rules.values())})
        if parts[0] == "mailFolders" and parts[-1] == "delta":
            return self._delta(parts[1], q)
        if parts[0] == "mailFolders" and parts[-1] == "messages":
            items = [{"id": k} for k, v in self.messages.items() if v["folder"] == parts[1]]
            return self._page(items, q, url)
        if parts[0] == "messages":
            mid = parts[1]
            if mid not in self.messages:
                return httpx.Response(404, json={"error": {"code": "ErrorItemNotFound", "message": "gone"}})
            msg = self.messages[mid]
            if len(parts) == 3 and parts[2] == "$value":
                return httpx.Response(200, content=raw_mime(msg["subject"]), headers={"content-type": "text/plain"})
            if len(parts) == 3 and parts[2] == "move":
                msg["folder"] = body["destinationId"]
                self.touch(mid)
                return httpx.Response(201, json={"id": mid})
            if method == "PATCH":
                msg["categories"] = body["categories"]
                self.touch(mid)
                return httpx.Response(200, json={"id": mid})
            return httpx.Response(200, json={"id": mid, "categories": msg["categories"], "parentFolderId": msg["folder"]})
        return httpx.Response(400, json={"error": {"code": "BadRequest", "message": path}})

    def _page(self, items: list[dict[str, Any]], q: dict[str, str], url: str) -> httpx.Response:
        skip = int(q.get("$skip", "0"))
        page = items[skip: skip + self.PAGE]
        body: dict[str, Any] = {"value": page}
        if skip + self.PAGE < len(items):
            base = url.split("?")[0]
            body["@odata.nextLink"] = f"{base}?$skip={skip + self.PAGE}"
        return httpx.Response(200, json=body)

    def _delta(self, folder: str, q: dict[str, str]) -> httpx.Response:
        if "$filter" in q and self.reject_filter:
            return httpx.Response(400, json={"error": {"code": "ErrorInvalidUrlQueryFilter"}})
        since_seq = int(q.get("$deltatoken", "0"))
        if since_seq in {int(t) for t in self.reject_token if t.isdigit()}:
            return httpx.Response(410, json={"error": {"code": "SyncStateNotFound"}})
        offset = int(q.get("$skiptoken", "0"))
        if "$filter" in q:
            cutoff = datetime.fromisoformat(q["$filter"].split(" ge ")[1].replace("Z", "+00:00"))
        else:
            cutoff = None
        items = [
            {"id": k, "receivedDateTime": v["received"].strftime("%Y-%m-%dT%H:%M:%SZ"), "categories": v["categories"],
             "isDraft": v["draft"], "parentFolderId": v["folder"], "conversationId": f"conv-{k}"}
            for k, v in sorted(self.messages.items(), key=lambda kv: kv[1]["changed"])
            if v["folder"] == folder and v["changed"] > since_seq and (cutoff is None or v["received"] >= cutoff)
        ]
        removed = [{"id": "gone-1", "@removed": {"reason": "deleted"}}] if since_seq and offset == 0 else []
        page = (removed + items)[offset: offset + self.PAGE]
        base = f"{ME}mailFolders/{folder}/messages/delta"
        body: dict[str, Any] = {"value": page}
        if offset + self.PAGE < len(removed + items):
            body["@odata.nextLink"] = f"{base}?$skiptoken={offset + self.PAGE}&$deltatoken={since_seq}"
        else:
            body["@odata.deltaLink"] = f"{base}?$deltatoken={self.seq}"
        return httpx.Response(200, json=body)


class FakeOAuth:
    def __init__(self, fail: Exception | None = None) -> None:
        self.refreshed: list[str] = []
        self.fail = fail

    async def refresh(self, refresh_token: str) -> TokenSet:
        if self.fail:
            raise self.fail
        self.refreshed.append(refresh_token)
        return TokenSet(access_token=f"fresh-{len(self.refreshed)}", refresh_token="rt-2",
                        expires_at=NOW + timedelta(hours=1))


@pytest.fixture
def graph() -> FakeGraph:
    return FakeGraph()


def connector(graph: FakeGraph, *, oauth: FakeOAuth | None = None, labels=None, mode=ProtectionMode.SCAN,
              token: str = "at-1", expires: datetime | None = None, persisted: list | None = None):
    sleeps: list[float] = []

    async def sleep(s: float) -> None:
        sleeps.append(s)

    async def on_refreshed(tokens: TokenSet) -> None:
        if persisted is not None:
            persisted.append(tokens)

    conn = GraphMailConnector(
        "mbx_1", "Avery@Outlook.com",
        GoogleCredentials(access_token=token, refresh_token="rt-1", expires_at=expires or NOW + timedelta(hours=1)),
        oauth or FakeOAuth(), http=httpx.AsyncClient(transport=httpx.MockTransport(graph.handler)),
        labels=labels, mode=mode, sleep=sleep, rng=lambda: 0.0, clock=lambda: NOW, on_tokens_refreshed=on_refreshed,
    )
    conn.sleeps = sleeps  # type: ignore[attr-defined]
    return conn


def verdict(level: str) -> Verdict:
    return Verdict(level=VerdictLevel(level), score=0, summary="s", lane=TriageLane.DETONATE)


def raw(mid: str) -> RawMessage:
    return RawMessage(provider_message_id=mid, mailbox_id="mbx_1", received_at=NOW, raw=b"x")


# ---------------------------------------------------------------- setup


async def test_setup_scan_creates_folders_and_categories_idempotently(graph):
    conn = connector(graph)
    labels = await conn.setup(ProtectionMode.SCAN)
    root = graph.folder_id("Secureddy")
    assert labels[LABEL_ROOT] == root and labels[INBOX_KEY] == "inbox-id" and labels[CATEGORIES_KEY] == "1"
    assert graph.folders[labels[LABEL_PENDING]] == {"displayName": "Checking", "parent": root}
    assert graph.folders[labels[LABEL_QUARANTINE]] == {"displayName": "Quarantine", "parent": root}
    names = {c["displayName"]: c["color"] for c in graph.categories}
    assert names[SAFE] == "preset4" and names[SUSP] == "preset1" and names[QUAR] == "preset0" and names["Family"]
    assert not graph.rules and HOLD_RULE_KEY not in labels
    before = (len(graph.folders), len(graph.categories))
    again = await connector(graph).setup(ProtectionMode.SCAN)
    assert again == labels and (len(graph.folders), len(graph.categories)) == before


async def test_setup_hold_installs_exactly_one_rule_and_scan_removes_it(graph):
    conn = connector(graph)
    labels = await conn.setup(ProtectionMode.HOLD)
    (rule,) = graph.rules.values()
    assert rule["displayName"] == HOLD_RULE_NAME and rule["conditions"] == {} and rule["isEnabled"] is True
    assert rule["actions"]["moveToFolder"] == labels[LABEL_PENDING] and rule["sequence"] == 1
    assert labels[HOLD_RULE_KEY] == rule["id"]
    # a stale duplicate pointing elsewhere is cleaned up; the right one is kept
    graph.rules["rule-x"] = {"id": "rule-x", "displayName": HOLD_RULE_NAME, "actions": {"moveToFolder": "old"}}
    labels2 = await connector(graph, labels=labels).setup(ProtectionMode.HOLD)
    assert list(graph.rules) == [rule["id"]] and labels2[HOLD_RULE_KEY] == rule["id"]
    labels3 = await conn.setup(ProtectionMode.SCAN)
    assert not graph.rules and HOLD_RULE_KEY not in labels3
    graph.rules["r9"] = {"id": "r9", "displayName": HOLD_RULE_NAME, "actions": {}}
    await conn.teardown()
    assert not graph.rules


async def test_folder_create_race_409_is_resolved(graph):
    graph.fail.append(("POST", "mailFolders", httpx.Response(409, json={"error": {"code": "ErrorFolderExists"}})))
    graph.folders["fld-race"] = {"displayName": "secureddy", "parent": None}  # created by "someone else"
    graph.folders.pop("fld-race")
    conn = connector(graph)

    original = graph.handler

    def handler(request):  # the folder appears right after our POST fails
        resp = original(request)
        if resp.status_code == 409:
            graph.folders["fld-race"] = {"displayName": "Secureddy", "parent": None}
        return resp

    conn._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    labels = await conn.setup(ProtectionMode.SCAN)
    assert labels[LABEL_ROOT] == "fld-race"


async def test_folder_create_other_errors_propagate(graph):
    graph.fail.append(("POST", "mailFolders", httpx.Response(403, json={"error": {"code": "ErrorAccessDenied"}})))
    with pytest.raises(GraphApiError) as exc:
        await connector(graph).setup(ProtectionMode.SCAN)
    assert exc.value.status == 403 and exc.value.code == "ErrorAccessDenied"


async def test_409_without_folder_reraises_and_category_409_is_fine(graph):
    graph.fail.append(("POST", "mailFolders", httpx.Response(409, json={"error": {"code": "ErrorFolderExists"}})))
    with pytest.raises(GraphApiError):
        await connector(graph).setup(ProtectionMode.SCAN)
    graph.fail.append(("POST", "outlook/masterCategories", httpx.Response(409, json={})))
    await connector(graph).setup(ProtectionMode.SCAN)
    graph.fail.append(("POST", "outlook/masterCategories", httpx.Response(400, json={})))
    graph.categories = []
    with pytest.raises(GraphApiError):
        await connector(graph).setup(ProtectionMode.SCAN)


# ---------------------------------------------------------------- polling


async def test_delta_poll_paging_skips_ours_and_follows_delta_link(graph):
    conn = connector(graph)
    await conn.setup(ProtectionMode.HOLD)
    checking = conn.labels[LABEL_PENDING]
    a = graph.deliver("one")
    b = graph.deliver("two")
    c = graph.deliver("three")
    graph.deliver("old", minutes_ago=60 * 48)  # before we started watching
    graph.deliver("ours", categories=[SAFE])
    graph.deliver("draft", draft=True)
    held = graph.deliver("held", folder=checking)
    messages, cursor = await conn.poll(None)
    assert sorted(m.provider_message_id for m in messages) == sorted([a, b, c, held])
    one = next(m for m in messages if m.provider_message_id == a)
    assert b"Subject: one" in one.raw and one.thread_id == f"conv-{a}" and one.received_at < NOW
    state = json.loads(cursor)
    assert state["inbox"].endswith(f"$deltatoken={graph.seq}") and state["checking"] and state["since"]
    # idempotent: the same cursor gives the same (empty) set; new mail shows up
    assert (await conn.poll(cursor))[0] == []
    d = graph.deliver("four")
    graph.touch(next(k for k, v in graph.messages.items() if v["subject"] == "old"))  # read-flag change
    messages, cursor2 = await conn.poll(cursor)
    assert [m.provider_message_id for m in messages] == [d]
    again, _ = await conn.poll(cursor)
    assert [m.provider_message_id for m in again] == [d]


async def test_expired_delta_token_reseeds(graph):
    conn = connector(graph)
    await conn.setup(ProtectionMode.SCAN)
    graph.deliver("one")
    _, cursor = await conn.poll(None)
    graph.reject_token.add(str(graph.seq))
    new = graph.deliver("two")
    messages, _ = await conn.poll(cursor)
    assert new in [m.provider_message_id for m in messages]


async def test_delta_filter_refused_falls_back_to_full_sync(graph):
    graph.reject_filter = True
    conn = connector(graph)
    await conn.setup(ProtectionMode.SCAN)
    recent = graph.deliver("recent")
    graph.deliver("ancient", minutes_ago=60 * 24 * 30)
    messages, _ = await conn.poll(None)
    assert [m.provider_message_id for m in messages] == [recent]


async def test_delta_other_errors_propagate(graph):
    conn = connector(graph)
    await conn.setup(ProtectionMode.SCAN)
    graph.fail.append(("GET", "delta", httpx.Response(403, json={"error": {"code": "Forbidden"}})))
    with pytest.raises(GraphApiError):
        await conn.poll(None)
    _, cursor = await conn.poll(None)
    graph.fail.append(("GET", "delta", httpx.Response(403, json={"error": {"code": "Forbidden"}})))
    with pytest.raises(GraphApiError):
        await conn.poll(cursor)


async def test_garbage_cursor_and_vanished_message(graph):
    conn = connector(graph)
    await conn.setup(ProtectionMode.SCAN)
    mid = graph.deliver("soon gone")
    graph.fail.append(("GET", f"messages/{mid}/$value", httpx.Response(404, json={"error": {"code": "ErrorItemNotFound"}})))
    messages, _ = await conn.poll("not json")
    assert messages == []
    assert GraphMailConnector._parse_cursor("[1]") == {}
    graph.fail.append(("GET", f"messages/{mid}/$value", httpx.Response(403, json={})))
    with pytest.raises(GraphApiError):
        await conn.poll(None)


# ---------------------------------------------------------------- verdicts


@pytest.mark.parametrize(
    ("level", "mode", "expected_cats", "expected_folder"),
    [
        ("safe", ProtectionMode.SCAN, [SAFE], "inbox-id"),
        ("suspicious", ProtectionMode.SCAN, [SUSP], "inbox-id"),
        ("malicious", ProtectionMode.SCAN, [QUAR], "quarantine"),
        ("unknown", ProtectionMode.SCAN, [], "inbox-id"),
        ("safe", ProtectionMode.HOLD, [SAFE], "inbox-id"),
        ("suspicious", ProtectionMode.HOLD, [SUSP], "inbox-id"),
        ("malicious", ProtectionMode.HOLD, [QUAR], "quarantine"),
        ("unknown", ProtectionMode.HOLD, [], "inbox-id"),
    ],
)
async def test_apply_verdict_every_level_and_mode(graph, level, mode, expected_cats, expected_folder):
    conn = connector(graph, mode=mode)
    labels = await conn.setup(mode)
    start = labels[LABEL_PENDING] if mode is ProtectionMode.HOLD else "inbox-id"
    mid = graph.deliver("x", folder=start, categories=["Family"])
    await conn.apply_verdict(raw(mid), verdict(level), PolicyConfig(mode=mode))
    msg = graph.messages[mid]
    assert msg["categories"] == ["Family", *expected_cats]  # the client's own category stays
    folder = labels[LABEL_QUARANTINE] if expected_folder == "quarantine" else expected_folder
    assert msg["folder"] == folder


async def test_strict_policy_quarantines_suspicious_and_relabel_swaps(graph):
    conn = connector(graph)
    labels = await conn.setup(ProtectionMode.SCAN)
    mid = graph.deliver("x", categories=[SAFE])
    strict = PolicyConfig(quarantine_at=VerdictLevel.SUSPICIOUS)
    await conn.apply_verdict(raw(mid), verdict("suspicious"), strict, relabel=True)
    assert graph.messages[mid]["categories"] == [SUSP, QUAR] and graph.messages[mid]["folder"] == labels[LABEL_QUARANTINE]
    patches = sum(1 for c in graph.calls if c[0] == "PATCH")
    await conn.apply_verdict(raw(mid), verdict("suspicious"), strict, relabel=True)
    assert sum(1 for c in graph.calls if c[0] == "PATCH") == patches  # no-op when nothing changes


def test_category_plan():
    assert verdict_category_plan(VerdictLevel.SAFE, quarantine=False, relabel=True) == ([SAFE], [SUSP])
    assert verdict_category_plan(VerdictLevel.UNKNOWN, quarantine=False) == ([], [])
    assert verdict_category_plan(VerdictLevel.MALICIOUS, quarantine=True) == ([QUAR], [])


async def test_release_quarantine_restore_mark_safe(graph):
    conn = connector(graph, mode=ProtectionMode.HOLD)
    labels = await conn.setup(ProtectionMode.HOLD)
    mid = graph.deliver("x", folder=labels[LABEL_PENDING])
    await conn.release(mid)
    assert graph.messages[mid]["folder"] == "inbox-id"
    moves = sum(1 for c in graph.calls if c[1].endswith("/move"))
    await conn.release(mid)  # already in the inbox: no move
    assert sum(1 for c in graph.calls if c[1].endswith("/move")) == moves
    await conn.quarantine(mid)
    assert graph.messages[mid]["folder"] == labels[LABEL_QUARANTINE] and QUAR in graph.messages[mid]["categories"]
    await conn.restore(mid)
    assert graph.messages[mid]["folder"] == "inbox-id" and graph.messages[mid]["categories"] == [REL]
    graph.messages[mid]["categories"] = [SUSP, QUAR, "Family"]
    graph.messages[mid]["folder"] = labels[LABEL_QUARANTINE]
    await conn.mark_safe(mid)
    assert graph.messages[mid]["categories"] == ["Family", SAFE] and graph.messages[mid]["folder"] == "inbox-id"
    await conn.mark_safe(mid)  # idempotent
    assert graph.messages[mid]["categories"] == ["Family", SAFE]


async def test_release_all_pending_pages_then_moves(graph):
    conn = connector(graph, mode=ProtectionMode.HOLD)
    labels = await conn.setup(ProtectionMode.HOLD)
    held = [graph.deliver(f"h{i}", folder=labels[LABEL_PENDING]) for i in range(5)]
    graph.deliver("normal")
    assert await conn.release_all_pending() == 5
    assert all(graph.messages[m]["folder"] == "inbox-id" for m in held)
    assert await conn.release_all_pending() == 0


async def test_labels_seed_skips_lookups(graph):
    labels = await connector(graph).setup(ProtectionMode.SCAN)
    graph.calls.clear()
    conn = connector(graph, labels={**labels, "_mode": "scan", "junk": "x"})
    assert "junk" not in conn.labels
    mid = graph.deliver("x")
    await conn.release(mid)
    assert not any(c[1].startswith("mailFolders") for c in graph.calls)


# ---------------------------------------------------------------- auth, throttling


async def test_expired_token_refreshes_first_and_persists(graph):
    persisted: list[TokenSet] = []
    oauth = FakeOAuth()
    conn = connector(graph, oauth=oauth, expires=NOW - timedelta(minutes=1), persisted=persisted)
    await conn.setup(ProtectionMode.SCAN)
    assert oauth.refreshed == ["rt-1"] and persisted[0].refresh_token == "rt-2"
    assert set(graph.tokens) == {"fresh-1"}


async def test_401_refreshes_once_then_auth_expired(graph):
    oauth = FakeOAuth()
    graph.reject_token.add("at-1")
    conn = connector(graph, oauth=oauth)
    await conn.setup(ProtectionMode.SCAN)
    assert oauth.refreshed == ["rt-1"]
    graph.reject_token.add("fresh-1")
    graph.reject_token.add("fresh-2")
    with pytest.raises(AuthExpired, match="twice"):
        await conn.release(graph.deliver("x"))


async def test_invalid_grant_is_auth_expired(graph):
    conn = connector(graph, oauth=FakeOAuth(fail=AuthExpired("Microsoft rejected the grant: invalid_grant")),
                     expires=NOW - timedelta(minutes=5))
    with pytest.raises(AuthExpired, match="invalid_grant"):
        await conn.setup(ProtectionMode.SCAN)


async def test_no_refresh_token(graph):
    conn = connector(graph, expires=NOW - timedelta(minutes=5))
    conn.credentials = GoogleCredentials(access_token="", refresh_token=None)
    with pytest.raises(AuthExpired, match="no refresh token"):
        await conn.setup(ProtectionMode.SCAN)


async def test_429_honours_retry_after_and_503_backs_off(graph):
    conn = connector(graph)
    graph.fail.append(("GET", "mailFolders/inbox", httpx.Response(429, headers={"Retry-After": "7"}, json={})))
    graph.fail.append(("GET", "mailFolders/inbox", httpx.Response(503, headers={"Retry-After": "999"}, json={})))
    graph.fail.append(("GET", "mailFolders/inbox", httpx.Response(500, text="oops")))
    await conn.setup(ProtectionMode.SCAN)
    assert conn.sleeps[:3] == [7.0, 30.0, 2.0]  # Retry-After, capped Retry-After, exponential backoff


async def test_gives_up_after_max_tries(graph):
    conn = connector(graph)
    for _ in range(4):
        graph.fail.append(("GET", "mailFolders/inbox", httpx.Response(503, headers={"Retry-After": "soon"}, json={})))
    with pytest.raises(ConnectorError) as exc:
        await conn.setup(ProtectionMode.SCAN)
    assert exc.value.retryable and len(conn.sleeps) == 3


async def test_network_errors_retry_then_fail():
    def boom(request):
        raise httpx.ConnectError("down", request=request)

    conn = connector(FakeGraph())
    conn._http = httpx.AsyncClient(transport=httpx.MockTransport(boom))
    with pytest.raises(ConnectorError, match="network error"):
        await conn.fetch_raw("m")


async def test_non_json_and_list_bodies(graph):
    conn = connector(graph)
    graph.fail.append(("GET", "mailFolders/inbox", httpx.Response(200, text="<html>")))
    with pytest.raises(ConnectorError, match="non-JSON"):
        await conn.setup(ProtectionMode.SCAN)
    graph.fail.append(("GET", "outlook/masterCategories", httpx.Response(200, json=[])))
    graph.fail.append(("GET", "mailFolders/inbox", httpx.Response(200, json={"id": "inbox-id"})))
    await conn.setup(ProtectionMode.SCAN)
    graph.fail.append(("DELETE", "messageRules", httpx.Response(204)))
    graph.fail.append(("GET", "messages/", httpx.Response(400, text="plain error")))
    mid = graph.deliver("x")
    with pytest.raises(GraphApiError, match="plain error"):
        await conn.release(mid)


async def test_owned_client_lifecycle():
    conn = GraphMailConnector("m", "a@b.c", GoogleCredentials(access_token="t"), FakeOAuth())
    assert conn.http is conn.http
    await conn.aclose()
    assert conn._http is None

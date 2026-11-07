"""Search, archive, read/unread, trash, web link and revoke on every connector."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from reddysec.mail.base import MailActions, SearchHit, clean_query, split_from
from reddysec.mail.gmail import GmailApiError, GmailConnector, GoogleCredentials
from reddysec.mail.imap import ImapConnector, ImapCredentials, Location
from reddysec.mail.outlook_graph import GraphMailConnector
from reddysec.models import Provider

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)


def test_helpers():
    assert split_from('"Ann B" <Ann@X.com>') == ("Ann B", "ann@x.com")
    assert split_from(None) == ("", "")
    assert clean_query('  walmart  "receipt"\\ \x00 ') == "walmart receipt"
    assert len(clean_query("a" * 500)) == 200


class FakeOAuth:
    def __init__(self) -> None:
        self.revoked: list[str] = []

    async def revoke(self, token: str) -> None:
        self.revoked.append(token)

    async def refresh(self, token: str):  # pragma: no cover - tokens never expire here
        raise AssertionError("no refresh expected")


def gmail(handler, **creds) -> tuple[GmailConnector, FakeOAuth]:
    oauth = FakeOAuth()
    credentials = GoogleCredentials(
        access_token=creds.get("access", "acc"), refresh_token=creds.get("refresh", "ref"),
        expires_at=NOW + timedelta(days=3650),
    )
    c = GmailConnector("mbx", "Me@Gmail.com", credentials, oauth, http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))  # type: ignore[arg-type]
    return c, oauth


class TestGmail:
    async def test_search_reads_headers_and_skips_vanished(self):
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            path = request.url.path
            if path.endswith("/messages"):
                assert request.url.params["q"] == "walmart receipt"
                return httpx.Response(200, json={"messages": [{"id": "a"}, {"id": "gone"}]})
            if path.endswith("/messages/a"):
                assert request.url.params["format"] == "metadata"
                return httpx.Response(200, json={
                    "id": "a", "snippet": "Thanks " * 100, "internalDate": "1762344000000", "labelIds": ["INBOX", "UNREAD"],
                    "payload": {"headers": [{"name": "From", "value": "Walmart <Help@Walmart.com>"},
                                            {"name": "Subject", "value": "Receipt"}, "junk"]},
                })
            if path.endswith("/messages/gone"):
                return httpx.Response(404, json={"error": {"message": "gone", "errors": [{"reason": "notFound"}]}})
            return httpx.Response(500)

        c, _ = gmail(handler)
        hits = await c.search('walmart "receipt"', 50)
        assert hits == [SearchHit("a", "Walmart", "help@walmart.com", "Receipt",
                                  datetime.fromtimestamp(1762344000, UTC), ("Thanks " * 100)[:300], True)]
        assert await c.search("  ", 5) == []
        assert isinstance(c, MailActions)

    async def test_search_other_errors_propagate(self):
        def handler(request):
            if request.url.path.endswith("/messages"):
                return httpx.Response(200, json={"messages": [{"id": "a"}]})
            return httpx.Response(403, json={"error": {"message": "no", "errors": [{"reason": "forbidden"}]}})

        c, _ = gmail(handler)
        with pytest.raises(GmailApiError):
            await c.search("x")

    async def test_actions_and_link_and_revoke(self):
        calls: list[tuple[str, str, dict]] = []

        def handler(request):
            body = json.loads(request.content) if request.content else {}
            calls.append((request.method, request.url.path.rsplit("/me/", 1)[1], body))
            return httpx.Response(200, json={})

        c, oauth = gmail(handler)
        await c.archive("m1")
        await c.set_read("m1", True)
        await c.set_read("m1", False)
        await c.trash("m1")
        assert calls == [
            ("POST", "messages/m1/modify", {"removeLabelIds": ["INBOX"]}),
            ("POST", "messages/m1/modify", {"removeLabelIds": ["UNREAD"]}),
            ("POST", "messages/m1/modify", {"addLabelIds": ["UNREAD"]}),
            ("POST", "messages/m1/trash", {}),
        ]
        assert await c.web_link("m 1") == "https://mail.google.com/mail/?authuser=me%40gmail.com#all/m%201"
        assert await c.revoke() is True and oauth.revoked == ["ref"]
        c2, oauth2 = gmail(handler, refresh="", access="")
        assert await c2.revoke() is False and oauth2.revoked == []


def graph(handler) -> GraphMailConnector:
    creds = GoogleCredentials(access_token="t", refresh_token="r", expires_at=NOW + timedelta(days=3650))
    return GraphMailConnector("mbx", "me@outlook.com", creds, FakeOAuth(),  # type: ignore[arg-type]
                              http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))


class TestGraph:
    async def test_search(self):
        def handler(request):
            q = parse_qs(urlsplit(str(request.url)).query)
            assert q["$search"] == ['"pay invoice"'] and q["$top"] == ["25"]
            return httpx.Response(200, json={"value": [
                {"id": "g1", "subject": "Invoice", "from": {"emailAddress": {"name": "Bob", "address": "Bob@X.com"}},
                 "receivedDateTime": "2026-11-05T10:00:00Z", "bodyPreview": "Pay now", "isRead": False},
                {"id": "g2", "from": None, "isRead": True}, "junk", {"subject": "no id"},
            ]})

        c = graph(handler)
        hits = await c.search('pay "invoice"', 99)
        assert [h.provider_message_id for h in hits] == ["g1", "g2"]
        assert hits[0].from_address == "bob@x.com" and hits[0].unread and not hits[1].unread
        assert hits[0].received_at == datetime(2026, 11, 5, 10, tzinfo=UTC)
        assert await c.search("") == []

    async def test_actions(self):
        calls = []

        def handler(request):
            calls.append((request.method, request.url.path.rsplit("/me/", 1)[1],
                          json.loads(request.content) if request.content else None))
            if request.method == "GET":
                return httpx.Response(200, json={"webLink": "https://outlook.live.com/owa/?ItemID=x"})
            return httpx.Response(200, json={})

        c = graph(handler)
        await c.archive("g1")
        await c.trash("g1")
        await c.set_read("g1", True)
        assert calls == [
            ("POST", "messages/g1/move", {"destinationId": "archive"}),
            ("POST", "messages/g1/move", {"destinationId": "deleteditems"}),
            ("PATCH", "messages/g1", {"isRead": True}),
        ]
        assert (await c.web_link("g1")).startswith("https://outlook.live.com/owa/")
        assert await c.revoke() is False

    async def test_web_link_falls_back(self):
        c = graph(lambda r: httpx.Response(200, json={"webLink": "javascript:alert(1)"}))
        assert await c.web_link("g1") == "https://outlook.live.com/mail/"


RAW = (b"From: =?utf-8?q?Caf=C3=A9?= <cafe@example.com>\r\nSubject: Lunch order\r\n"
       b"Message-ID: <a@b>\r\n\r\nYour meal is ready\r\n")


def imap(server) -> ImapConnector:
    creds = ImapCredentials(username="client@yahoo.com", password="app-password")
    return ImapConnector("mbx", "client@yahoo.com", Provider.YAHOO, creds, session_factory=server.session)


class TestImap:
    async def test_search_newest_first_ascii_only(self, imap_server):
        imap_server.deliver("INBOX", RAW, date=NOW - timedelta(days=1), flags={"\\Seen"})
        imap_server.deliver("INBOX", RAW.replace(b"Lunch", b"Dinner"), date=NOW)
        imap_server.deliver("INBOX", b"Subject: other\r\n\r\nnothing\r\n")
        c = imap(imap_server)
        hits = await c.search("lunch é")
        assert [h.subject for h in hits] == ["Lunch order"]
        assert hits[0].from_name == "Café" and hits[0].from_address == "cafe@example.com" and not hits[0].unread
        both = await c.search("ready")
        assert [h.subject for h in both] == ["Dinner order", "Lunch order"] and both[0].unread
        assert await c.search("ééé") == []
        assert await c.web_link(both[0].provider_message_id) == "https://mail.yahoo.com/"
        assert await c.revoke() is False

    async def test_archive_trash_read(self, imap_server):
        uid = imap_server.deliver("INBOX", RAW)
        c = imap(imap_server)
        pid = str(Location("INBOX", 111, uid))
        await c.set_read(pid, True)
        assert "\\Seen" in imap_server.folders["INBOX"].messages[uid]["flags"]
        await c.set_read(pid, False)
        assert "\\Seen" not in imap_server.folders["INBOX"].messages[uid]["flags"]
        await c.archive(pid)  # no Archive folder yet: created
        assert "Archive" in imap_server.folders and len(imap_server.folders["Archive"].messages) == 1
        uid2 = imap_server.deliver("INBOX", RAW.replace(b"<a@b>", b"<c@d>"))
        imap_server.folders["Deleted Messages"] = type(imap_server.folders["INBOX"])(uidvalidity=5)
        await c.trash(str(Location("INBOX", 111, uid2)))
        assert len(imap_server.folders["Deleted Messages"].messages) == 1

    async def test_special_use_flag_wins_and_missing_message(self, imap_server):
        from reddysec.mail.base import ConnectorError
        from reddysec.mail.imap import FolderInfo

        c = imap(imap_server)

        class Sess:
            def list_folders(self):
                return [FolderInfo("Bin", "/", frozenset({"\\Trash"})), FolderInfo("Trash", "/")]

        assert c._special_folder(Sess(), "\\Trash", ("Trash",)) == "Bin"  # type: ignore[arg-type]
        with pytest.raises(ConnectorError):
            await c.archive("INBOX:111:999")

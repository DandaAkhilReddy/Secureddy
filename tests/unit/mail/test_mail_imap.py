"""ImapConnector against the in-memory IMAP server, and ImaplibSession parsing
against a scripted stand-in for imaplib.IMAP4_SSL."""

from __future__ import annotations

import imaplib
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from reddysec.mail.base import (
    ALL_LABELS,
    LABEL_PENDING,
    LABEL_QUARANTINE,
    LABEL_ROOT,
    AuthExpired,
    ConnectorError,
)
from reddysec.mail.imap import (
    IMAP_PRESETS,
    INSTRUCTIONS_KEY,
    KEYWORD_RELEASED,
    KEYWORD_SAFE,
    KEYWORD_SUSPICIOUS,
    FetchedMessage,
    ImapAuthError,
    ImapConnector,
    ImapCredentials,
    ImaplibSession,
    Location,
    hold_instructions,
    parse_cursor,
    parse_internaldate,
    resolve_endpoint,
    xoauth2_string,
)
from reddysec.models import (
    PolicyConfig,
    ProtectionMode,
    Provider,
    RawMessage,
    TriageLane,
    Verdict,
    VerdictLevel,
)

from .conftest import FIXED_NOW, FakeImapServer, sample_raw

CREDS = ImapCredentials(username="client@yahoo.com", password="app-password")


def verdict(level: VerdictLevel) -> Verdict:
    return Verdict(level=level, score=50, summary="s", lane=TriageLane.DETONATE)


def connector(server: FakeImapServer, mode: ProtectionMode = ProtectionMode.SCAN, **kw: Any) -> ImapConnector:
    return ImapConnector(
        "mbx_1", "client@yahoo.com", Provider.YAHOO, CREDS, session_factory=server.session, mode=mode, **kw
    )


def checking(server: FakeImapServer) -> str:
    return server.folder_path(LABEL_PENDING)


def quarantine(server: FakeImapServer) -> str:
    return server.folder_path(LABEL_QUARANTINE)


class TestPresetsAndCredentials:
    def test_presets(self):
        assert resolve_endpoint(Provider.YAHOO, CREDS) == ("imap.mail.yahoo.com", 993)
        assert resolve_endpoint(Provider.ICLOUD, CREDS) == ("imap.mail.me.com", 993)
        assert resolve_endpoint(Provider.OUTLOOK, CREDS) == ("outlook.office365.com", 993)
        custom = ImapCredentials(username="u", password="p", host="mail.example.com", port=1993)
        assert resolve_endpoint(Provider.GENERIC_IMAP, custom) == ("mail.example.com", 1993)
        assert resolve_endpoint(
            Provider.GENERIC_IMAP, ImapCredentials(username="u", password="p", host="h")
        ) == ("h", 993)
        with pytest.raises(ValueError, match="explicit IMAP host"):
            resolve_endpoint(Provider.GENERIC_IMAP, CREDS)
        assert set(IMAP_PRESETS) == {Provider.YAHOO, Provider.ICLOUD, Provider.OUTLOOK}

    def test_credentials_require_a_secret(self):
        with pytest.raises(ValueError):
            ImapCredentials(username="u")
        creds = ImapCredentials.from_secret(
            {"username": "u", "oauth_access_token": "tok", "extra": "ignored"}
        )
        assert creds.oauth_access_token == "tok" and creds.password is None

    def test_xoauth2_string(self):
        assert xoauth2_string("u@y.com", "tok") == b"user=u@y.com\x01auth=Bearer tok\x01\x01"

    def test_default_session_factory_is_imaplib_backed(self):
        c = ImapConnector("m", "a@yahoo.com", Provider.YAHOO, CREDS)
        assert c._session_factory is not None  # real sessions are created lazily per operation

    def test_location_parse(self):
        loc = Location.parse("Secureddy/Checking:1001:42")
        assert (loc.folder, loc.uidvalidity, loc.uid) == ("Secureddy/Checking", 1001, 42)
        assert str(loc) == "Secureddy/Checking:1001:42"
        with pytest.raises(ConnectorError) as info:
            Location.parse("gmail-style-id")
        assert not info.value.retryable

    def test_parse_cursor(self):
        assert parse_cursor(None, 2) == [None, None]
        assert parse_cursor("111:5", 2)[0].last_uid == 5 and parse_cursor("111:5", 2)[1] is None
        assert [c.uidvalidity for c in parse_cursor("111:5|222:9", 2)] == [111, 222]
        assert parse_cursor("garbage", 1) == [None]
        assert parse_cursor("111:5|222:9", 1)[0].uidvalidity == 111  # extra parts ignored

    def test_parse_internaldate(self):
        assert parse_internaldate("05-Nov-2026 10:20:30 -0800") == datetime(
            2026, 11, 5, 18, 20, 30, tzinfo=UTC
        )
        assert parse_internaldate(" 5-Nov-2026 10:20:30 +0000") == datetime(
            2026, 11, 5, 10, 20, 30, tzinfo=UTC
        )


class TestSetup:
    async def test_creates_folder_tree_root_first_and_is_idempotent(self, imap_server: FakeImapServer):
        c = connector(imap_server)
        folders = await c.setup(ProtectionMode.SCAN)
        created = [args[0] for name, args in imap_server.calls if name == "create"]
        assert created == ALL_LABELS  # "/" delimiter: identical to the label names
        assert created[0] == LABEL_ROOT
        assert folders == {name: name for name in ALL_LABELS}
        assert INSTRUCTIONS_KEY not in folders
        imap_server.calls.clear()
        assert await c.setup(ProtectionMode.SCAN) == folders
        assert not [1 for name, _ in imap_server.calls if name == "create"]
        assert imap_server.logouts == 2  # one connection per operation batch

    async def test_uses_server_delimiter(self):
        server = FakeImapServer(delimiter=".")
        folders = await connector(server).setup(ProtectionMode.HOLD)
        assert folders[LABEL_PENDING] == "Secureddy.Checking"
        assert "Secureddy.Checking" in server.folders
        assert "Secureddy.Checking" in folders[INSTRUCTIONS_KEY]

    @pytest.mark.parametrize(
        ("provider", "needle"),
        [
            (Provider.YAHOO, "Yahoo Mail"),
            (Provider.ICLOUD, "iCloud"),
            (Provider.OUTLOOK, "Outlook.com"),
            (Provider.GENERIC_IMAP, "server-side rule"),
        ],
    )
    def test_hold_instructions_per_provider(self, provider: Provider, needle: str):
        text = hold_instructions(provider, "Secureddy/Checking")
        assert needle in text and "Secureddy/Checking" in text

    async def test_hold_setup_returns_instructions(self, imap_server: FakeImapServer):
        result = await connector(imap_server).setup(ProtectionMode.HOLD)
        assert "Filters" in result[INSTRUCTIONS_KEY] and "app password" in result[INSTRUCTIONS_KEY]

    async def test_teardown_is_noop_with_instructions(self, imap_server: FakeImapServer):
        c = connector(imap_server)
        await c.setup(ProtectionMode.HOLD)
        imap_server.calls.clear()
        await c.teardown()
        assert imap_server.calls == []
        assert "Secureddy/Checking" in c.teardown_instructions()


class TestPoll:
    async def test_first_poll_returns_recent_and_sets_cursor(self, imap_server: FakeImapServer):
        for i in range(60):
            imap_server.deliver(
                "INBOX",
                sample_raw(f"m{i}"),
                date=FIXED_NOW - timedelta(minutes=60 - i),
                flags={"\\Seen"} if i == 0 else None,
            )
        c = connector(imap_server, recent_limit=50)
        messages, cursor = await c.poll(None)
        assert len(messages) == 50
        assert messages[0].provider_message_id == "INBOX:111:11"
        assert messages[-1].provider_message_id == "INBOX:111:60"
        assert cursor == "111:60"
        last = messages[-1]
        assert last.raw == sample_raw("m59")
        assert last.received_at == FIXED_NOW - timedelta(minutes=1)
        assert last.provider_labels == ["INBOX"]
        assert last.thread_id is None
        assert last.mailbox_id == "mbx_1"

    async def test_incremental_poll_filters_star_quirk(self, imap_server: FakeImapServer):
        imap_server.deliver("INBOX", sample_raw("a"))
        c = connector(imap_server)
        _, cursor = await c.poll(None)
        assert cursor == "111:1"
        again, cursor2 = await c.poll(cursor)
        assert again == [] and cursor2 == "111:1"  # the server returned uid 1 for "UID 2:*"; we ignored it
        assert ("search", ("UID 2:*",)) in imap_server.calls
        imap_server.deliver("INBOX", sample_raw("b"), flags={"\\Flagged"})
        new, cursor3 = await c.poll(cursor2)
        assert [m.provider_message_id for m in new] == ["INBOX:111:2"] and cursor3 == "111:2"
        assert new[0].provider_labels == ["INBOX", "\\Flagged"]

    async def test_poll_is_idempotent(self, imap_server: FakeImapServer):
        imap_server.deliver("INBOX", sample_raw("a"))
        c = connector(imap_server)
        _, cursor = await c.poll(None)
        imap_server.deliver("INBOX", sample_raw("b"))
        first = await c.poll(cursor)
        second = await c.poll(cursor)
        assert (
            [m.provider_message_id for m in first[0]]
            == [m.provider_message_id for m in second[0]]
            == ["INBOX:111:2"]
        )
        assert first[1] == second[1]

    async def test_uidvalidity_change_resyncs(self, imap_server: FakeImapServer):
        imap_server.deliver("INBOX", sample_raw("a"))
        c = connector(imap_server, recent_limit=2)
        _, cursor = await c.poll(None)
        # Server rebuilt the folder: new UIDVALIDITY, uids start again.
        imap_server.folders["INBOX"].uidvalidity = 999
        imap_server.folders["INBOX"].messages.clear()
        imap_server.folders["INBOX"].uidnext = 1
        for s in ("x", "y", "z"):
            imap_server.deliver("INBOX", sample_raw(s))
        messages, cursor2 = await c.poll(cursor)
        assert [m.provider_message_id for m in messages] == ["INBOX:999:2", "INBOX:999:3"]
        assert cursor2 == "999:3"

    async def test_empty_folder_cursor_uses_uidnext(self, imap_server: FakeImapServer):
        messages, cursor = await connector(imap_server).poll(None)
        assert messages == [] and cursor == "111:0"

    async def test_hold_polls_checking_folder_with_composite_cursor(self, imap_server: FakeImapServer):
        c = connector(imap_server, ProtectionMode.HOLD)
        await c.setup(ProtectionMode.HOLD)
        chk = checking(imap_server)
        imap_server.deliver("INBOX", sample_raw("inbox"))
        imap_server.deliver(chk, sample_raw("held"))
        uv = imap_server.folders[chk].uidvalidity
        messages, cursor = await c.poll("111:0")  # a SCAN-era cursor: only the inbox part exists
        assert [m.provider_message_id for m in messages] == ["INBOX:111:1", f"{chk}:{uv}:1"]
        assert cursor == f"111:1|{uv}:1"
        imap_server.deliver(chk, sample_raw("held2"))
        more, cursor2 = await c.poll(cursor)
        assert [m.provider_message_id for m in more] == [f"{chk}:{uv}:2"]
        assert cursor2 == f"111:1|{uv}:2"
        # back to SCAN: the inbox part is reused, the checking part dropped
        c.mode = ProtectionMode.SCAN
        none, cursor3 = await c.poll(cursor2)
        assert none == [] and cursor3 == "111:1"


class TestApplyVerdict:
    async def polled(
        self, c: ImapConnector, server: FakeImapServer, folder: str = "INBOX", subject: str = "m"
    ) -> RawMessage:
        server.deliver(folder, sample_raw(subject))
        messages, _ = await c.poll(None)
        return next(m for m in messages if m.provider_message_id.startswith(folder + ":"))

    async def test_safe_in_scan_sets_keyword_and_stays(self, imap_server: FakeImapServer):
        c = connector(imap_server)
        await c.setup(ProtectionMode.SCAN)
        raw = await self.polled(c, imap_server)
        await c.apply_verdict(raw, verdict(VerdictLevel.SAFE), PolicyConfig())
        assert imap_server.folders["INBOX"].messages[1]["flags"] == {KEYWORD_SAFE}
        assert not [1 for name, _ in imap_server.calls if name in ("move", "copy")]

    async def test_suspicious_keyword_and_strict_policy_quarantines(self, imap_server: FakeImapServer):
        c = connector(imap_server)
        await c.setup(ProtectionMode.SCAN)
        raw = await self.polled(c, imap_server)
        await c.apply_verdict(raw, verdict(VerdictLevel.SUSPICIOUS), PolicyConfig())
        assert imap_server.folders["INBOX"].messages[1]["flags"] == {KEYWORD_SUSPICIOUS}
        await c.apply_verdict(
            raw, verdict(VerdictLevel.SUSPICIOUS), PolicyConfig(quarantine_at=VerdictLevel.SUSPICIOUS)
        )
        assert imap_server.folders["INBOX"].messages == {}
        moved = imap_server.folders[quarantine(imap_server)].messages
        assert len(moved) == 1 and KEYWORD_SUSPICIOUS in next(iter(moved.values()))["flags"]

    async def test_malicious_moves_to_quarantine_with_move(self, imap_server: FakeImapServer):
        c = connector(imap_server)
        await c.setup(ProtectionMode.SCAN)
        raw = await self.polled(c, imap_server)
        await c.apply_verdict(raw, verdict(VerdictLevel.MALICIOUS), PolicyConfig())
        assert imap_server.folders["INBOX"].messages == {}
        assert len(imap_server.folders[quarantine(imap_server)].messages) == 1
        assert ("move", (1, quarantine(imap_server))) in imap_server.calls
        # applying again finds it by Message-ID already in Quarantine: no second move
        imap_server.calls.clear()
        await c.apply_verdict(raw, verdict(VerdictLevel.MALICIOUS), PolicyConfig())
        assert not [1 for name, _ in imap_server.calls if name == "move"]

    async def test_without_move_capability_uses_copy_delete_uid_expunge(self):
        server = FakeImapServer(capabilities={"IMAP4REV1", "UIDPLUS"})
        c = connector(server)
        await c.setup(ProtectionMode.SCAN)
        raw = await self.polled(c, server)
        await c.apply_verdict(raw, verdict(VerdictLevel.MALICIOUS), PolicyConfig())
        names = [name for name, _ in server.calls]
        assert "copy" in names and "uid_expunge" in names and "expunge" not in names and "move" not in names
        assert ("store", (1, "+FLAGS", ("\\Deleted",))) in server.calls
        assert server.folders["INBOX"].messages == {}
        assert len(server.folders[quarantine(server)].messages) == 1

    async def test_without_uidplus_falls_back_to_expunge(self):
        server = FakeImapServer(capabilities={"IMAP4REV1"})
        c = connector(server)
        await c.setup(ProtectionMode.SCAN)
        raw = await self.polled(c, server)
        await c.apply_verdict(raw, verdict(VerdictLevel.MALICIOUS), PolicyConfig())
        assert ("expunge", ()) in server.calls
        assert server.folders["INBOX"].messages == {}

    async def test_keywords_skipped_when_server_forbids_them(self):
        server = FakeImapServer(permanent_flags={"\\Seen", "\\Deleted"})
        c = connector(server)
        await c.setup(ProtectionMode.SCAN)
        raw = await self.polled(c, server)
        await c.apply_verdict(raw, verdict(VerdictLevel.SAFE), PolicyConfig())
        assert server.folders["INBOX"].messages[1]["flags"] == set()
        assert not [1 for name, _ in server.calls if name == "store"]

    async def test_hold_release_moves_checking_to_inbox(self, imap_server: FakeImapServer):
        c = connector(imap_server, ProtectionMode.HOLD)
        await c.setup(ProtectionMode.HOLD)
        chk = checking(imap_server)
        raw = await self.polled(c, imap_server, folder=chk, subject="held")
        await c.apply_verdict(raw, verdict(VerdictLevel.SAFE), PolicyConfig(mode=ProtectionMode.HOLD))
        assert imap_server.folders[chk].messages == {}
        (msg,) = imap_server.folders["INBOX"].messages.values()
        assert KEYWORD_SAFE in msg["flags"]
        # UNKNOWN: released without a keyword
        raw2 = await self.polled(c, imap_server, folder=chk, subject="held2")
        await c.apply_verdict(raw2, verdict(VerdictLevel.UNKNOWN), PolicyConfig())  # connector mode wins
        assert imap_server.folders[chk].messages == {}
        assert len(imap_server.folders["INBOX"].messages) == 2
        # MALICIOUS held mail goes straight to Quarantine
        raw3 = await self.polled(c, imap_server, folder=chk, subject="held3")
        await c.apply_verdict(raw3, verdict(VerdictLevel.MALICIOUS), PolicyConfig(mode=ProtectionMode.HOLD))
        assert len(imap_server.folders[quarantine(imap_server)].messages) == 1
        assert len(imap_server.folders["INBOX"].messages) == 2

    async def test_missing_message_is_permanent_error(self, imap_server: FakeImapServer):
        c = connector(imap_server)
        await c.setup(ProtectionMode.SCAN)
        raw = RawMessage(
            provider_message_id="INBOX:111:77", mailbox_id="mbx_1", received_at=FIXED_NOW, raw=b"no headers"
        )
        with pytest.raises(ConnectorError, match="not found") as info:
            await c.apply_verdict(raw, verdict(VerdictLevel.SAFE), PolicyConfig())
        assert not info.value.retryable


class TestRelocate:
    async def test_release_only_moves_held_messages(self, imap_server: FakeImapServer):
        c = connector(imap_server, ProtectionMode.HOLD)
        await c.setup(ProtectionMode.HOLD)
        chk = checking(imap_server)
        imap_server.deliver(chk, sample_raw("held"))
        imap_server.deliver("INBOX", sample_raw("inbox"))
        uv = imap_server.folders[chk].uidvalidity
        await c.release(f"{chk}:{uv}:1")
        assert imap_server.folders[chk].messages == {} and len(imap_server.folders["INBOX"].messages) == 2
        imap_server.calls.clear()
        await c.release("INBOX:111:1")  # already in the inbox: nothing moves
        assert not [1 for name, _ in imap_server.calls if name == "move"]

    async def test_quarantine_and_restore_after_move_via_resolver(self, imap_server: FakeImapServer):
        resolved: list[str] = []

        async def resolver(pid: str) -> str | None:
            resolved.append(pid)
            return "<m@example.com>"

        c = connector(imap_server, message_id_resolver=resolver)
        await c.setup(ProtectionMode.SCAN)
        imap_server.deliver("INBOX", sample_raw("m", message_id="<m@example.com>"))
        imap_server.deliver("INBOX", sample_raw("other", message_id="<other@example.com>"))
        await c.quarantine("INBOX:111:1")
        q = quarantine(imap_server)
        assert list(imap_server.folders["INBOX"].messages) == [2]
        assert len(imap_server.folders[q].messages) == 1
        assert resolved == ["INBOX:111:1"]  # resolver consulted once, before the batch
        # The DB still knows the message as INBOX:111:1; restore must find it in Quarantine.
        await c.restore("INBOX:111:1")
        assert imap_server.folders[q].messages == {}
        restored = [
            m for m in imap_server.folders["INBOX"].messages.values() if b"<m@example.com>" in m["raw"]
        ]
        assert len(restored) == 1 and KEYWORD_RELEASED in restored[0]["flags"]
        assert ("search", ('HEADER Message-ID "<m@example.com>"',)) in imap_server.calls

    async def test_moved_message_without_resolver_is_not_found(self, imap_server: FakeImapServer):
        c = connector(imap_server)
        await c.setup(ProtectionMode.SCAN)
        imap_server.deliver("INBOX", sample_raw("m"))
        await c.quarantine("INBOX:111:1")
        with pytest.raises(ConnectorError, match="not found") as info:
            await c.restore("INBOX:111:1")
        assert not info.value.retryable

    async def test_resolver_failure_is_tolerated(self, imap_server: FakeImapServer):
        async def resolver(pid: str) -> str | None:
            raise RuntimeError("db down")

        c = connector(imap_server, message_id_resolver=resolver)
        await c.setup(ProtectionMode.SCAN)
        imap_server.deliver("INBOX", sample_raw("m"))
        await c.quarantine("INBOX:111:1")  # the message is still at its location: no resolver needed
        assert imap_server.folders["INBOX"].messages == {}

    async def test_fetch_raw(self, imap_server: FakeImapServer):
        c = connector(imap_server)
        imap_server.deliver("INBOX", sample_raw("m"))
        assert await c.fetch_raw("INBOX:111:1") == sample_raw("m")
        with pytest.raises(ConnectorError, match="not found"):
            await c.fetch_raw("INBOX:111:9")

    async def test_release_all_pending(self, imap_server: FakeImapServer):
        c = connector(imap_server, ProtectionMode.HOLD)
        await c.setup(ProtectionMode.HOLD)
        chk = checking(imap_server)
        for s in ("a", "b", "c"):
            imap_server.deliver(chk, sample_raw(s))
        assert await c.release_all_pending() == 3
        assert imap_server.folders[chk].messages == {} and len(imap_server.folders["INBOX"].messages) == 3
        assert await c.release_all_pending() == 0

    async def test_folders_from_mailbox_row_skip_discovery(self, imap_server: FakeImapServer):
        await connector(imap_server).setup(ProtectionMode.SCAN)
        imap_server.calls.clear()
        c = connector(imap_server, folders={name: name for name in ALL_LABELS} | {"_mode": "scan"})
        imap_server.deliver("INBOX", sample_raw("m"))
        await c.quarantine("INBOX:111:1")
        assert not [1 for name, _ in imap_server.calls if name == "list"]


class TestErrors:
    async def test_login_failure_is_auth_expired(self, imap_server: FakeImapServer):
        imap_server.fail_auth = True
        with pytest.raises(AuthExpired, match="login rejected"):
            await connector(imap_server).poll(None)
        assert imap_server.logouts == 1  # connection closed even on failure

    async def test_wrong_password_is_auth_expired(self, imap_server: FakeImapServer):
        bad = ImapCredentials(username="client@yahoo.com", password="wrong")
        c = ImapConnector("m", "client@yahoo.com", Provider.YAHOO, bad, session_factory=imap_server.session)
        with pytest.raises(AuthExpired):
            await c.poll(None)

    async def test_xoauth2_is_used_when_token_present(self, imap_server: FakeImapServer):
        creds = ImapCredentials(username="client@yahoo.com", oauth_access_token="ya29.x")
        c = ImapConnector("m", "client@yahoo.com", Provider.YAHOO, creds, session_factory=imap_server.session)
        await c.poll(None)
        assert imap_server.auth_log == [("xoauth2", "client@yahoo.com", "ya29.x")]
        imap_server.fail_auth = True
        with pytest.raises(AuthExpired):
            await c.poll(None)

    async def test_connection_and_protocol_errors_are_retryable(self, imap_server: FakeImapServer):
        imap_server.factory_error = OSError("connection refused")
        with pytest.raises(ConnectorError, match="connection failed") as info:
            await connector(imap_server).poll(None)
        assert info.value.retryable
        imap_server.factory_error = None
        imap_server.raise_on["select"] = imaplib.IMAP4.error("NO server busy")
        with pytest.raises(ConnectorError, match="IMAP failure") as info:
            await connector(imap_server).poll(None)
        assert info.value.retryable
        imap_server.raise_on["select"] = OSError("reset by peer")
        with pytest.raises(ConnectorError) as info:
            await connector(imap_server).poll(None)
        assert info.value.retryable

    async def test_locate_tolerates_missing_folders(self, imap_server: FakeImapServer):
        async def resolver(pid: str) -> str | None:
            return "<m@example.com>"

        c = connector(imap_server, message_id_resolver=resolver)
        await c.setup(ProtectionMode.SCAN)
        imap_server.deliver("INBOX", sample_raw("m", message_id="<m@example.com>"))
        del imap_server.folders[quarantine(imap_server)]  # client deleted our folder
        await c.release(
            "Gone/Folder:1:1"
        )  # recorded folder is gone; found by Message-ID in INBOX; not held -> no-op
        assert len(imap_server.folders["INBOX"].messages) == 1


# ------------------------------------------------------- imaplib adapter tests
class FakeImap4:
    """Scripted stand-in for imaplib.IMAP4_SSL: records commands, returns canned data."""

    def __init__(self, host: str, port: int, *, timeout: float) -> None:
        self.host, self.port, self.timeout = host, port, timeout
        self.commands: list[tuple[Any, ...]] = []
        self.capabilities = ("IMAP4REV1", "move", "UIDPLUS")
        self.responses: dict[str, list[Any]] = {
            "UIDVALIDITY": [b"4242"],
            "UIDNEXT": [b"17"],
            "PERMANENTFLAGS": [b"(\\Answered \\Flagged \\Deleted \\Seen \\*)"],
        }
        self.login_ok = True
        self.fail_commands: set[str] = set()
        self.fetch_data: list[Any] = [
            (b'1 (UID 5 INTERNALDATE "05-Nov-2026 10:20:30 +0000" RFC822 {12}', b"From: a@b\r\n\r\n"),
            b" FLAGS (\\Seen $ReddySafe))",
            (b'2 (UID 6 FLAGS () INTERNALDATE "05-Nov-2026 11:00:00 -0100" RFC822 {3}', b"xyz"),
            b")",
            b"garbage-without-record-start",
        ]
        self.list_data: list[Any] = [
            b'(\\HasNoChildren) "/" INBOX',
            b'(\\HasChildren \\Noselect) "/" "Secureddy"',
            (b'(\\HasNoChildren) "/" {23}', b"Secureddy/Checking"),
            b'(\\Noinferiors) NIL "Weird \\"quoted\\""',
            None,
            b"unparseable line",
        ]

    def _result(self, name: str, data: list[Any]) -> tuple[str, list[Any]]:
        if name in self.fail_commands:
            return "NO", [b"[CANNOT] nope"]
        return "OK", data

    def login(self, user: str, password: str) -> tuple[str, list[Any]]:
        self.commands.append(("LOGIN", user, password))
        if not self.login_ok:
            raise imaplib.IMAP4.error("[AUTHENTICATIONFAILED] Invalid credentials (Failure)")
        return "OK", [b"LOGIN completed"]

    def authenticate(self, mechanism: str, authobject: Any) -> tuple[str, list[Any]]:
        self.commands.append(("AUTHENTICATE", mechanism, authobject(b"")))
        if not self.login_ok:
            raise imaplib.IMAP4.error("[AUTHENTICATIONFAILED] bad token")
        return "OK", [b"Success"]

    def list(self) -> tuple[str, list[Any]]:
        self.commands.append(("LIST",))
        return self._result("LIST", self.list_data)

    def create(self, mailbox: str) -> tuple[str, list[Any]]:
        self.commands.append(("CREATE", mailbox))
        return self._result("CREATE", [b"CREATE completed"])

    def select(self, mailbox: str, readonly: bool = False) -> tuple[str, list[Any]]:
        self.commands.append(("SELECT", mailbox))
        return self._result("SELECT", [b"3"])

    def response(self, code: str) -> tuple[str, list[Any]]:
        return code, self.responses.get(code, [None])

    def uid(self, command: str, *args: Any) -> tuple[str, list[Any]]:
        self.commands.append(("UID", command, *args))
        if command == "SEARCH":
            return self._result("SEARCH", [b"3 1 2"] if "EMPTY" not in args[0] else [b""])
        if command == "FETCH":
            return self._result("FETCH", self.fetch_data)
        return self._result(command, [b"OK"])

    def expunge(self) -> tuple[str, list[Any]]:
        self.commands.append(("EXPUNGE",))
        return self._result("EXPUNGE", [b"1"])

    def logout(self) -> tuple[str, list[Any]]:
        self.commands.append(("LOGOUT",))
        if "LOGOUT" in self.fail_commands:
            raise imaplib.IMAP4.error("already closed")
        return "BYE", [b"bye"]


@pytest.fixture
def imaplib_session() -> tuple[ImaplibSession, FakeImap4]:
    holder: dict[str, FakeImap4] = {}

    def factory(host: str, port: int, *, timeout: float) -> FakeImap4:
        holder["conn"] = FakeImap4(host, port, timeout=timeout)
        return holder["conn"]

    session = ImaplibSession("imap.mail.yahoo.com", 993, timeout=12.0, connection_factory=factory)
    return session, holder["conn"]


class TestImaplibSession:
    def test_connection_parameters(self, imaplib_session):
        _session, conn = imaplib_session
        assert (conn.host, conn.port, conn.timeout) == ("imap.mail.yahoo.com", 993, 12.0)

    def test_login_and_xoauth2(self, imaplib_session):
        session, conn = imaplib_session
        session.login("u", "p")
        session.authenticate_xoauth2("u", "tok")
        assert conn.commands == [
            ("LOGIN", "u", "p"),
            ("AUTHENTICATE", "XOAUTH2", b"user=u\x01auth=Bearer tok\x01\x01"),
        ]
        conn.login_ok = False
        with pytest.raises(ImapAuthError):
            session.login("u", "p")
        with pytest.raises(ImapAuthError):
            session.authenticate_xoauth2("u", "tok")

    def test_capabilities_are_uppercased(self, imaplib_session):
        session, _conn = imaplib_session
        assert session.capabilities() == frozenset({"IMAP4REV1", "MOVE", "UIDPLUS"})

    def test_list_folders_parsing(self, imaplib_session):
        session, _conn = imaplib_session
        folders = session.list_folders()
        assert [(f.name, f.delimiter) for f in folders] == [
            ("INBOX", "/"),
            ("Secureddy", "/"),
            ("Secureddy/Checking", "/"),
            ('Weird "quoted"', "/"),
        ]
        assert "\\Noselect" in folders[1].flags

    def test_select_parses_untagged_responses(self, imaplib_session):
        session, conn = imaplib_session
        info = session.select("Secureddy/Checking")
        assert (info.uidvalidity, info.uidnext, info.exists) == (4242, 17, 3)
        assert info.allows_keywords and "\\Deleted" in info.permanent_flags
        assert conn.commands[-1] == ("SELECT", "Secureddy/Checking")
        conn.responses = {}
        info = session.select("INBOX")
        assert (info.uidvalidity, info.uidnext, info.permanent_flags) == (0, 0, frozenset())
        assert not info.allows_keywords

    def test_search_and_fetch_parsing(self, imaplib_session):
        session, conn = imaplib_session
        assert session.uid_search("UID 2:*") == [1, 2, 3]
        assert conn.commands[-1] == ("UID", "SEARCH", "UID 2:*")
        assert session.uid_search("EMPTY") == []
        assert session.uid_fetch([]) == []
        messages = session.uid_fetch([5, 6])
        assert conn.commands[-1] == ("UID", "FETCH", "5,6", "(UID INTERNALDATE FLAGS RFC822)")
        assert [m.uid for m in messages] == [5, 6]
        assert messages[0].raw == b"From: a@b\r\n\r\n"
        assert messages[0].flags == frozenset({"\\Seen", "$ReddySafe"})  # flags came after the literal
        assert messages[0].internal_date == datetime(2026, 11, 5, 10, 20, 30, tzinfo=UTC)
        assert messages[1].internal_date == datetime(2026, 11, 5, 12, 0, 0, tzinfo=UTC)
        assert messages[1].flags == frozenset()
        assert isinstance(messages[0], FetchedMessage)

    def test_fetch_without_internaldate_or_uid(self, imaplib_session):
        session, conn = imaplib_session
        conn.fetch_data = [(b"1 (UID 9 RFC822 {1}", b"x"), (b"2 (RFC822 {1}", b"y")]
        (only,) = session.uid_fetch([9])
        assert only.uid == 9 and only.internal_date.tzinfo is UTC

    def test_mutating_commands_and_quoting(self, imaplib_session):
        session, conn = imaplib_session
        session.create_folder("Secureddy")
        session.uid_store(5, "+FLAGS", ["\\Deleted", "$ReddySafe"])
        session.uid_copy(5, "Secureddy/Quarantine")
        session.uid_move(5, 'Odd "Name"')
        session.uid_expunge(5)
        session.expunge()
        session.logout()
        assert conn.commands == [
            ("CREATE", "Secureddy"),
            ("UID", "STORE", "5", "+FLAGS", "(\\Deleted $ReddySafe)"),
            ("UID", "COPY", "5", "Secureddy/Quarantine"),
            ("UID", "MOVE", "5", '"Odd \\"Name\\""'),
            ("UID", "EXPUNGE", "5"),
            ("EXPUNGE",),
            ("LOGOUT",),
        ]

    def test_no_responses_raise_and_logout_swallows(self, imaplib_session):
        session, conn = imaplib_session
        conn.fail_commands = {"SELECT", "LIST", "LOGOUT"}
        with pytest.raises(imaplib.IMAP4.error, match="SELECT failed"):
            session.select("INBOX")
        with pytest.raises(imaplib.IMAP4.error, match="LIST failed"):
            session.list_folders()
        session.logout()  # swallowed

    def test_default_factory_builds_ssl_connection(self, monkeypatch: pytest.MonkeyPatch):
        created: dict[str, Any] = {}

        class StubSSL:
            def __init__(self, host, port, *, ssl_context, timeout):
                created.update(host=host, port=port, ctx=ssl_context, timeout=timeout)

        monkeypatch.setattr(imaplib, "IMAP4_SSL", StubSSL)
        ImaplibSession("imap.example", 993, timeout=5.0)
        assert created["host"] == "imap.example" and created["port"] == 993 and created["timeout"] == 5.0
        assert created["ctx"] is not None


class TestMoreEdges:
    async def test_logout_failure_is_swallowed(self, imap_server: FakeImapServer):
        imap_server.fail_logout = True
        imap_server.deliver("INBOX", sample_raw("m"))
        messages, _ = await connector(imap_server).poll(None)
        assert len(messages) == 1 and imap_server.logouts == 1

    async def test_folders_are_discovered_on_demand(self, imap_server: FakeImapServer):
        c = connector(imap_server, ProtectionMode.HOLD)  # no setup() call
        assert await c.release_all_pending() == 0
        assert checking(imap_server) in imap_server.folders  # created on the way

    async def test_unknown_message_id_is_not_found(self, imap_server: FakeImapServer):
        async def resolver(pid: str) -> str | None:
            return "<nobody@example.com>"

        c = connector(imap_server, message_id_resolver=resolver)
        await c.setup(ProtectionMode.SCAN)
        with pytest.raises(ConnectorError, match="not found"):
            await c.restore("INBOX:111:5")


class TestBackfill:
    async def test_since_newest_first_skips_known_and_caps(self, imap_server: FakeImapServer):
        now = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)
        old = imap_server.deliver("INBOX", b"Subject: old\r\n\r\nx", date=now - timedelta(days=9))
        edge = imap_server.deliver("INBOX", b"Subject: edge\r\n\r\nx", date=now - timedelta(days=7, hours=2))
        a = imap_server.deliver("INBOX", b"Subject: a\r\n\r\nx", date=now - timedelta(days=3))
        b = imap_server.deliver("INBOX", b"Subject: b\r\n\r\nx", date=now - timedelta(days=1))
        c = imap_server.deliver("INBOX", b"Subject: c\r\n\r\nx", date=now - timedelta(hours=1))
        conn = connector(imap_server)
        uv = imap_server.folders["INBOX"].uidvalidity
        since = now - timedelta(days=7)

        got = await conn.backfill(since, 2, skip={f"INBOX:{uv}:{c}"})

        assert [m.provider_message_id for m in got] == [f"INBOX:{uv}:{b}", f"INBOX:{uv}:{a}"]
        searches = [args[0] for name, args in imap_server.calls if name == "search"]
        assert searches == ["SINCE 29-Oct-2026"]  # a day early: date-only, server time zone
        fetches = [args[0] for name, args in imap_server.calls if name == "fetch"]
        assert fetches == [(a, b)]  # only what is returned is downloaded
        rest = await conn.backfill(since, 10, skip={m.provider_message_id for m in got})
        # "edge" matched SINCE (date-granular) but is older than since: dropped.
        assert [m.provider_message_id for m in rest] == [f"INBOX:{uv}:{c}"]
        assert old not in {int(m.provider_message_id.rsplit(":", 1)[1]) for m in rest} and edge
        assert await conn.backfill(since, 0) == []

    def test_imap_date_ignores_locale(self):
        from reddysec.mail.imap import imap_date

        assert imap_date(datetime(2026, 3, 1, 0, 30, tzinfo=UTC)) == "28-Feb-2026"

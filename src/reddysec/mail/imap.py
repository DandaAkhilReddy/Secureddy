"""IMAP connector for Yahoo, iCloud, Outlook.com and generic servers.

IMAP has no server-side rules API, so HOLD mode on these providers depends on
a rule the client creates in the provider's web UI (``setup`` returns the
exact instructions). Everything else (folders, keywords, moves) is done over
IMAP.

Design notes
------------
* ``ImapSession`` is a small synchronous protocol over the handful of IMAP
  commands we use. ``ImaplibSession`` implements it with the stdlib; tests use
  an in-memory fake. The connector runs one session per operation batch in a
  worker thread (``asyncio.to_thread``), so a stuck server never blocks the
  event loop and every batch starts from a clean connection.
* Message identity. ``provider_message_id`` is ``"{folder}:{uidvalidity}:{uid}"``:
  cheap, exact, and stable until the message moves. Moving a message (hold
  release, quarantine, restore) gives it a new UID, so later operations that
  only receive the id locate the message by its RFC ``Message-ID`` header via
  the injectable ``message_id_resolver`` (the worker wires it to the messages
  table). ``apply_verdict`` has the raw bytes and needs no resolver.
* Keywords. Verdicts for messages that stay in the inbox are recorded as IMAP
  keywords (``$ReddySafe`` ...) when the folder's PERMANENTFLAGS advertises
  ``\\*``; otherwise it is a no-op. We never COPY a message into a verdict
  folder: that would duplicate the client's mail.
"""

from __future__ import annotations

import asyncio
import imaplib
import re
import ssl
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from email.parser import BytesHeaderParser
from typing import Any, Protocol, TypeVar

from pydantic import BaseModel, model_validator

from reddysec.core.logging import get_logger
from reddysec.mail.base import (
    ALL_LABELS,
    LABEL_PENDING,
    LABEL_QUARANTINE,
    LABEL_RELEASED,
    LABEL_SAFE,
    LABEL_SUSPICIOUS,
    AuthExpired,
    ConnectorError,
)
from reddysec.mail.gmail import should_quarantine
from reddysec.models import PolicyConfig, ProtectionMode, Provider, RawMessage, Verdict, VerdictLevel

log = get_logger(__name__)

T = TypeVar("T")

INBOX = "INBOX"
INSTRUCTIONS_KEY = "_instructions"
KEYWORD_SAFE = "$ReddySafe"
KEYWORD_SUSPICIOUS = "$ReddySuspicious"
KEYWORD_RELEASED = "$ReddyReleased"
RECENT_LIMIT = 50

IMAP_PRESETS: dict[Provider, tuple[str, int]] = {
    Provider.YAHOO: ("imap.mail.yahoo.com", 993),
    Provider.ICLOUD: ("imap.mail.me.com", 993),
    Provider.OUTLOOK: ("outlook.office365.com", 993),
}


class ImapCredentials(BaseModel):
    username: str
    password: str | None = None
    oauth_access_token: str | None = None
    host: str | None = None
    port: int | None = None

    @model_validator(mode="after")
    def _one_secret(self) -> ImapCredentials:
        if not self.password and not self.oauth_access_token:
            raise ValueError("either password or oauth_access_token is required")
        return self

    @classmethod
    def from_secret(cls, secret: dict[str, Any]) -> ImapCredentials:
        return cls.model_validate(
            {k: secret.get(k) for k in ("username", "password", "oauth_access_token", "host", "port")}
        )


def resolve_endpoint(provider: Provider, credentials: ImapCredentials) -> tuple[str, int]:
    """Preset host/port per provider; generic IMAP must carry them in the secret."""
    if credentials.host:
        return credentials.host, int(credentials.port or 993)
    try:
        return IMAP_PRESETS[provider]
    except KeyError:
        raise ValueError(f"provider {provider.value} needs an explicit IMAP host") from None


def xoauth2_string(username: str, access_token: str) -> bytes:
    """SASL XOAUTH2 initial client response (RFC 7628 style, as Google/Yahoo/MS use it)."""
    return f"user={username}\x01auth=Bearer {access_token}\x01\x01".encode()


# ---------------------------------------------------------------- session API
@dataclass(frozen=True)
class FolderInfo:
    name: str
    delimiter: str
    flags: frozenset[str] = frozenset()


@dataclass(frozen=True)
class SelectInfo:
    uidvalidity: int
    uidnext: int
    exists: int = 0
    permanent_flags: frozenset[str] = frozenset()

    @property
    def allows_keywords(self) -> bool:
        return "\\*" in self.permanent_flags


@dataclass(frozen=True)
class FetchedMessage:
    uid: int
    raw: bytes
    internal_date: datetime
    flags: frozenset[str] = frozenset()


class ImapAuthError(Exception):
    """Raised by a session when the server rejects the credentials."""


class ImapSession(Protocol):
    """The synchronous subset of IMAP we rely on. One instance == one connection."""

    def login(self, username: str, password: str) -> None: ...
    def authenticate_xoauth2(self, username: str, access_token: str) -> None: ...
    def capabilities(self) -> frozenset[str]: ...
    def list_folders(self) -> list[FolderInfo]: ...
    def create_folder(self, name: str) -> None: ...
    def select(self, folder: str) -> SelectInfo: ...
    def uid_search(self, criteria: str) -> list[int]: ...
    def uid_fetch(self, uids: Sequence[int]) -> list[FetchedMessage]: ...
    def uid_store(self, uid: int, op: str, flags: Sequence[str]) -> None: ...
    def uid_copy(self, uid: int, folder: str) -> None: ...
    def uid_move(self, uid: int, folder: str) -> None: ...
    def uid_expunge(self, uid: int) -> None: ...
    def expunge(self) -> None: ...
    def logout(self) -> None: ...


# ------------------------------------------------------------ imaplib backend
_LIST_RE = re.compile(rb'^\((?P<flags>[^)]*)\)\s+(?:"(?P<delim>[^"]*)"|(?P<nil>NIL))\s+(?P<name>.*)$', re.S)
_UID_RE = re.compile(rb"UID (\d+)")
_INTERNALDATE_RE = re.compile(rb'INTERNALDATE "([^"]+)"')
_FLAGS_RE = re.compile(rb"FLAGS \(([^)]*)\)")


def _quote_mailbox(name: str) -> str:
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def parse_internaldate(value: str) -> datetime:
    """``"05-Nov-2026 10:20:30 -0800"`` -> aware UTC datetime."""
    return datetime.strptime(value.strip(), "%d-%b-%Y %H:%M:%S %z").astimezone(UTC)


class ImaplibSession:
    """``ImapSession`` on top of ``imaplib.IMAP4_SSL``. ``connection_factory``
    is injectable so the response parsing can be tested without a server."""

    def __init__(
        self,
        host: str,
        port: int = 993,
        *,
        timeout: float = 30.0,
        connection_factory: Callable[..., Any] | None = None,
    ):
        factory = connection_factory or self._default_factory
        self._conn = factory(host, port, timeout=timeout)

    @staticmethod
    def _default_factory(host: str, port: int, *, timeout: float) -> imaplib.IMAP4_SSL:
        return imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context(), timeout=timeout)

    @staticmethod
    def _check(result: tuple[str, Any], what: str) -> Any:
        typ, data = result
        if typ != "OK":
            detail = data[-1] if data else b""
            if isinstance(detail, bytes):
                detail = detail.decode("utf-8", "replace")
            raise imaplib.IMAP4.error(f"{what} failed: {typ} {detail}")
        return data

    def login(self, username: str, password: str) -> None:
        try:
            self._conn.login(username, password)
        except imaplib.IMAP4.error as exc:
            raise ImapAuthError(str(exc)) from exc

    def authenticate_xoauth2(self, username: str, access_token: str) -> None:
        payload = xoauth2_string(username, access_token)
        try:
            self._conn.authenticate("XOAUTH2", lambda _challenge: payload)
        except imaplib.IMAP4.error as exc:
            raise ImapAuthError(str(exc)) from exc

    def capabilities(self) -> frozenset[str]:
        return frozenset(str(c).upper() for c in self._conn.capabilities)

    def list_folders(self) -> list[FolderInfo]:
        data = self._check(self._conn.list(), "LIST")
        folders: list[FolderInfo] = []
        for item in data:
            if item is None:
                continue
            literal_name: bytes | None = None
            if isinstance(item, tuple):  # name sent as a literal: (b'(\\X) "/" {5}', b'name')
                item, literal_name = item[0], item[1]
            match = _LIST_RE.match(item)
            if not match:
                continue
            delimiter = (
                (match.group("delim") or b"/").decode("ascii", "replace")
                if match.group("nil") is None
                else "/"
            )
            name_raw = literal_name if literal_name is not None else match.group("name").strip()
            if name_raw.startswith(b'"') and name_raw.endswith(b'"'):
                name_raw = name_raw[1:-1].replace(b'\\"', b'"').replace(b"\\\\", b"\\")
            flags = frozenset(f.decode("ascii", "replace") for f in match.group("flags").split())
            folders.append(
                FolderInfo(name=name_raw.decode("utf-8", "replace"), delimiter=delimiter, flags=flags)
            )
        return folders

    def create_folder(self, name: str) -> None:
        self._check(self._conn.create(name), "CREATE")

    def select(self, folder: str) -> SelectInfo:
        data = self._check(self._conn.select(folder), "SELECT")
        exists = int(data[0]) if data and data[0] else 0

        def single(code: str, default: int) -> int:
            _typ, values = self._conn.response(code)
            value = values[0] if values else None
            return int(value) if value else default

        _typ, pflags = self._conn.response("PERMANENTFLAGS")
        permanent: frozenset[str] = frozenset()
        if pflags and pflags[0]:
            permanent = frozenset(f.decode("ascii", "replace") for f in pflags[0].strip(b"()").split())
        return SelectInfo(
            uidvalidity=single("UIDVALIDITY", 0),
            uidnext=single("UIDNEXT", 0),
            exists=exists,
            permanent_flags=permanent,
        )

    def uid_search(self, criteria: str) -> list[int]:
        data = self._check(self._conn.uid("SEARCH", criteria), "UID SEARCH")
        if not data or not data[0]:
            return []
        return sorted(int(x) for x in data[0].split())

    def uid_fetch(self, uids: Sequence[int]) -> list[FetchedMessage]:
        if not uids:
            return []
        sequence = ",".join(str(u) for u in uids)
        data = self._check(self._conn.uid("FETCH", sequence, "(UID INTERNALDATE FLAGS RFC822)"), "UID FETCH")
        return self._parse_fetch(data)

    @staticmethod
    def _parse_fetch(data: list[Any]) -> list[FetchedMessage]:
        """imaplib returns a flat list mixing ``(attributes, literal)`` tuples and
        trailing ``b')'`` chunks; servers may put FLAGS before or after the
        literal, so attributes are gathered until the next tuple starts."""
        records: list[tuple[bytearray, bytes]] = []
        for item in data:
            if isinstance(item, tuple) and len(item) == 2:
                records.append((bytearray(item[0]), item[1]))
            elif isinstance(item, bytes) and records:
                records[-1][0].extend(b" " + item)
        out: list[FetchedMessage] = []
        for attrs, raw in records:
            uid_match = _UID_RE.search(attrs)
            if not uid_match:
                continue
            date_match = _INTERNALDATE_RE.search(attrs)
            internal = (
                parse_internaldate(date_match.group(1).decode("ascii")) if date_match else datetime.now(UTC)
            )
            flags_match = _FLAGS_RE.search(attrs)
            flags = (
                frozenset(f.decode("ascii", "replace") for f in flags_match.group(1).split())
                if flags_match
                else frozenset()
            )
            out.append(
                FetchedMessage(
                    uid=int(uid_match.group(1)), raw=bytes(raw), internal_date=internal, flags=flags
                )
            )
        return out

    def uid_store(self, uid: int, op: str, flags: Sequence[str]) -> None:
        self._check(self._conn.uid("STORE", str(uid), op, "(" + " ".join(flags) + ")"), "UID STORE")

    def uid_copy(self, uid: int, folder: str) -> None:
        self._check(self._conn.uid("COPY", str(uid), folder), "UID COPY")

    def uid_move(self, uid: int, folder: str) -> None:
        self._check(self._conn.uid("MOVE", str(uid), _quote_mailbox(folder)), "UID MOVE")

    def uid_expunge(self, uid: int) -> None:
        self._check(self._conn.uid("EXPUNGE", str(uid)), "UID EXPUNGE")

    def expunge(self) -> None:
        self._check(self._conn.expunge(), "EXPUNGE")

    def logout(self) -> None:
        try:
            self._conn.logout()
        except (imaplib.IMAP4.error, OSError):
            pass


# ------------------------------------------------------------------ connector
@dataclass(frozen=True)
class Location:
    folder: str
    uidvalidity: int
    uid: int

    @classmethod
    def parse(cls, provider_message_id: str) -> Location:
        try:
            folder, uidvalidity, uid = provider_message_id.rsplit(":", 2)
            return cls(folder=folder, uidvalidity=int(uidvalidity), uid=int(uid))
        except ValueError as exc:
            raise ConnectorError(f"not an IMAP message id: {provider_message_id!r}", retryable=False) from exc

    def __str__(self) -> str:
        return f"{self.folder}:{self.uidvalidity}:{self.uid}"


@dataclass(frozen=True)
class FolderCursor:
    uidvalidity: int
    last_uid: int


def parse_cursor(cursor: str | None, folder_count: int) -> list[FolderCursor | None]:
    """``"uv:uid"`` for the inbox alone, ``"uv:uid|uv:uid"`` when the Checking
    folder is polled too (HOLD). Positional, inbox first, so switching modes
    only resyncs the folder whose part is missing."""
    parts: list[FolderCursor | None] = [None] * folder_count
    if not cursor:
        return parts
    for i, piece in enumerate(cursor.split("|")[:folder_count]):
        try:
            uv, last = piece.split(":")
            parts[i] = FolderCursor(int(uv), int(last))
        except ValueError:
            parts[i] = None
    return parts


def hold_instructions(provider: Provider, checking_folder: str) -> str:
    """Plain-English steps for the provider-side rule HOLD mode needs. IMAP
    cannot create server rules, so the client (or our concierge, with them)
    does this once in the provider's settings."""
    if provider is Provider.YAHOO:
        return (
            "In Yahoo Mail open Settings, then More Settings, then Filters, and add a filter. "
            f"Set the rule to: From contains '@', and choose the folder '{checking_folder}'. "
            "Save it. New mail will wait in that folder until we have checked it. "
            "Yahoo requires an app password for IMAP; your normal password will not work."
        )
    if provider is Provider.ICLOUD:
        return (
            "In iCloud Mail on the web open Settings, then Rules, and add a rule: "
            f"if a message is from an address that contains '@', move it to the folder '{checking_folder}'."
        )
    if provider is Provider.OUTLOOK:
        return (
            "In Outlook.com open Settings, then Mail, then Rules, and add a rule: "
            f"condition 'From contains @', action 'Move to' the folder '{checking_folder}'. "
            "Outlook runs rules after its junk filter, so junk mail is not held."
        )
    return (
        "Create a server-side rule in your mail provider that moves every incoming message "
        f"into the folder '{checking_folder}'."
    )


class ImapConnector:
    provider: Provider

    def __init__(
        self,
        mailbox_id: str,
        address: str,
        provider: Provider,
        credentials: ImapCredentials,
        *,
        session_factory: Callable[[], ImapSession] | None = None,
        mode: ProtectionMode = ProtectionMode.SCAN,
        folders: dict[str, str] | None = None,
        message_id_resolver: Callable[[str], Awaitable[str | None]] | None = None,
        recent_limit: int = RECENT_LIMIT,
    ):
        self.mailbox_id = mailbox_id
        self.address = address.lower()
        self.provider = provider
        self.credentials = credentials
        self.mode = mode
        self._recent_limit = recent_limit
        self._resolver = message_id_resolver
        self._folders: dict[str, str] = {k: v for k, v in (folders or {}).items() if k in ALL_LABELS}
        if session_factory is None:
            host, port = resolve_endpoint(provider, credentials)
            session_factory = lambda: ImaplibSession(host, port)  # noqa: E731
        self._session_factory = session_factory

    # -------------------------------------------------------------- plumbing
    def _authenticate(self, sess: ImapSession) -> None:
        if self.credentials.oauth_access_token:
            sess.authenticate_xoauth2(self.credentials.username, self.credentials.oauth_access_token)
        else:
            sess.login(self.credentials.username, self.credentials.password or "")

    def _with_session(self, op: Callable[[ImapSession], T]) -> T:
        """Open, authenticate, run ``op``, log out: one connection per batch.
        A fresh connection per batch is the simplest reliable way to cope with
        consumer IMAP servers that drop idle connections."""
        try:
            sess = self._session_factory()
        except (OSError, ssl.SSLError, imaplib.IMAP4.error) as exc:
            raise ConnectorError(f"IMAP connection failed: {exc}", retryable=True) from exc
        try:
            try:
                self._authenticate(sess)
            except ImapAuthError as exc:
                raise AuthExpired(f"IMAP login rejected: {exc}") from exc
            return op(sess)
        except ConnectorError:
            raise
        except (imaplib.IMAP4.error, OSError, ssl.SSLError, EOFError) as exc:
            raise ConnectorError(f"IMAP failure: {exc}", retryable=True) from exc
        finally:
            try:
                sess.logout()
            except Exception:  # noqa: BLE001 - logout is best effort
                pass

    async def _run(self, op: Callable[[ImapSession], T]) -> T:
        return await asyncio.to_thread(self._with_session, op)

    # --------------------------------------------------------------- folders
    def _folder_names(self, delimiter: str) -> dict[str, str]:
        return {name: name.replace("/", delimiter) for name in ALL_LABELS}

    def _ensure_folders(self, sess: ImapSession) -> dict[str, str]:
        existing = sess.list_folders()
        delimiter = next((f.delimiter for f in existing if f.delimiter), "/")
        present = {f.name for f in existing}
        wanted = self._folder_names(delimiter)
        for label in ALL_LABELS:  # root first; some servers require the parent to exist
            target = wanted[label]
            if target not in present:
                sess.create_folder(target)
                log.info("imap.folder_created", mailbox_id=self.mailbox_id, folder=target)
        self._folders = dict(wanted)
        return dict(self._folders)

    def _folder(self, sess: ImapSession, label: str) -> str:
        if label not in self._folders:
            self._ensure_folders(sess)
        return self._folders[label]

    def _move(self, sess: ImapSession, uid: int, destination: str) -> None:
        """UID MOVE when the server has it; otherwise COPY + \\Deleted + expunge.
        UID EXPUNGE (UIDPLUS) is preferred over a bare EXPUNGE so we never purge
        messages the client flagged as deleted but has not expunged."""
        caps = sess.capabilities()
        if "MOVE" in caps:
            sess.uid_move(uid, destination)
            return
        sess.uid_copy(uid, destination)
        sess.uid_store(uid, "+FLAGS", ["\\Deleted"])
        if "UIDPLUS" in caps:
            sess.uid_expunge(uid)
        else:
            sess.expunge()

    def _locate(
        self, sess: ImapSession, loc: Location, rfc_message_id: str | None, prefer: Iterable[str] = ()
    ) -> tuple[str, int, SelectInfo] | None:
        """Find a message: first at its recorded location, then by Message-ID
        across our folders and the inbox. Leaves the found folder selected."""
        try:
            info = sess.select(loc.folder)
        except (imaplib.IMAP4.error, OSError):
            info = None
        if (
            info is not None
            and info.uidvalidity == loc.uidvalidity
            and sess.uid_search(f"UID {loc.uid}") == [loc.uid]
        ):
            return loc.folder, loc.uid, info
        if not rfc_message_id:
            return None
        safe_id = rfc_message_id.replace('"', "").replace("\\", "")
        candidates = [
            *prefer,
            self._folder(sess, LABEL_QUARANTINE),
            self._folder(sess, LABEL_PENDING),
            INBOX,
            self._folder(sess, LABEL_SAFE),
            self._folder(sess, LABEL_SUSPICIOUS),
            self._folder(sess, LABEL_RELEASED),
        ]
        for folder in dict.fromkeys(candidates):
            try:
                info = sess.select(folder)
            except (imaplib.IMAP4.error, OSError):
                continue
            uids = sess.uid_search(f'HEADER Message-ID "{safe_id}"')
            if uids:
                return folder, uids[-1], info
        return None

    async def _resolve_message_id(self, provider_message_id: str) -> str | None:
        if self._resolver is None:
            return None
        try:
            return await self._resolver(provider_message_id)
        except Exception as exc:  # noqa: BLE001 - a lookup failure must not mask the IMAP error
            log.warning("imap.resolver_failed", mailbox_id=self.mailbox_id, error=str(exc))
            return None

    # ------------------------------------------------------ MailboxConnector
    async def setup(self, mode: ProtectionMode) -> dict[str, str]:
        self.mode = mode
        folders = await self._run(self._ensure_folders)
        result = dict(folders)
        if mode is ProtectionMode.HOLD:
            result[INSTRUCTIONS_KEY] = hold_instructions(self.provider, folders[LABEL_PENDING])
        return result

    async def poll(self, cursor: str | None) -> tuple[list[RawMessage], str | None]:
        hold = self.mode is ProtectionMode.HOLD

        def op(sess: ImapSession) -> tuple[list[RawMessage], str]:
            folders = [INBOX] + ([self._folder(sess, LABEL_PENDING)] if hold else [])
            previous = parse_cursor(cursor, len(folders))
            messages: list[RawMessage] = []
            parts: list[str] = []
            for folder, prev in zip(folders, previous, strict=True):
                info = sess.select(folder)
                if prev is None or prev.uidvalidity != info.uidvalidity:
                    # First poll or the server renumbered the folder: resync the
                    # most recent messages instead of trusting stale UIDs.
                    uids = sess.uid_search("ALL")[-self._recent_limit :]
                    last = max(uids) if uids else max(info.uidnext - 1, 0)
                else:
                    # "UID n:*" also returns the highest UID when n is past the
                    # end (RFC 3501), hence the explicit filter.
                    uids = [u for u in sess.uid_search(f"UID {prev.last_uid + 1}:*") if u > prev.last_uid]
                    last = max(uids) if uids else prev.last_uid
                for fetched in sess.uid_fetch(uids) if uids else []:
                    messages.append(self._to_raw(folder, info.uidvalidity, fetched))
                parts.append(f"{info.uidvalidity}:{last}")
            return messages, "|".join(parts)

        return await self._run(op)

    async def fetch_raw(self, provider_message_id: str) -> bytes:
        loc = Location.parse(provider_message_id)
        rfc_id = await self._resolve_message_id(provider_message_id)

        def op(sess: ImapSession) -> bytes:
            found = self._locate(sess, loc, rfc_id)
            if found is None:
                raise ConnectorError(f"message {provider_message_id} not found", retryable=False)
            _folder, uid, _info = found
            fetched = sess.uid_fetch([uid])
            if not fetched:
                raise ConnectorError(f"message {provider_message_id} vanished during fetch", retryable=False)
            return fetched[0].raw

        return await self._run(op)

    async def apply_verdict(self, msg: RawMessage, verdict: Verdict, policy: PolicyConfig) -> None:
        loc = Location.parse(msg.provider_message_id)
        rfc_id = _rfc_message_id(msg.raw)
        quarantine = should_quarantine(verdict, policy)
        hold = self.mode is ProtectionMode.HOLD or policy.mode is ProtectionMode.HOLD
        keyword = {VerdictLevel.SAFE: KEYWORD_SAFE, VerdictLevel.SUSPICIOUS: KEYWORD_SUSPICIOUS}.get(
            verdict.level
        )

        def op(sess: ImapSession) -> None:
            found = self._locate(sess, loc, rfc_id, prefer=[loc.folder])
            if found is None:
                raise ConnectorError(f"message {msg.provider_message_id} not found", retryable=False)
            folder, uid, info = found
            if keyword and info.allows_keywords:
                sess.uid_store(uid, "+FLAGS", [keyword])  # flags travel with a later move
            quarantine_folder = self._folder(sess, LABEL_QUARANTINE)
            checking_folder = self._folder(sess, LABEL_PENDING)
            if quarantine:
                if folder != quarantine_folder:
                    self._move(sess, uid, quarantine_folder)
            elif hold and folder == checking_folder:
                self._move(sess, uid, INBOX)

        await self._run(op)

    async def release(self, provider_message_id: str) -> None:
        await self._relocate(provider_message_id, destination=INBOX, only_from=LABEL_PENDING)

    async def quarantine(self, provider_message_id: str) -> None:
        await self._relocate(provider_message_id, destination_label=LABEL_QUARANTINE)

    async def restore(self, provider_message_id: str) -> None:
        await self._relocate(
            provider_message_id, destination=INBOX, prefer_label=LABEL_QUARANTINE, keyword=KEYWORD_RELEASED
        )

    async def release_all_pending(self) -> int:
        def op(sess: ImapSession) -> int:
            checking = self._folder(sess, LABEL_PENDING)
            sess.select(checking)
            uids = sess.uid_search("ALL")
            for uid in uids:
                self._move(sess, uid, INBOX)
            return len(uids)

        count = await self._run(op)
        log.info("imap.release_all_pending", mailbox_id=self.mailbox_id, count=count)
        return count

    async def teardown(self) -> None:
        """Nothing to undo server-side: the HOLD rule lives in the provider's
        settings. Operators read ``teardown_instructions`` to the client."""
        log.info("imap.teardown", mailbox_id=self.mailbox_id, instructions=self.teardown_instructions())

    def teardown_instructions(self) -> str:
        checking = self._folders.get(LABEL_PENDING, LABEL_PENDING)
        return (
            f"Hold mode is off. Please delete or disable the rule that moves mail to '{checking}' "
            "in your mail provider's settings; otherwise new mail will keep landing there."
        )

    # ------------------------------------------------------------ internals
    async def _relocate(
        self,
        provider_message_id: str,
        *,
        destination: str | None = None,
        destination_label: str | None = None,
        only_from: str | None = None,
        prefer_label: str | None = None,
        keyword: str | None = None,
    ) -> None:
        loc = Location.parse(provider_message_id)
        rfc_id = await self._resolve_message_id(provider_message_id)

        def op(sess: ImapSession) -> None:
            prefer = [self._folder(sess, prefer_label)] if prefer_label else []
            found = self._locate(sess, loc, rfc_id, prefer=prefer)
            if found is None:
                raise ConnectorError(f"message {provider_message_id} not found", retryable=False)
            folder, uid, info = found
            target = destination or self._folder(sess, destination_label or "")
            if only_from and folder != self._folder(sess, only_from):
                return  # not held: nothing to release
            if keyword and info.allows_keywords:
                sess.uid_store(uid, "+FLAGS", [keyword])
            if folder != target:
                self._move(sess, uid, target)

        await self._run(op)

    def _to_raw(self, folder: str, uidvalidity: int, fetched: FetchedMessage) -> RawMessage:
        return RawMessage(
            provider_message_id=str(Location(folder, uidvalidity, fetched.uid)),
            mailbox_id=self.mailbox_id,
            received_at=fetched.internal_date,
            raw=fetched.raw,
            provider_labels=[folder, *sorted(fetched.flags)],
            thread_id=None,
        )


def _rfc_message_id(raw: bytes) -> str | None:
    try:
        headers = BytesHeaderParser().parsebytes(raw, headersonly=True)
    except Exception:  # noqa: BLE001 - a malformed header block is not fatal here
        return None
    value = headers.get("Message-ID")
    return value.strip() if value else None


__all__ = [
    "IMAP_PRESETS",
    "INSTRUCTIONS_KEY",
    "FetchedMessage",
    "FolderInfo",
    "ImapAuthError",
    "ImapConnector",
    "ImapCredentials",
    "ImapSession",
    "ImaplibSession",
    "Location",
    "SelectInfo",
    "hold_instructions",
    "parse_cursor",
    "parse_internaldate",
    "resolve_endpoint",
    "xoauth2_string",
]

"""Outlook.com, Hotmail and Microsoft 365 mailboxes over Microsoft Graph v1.0.

What we create in the client's mailbox (visible on purpose, like the Gmail
labels):

* Folders: ``Secureddy`` with two child folders, ``Checking`` (HOLD mode
  parks new mail here) and ``Quarantine``.
* Categories (Outlook's coloured tags) for verdicts that stay in the inbox:
  "Secureddy: Checked" (green), "Secureddy: Suspicious" (orange),
  "Secureddy: Quarantine" (red) and "Secureddy: Released by you" (blue). The
  client's own categories on a message are never touched.

Message identity: every request sends ``Prefer: IdType="ImmutableId"`` so a
message keeps its id when we move it between folders (Graph's default ids
change on every move). That makes ``provider_message_id`` stable for the
whole life of the message, unlike IMAP UIDs.

Polling: a delta query per folder (inbox and Checking). The cursor is a small
JSON document holding each folder's ``@odata.deltaLink`` plus the time we
started watching, so a read/flag change on an old message (which also shows
up in a delta) is never mistaken for new mail. An expired delta token (HTTP
410) re-seeds that folder.

HOLD mode: an inbox *message rule* that moves every incoming message to
``Secureddy/Checking``. A rule with no conditions (``"conditions": {}``)
applies to all mail in Outlook; Graph accepting and running such a rule the
same way **must be validated against a real mailbox** before Hold mode is
offered on Microsoft accounts, just like the Gmail filter. Outlook runs its
junk filter before rules, so junk mail is not held; a client rule that runs
after ours may still move a message out of Checking (it then simply is not
held). The dead man's switch releases everything in Checking if we stop.

Throttling: 429 and 503 honour ``Retry-After`` (capped); other 5xx and network
errors back off exponentially. A 401 refreshes the token once; a refused
refresh (``invalid_grant``) surfaces as ``AuthExpired`` so the worker asks the
client to reconnect.
"""

from __future__ import annotations

import asyncio
import json
import random
from collections.abc import Awaitable, Callable, Collection, Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from reddysec.core.logging import get_logger
from reddysec.mail.base import (
    LABEL_PENDING,
    LABEL_QUARANTINE,
    LABEL_RELEASED,
    LABEL_ROOT,
    LABEL_SAFE,
    LABEL_SUSPICIOUS,
    AuthExpired,
    ConnectorError,
)
from reddysec.mail.gmail import GoogleCredentials as OAuthCredentials
from reddysec.mail.gmail import should_quarantine
from reddysec.mail.oauth_google import TokenSet
from reddysec.models import PolicyConfig, ProtectionMode, Provider, RawMessage, Verdict, VerdictLevel

log = get_logger(__name__)

GRAPH_ME = "https://graph.microsoft.com/v1.0/me"
ROOT_FOLDER = "Secureddy"
CHILD_FOLDERS = {LABEL_PENDING: "Checking", LABEL_QUARANTINE: "Quarantine"}
INBOX_KEY = "_inbox"
HOLD_RULE_KEY = "_hold_rule_id"
CATEGORIES_KEY = "_categories"
HOLD_RULE_NAME = "Secureddy: hold new mail for checking"

CATEGORY = {
    LABEL_SAFE: "Secureddy: Checked",
    LABEL_SUSPICIOUS: "Secureddy: Suspicious",
    LABEL_QUARANTINE: "Secureddy: Quarantine",
    LABEL_RELEASED: "Secureddy: Released by you",
}
# Outlook category presets: preset0 red, preset1 orange, preset4 green, preset7 blue.
CATEGORY_COLOR = {
    LABEL_SAFE: "preset4",
    LABEL_SUSPICIOUS: "preset1",
    LABEL_QUARANTINE: "preset0",
    LABEL_RELEASED: "preset7",
}
VERDICT_CATEGORIES = frozenset(CATEGORY.values())

DELTA_SELECT = "id,receivedDateTime,categories,isDraft,parentFolderId,conversationId"
SEED_WINDOW = timedelta(days=1)
PAGE_SIZE = 100
MAX_TRIES = 4
BACKOFF_BASE_S = 0.5
BACKOFF_CAP_S = 8.0
RETRY_AFTER_CAP_S = 30.0
FETCH_CONCURRENCY = 4
RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})
SYNC_STATE_ERRORS = frozenset({"syncstatenotfound", "syncstateinvalid", "resyncrequired"})


class GraphApiError(ConnectorError):
    def __init__(self, status: int, message: str, *, code: str = "", retryable: bool = False):
        super().__init__(message, retryable=retryable)
        self.status = status
        self.code = code


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_dt(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _retry_after(resp: httpx.Response) -> float | None:
    value = resp.headers.get("Retry-After")
    if not value:
        return None
    try:
        return max(0.0, min(float(value), RETRY_AFTER_CAP_S))
    except ValueError:
        return None


def _error_details(resp: httpx.Response) -> tuple[str, str]:
    try:
        err = resp.json().get("error", {})
    except (json.JSONDecodeError, AttributeError):
        return "", resp.text[:200]
    if isinstance(err, dict):
        return str(err.get("code", "")), str(err.get("message", ""))
    return "", str(err)


class GraphMailConnector:
    """MailboxConnector for Microsoft mailboxes. ``labels`` (from the mailbox
    row) caches folder ids and the hold rule id; anything missing is looked up
    or created again, so a client deleting our folder heals on the next action."""

    provider = Provider.MICROSOFT

    def __init__(
        self,
        mailbox_id: str,
        address: str,
        credentials: OAuthCredentials,
        oauth: Any,
        *,
        http: httpx.AsyncClient | None = None,
        on_tokens_refreshed: Callable[[TokenSet], Awaitable[None]] | None = None,
        labels: dict[str, str] | None = None,
        mode: ProtectionMode = ProtectionMode.SCAN,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        rng: Callable[[], float] = random.random,
        clock: Callable[[], datetime] | None = None,
    ):
        self.mailbox_id = mailbox_id
        self.address = address.lower()
        self.credentials = credentials
        self.mode = mode
        self._oauth = oauth
        self._http = http
        self._owns_http = http is None
        self._on_tokens_refreshed = on_tokens_refreshed
        keep = {LABEL_ROOT, LABEL_PENDING, LABEL_QUARANTINE, INBOX_KEY, HOLD_RULE_KEY, CATEGORIES_KEY}
        self._labels: dict[str, str] = {k: v for k, v in (labels or {}).items() if k in keep}
        self._sleep = sleep
        self._rng = rng
        self._clock = clock or (lambda: datetime.now(UTC))
        self._refresh_lock = asyncio.Lock()

    # ----------------------------------------------------------------- http
    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=30.0)
        return self._http

    async def aclose(self) -> None:
        if self._owns_http and self._http is not None:
            await self._http.aclose()
            self._http = None

    @property
    def labels(self) -> dict[str, str]:
        return dict(self._labels)

    async def _ensure_token(self, *, force: bool = False) -> str:
        async with self._refresh_lock:
            if force or self.credentials.is_expired(self._clock()):
                if not self.credentials.refresh_token:
                    raise AuthExpired("Microsoft access token expired and no refresh token is stored")
                tokens = await self._oauth.refresh(self.credentials.refresh_token)
                self.credentials = OAuthCredentials.from_token_set(tokens)
                if self._on_tokens_refreshed is not None:
                    await self._on_tokens_refreshed(tokens)
            return self.credentials.access_token

    def _backoff(self, attempt: int) -> float:
        return min(BACKOFF_CAP_S, BACKOFF_BASE_S * (2**attempt)) + self._rng() * BACKOFF_BASE_S

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        raw: bool = False,
        prefer: str = "",
    ) -> Any:
        """One Graph call: pre-emptive refresh, one refresh-and-retry on 401,
        Retry-After on 429/503, exponential backoff on other 5xx/network errors."""
        url = path if path.startswith("http") else f"{GRAPH_ME}/{path.lstrip('/')}"
        refreshed = False
        last_error = ""
        for attempt in range(MAX_TRIES):
            token = await self._ensure_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "*/*" if raw else "application/json",
                "Prefer": ", ".join(p for p in ('IdType="ImmutableId"', prefer) if p),
            }
            try:
                resp = await self.http.request(method, url, params=params, json=json_body, headers=headers)
            except httpx.HTTPError as exc:
                last_error = f"network error: {exc}"
                log.warning("graph.network_error", mailbox_id=self.mailbox_id, attempt=attempt, error=str(exc))
                if attempt < MAX_TRIES - 1:
                    await self._sleep(self._backoff(attempt))
                continue

            if 200 <= resp.status_code < 300:
                if raw:
                    return resp.content
                if not resp.content:
                    return {}
                try:
                    body = resp.json()
                except json.JSONDecodeError as exc:
                    raise ConnectorError("Microsoft Graph returned a non-JSON body", retryable=True) from exc
                return body if isinstance(body, dict) else {"value": body}

            code, message = _error_details(resp)
            if resp.status_code == 401:
                if refreshed:
                    raise AuthExpired("Microsoft rejected the access token twice; the mailbox must be reconnected")
                refreshed = True
                await self._ensure_token(force=True)
                continue
            if resp.status_code in RETRYABLE_STATUSES:
                last_error = f"HTTP {resp.status_code} {code}: {message}"
                log.warning("graph.retryable_status", mailbox_id=self.mailbox_id, status=resp.status_code, attempt=attempt)
                if attempt < MAX_TRIES - 1:
                    wait = _retry_after(resp)
                    await self._sleep(wait if wait is not None else self._backoff(attempt))
                continue
            raise GraphApiError(
                resp.status_code,
                f"Graph {method} {path}: HTTP {resp.status_code} {code} {message}".strip(),
                code=code,
            )
        raise ConnectorError(f"Graph {method} {path} failed after {MAX_TRIES} tries: {last_error}", retryable=True)

    async def _pages(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        url: str | None = path
        first = True
        while url:
            body = await self._request("GET", url, params=params if first else None)
            first = False
            items.extend(v for v in body.get("value", []) if isinstance(v, dict))
            url = body.get("@odata.nextLink")
        return items

    # --------------------------------------------------------------- folders
    async def _ensure_folders(self) -> dict[str, str]:
        inbox = await self._request("GET", "mailFolders/inbox", params={"$select": "id"})
        self._labels[INBOX_KEY] = str(inbox["id"])
        root = await self._find_or_create("mailFolders", ROOT_FOLDER)
        self._labels[LABEL_ROOT] = root
        for label, name in CHILD_FOLDERS.items():
            self._labels[label] = await self._find_or_create(f"mailFolders/{root}/childFolders", name)
        return dict(self._labels)

    async def _find_or_create(self, collection: str, name: str) -> str:
        def match(folders: list[dict[str, Any]]) -> str | None:
            for f in folders:
                if str(f.get("displayName", "")).casefold() == name.casefold() and f.get("id"):
                    return str(f["id"])
            return None

        found = match(await self._pages(collection, {"$top": PAGE_SIZE, "$select": "id,displayName"}))
        if found:
            return found
        try:
            created = await self._request("POST", collection, json_body={"displayName": name})
        except GraphApiError as exc:
            if exc.status != 409:  # ErrorFolderExists: someone else created it first
                raise
            found = match(await self._pages(collection, {"$top": PAGE_SIZE, "$select": "id,displayName"}))
            if found:
                return found
            raise
        log.info("graph.folder_created", mailbox_id=self.mailbox_id, folder=name)
        return str(created["id"])

    async def _folder_ids(self) -> dict[str, str]:
        if any(k not in self._labels for k in (INBOX_KEY, LABEL_ROOT, LABEL_PENDING, LABEL_QUARANTINE)):
            await self._ensure_folders()
        return self._labels

    async def _ensure_categories(self) -> None:
        existing = {
            str(c.get("displayName", "")).casefold()
            for c in (await self._request("GET", "outlook/masterCategories")).get("value", [])
            if isinstance(c, dict)
        }
        for label, name in CATEGORY.items():
            if name.casefold() in existing:
                continue
            try:
                await self._request(
                    "POST", "outlook/masterCategories", json_body={"displayName": name, "color": CATEGORY_COLOR[label]}
                )
            except GraphApiError as exc:
                if exc.status != 409:
                    raise
        self._labels[CATEGORIES_KEY] = "1"

    # ------------------------------------------------------------ hold rule
    async def _hold_rules(self) -> list[dict[str, Any]]:
        body = await self._request("GET", "mailFolders/inbox/messageRules")
        return [r for r in body.get("value", []) if isinstance(r, dict) and r.get("displayName") == HOLD_RULE_NAME]

    async def _ensure_hold_rule(self) -> str:
        checking = (await self._folder_ids())[LABEL_PENDING]
        keep: str | None = None
        for rule in await self._hold_rules():
            actions = rule.get("actions") or {}
            correct = actions.get("moveToFolder") == checking and rule.get("isEnabled", True)
            if correct and keep is None:
                keep = str(rule["id"])
            else:
                await self._request("DELETE", f"mailFolders/inbox/messageRules/{rule['id']}")
        if keep is None:
            created = await self._request(
                "POST",
                "mailFolders/inbox/messageRules",
                json_body={
                    "displayName": HOLD_RULE_NAME,
                    "sequence": 1,
                    "isEnabled": True,
                    # No conditions = every incoming message. Validate on a real
                    # mailbox before offering Hold mode (module docstring).
                    "conditions": {},
                    "actions": {"moveToFolder": checking, "stopProcessingRules": False},
                },
            )
            keep = str(created["id"])
            log.info("graph.hold_rule_created", mailbox_id=self.mailbox_id)
        return keep

    async def _delete_hold_rules(self) -> int:
        n = 0
        for rule in await self._hold_rules():
            await self._request("DELETE", f"mailFolders/inbox/messageRules/{rule['id']}")
            n += 1
        self._labels.pop(HOLD_RULE_KEY, None)
        return n

    # ------------------------------------------------------ MailboxConnector
    async def setup(self, mode: ProtectionMode) -> dict[str, str]:
        self.mode = mode
        await self._ensure_folders()
        await self._ensure_categories()
        if mode is ProtectionMode.HOLD:
            self._labels[HOLD_RULE_KEY] = await self._ensure_hold_rule()
        else:
            await self._delete_hold_rules()
        return dict(self._labels)

    async def poll(self, cursor: str | None) -> tuple[list[RawMessage], str | None]:
        folders = await self._folder_ids()
        state = self._parse_cursor(cursor)
        since = _parse_dt(state.get("since")) or (self._clock() - SEED_WINDOW)
        new_state: dict[str, Any] = {"v": 1, "since": _iso(since)}
        candidates: dict[str, dict[str, Any]] = {}
        for key, folder_id in (("inbox", folders[INBOX_KEY]), ("checking", folders[LABEL_PENDING])):
            items, delta_link = await self._delta(folder_id, state.get(key), since=since)
            new_state[key] = delta_link
            for item in items:
                if self._is_new_mail(item, since):
                    candidates.setdefault(str(item["id"]), item)
        messages = await self._fetch_many(list(candidates.values()))
        return messages, json.dumps(new_state, separators=(",", ":"))

    async def fetch_raw(self, provider_message_id: str) -> bytes:
        return await self._request("GET", f"messages/{provider_message_id}/$value", raw=True)

    async def backfill(self, since: datetime, limit: int, *, skip: Collection[str] = ()) -> list[RawMessage]:
        """Inbox mail received since ``since``, newest first: list ids and
        dates a page at a time, drop what we already have, then download at
        most ``limit`` bodies."""
        if limit <= 0:
            return []
        folders = await self._folder_ids()
        known = set(skip)
        params: dict[str, Any] = {
            "$select": DELTA_SELECT,
            "$filter": f"receivedDateTime ge {_iso(since)}",
            "$orderby": "receivedDateTime desc",
            "$top": PAGE_SIZE,
        }
        wanted: dict[str, dict[str, Any]] = {}
        url: str | None = f"mailFolders/{folders[INBOX_KEY]}/messages"
        first = True
        while url and len(wanted) < limit:
            body = await self._request("GET", url, params=params if first else None)
            first = False
            for item in body.get("value", []):
                if not isinstance(item, dict) or not item.get("id") or item.get("isDraft"):
                    continue
                if str(item["id"]) in known or set(item.get("categories") or []) & VERDICT_CATEGORIES:
                    continue
                wanted.setdefault(str(item["id"]), item)
                if len(wanted) >= limit:
                    break
            url = body.get("@odata.nextLink")
        messages = await self._fetch_many(list(wanted.values()))
        return sorted(messages, key=lambda m: m.received_at, reverse=True)

    async def apply_verdict(
        self, msg: RawMessage, verdict: Verdict, policy: PolicyConfig, *, relabel: bool = False
    ) -> None:
        hold = self.mode is ProtectionMode.HOLD or policy.mode is ProtectionMode.HOLD
        add, remove = verdict_category_plan(verdict.level, quarantine=should_quarantine(verdict, policy), relabel=relabel)
        folders = await self._folder_ids()
        parent = await self._set_categories(msg.provider_message_id, add=add, remove=remove)
        if should_quarantine(verdict, policy):
            await self._move(msg.provider_message_id, folders[LABEL_QUARANTINE], parent)
        elif hold:
            await self._move(msg.provider_message_id, folders[INBOX_KEY], parent)

    async def release(self, provider_message_id: str) -> None:
        folders = await self._folder_ids()
        parent = await self._parent(provider_message_id)
        await self._move(provider_message_id, folders[INBOX_KEY], parent)

    async def quarantine(self, provider_message_id: str) -> None:
        folders = await self._folder_ids()
        parent = await self._set_categories(provider_message_id, add=[CATEGORY[LABEL_QUARANTINE]], remove=[])
        await self._move(provider_message_id, folders[LABEL_QUARANTINE], parent)

    async def restore(self, provider_message_id: str) -> None:
        folders = await self._folder_ids()
        parent = await self._set_categories(
            provider_message_id, add=[CATEGORY[LABEL_RELEASED]], remove=[CATEGORY[LABEL_QUARANTINE]]
        )
        await self._move(provider_message_id, folders[INBOX_KEY], parent)

    async def mark_safe(self, provider_message_id: str) -> None:
        folders = await self._folder_ids()
        parent = await self._set_categories(
            provider_message_id,
            add=[CATEGORY[LABEL_SAFE]],
            remove=[CATEGORY[LABEL_SUSPICIOUS], CATEGORY[LABEL_QUARANTINE]],
        )
        await self._move(provider_message_id, folders[INBOX_KEY], parent)

    async def release_all_pending(self) -> int:
        folders = await self._folder_ids()
        held = await self._pages(
            f"mailFolders/{folders[LABEL_PENDING]}/messages", {"$select": "id", "$top": PAGE_SIZE}
        )
        ids = [str(m["id"]) for m in held if m.get("id")]
        for message_id in ids:  # collect first: moving while paging would shift the pages
            await self._request("POST", f"messages/{message_id}/move", json_body={"destinationId": folders[INBOX_KEY]})
        log.info("graph.release_all_pending", mailbox_id=self.mailbox_id, count=len(ids))
        return len(ids)

    async def teardown(self) -> None:
        await self._delete_hold_rules()

    # ------------------------------------------------------------ internals
    @staticmethod
    def _parse_cursor(cursor: str | None) -> dict[str, Any]:
        if not cursor:
            return {}
        try:
            data = json.loads(cursor)
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    async def _delta(
        self, folder_id: str, link: str | None, *, since: datetime
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Follow a folder's delta to its end. ``link`` None starts a fresh sync
        limited to mail since ``since``; an expired token (410) starts afresh."""
        if link:
            try:
                return await self._follow_delta(link, None)
            except GraphApiError as exc:
                if exc.status != 410 and exc.code.lower() not in SYNC_STATE_ERRORS:
                    raise
                log.warning("graph.delta_expired", mailbox_id=self.mailbox_id, folder=folder_id)
        start = f"mailFolders/{folder_id}/messages/delta"
        params = {"$select": DELTA_SELECT, "$filter": f"receivedDateTime ge {_iso(since)}"}
        try:
            return await self._follow_delta(start, params)
        except GraphApiError as exc:
            if exc.status != 400:
                raise
            # Some mailboxes refuse the filter on a delta; fall back to a full
            # sync and filter by receivedDateTime ourselves (_is_new_mail).
            return await self._follow_delta(start, {"$select": DELTA_SELECT})

    async def _follow_delta(self, url: str, params: dict[str, Any] | None) -> tuple[list[dict[str, Any]], str | None]:
        items: list[dict[str, Any]] = []
        next_url: str | None = url
        first = True
        delta_link: str | None = None
        while next_url:
            body = await self._request(
                "GET", next_url, params=params if first else None, prefer=f"odata.maxpagesize={PAGE_SIZE}"
            )
            first = False
            items.extend(v for v in body.get("value", []) if isinstance(v, dict))
            next_url = body.get("@odata.nextLink")
            delta_link = body.get("@odata.deltaLink", delta_link)
        return items, delta_link

    def _is_new_mail(self, item: dict[str, Any], since: datetime) -> bool:
        if "@removed" in item or not item.get("id") or item.get("isDraft"):
            return False
        if set(item.get("categories") or []) & VERDICT_CATEGORIES:
            return False  # already ours: seeing it again because we tagged it
        received = _parse_dt(item.get("receivedDateTime"))
        return received is None or received >= since

    async def _fetch_many(self, items: list[dict[str, Any]]) -> list[RawMessage]:
        semaphore = asyncio.Semaphore(FETCH_CONCURRENCY)

        async def fetch_one(item: dict[str, Any]) -> RawMessage | None:
            async with semaphore:
                try:
                    raw = await self.fetch_raw(str(item["id"]))
                except GraphApiError as exc:
                    if exc.status == 404:
                        return None  # deleted between listing and fetching
                    raise
            return RawMessage(
                provider_message_id=str(item["id"]),
                mailbox_id=self.mailbox_id,
                received_at=_parse_dt(item.get("receivedDateTime")) or self._clock(),
                raw=raw,
                provider_labels=[str(c) for c in item.get("categories") or []],
                thread_id=item.get("conversationId"),
            )

        results = await asyncio.gather(*(fetch_one(i) for i in items))
        return [r for r in results if r is not None]

    async def _parent(self, message_id: str) -> str:
        body = await self._request("GET", f"messages/{message_id}", params={"$select": "parentFolderId"})
        return str(body.get("parentFolderId", ""))

    async def _set_categories(self, message_id: str, *, add: Iterable[str], remove: Iterable[str]) -> str:
        """Add/remove our categories, keeping the client's own. Returns the
        message's current folder id."""
        body = await self._request("GET", f"messages/{message_id}", params={"$select": "categories,parentFolderId"})
        current = [str(c) for c in body.get("categories") or []]
        drop = set(remove)
        wanted = [c for c in current if c not in drop]
        wanted += [c for c in dict.fromkeys(add) if c not in wanted]
        if wanted != current:
            await self._request("PATCH", f"messages/{message_id}", json_body={"categories": wanted})
        return str(body.get("parentFolderId", ""))

    async def _move(self, message_id: str, destination: str, parent: str) -> None:
        if parent == destination:
            return
        await self._request("POST", f"messages/{message_id}/move", json_body={"destinationId": destination})


def verdict_category_plan(level: VerdictLevel, *, quarantine: bool, relabel: bool = False) -> tuple[list[str], list[str]]:
    """Categories to add/remove for a verdict. UNKNOWN gets none: we neither
    claim "Checked" nor accuse "Suspicious". A quarantined message always
    carries the Quarantine category so it is easy to find."""
    by_level = {
        VerdictLevel.SAFE: CATEGORY[LABEL_SAFE],
        VerdictLevel.SUSPICIOUS: CATEGORY[LABEL_SUSPICIOUS],
        VerdictLevel.MALICIOUS: CATEGORY[LABEL_QUARANTINE],
    }
    add: list[str] = [by_level[level]] if level in by_level else []
    if quarantine and CATEGORY[LABEL_QUARANTINE] not in add:
        add.append(CATEGORY[LABEL_QUARANTINE])
    remove: list[str] = []
    if relabel:
        remove = [c for c in (CATEGORY[LABEL_SAFE], CATEGORY[LABEL_SUSPICIOUS]) if c not in add]
    return add, remove

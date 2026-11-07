"""Gmail connector over the REST API with httpx.

Why not ``googleapiclient``: it is synchronous, discovery-document driven and
hard to test offline. The handful of endpoints we need are stable and simple,
so a thin async client with explicit retry/refresh behaviour is both smaller
and more predictable.

HOLD mode relies on a Gmail *filter* whose criteria match every incoming
message and whose action removes INBOX and adds our "Checking" label. Gmail
filters apply to incoming mail only, which is exactly the semantics we want:
existing mail is untouched. Because a filter needs a criterion, we use
``HOLD_QUERY(address)`` ("deliveredto:<address> OR to:<address>") as a
catch-all; whether this catches 100% of deliveries (BCC, aliases, group
expansions) must be validated in dogfooding before Hold mode is offered to
clients, and the dead man's switch exists so that nothing is ever trapped.
"""

from __future__ import annotations

import asyncio
import base64
import json
import random
from collections.abc import Awaitable, Callable, Collection, Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from pydantic import BaseModel

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
from reddysec.mail.oauth_google import GoogleOAuth, TokenSet
from reddysec.models import PolicyConfig, ProtectionMode, Provider, RawMessage, Verdict, VerdictLevel

log = get_logger(__name__)

GMAIL_API = "https://gmail.googleapis.com/gmail/v1/users/me"
HOLD_FILTER_KEY = "_hold_filter_id"
INBOX = "INBOX"

# Messages carrying these system labels are never ours to scan: outgoing mail,
# drafts, and mail Gmail already put in spam/trash.
SKIP_SYSTEM_LABELS = frozenset({"DRAFT", "SENT", "SPAM", "TRASH"})
# Messages carrying one of our verdict labels were already processed; seeing
# them again in history (because *we* modified them) must not start a loop.
VERDICT_LABELS = (LABEL_SAFE, LABEL_SUSPICIOUS, LABEL_QUARANTINE, LABEL_RELEASED)

SEED_QUERY = "newer_than:1d"
# Backfill reads the inbox only, like IMAP and Graph: archived mail stays
# archived (HOLD mode puts a checked message *into* the inbox).
BACKFILL_EXCLUDE = "in:inbox -in:sent -in:drafts -in:spam -in:trash"
SEED_MAX_RESULTS = 50
HISTORY_PAGE_SIZE = 500
LIST_PAGE_SIZE = 500
BATCH_MODIFY_CHUNK = 100
MAX_TRIES = 4
BACKOFF_BASE_S = 0.5
BACKOFF_CAP_S = 8.0
TOKEN_SKEW_S = 60
FETCH_CONCURRENCY = 4
RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})
RATE_LIMIT_REASONS = frozenset({"rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded"})


def HOLD_QUERY(address: str) -> str:  # noqa: N802 - named like a constant on purpose
    """Gmail filter criteria that match every incoming message for ``address``.
    Gmail filters apply to incoming mail only; a catch-all criterion is needed
    because a filter without criteria is rejected. This must be validated in
    dogfooding: aliases and BCC deliveries are the likely gaps."""
    return f"deliveredto:{address} OR to:{address}"


class GmailApiError(ConnectorError):
    """A non-2xx Gmail API response. ``status`` lets callers special-case 404."""

    def __init__(self, status: int, message: str, *, reason: str = "", retryable: bool):
        super().__init__(message, retryable=retryable)
        self.status = status
        self.reason = reason


class GoogleCredentials(BaseModel):
    access_token: str = ""
    refresh_token: str | None = None
    expires_at: datetime | None = None

    @classmethod
    def from_secret(cls, secret: dict[str, Any]) -> GoogleCredentials:
        raw_exp = secret.get("expires_at")
        expires_at = datetime.fromisoformat(raw_exp) if isinstance(raw_exp, str) and raw_exp else None
        if expires_at is not None and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        return cls(
            access_token=str(secret.get("access_token") or ""),
            refresh_token=secret.get("refresh_token"),
            expires_at=expires_at,
        )

    @classmethod
    def from_token_set(cls, tokens: TokenSet) -> GoogleCredentials:
        return cls(
            access_token=tokens.access_token, refresh_token=tokens.refresh_token, expires_at=tokens.expires_at
        )

    def is_expired(self, now: datetime, skew_s: int = TOKEN_SKEW_S) -> bool:
        if not self.access_token:
            return True
        if self.expires_at is None:
            return False  # unknown lifetime: try it, the 401 path refreshes
        return self.expires_at <= now + timedelta(seconds=skew_s)


def verdict_label_plan(
    level: VerdictLevel, policy: PolicyConfig, label_ids: dict[str, str], *, hold: bool, relabel: bool = False
) -> tuple[list[str], list[str]]:
    """Which label ids to add/remove for a verdict. Pure, so it is easy to test
    every level x mode x policy combination.

    UNKNOWN (analysis failed or timed out) gets no verdict label: we neither
    claim "Checked" nor accuse "Suspicious". It is released like a safe
    message because the product's rule is that our failures never trap mail.
    A quarantined message always carries the Quarantine label (even when the
    verdict was only Suspicious under a strict policy) so the client can find
    everything we withheld in one place.
    """
    add: list[str] = []
    remove: list[str] = [label_ids[LABEL_PENDING]]
    by_level = {
        VerdictLevel.SAFE: LABEL_SAFE,
        VerdictLevel.SUSPICIOUS: LABEL_SUSPICIOUS,
        VerdictLevel.MALICIOUS: LABEL_QUARANTINE,
    }
    if level in by_level:
        add.append(label_ids[by_level[level]])
    quarantine = level is not VerdictLevel.UNKNOWN and level.rank >= policy.quarantine_at.rank
    if quarantine:
        remove.append(INBOX)
        if label_ids[LABEL_QUARANTINE] not in add:
            add.append(label_ids[LABEL_QUARANTINE])
    elif hold:
        add.append(INBOX)
    if relabel:
        # A re-check replaces the earlier verdict word; Quarantine and
        # "Released by you" are about where the message is, so they stay.
        remove.extend(label_ids[name] for name in (LABEL_SAFE, LABEL_SUSPICIOUS) if label_ids[name] not in add)
    return add, remove


def should_quarantine(verdict: Verdict, policy: PolicyConfig) -> bool:
    return verdict.level is not VerdictLevel.UNKNOWN and verdict.level.rank >= policy.quarantine_at.rank


class GmailConnector:
    """MailboxConnector for Gmail.

    ``labels`` seeds the label-name -> id cache (from the mailbox row); missing
    entries are looked up or created on demand, so a client deleting one of our
    labels heals itself on the next action. ``mode`` is the mailbox's current
    protection mode and is refreshed by ``setup``.
    """

    provider = Provider.GMAIL

    def __init__(
        self,
        mailbox_id: str,
        address: str,
        credentials: GoogleCredentials,
        oauth: GoogleOAuth,
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
        self._labels: dict[str, str] = {
            k: v for k, v in (labels or {}).items() if not k.startswith("_") or k == HOLD_FILTER_KEY
        }
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
        """Current label map (name -> id, plus ``_hold_filter_id`` when installed)."""
        return dict(self._labels)

    async def _ensure_token(self, *, force: bool = False) -> str:
        async with self._refresh_lock:
            if force or self.credentials.is_expired(self._clock()):
                if not self.credentials.refresh_token:
                    raise AuthExpired("Gmail access token expired and no refresh token is stored")
                tokens = await self._oauth.refresh(self.credentials.refresh_token)
                self.credentials = GoogleCredentials.from_token_set(tokens)
                if self._on_tokens_refreshed is not None:
                    await self._on_tokens_refreshed(tokens)
            return self.credentials.access_token

    def _backoff_delay(self, attempt: int) -> float:
        return min(BACKOFF_CAP_S, BACKOFF_BASE_S * (2**attempt)) + self._rng() * BACKOFF_BASE_S

    async def _pause_before_retry(self, attempt: int) -> None:
        if attempt < MAX_TRIES - 1:  # no point sleeping after the final attempt
            await self._sleep(self._backoff_delay(attempt))

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """One API call with: pre-emptive refresh, one refresh-and-retry on 401,
        exponential backoff with jitter on 429/5xx/network errors (MAX_TRIES),
        and typed errors for everything else."""
        url = path if path.startswith("http") else f"{GMAIL_API}/{path.lstrip('/')}"
        refreshed = False
        last_error: str = ""
        for attempt in range(MAX_TRIES):
            token = await self._ensure_token()
            try:
                resp = await self.http.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                )
            except httpx.HTTPError as exc:
                last_error = f"network error: {exc}"
                log.warning(
                    "gmail.network_error", mailbox_id=self.mailbox_id, attempt=attempt, error=str(exc)
                )
                await self._pause_before_retry(attempt)
                continue

            if 200 <= resp.status_code < 300:
                if not resp.content:
                    return {}
                try:
                    body = resp.json()
                except json.JSONDecodeError as exc:
                    raise ConnectorError("Gmail returned a non-JSON body", retryable=True) from exc
                return body if isinstance(body, dict) else {"_": body}

            reason, message = _error_details(resp)
            if resp.status_code == 401:
                if refreshed:
                    raise AuthExpired(
                        "Gmail rejected the access token twice; the mailbox must be reconnected"
                    )
                refreshed = True
                await self._ensure_token(force=True)
                continue
            if resp.status_code in RETRYABLE_STATUSES or (
                resp.status_code == 403 and reason in RATE_LIMIT_REASONS
            ):
                last_error = f"HTTP {resp.status_code} {reason}: {message}"
                log.warning(
                    "gmail.retryable_status",
                    mailbox_id=self.mailbox_id,
                    status=resp.status_code,
                    attempt=attempt,
                )
                await self._pause_before_retry(attempt)
                continue
            raise GmailApiError(
                resp.status_code,
                f"Gmail API {method} {path}: HTTP {resp.status_code} {reason} {message}".strip(),
                reason=reason,
                retryable=False,
            )
        raise ConnectorError(
            f"Gmail API {method} {path} failed after {MAX_TRIES} tries: {last_error}", retryable=True
        )

    # --------------------------------------------------------------- labels
    async def _list_labels(self) -> dict[str, str]:
        body = await self._request("GET", "labels")
        return {lbl["name"]: lbl["id"] for lbl in body.get("labels", []) if "name" in lbl and "id" in lbl}

    async def _ensure_labels(self) -> dict[str, str]:
        """Create any of our labels that are missing. Nested labels are created
        by name ("Secureddy/Checking"); the root must exist first, which
        ALL_LABELS guarantees by ordering."""
        existing = await self._list_labels()
        for name in ALL_LABELS:
            if name in existing:
                self._labels[name] = existing[name]
                continue
            created = await self._request(
                "POST",
                "labels",
                json_body={"name": name, "labelListVisibility": "labelShow", "messageListVisibility": "show"},
            )
            self._labels[name] = created["id"]
            log.info("gmail.label_created", mailbox_id=self.mailbox_id, label=name)
        return dict(self._labels)

    async def _label_ids(self) -> dict[str, str]:
        if any(name not in self._labels for name in ALL_LABELS):
            await self._ensure_labels()
        return self._labels

    def _verdict_label_ids(self) -> set[str]:
        return {self._labels[name] for name in VERDICT_LABELS if name in self._labels}

    # -------------------------------------------------------------- filters
    async def _list_hold_filters(self) -> list[dict[str, Any]]:
        body = await self._request("GET", "settings/filters")
        query = HOLD_QUERY(self.address)
        return [f for f in body.get("filter", []) if f.get("criteria", {}).get("query") == query]

    async def _ensure_hold_filter(self) -> str:
        """Exactly one hold filter with the right action; extras and stale ones
        (pointing at a label id that no longer exists) are deleted."""
        checking_id = (await self._label_ids())[LABEL_PENDING]
        keep: str | None = None
        for f in await self._list_hold_filters():
            action = f.get("action", {})
            correct = checking_id in action.get("addLabelIds", []) and INBOX in action.get(
                "removeLabelIds", []
            )
            if correct and keep is None:
                keep = f["id"]
            else:
                await self._request("DELETE", f"settings/filters/{f['id']}")
        if keep is None:
            created = await self._request(
                "POST",
                "settings/filters",
                json_body={
                    "criteria": {"query": HOLD_QUERY(self.address)},
                    "action": {"removeLabelIds": [INBOX], "addLabelIds": [checking_id]},
                },
            )
            keep = created["id"]
            log.info("gmail.hold_filter_created", mailbox_id=self.mailbox_id)
        return keep

    async def _delete_hold_filters(self) -> int:
        n = 0
        for f in await self._list_hold_filters():
            await self._request("DELETE", f"settings/filters/{f['id']}")
            n += 1
        self._labels.pop(HOLD_FILTER_KEY, None)
        return n

    # ------------------------------------------------------ MailboxConnector
    async def setup(self, mode: ProtectionMode) -> dict[str, str]:
        self.mode = mode
        await self._ensure_labels()
        if mode is ProtectionMode.HOLD:
            self._labels[HOLD_FILTER_KEY] = await self._ensure_hold_filter()
        else:
            await self._delete_hold_filters()
        return dict(self._labels)

    async def poll(self, cursor: str | None) -> tuple[list[RawMessage], str | None]:
        await self._label_ids()
        if cursor is None:
            return await self._seed()
        try:
            ids, new_cursor = await self._history_since(cursor)
        except GmailApiError as exc:
            if exc.status == 404:
                # startHistoryId is older than Gmail keeps (about a week), or the
                # mailbox was reset. Re-seed from recent mail rather than fail forever.
                log.warning("gmail.history_expired", mailbox_id=self.mailbox_id, cursor=cursor)
                return await self._seed()
            raise
        return await self._fetch_many(ids), new_cursor

    async def fetch_raw(self, provider_message_id: str) -> bytes:
        body = await self._request("GET", f"messages/{provider_message_id}", params={"format": "raw"})
        return _decode_raw(body)

    async def backfill(self, since: datetime, limit: int, *, skip: Collection[str] = ()) -> list[RawMessage]:
        """List mail since ``since`` (newest first, Gmail's own order), drop
        ids we already have, then download at most ``limit`` bodies."""
        if limit <= 0:
            return []
        await self._label_ids()
        query = f"after:{int(since.timestamp())} {BACKFILL_EXCLUDE}"
        known = set(skip)
        wanted: list[str] = []
        page_token: str | None = None
        while len(wanted) < limit:
            params: dict[str, Any] = {"maxResults": LIST_PAGE_SIZE, "q": query}
            if page_token:
                params["pageToken"] = page_token
            body = await self._request("GET", "messages", params=params)
            for item in body.get("messages", []):
                message_id = item.get("id")
                if message_id and message_id not in known and message_id not in wanted:
                    wanted.append(message_id)
                    if len(wanted) >= limit:
                        break
            page_token = body.get("nextPageToken")
            if not page_token:
                break
        messages = [m for m in await self._fetch_many(wanted) if m.received_at >= since]
        return sorted(messages, key=lambda m: m.received_at, reverse=True)

    async def apply_verdict(
        self, msg: RawMessage, verdict: Verdict, policy: PolicyConfig, *, relabel: bool = False
    ) -> None:
        # Either the connector (mailbox row) or the policy saying HOLD wins: the
        # cost of a redundant INBOX add is nil, the cost of leaving a held
        # message in "Checking" is trapped mail.
        hold = self.mode is ProtectionMode.HOLD or policy.mode is ProtectionMode.HOLD
        add, remove = verdict_label_plan(
            verdict.level, policy, await self._label_ids(), hold=hold, relabel=relabel
        )
        await self._modify(msg.provider_message_id, add=add, remove=remove)

    async def release(self, provider_message_id: str) -> None:
        labels = await self._label_ids()
        await self._modify(provider_message_id, add=[INBOX], remove=[labels[LABEL_PENDING]])

    async def quarantine(self, provider_message_id: str) -> None:
        labels = await self._label_ids()
        await self._modify(
            provider_message_id, add=[labels[LABEL_QUARANTINE]], remove=[INBOX, labels[LABEL_PENDING]]
        )

    async def restore(self, provider_message_id: str) -> None:
        labels = await self._label_ids()
        await self._modify(
            provider_message_id, add=[INBOX, labels[LABEL_RELEASED]], remove=[labels[LABEL_QUARANTINE]]
        )

    async def mark_safe(self, provider_message_id: str) -> None:
        labels = await self._label_ids()
        await self._modify(
            provider_message_id,
            add=[labels[LABEL_SAFE], INBOX],
            remove=[labels[LABEL_SUSPICIOUS], labels[LABEL_QUARANTINE], labels[LABEL_PENDING]],
        )

    async def release_all_pending(self) -> int:
        labels = await self._label_ids()
        ids = await self._list_message_ids(label_ids=[labels[LABEL_PENDING]])
        for chunk in _chunks(ids, BATCH_MODIFY_CHUNK):
            await self._request(
                "POST",
                "messages/batchModify",
                json_body={"ids": chunk, "addLabelIds": [INBOX], "removeLabelIds": [labels[LABEL_PENDING]]},
            )
        log.info("gmail.release_all_pending", mailbox_id=self.mailbox_id, count=len(ids))
        return len(ids)

    async def teardown(self) -> None:
        await self._delete_hold_filters()

    # ---------------------------------------------------------------- watch
    async def watch(self, topic_name: str, label_ids: list[str] | None = None) -> datetime:
        """Ask Gmail to publish change notifications to a Pub/Sub topic. Must be
        renewed before ``expiration`` (Gmail grants at most 7 days)."""
        body = await self._request(
            "POST",
            "watch",
            json_body={
                "topicName": topic_name,
                "labelIds": list(label_ids or []),
                "labelFilterBehavior": "INCLUDE",
            },
        )
        return datetime.fromtimestamp(int(body["expiration"]) / 1000, UTC)

    async def stop_watch(self) -> None:
        await self._request("POST", "stop")

    @staticmethod
    def parse_pubsub_push(body: dict[str, Any]) -> tuple[str, str]:
        """Decode a Pub/Sub push envelope into (email_address, history_id).
        The payload only says *something changed*; the worker still polls
        history from its stored cursor, so a lost push costs latency, not mail."""
        try:
            data = base64.b64decode(body["message"]["data"])
            payload = json.loads(data)
            return str(payload["emailAddress"]).lower(), str(payload["historyId"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("malformed Pub/Sub push body") from exc

    # ------------------------------------------------------------ internals
    async def _modify(self, message_id: str, *, add: Iterable[str], remove: Iterable[str]) -> None:
        payload: dict[str, Any] = {}
        add_ids = [x for x in dict.fromkeys(add) if x]
        remove_ids = [x for x in dict.fromkeys(remove) if x]
        if add_ids:
            payload["addLabelIds"] = add_ids
        if remove_ids:
            payload["removeLabelIds"] = remove_ids
        if not payload:
            return
        await self._request("POST", f"messages/{message_id}/modify", json_body=payload)

    async def _list_message_ids(
        self, *, query: str | None = None, label_ids: list[str] | None = None, limit: int | None = None
    ) -> list[str]:
        ids: list[str] = []
        page_token: str | None = None
        while True:
            params: dict[str, Any] = {"maxResults": min(limit or LIST_PAGE_SIZE, LIST_PAGE_SIZE)}
            if query:
                params["q"] = query
            if label_ids:
                params["labelIds"] = label_ids
            if page_token:
                params["pageToken"] = page_token
            body = await self._request("GET", "messages", params=params)
            ids.extend(m["id"] for m in body.get("messages", []))
            page_token = body.get("nextPageToken")
            if not page_token or (limit is not None and len(ids) >= limit):
                break
        return ids[:limit] if limit is not None else ids

    async def _seed(self) -> tuple[list[RawMessage], str | None]:
        """First poll (or resync): recent mail plus, in HOLD mode, everything
        already parked under "Checking". The profile's historyId is read
        *before* listing so a message arriving in between shows up in the next
        history poll instead of falling through the gap."""
        profile = await self._request("GET", "profile")
        cursor = str(profile.get("historyId", "")) or None
        ids = await self._list_message_ids(query=SEED_QUERY, limit=SEED_MAX_RESULTS)
        if self.mode is ProtectionMode.HOLD:
            ids.extend(await self._list_message_ids(label_ids=[self._labels[LABEL_PENDING]]))
        messages = await self._fetch_many(list(dict.fromkeys(ids)))
        return messages, cursor

    async def _history_since(self, cursor: str) -> tuple[list[str], str]:
        ids: list[str] = []
        skip_ids = self._verdict_label_ids()
        page_token: str | None = None
        new_cursor = cursor
        while True:
            params: dict[str, Any] = {
                "startHistoryId": cursor,
                "historyTypes": "messageAdded",
                "maxResults": HISTORY_PAGE_SIZE,
            }
            if page_token:
                params["pageToken"] = page_token
            body = await self._request("GET", "history", params=params)
            for record in body.get("history", []):
                for added in record.get("messagesAdded", []):
                    message = added.get("message", {})
                    label_ids = set(message.get("labelIds", []))
                    if label_ids & SKIP_SYSTEM_LABELS or label_ids & skip_ids:
                        continue
                    if message.get("id"):
                        ids.append(message["id"])
            if body.get("historyId"):
                new_cursor = str(body["historyId"])
            page_token = body.get("nextPageToken")
            if not page_token:
                break
        return list(dict.fromkeys(ids)), new_cursor

    async def _fetch_many(self, ids: list[str]) -> list[RawMessage]:
        """Fetch raw messages with bounded concurrency. A 404 means the message
        vanished between listing and fetching (user deleted it); skip it."""
        semaphore = asyncio.Semaphore(FETCH_CONCURRENCY)
        skip_ids = self._verdict_label_ids()

        async def fetch_one(message_id: str) -> RawMessage | None:
            async with semaphore:
                try:
                    body = await self._request("GET", f"messages/{message_id}", params={"format": "raw"})
                except GmailApiError as exc:
                    if exc.status == 404:
                        return None
                    raise
            label_ids = set(body.get("labelIds", []))
            if label_ids & SKIP_SYSTEM_LABELS or label_ids & skip_ids:
                return None
            return self._to_raw_message(body)

        results = await asyncio.gather(*(fetch_one(i) for i in ids))
        return [r for r in results if r is not None]

    def _to_raw_message(self, body: dict[str, Any]) -> RawMessage:
        internal_ms = int(body.get("internalDate", 0) or 0)
        received_at = datetime.fromtimestamp(internal_ms / 1000, UTC) if internal_ms else self._clock()
        return RawMessage(
            provider_message_id=body["id"],
            mailbox_id=self.mailbox_id,
            received_at=received_at,
            raw=_decode_raw(body),
            provider_labels=list(body.get("labelIds", [])),
            thread_id=body.get("threadId"),
        )


def _decode_raw(body: dict[str, Any]) -> bytes:
    raw = body.get("raw")
    if not raw:
        raise ConnectorError("Gmail message body did not include raw content", retryable=False)
    padded = raw + "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(padded)


def _error_details(resp: httpx.Response) -> tuple[str, str]:
    try:
        err = resp.json().get("error", {})
    except (json.JSONDecodeError, AttributeError):
        return "", resp.text[:200]
    if isinstance(err, dict):
        errors = err.get("errors") or [{}]
        reason = str(errors[0].get("reason", "")) if isinstance(errors[0], dict) else ""
        return reason or str(err.get("status", "")), str(err.get("message", ""))
    return "", str(err)


def _chunks(items: list[str], size: int) -> Iterable[list[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]

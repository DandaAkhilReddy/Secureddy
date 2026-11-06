"""GmailConnector against the in-memory Gmail server (httpx.MockTransport)."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from reddysec.mail.base import (
    ALL_LABELS,
    LABEL_PENDING,
    LABEL_QUARANTINE,
    LABEL_RELEASED,
    LABEL_ROOT,
    LABEL_SAFE,
    LABEL_SUSPICIOUS,
    AuthExpired,
    ConnectorError,
)
from reddysec.mail.gmail import (
    HOLD_FILTER_KEY,
    HOLD_QUERY,
    GmailApiError,
    GmailConnector,
    GoogleCredentials,
    verdict_label_plan,
)
from reddysec.models import PolicyConfig, ProtectionMode, TriageLane, Verdict, VerdictLevel

from .conftest import FIXED_NOW, GmailEnv, sample_raw


def verdict(level: VerdictLevel) -> Verdict:
    return Verdict(level=level, score=50, summary="s", lane=TriageLane.DETONATE)


class TestSetup:
    async def test_scan_creates_labels_root_first_and_is_idempotent(self, gmail_env: GmailEnv):
        labels = await gmail_env.connector.setup(ProtectionMode.SCAN)
        created = [c.json["name"] for c in gmail_env.server.calls_to("POST", "labels")]
        assert created == ALL_LABELS
        assert created[0] == LABEL_ROOT
        assert all(
            c.json["labelListVisibility"] == "labelShow" for c in gmail_env.server.calls_to("POST", "labels")
        )
        assert all(
            c.json["messageListVisibility"] == "show" for c in gmail_env.server.calls_to("POST", "labels")
        )
        assert set(labels) == set(ALL_LABELS)
        assert HOLD_FILTER_KEY not in labels

        gmail_env.server.calls.clear()
        again = await gmail_env.connector.setup(ProtectionMode.SCAN)
        assert again == labels
        assert not gmail_env.server.calls_to("POST", "labels")

    async def test_partial_labels_are_completed(self, gmail_env: GmailEnv):
        # The client deleted two of our labels: setup recreates just those.
        await gmail_env.connector.setup(ProtectionMode.SCAN)
        for name in (LABEL_SAFE, LABEL_RELEASED):
            lid = gmail_env.server.label_id(name)
            del gmail_env.server.labels[lid]
        gmail_env.server.calls.clear()
        labels = await gmail_env.new_connector().setup(ProtectionMode.SCAN)
        assert sorted(c.json["name"] for c in gmail_env.server.calls_to("POST", "labels")) == sorted(
            [LABEL_SAFE, LABEL_RELEASED]
        )
        assert labels[LABEL_SAFE] == gmail_env.server.label_id(LABEL_SAFE)

    async def test_hold_installs_exactly_one_filter(self, gmail_env: GmailEnv):
        labels = await gmail_env.connector.setup(ProtectionMode.HOLD)
        checking = labels[LABEL_PENDING]
        assert len(gmail_env.server.filters) == 1
        flt = next(iter(gmail_env.server.filters.values()))
        assert flt["criteria"] == {"query": HOLD_QUERY("client@gmail.com")}
        assert flt["criteria"]["query"] == "deliveredto:client@gmail.com OR to:client@gmail.com"
        assert flt["action"] == {"removeLabelIds": ["INBOX"], "addLabelIds": [checking]}
        assert labels[HOLD_FILTER_KEY] == flt["id"]

        gmail_env.server.calls.clear()
        again = await gmail_env.connector.setup(ProtectionMode.HOLD)
        assert again[HOLD_FILTER_KEY] == flt["id"]
        assert not gmail_env.server.calls_to("POST", "settings/filters")
        assert len(gmail_env.server.filters) == 1

    async def test_hold_replaces_stale_and_duplicate_filters(self, gmail_env: GmailEnv):
        await gmail_env.connector.setup(ProtectionMode.HOLD)
        q = HOLD_QUERY("client@gmail.com")
        # one stale (wrong label id), one duplicate correct one
        good = next(iter(gmail_env.server.filters.values()))
        gmail_env.server.filters["stale"] = {
            "id": "stale",
            "criteria": {"query": q},
            "action": {"addLabelIds": ["Label_old"], "removeLabelIds": ["INBOX"]},
        }
        gmail_env.server.filters["dup"] = {"id": "dup", **{k: v for k, v in good.items() if k != "id"}}
        gmail_env.server.filters["other"] = {
            "id": "other",
            "criteria": {"from": "x@y"},
            "action": {"addLabelIds": ["STARRED"]},
        }
        labels = await gmail_env.connector.setup(ProtectionMode.HOLD)
        assert set(gmail_env.server.filters) == {good["id"], "other"}
        assert labels[HOLD_FILTER_KEY] == good["id"]

    async def test_switching_to_scan_removes_filter_and_teardown(self, gmail_env: GmailEnv):
        await gmail_env.connector.setup(ProtectionMode.HOLD)
        labels = await gmail_env.connector.setup(ProtectionMode.SCAN)
        assert gmail_env.server.filters == {}
        assert HOLD_FILTER_KEY not in labels
        await gmail_env.connector.setup(ProtectionMode.HOLD)
        assert len(gmail_env.server.filters) == 1
        await gmail_env.connector.teardown()
        assert gmail_env.server.filters == {}
        assert HOLD_FILTER_KEY not in gmail_env.connector.labels

    async def test_constructor_label_cache_drops_private_keys(self, gmail_env: GmailEnv):
        c = gmail_env.new_connector(
            labels={LABEL_ROOT: "L1", "_mode": "scan", HOLD_FILTER_KEY: "f1", "_instructions": "x"}
        )
        assert c.labels == {LABEL_ROOT: "L1", HOLD_FILTER_KEY: "f1"}


class TestPoll:
    async def test_seed_reads_history_id_before_listing_and_skips_sent(self, gmail_env: GmailEnv):
        server = gmail_env.server
        inbox_id = server.add_message(
            sample_raw("one"),
            internal_ms=int((FIXED_NOW - timedelta(hours=1)).timestamp() * 1000),
            thread_id="thr1",
        )
        server.add_message(sample_raw("sent"), labels=("SENT",))
        server.add_message(
            sample_raw("old"), internal_ms=int((FIXED_NOW - timedelta(days=3)).timestamp() * 1000)
        )
        server.add_message(sample_raw("spam"), labels=("SPAM",))
        await gmail_env.connector.setup(ProtectionMode.SCAN)
        server.calls.clear()

        messages, cursor = await gmail_env.connector.poll(None)
        assert [m.provider_message_id for m in messages] == [inbox_id]
        assert cursor == str(server.history_id)
        paths = [c.path for c in server.calls]
        assert paths.index("profile") < paths.index("messages")
        list_call = server.calls_to("GET", "messages")[0]
        assert list_call.params == {"maxResults": ["50"], "q": ["newer_than:1d"]}
        msg = messages[0]
        assert msg.raw == sample_raw("one")
        assert msg.thread_id == "thr1"
        assert msg.received_at == FIXED_NOW - timedelta(hours=1)
        assert msg.received_at.tzinfo is UTC
        assert set(msg.provider_labels) == {"INBOX", "UNREAD"}
        assert server.calls_to("GET", f"messages/{inbox_id}")[0].params == {"format": ["raw"]}

    async def test_seed_in_hold_mode_includes_checking_label(self, gmail_env: GmailEnv):
        server = gmail_env.server
        labels = await gmail_env.connector.setup(ProtectionMode.HOLD)
        checking = labels[LABEL_PENDING]
        held = server.add_message(
            sample_raw("held"),
            labels=(checking,),
            internal_ms=int((FIXED_NOW - timedelta(days=2)).timestamp() * 1000),
        )
        recent = server.add_message(sample_raw("recent"))
        both = server.add_message(sample_raw("both"), labels=(checking, "UNREAD"))
        messages, _ = await gmail_env.connector.poll(None)
        assert sorted(m.provider_message_id for m in messages) == sorted([held, recent, both])  # deduplicated
        list_calls = server.calls_to("GET", "messages")
        assert any(c.params.get("labelIds") == [checking] for c in list_calls)

    async def test_history_poll_paginates_dedupes_and_skips(self, gmail_env: GmailEnv):
        server = gmail_env.server
        labels = await gmail_env.connector.setup(ProtectionMode.SCAN)
        _, cursor = await gmail_env.connector.poll(None)
        server.history_page_size = 2
        a = server.add_message(sample_raw("a"))
        b = server.add_message(sample_raw("b"))
        server.add_message(sample_raw("draft"), labels=("DRAFT",))
        server.add_message(sample_raw("sent"), labels=("SENT",))
        server.add_message(sample_raw("trash"), labels=("TRASH",))
        server.add_message(sample_raw("done"), labels=("INBOX", labels[LABEL_SAFE]))
        server.add_message(sample_raw("quar"), labels=(labels[LABEL_QUARANTINE],))
        # a second history record for message "a" (e.g. label change replayed as add)
        server.history_id += 1
        server.history.append(
            {"id": str(server.history_id), "messagesAdded": [{"message": {"id": a, "labelIds": ["INBOX"]}}]}
        )
        server.calls.clear()

        messages, new_cursor = await gmail_env.connector.poll(cursor)
        assert [m.provider_message_id for m in messages] == [a, b]
        assert new_cursor == str(server.history_id)
        history_calls = server.calls_to("GET", "history")
        assert len(history_calls) == 4  # 8 records / 2 per page
        first = history_calls[0].params
        assert first["startHistoryId"] == [cursor]
        assert first["historyTypes"] == ["messageAdded"]
        assert "labelId" not in first  # held mail is not in INBOX; never filter by label
        assert history_calls[1].params["pageToken"] == ["2"]
        # Only the two real messages were fetched.
        fetched = [c.path for c in server.calls if c.method == "GET" and c.path.startswith("messages/")]
        assert sorted(fetched) == sorted([f"messages/{a}", f"messages/{b}"])

    async def test_history_poll_is_idempotent_and_handles_no_changes(self, gmail_env: GmailEnv):
        server = gmail_env.server
        await gmail_env.connector.setup(ProtectionMode.SCAN)
        _, cursor = await gmail_env.connector.poll(None)
        a = server.add_message(sample_raw("a"))
        first, c1 = await gmail_env.connector.poll(cursor)
        second, c2 = await gmail_env.connector.poll(cursor)
        assert [m.provider_message_id for m in first] == [m.provider_message_id for m in second] == [a]
        assert c1 == c2
        none, c3 = await gmail_env.connector.poll(c1)
        assert none == [] and c3 == c1

    async def test_history_404_triggers_resync(self, gmail_env: GmailEnv):
        server = gmail_env.server
        await gmail_env.connector.setup(ProtectionMode.SCAN)
        a = server.add_message(sample_raw("a"))
        server.oldest_history_id = server.history_id + 50
        server.calls.clear()
        messages, cursor = await gmail_env.connector.poll("5")
        assert [m.provider_message_id for m in messages] == [a]
        assert cursor == str(server.history_id)
        assert server.calls_to("GET", "history") and server.calls_to("GET", "profile")

    async def test_other_history_errors_propagate(self, gmail_env: GmailEnv):
        await gmail_env.connector.setup(ProtectionMode.SCAN)
        gmail_env.server.force(
            400,
            {
                "error": {
                    "code": 400,
                    "message": "Invalid startHistoryId",
                    "errors": [{"reason": "invalidArgument"}],
                }
            },
        )
        with pytest.raises(GmailApiError) as info:
            await gmail_env.connector.poll("abc")
        assert (
            info.value.status == 400 and not info.value.retryable and info.value.reason == "invalidArgument"
        )

    async def test_message_deleted_between_list_and_fetch_is_skipped(self, gmail_env: GmailEnv):
        server = gmail_env.server
        await gmail_env.connector.setup(ProtectionMode.SCAN)
        _, cursor = await gmail_env.connector.poll(None)
        gone = server.add_message(sample_raw("gone"))
        keep = server.add_message(sample_raw("keep"))
        del server.messages[gone]
        messages, _ = await gmail_env.connector.poll(cursor)
        assert [m.provider_message_id for m in messages] == [keep]

    async def test_fetch_raw_and_missing_raw(self, gmail_env: GmailEnv):
        server = gmail_env.server
        mid = server.add_message(sample_raw("x"))
        assert await gmail_env.connector.fetch_raw(mid) == sample_raw("x")
        server.messages[mid]["raw"] = ""
        with pytest.raises(ConnectorError) as info:
            await gmail_env.connector.fetch_raw(mid)
        assert not info.value.retryable
        with pytest.raises(GmailApiError) as info2:
            await gmail_env.connector.fetch_raw("nope")
        assert info2.value.status == 404

    async def test_raw_decoding_handles_unpadded_base64url(self, gmail_env: GmailEnv):
        raw = b"From: a@b\r\n\r\nx"  # length not a multiple of 3 -> padding stripped by Gmail
        mid = gmail_env.server.add_message(raw)
        assert "=" not in gmail_env.server.messages[mid]["raw"]
        assert await gmail_env.connector.fetch_raw(mid) == raw


class TestVerdictPlan:
    LABELS = {
        LABEL_PENDING: "Lp",
        LABEL_SAFE: "Ls",
        LABEL_SUSPICIOUS: "Lsu",
        LABEL_QUARANTINE: "Lq",
        LABEL_RELEASED: "Lr",
    }

    @pytest.mark.parametrize(
        ("level", "hold", "quarantine_at", "add", "remove"),
        [
            (VerdictLevel.SAFE, False, VerdictLevel.MALICIOUS, ["Ls"], ["Lp"]),
            (VerdictLevel.SAFE, True, VerdictLevel.MALICIOUS, ["Ls", "INBOX"], ["Lp"]),
            (VerdictLevel.SUSPICIOUS, False, VerdictLevel.MALICIOUS, ["Lsu"], ["Lp"]),
            (VerdictLevel.SUSPICIOUS, True, VerdictLevel.MALICIOUS, ["Lsu", "INBOX"], ["Lp"]),
            (VerdictLevel.SUSPICIOUS, True, VerdictLevel.SUSPICIOUS, ["Lsu", "Lq"], ["Lp", "INBOX"]),
            (VerdictLevel.MALICIOUS, False, VerdictLevel.MALICIOUS, ["Lq"], ["Lp", "INBOX"]),
            (VerdictLevel.MALICIOUS, True, VerdictLevel.MALICIOUS, ["Lq"], ["Lp", "INBOX"]),
            (VerdictLevel.UNKNOWN, False, VerdictLevel.MALICIOUS, [], ["Lp"]),
            (VerdictLevel.UNKNOWN, True, VerdictLevel.MALICIOUS, ["INBOX"], ["Lp"]),
            (
                VerdictLevel.UNKNOWN,
                True,
                VerdictLevel.SAFE,
                ["INBOX"],
                ["Lp"],
            ),  # UNKNOWN is never quarantined
        ],
    )
    def test_plan(self, level, hold, quarantine_at, add, remove):
        policy = PolicyConfig(quarantine_at=quarantine_at)
        assert verdict_label_plan(level, policy, self.LABELS, hold=hold) == (add, remove)


class TestActions:
    async def test_apply_verdict_single_modify_call_per_mode(self, gmail_env: GmailEnv):
        server = gmail_env.server
        labels = await gmail_env.connector.setup(ProtectionMode.SCAN)
        mid = server.add_message(sample_raw("m"), labels=("INBOX",))
        (raw,) = (await gmail_env.connector.poll(None))[0]
        server.calls.clear()
        await gmail_env.connector.apply_verdict(raw, verdict(VerdictLevel.MALICIOUS), PolicyConfig())
        calls = server.calls_to("POST", f"messages/{mid}/modify")
        assert len(calls) == 1
        assert calls[0].json == {
            "addLabelIds": [labels[LABEL_QUARANTINE]],
            "removeLabelIds": [labels[LABEL_PENDING], "INBOX"],
        }
        assert "INBOX" not in server.messages[mid]["labelIds"]

        # HOLD mode via the policy alone also releases to INBOX.
        held = server.add_message(sample_raw("h"), labels=(labels[LABEL_PENDING],))
        raw_h = next(m for m in (await gmail_env.connector.poll(None))[0] if m.provider_message_id == held)
        server.calls.clear()
        await gmail_env.connector.apply_verdict(
            raw_h, verdict(VerdictLevel.SAFE), PolicyConfig(mode=ProtectionMode.HOLD)
        )
        (call,) = server.calls_to("POST", f"messages/{held}/modify")
        assert call.json == {
            "addLabelIds": [labels[LABEL_SAFE], "INBOX"],
            "removeLabelIds": [labels[LABEL_PENDING]],
        }
        assert set(server.messages[held]["labelIds"]) == {labels[LABEL_SAFE], "INBOX"}

    async def test_apply_verdict_connector_mode_wins_over_policy(self, gmail_env: GmailEnv):
        labels = await gmail_env.connector.setup(ProtectionMode.HOLD)
        held = gmail_env.server.add_message(sample_raw("h"), labels=(labels[LABEL_PENDING],))
        (raw,) = (await gmail_env.connector.poll(None))[0]
        await gmail_env.connector.apply_verdict(
            raw, verdict(VerdictLevel.UNKNOWN), PolicyConfig()
        )  # policy says scan
        assert set(gmail_env.server.messages[held]["labelIds"]) == {"INBOX"}

    async def test_release_quarantine_restore_payloads(self, gmail_env: GmailEnv):
        server = gmail_env.server
        labels = await gmail_env.connector.setup(ProtectionMode.SCAN)
        mid = server.add_message(sample_raw("m"), labels=(labels[LABEL_PENDING],))
        await gmail_env.connector.release(mid)
        await gmail_env.connector.quarantine(mid)
        await gmail_env.connector.restore(mid)
        payloads = [c.json for c in server.calls_to("POST", f"messages/{mid}/modify")]
        assert payloads == [
            {"addLabelIds": ["INBOX"], "removeLabelIds": [labels[LABEL_PENDING]]},
            {"addLabelIds": [labels[LABEL_QUARANTINE]], "removeLabelIds": ["INBOX", labels[LABEL_PENDING]]},
            {"addLabelIds": ["INBOX", labels[LABEL_RELEASED]], "removeLabelIds": [labels[LABEL_QUARANTINE]]},
        ]
        assert set(server.messages[mid]["labelIds"]) == {"INBOX", labels[LABEL_RELEASED]}

    async def test_release_all_pending_batches_by_100(self, gmail_env: GmailEnv):
        server = gmail_env.server
        labels = await gmail_env.connector.setup(ProtectionMode.HOLD)
        checking = labels[LABEL_PENDING]
        ids = [
            server.add_message(sample_raw(f"h{i}"), labels=(checking,), record_history=False)
            for i in range(250)
        ]
        server.add_message(sample_raw("inbox"), labels=("INBOX",), record_history=False)
        server.calls.clear()
        assert await gmail_env.connector.release_all_pending() == 250
        batches = server.calls_to("POST", "messages/batchModify")
        assert [len(b.json["ids"]) for b in batches] == [100, 100, 50]
        assert all(
            b.json["addLabelIds"] == ["INBOX"] and b.json["removeLabelIds"] == [checking] for b in batches
        )
        assert sorted(sum((b.json["ids"] for b in batches), [])) == sorted(ids)
        assert all(
            "INBOX" in server.messages[i]["labelIds"] and checking not in server.messages[i]["labelIds"]
            for i in ids
        )
        # the list was paginated with the label filter
        lists = server.calls_to("GET", "messages")
        assert len(lists) == 3 and all(c.params["labelIds"] == [checking] for c in lists)
        assert await gmail_env.connector.release_all_pending() == 0

    async def test_labels_heal_when_cache_is_empty(self, gmail_env: GmailEnv):
        await gmail_env.connector.setup(ProtectionMode.SCAN)
        fresh = gmail_env.new_connector(labels={})
        mid = gmail_env.server.add_message(sample_raw("m"))
        await fresh.release(mid)
        assert set(fresh.labels) == set(ALL_LABELS)
        assert not gmail_env.server.calls_to("POST", "labels")[len(ALL_LABELS) :]  # nothing created twice


class TestAuthAndRetry:
    async def test_401_refreshes_once_and_retries(self, gmail_env: GmailEnv):
        server = gmail_env.server
        server.valid_tokens = set()  # the connector's current token is now rejected
        labels = await gmail_env.connector.setup(ProtectionMode.SCAN)
        assert labels
        assert gmail_env.connector.credentials.access_token == "access-1"
        assert gmail_env.connector.credentials.refresh_token == "refresh-1"
        assert gmail_env.connector.credentials.expires_at == FIXED_NOW + timedelta(seconds=3599)
        assert len(gmail_env.refreshed) == 1 and gmail_env.refreshed[0].access_token == "access-1"
        token_calls = [c for c in gmail_env.auth.calls if c.path == "/token"]
        assert len(token_calls) == 1

    async def test_expired_token_refreshes_preemptively(self, gmail_env: GmailEnv):
        creds = GoogleCredentials(
            access_token="stale", refresh_token="refresh-1", expires_at=FIXED_NOW - timedelta(minutes=1)
        )
        c = gmail_env.new_connector(credentials=creds)
        await c.fetch_raw(gmail_env.server.add_message(sample_raw("m")))
        first_gmail_call = gmail_env.server.calls[0]
        assert first_gmail_call.path.startswith("messages/")
        assert c.credentials.access_token == "access-1"
        assert all(
            call.token == "access-1" for call in gmail_env.server.calls
        )  # the stale token was never sent
        assert len([c for c in gmail_env.auth.calls if c.path == "/token"]) == 1

    async def test_second_401_is_auth_expired(self, gmail_env: GmailEnv):
        gmail_env.server.valid_tokens = set()
        gmail_env.auth.next_access_token = lambda: "never-valid"  # type: ignore[method-assign]
        with pytest.raises(AuthExpired, match="twice"):
            await gmail_env.connector.setup(ProtectionMode.SCAN)

    async def test_invalid_grant_on_refresh_is_auth_expired(self, gmail_env: GmailEnv):
        gmail_env.server.valid_tokens = set()
        gmail_env.auth.refresh_error = "invalid_grant"
        with pytest.raises(AuthExpired):
            await gmail_env.connector.setup(ProtectionMode.SCAN)
        assert gmail_env.refreshed == []

    async def test_no_refresh_token_is_auth_expired(self, gmail_env: GmailEnv):
        creds = GoogleCredentials(access_token="", refresh_token=None, expires_at=None)
        with pytest.raises(AuthExpired, match="no refresh token"):
            await gmail_env.new_connector(credentials=creds).setup(ProtectionMode.SCAN)

    async def test_429_backs_off_with_jitter_then_succeeds(self, gmail_env: GmailEnv):
        gmail_env.server.force(429, times=3)
        mid = gmail_env.server.add_message(sample_raw("m"))
        assert await gmail_env.connector.fetch_raw(mid) == sample_raw("m")
        # 0.5*2^n + jitter(0.5*0.5)
        assert gmail_env.sleeps == [0.75, 1.25, 2.25]

    async def test_persistent_5xx_is_retryable_connector_error(self, gmail_env: GmailEnv):
        gmail_env.server.force(503, times=4)
        with pytest.raises(ConnectorError, match="after 4 tries") as info:
            await gmail_env.connector.fetch_raw("m1")
        assert info.value.retryable and not isinstance(info.value, GmailApiError)
        assert len(gmail_env.sleeps) == 3  # no sleep after the final attempt

    async def test_403_rate_limit_is_retried_but_other_403_is_not(self, gmail_env: GmailEnv):
        server = gmail_env.server
        mid = server.add_message(sample_raw("m"))
        server.force(
            403,
            {
                "error": {
                    "code": 403,
                    "message": "Rate Limit Exceeded",
                    "errors": [{"reason": "rateLimitExceeded"}],
                }
            },
        )
        assert await gmail_env.connector.fetch_raw(mid) == sample_raw("m")
        server.force(
            403,
            {
                "error": {
                    "code": 403,
                    "message": "Insufficient Permission",
                    "errors": [{"reason": "insufficientPermissions"}],
                }
            },
        )
        with pytest.raises(GmailApiError) as info:
            await gmail_env.connector.fetch_raw(mid)
        assert info.value.status == 403 and not info.value.retryable

    async def test_network_errors_are_retried(self, gmail_env: GmailEnv):
        mid = gmail_env.server.add_message(sample_raw("m"))
        gmail_env.server.force_exception(httpx.ConnectError("boom"), times=2)
        assert await gmail_env.connector.fetch_raw(mid) == sample_raw("m")
        gmail_env.server.force_exception(httpx.ReadTimeout("slow"), times=4)
        with pytest.raises(ConnectorError, match="network error") as info:
            await gmail_env.connector.fetch_raw(mid)
        assert info.value.retryable

    async def test_non_json_success_body(self, gmail_env: GmailEnv):
        gmail_env.server.fail_next.append(httpx.Response(200, text="<html>"))
        with pytest.raises(ConnectorError, match="non-JSON"):
            await gmail_env.connector.fetch_raw("m1")

    async def test_error_details_without_json(self, gmail_env: GmailEnv):
        gmail_env.server.fail_next.append(httpx.Response(400, text="plain failure"))
        with pytest.raises(GmailApiError, match="plain failure"):
            await gmail_env.connector.fetch_raw("m1")
        gmail_env.server.fail_next.append(httpx.Response(400, json={"error": "string-shaped"}))
        with pytest.raises(GmailApiError, match="string-shaped"):
            await gmail_env.connector.fetch_raw("m1")

    async def test_owns_http_client_when_none_given(self, gmail_env: GmailEnv):
        c = GmailConnector("m", "a@gmail.com", GoogleCredentials(access_token="t"), gmail_env.oauth)
        assert isinstance(c.http, httpx.AsyncClient)
        await c.aclose()
        await gmail_env.connector.aclose()  # does not close a shared client
        assert not gmail_env.http.is_closed


class TestWatch:
    async def test_watch_and_stop(self, gmail_env: GmailEnv):
        expiration = await gmail_env.connector.watch("projects/p/topics/t")
        assert expiration == datetime.fromtimestamp(gmail_env.server.watch_expiration_ms / 1000, UTC)
        (call,) = gmail_env.server.calls_to("POST", "watch")
        assert call.json == {
            "topicName": "projects/p/topics/t",
            "labelIds": [],
            "labelFilterBehavior": "INCLUDE",
        }
        await gmail_env.connector.stop_watch()
        assert gmail_env.server.calls_to("POST", "stop")

    def test_parse_pubsub_push(self):
        data = base64.b64encode(
            json.dumps({"emailAddress": "Client@Gmail.com", "historyId": 12345}).encode()
        ).decode()
        body = {
            "message": {"data": data, "messageId": "1", "publishTime": "2026-11-05T12:00:00Z"},
            "subscription": "s",
        }
        assert GmailConnector.parse_pubsub_push(body) == ("client@gmail.com", "12345")
        for bad in [
            {},
            {"message": {}},
            {"message": {"data": "!!!"}},
            {"message": {"data": base64.b64encode(b"{}").decode()}},
        ]:
            with pytest.raises(ValueError):
                GmailConnector.parse_pubsub_push(bad)


class TestCredentials:
    def test_from_secret_and_expiry(self):
        creds = GoogleCredentials.from_secret(
            {"access_token": "a", "refresh_token": "r", "expires_at": "2026-11-05T12:00:00"}
        )
        assert creds.expires_at == FIXED_NOW  # naive -> UTC
        assert creds.is_expired(FIXED_NOW - timedelta(seconds=30))  # within skew
        assert not creds.is_expired(FIXED_NOW - timedelta(minutes=5))
        assert GoogleCredentials.from_secret({}).is_expired(FIXED_NOW)  # no token
        assert not GoogleCredentials(access_token="a").is_expired(FIXED_NOW)  # unknown lifetime: try it


class TestEdges:
    async def test_modify_with_nothing_to_do_makes_no_call(self, gmail_env: GmailEnv):
        await gmail_env.connector._modify("m1", add=["", None], remove=[])  # type: ignore[list-item]
        assert gmail_env.server.calls == []

    async def test_fetch_error_other_than_404_propagates_from_poll(self, gmail_env: GmailEnv):
        await gmail_env.connector.setup(ProtectionMode.SCAN)
        _, cursor = await gmail_env.connector.poll(None)
        gmail_env.server.add_message(sample_raw("a"))
        gmail_env.server.calls.clear()
        # The history call succeeds; the first message fetch gets a 400.
        original = gmail_env.server.handle

        def flaky(request):
            if "/messages/" in request.url.path and request.method == "GET":
                return httpx.Response(
                    400, json={"error": {"code": 400, "message": "bad", "errors": [{"reason": "invalid"}]}}
                )
            return original(request)

        gmail_env.server.handle = flaky  # type: ignore[method-assign]
        with pytest.raises(GmailApiError) as info:
            await gmail_env.connector.poll(cursor)
        assert info.value.status == 400

"""Unit tests for the plain-English presenters and the Pub/Sub decoder."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import pytest

from reddysec.store.models import AuditLog, MailboxRow, MessageRow, UserRow
from reddysec.web import presenters as p
from reddysec.web.queries import WeeklyCounts
from reddysec.web.routes.hooks import decode_push


def user(**kw) -> UserRow:
    defaults = {
        "id": "usr_1",
        "display_name": "Avery Client",
        "login_email": "avery@example.com",
        "role": "principal",
    }
    return UserRow(**{**defaults, **kw})


def mailbox(**kw) -> MailboxRow:
    defaults = {
        "id": "mbx_1",
        "user_id": "usr_1",
        "provider": "gmail",
        "address": "a@gmail.com",
        "mode": "scan",
        "status": "active",
        "labels": {"x": "y"},
    }
    return MailboxRow(**{**defaults, **kw})


def message(**kw) -> MessageRow:
    defaults = {
        "id": "msg_1",
        "mailbox_id": "mbx_1",
        "provider_message_id": "p",
        "received_at": datetime.now(UTC),
        "state": "done",
        "level": "safe",
        "quarantined": False,
        "verdict": None,
        "url_count": 0,
        "attachment_count": 0,
    }
    return MessageRow(**{**defaults, **kw})


class TestChips:
    def test_verdict_chip_by_state_and_level(self):
        assert p.verdict_chip(message(state="pending", level=None)).label == "Checking"
        assert p.verdict_chip(message(state="analyzing", level=None)).tone == "grey"
        assert p.verdict_chip(message(state="failed", level=None)).label == "Could not check"
        assert p.verdict_chip(message(level="malicious", quarantined=True)) == p.Chip("Suspicious", "bad")
        assert p.moved_chip(message(level="malicious", quarantined=True)) == p.Chip("Moved out of inbox", "grey")
        assert p.moved_chip(message(level="suspicious")) is None
        assert p.moved_chip(message(level="malicious", quarantined=True, state="restore_requested")) is None
        assert p.verdict_chip(message(level="safe")).label == "Checked"
        assert p.verdict_chip(message(level="suspicious")).tone == "warn"
        assert p.verdict_chip(message(level="weird")).label == "Could not check"
        restored = message(level="malicious", quarantined=True, state="restore_requested")
        assert (
            p.verdict_chip(restored).label == "Suspicious"
        )  # the verdict stands even if the client overrode it

    def test_mailbox_chips(self):
        assert p.mailbox_status_chip(mailbox(labels={})).label == "Setting up"
        assert p.mailbox_status_chip(mailbox()).label == "Protected"
        assert p.mailbox_status_chip(mailbox(status="error")).label == "Needs attention"
        assert p.mailbox_status_chip(mailbox(status="odd")).label == "Odd"
        assert p.mode_chip(mailbox(mode="hold")).label == "Hold"
        assert p.mode_chip(mailbox()).label == "Scan"
        assert p.provider_label("yahoo") == "Yahoo Mail" and p.provider_label("exotic") == "Exotic"

    def test_lane_and_state_notes(self):
        assert "sandbox" in p.lane_label("detonate")
        assert p.lane_label(None) == "" and p.lane_label("other") == ""
        assert p.lane_short("detonate") == "Sandboxed" and p.lane_short(None) == ""
        assert "returns to your inbox" in p.state_note(message(state="restore_requested"))
        assert p.state_note(message()) == ""


class TestTimeAndNames:
    def test_first_name(self):
        assert p.first_name(user()) == "Avery"
        assert p.first_name(user(display_name="  ")) == "avery"
        assert p.first_name(user(display_name="Cher")) == "Cher"

    def test_format_dt_treats_naive_as_utc(self):
        naive = datetime(2026, 11, 5, 14, 3)
        assert p.format_dt(naive) == "5 Nov 2026, 14:03 UTC"
        assert p.format_dt(naive.replace(tzinfo=UTC)) == "5 Nov 2026, 14:03 UTC"
        assert p.format_dt(None) == ""

    def test_humanize_ago(self):
        now = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
        assert p.humanize_ago(None, now) == ""
        assert p.humanize_ago(now - timedelta(seconds=5), now) == "just now"
        assert p.humanize_ago(now - timedelta(minutes=1), now) == "1 minute ago"
        assert p.humanize_ago(now - timedelta(minutes=12), now) == "12 minutes ago"
        assert p.humanize_ago(now - timedelta(hours=1), now) == "1 hour ago"
        assert p.humanize_ago(now - timedelta(hours=5), now) == "5 hours ago"
        assert p.humanize_ago(now - timedelta(days=1), now) == "1 day ago"
        assert p.humanize_ago(now - timedelta(days=3), now) == "3 days ago"
        assert p.humanize_ago(now - timedelta(days=30), now) == "6 Oct 2026, 12:00 UTC"
        assert p.humanize_ago(now + timedelta(hours=1), now) == "5 Nov 2026, 13:00 UTC"
        assert p.humanize_ago(datetime(2026, 11, 5, 11, 0), now) == "1 hour ago"  # naive input


class TestSentences:
    @pytest.mark.parametrize(
        ("counts", "expected"),
        [
            (WeeklyCounts(0, 0, 0), "We have not seen any new email with links or files this week. Everything is quiet."),
            (WeeklyCounts(1, 0, 0), "We checked 1 email with links or files this week. Nothing looked suspicious."),
            (WeeklyCounts(42, 1, 1), "We checked 42 emails with links or files this week. 1 looked suspicious. We moved it out of your inbox."),
            (
                WeeklyCounts(42, 5, 3),
                "We checked 42 emails with links or files this week. 5 looked suspicious. We moved 3 out of your inbox.",
            ),
            (
                WeeklyCounts(42, 3, 3),
                "We checked 42 emails with links or files this week. 3 looked suspicious. We moved all of them out of your inbox.",
            ),
            (WeeklyCounts(5, 1, 0), "We checked 5 emails with links or files this week. 1 looked suspicious."),
        ],
    )
    def test_weekly_sentence(self, counts, expected):
        assert p.weekly_sentence(counts, has_mailboxes=True) == expected

    @pytest.mark.parametrize(
        ("period", "expected"),
        [
            ("today", "We checked 120 emails with links or files today. 3 looked suspicious."),
            ("7d", "We checked 120 emails with links or files this week. 3 looked suspicious."),
            ("1m", "We checked 120 emails with links or files this month. 3 looked suspicious."),
            ("1y", "We checked 120 emails with links or files this year. 3 looked suspicious."),
            ("bogus", "We checked 120 emails with links or files this week. 3 looked suspicious."),
        ],
    )
    def test_sentence_follows_the_period(self, period, expected):
        assert p.weekly_sentence(WeeklyCounts(120, 3, 0, 117), has_mailboxes=True, period=period) == expected
        assert p.weekly_sentence(WeeklyCounts(), has_mailboxes=True, period="today") == (
            "We have not seen any new email with links or files today. Everything is quiet.")

    def test_weekly_sentence_without_mailboxes(self):
        assert p.weekly_sentence(WeeklyCounts(), has_mailboxes=False).startswith("Connect a mailbox")


class TestAuditCopy:
    def test_action_phrase(self):
        assert p.action_phrase("mode_changed") == "Changed the protection mode"
        assert p.action_phrase("something_new") == "Something new"

    def test_actor_label(self):
        viewer = user()
        assert p.actor_label(AuditLog(actor_id="usr_1", actor_role="principal", action="x"), viewer) == "You"
        assert (
            p.actor_label(AuditLog(actor_id="usr_9", actor_role="concierge", action="x"), viewer)
            == "Secureddy analyst"
        )
        assert (
            p.actor_label(AuditLog(actor_id=None, actor_role="system", action="x"), viewer)
            == "Secureddy (automatic)"
        )
        assert (
            p.actor_label(AuditLog(actor_id="u", actor_role="robot_overlord", action="x"), viewer)
            == "Robot Overlord"
        )

    def test_detail_phrase_branches(self):
        def entry(action, **details):
            return AuditLog(action=action, details=details, actor_role="principal")

        assert p.detail_phrase(entry("mode_changed", **{"from": "scan", "to": "hold"})) == "Scan to Hold"
        assert (
            p.detail_phrase(entry("verdict_override", **{"from": "safe", "to": "malicious"}))
            == "Checked to Suspicious"
        )
        assert p.detail_phrase(entry("review_requested", note="Looks odd")) == "Looks odd"
        assert p.detail_phrase(entry("review_requested")) == ""
        assert p.detail_phrase(entry("client_feedback", feedback="fine")) == "Marked as fine"
        assert p.detail_phrase(entry("client_feedback", feedback="bad")) == "Marked as bad"
        assert p.detail_phrase(entry("login", method="google")) == "With Google"
        assert p.detail_phrase(entry("login", method="telepathy")) == ""
        assert p.detail_phrase(entry("mailbox_connected", provider="icloud")) == "iCloud Mail"
        assert p.detail_phrase(entry("logout")) == ""
        assert p.detail_phrase(AuditLog(action="logout", details=None, actor_role="principal")) == ""


class TestReport:
    def test_bar_class(self):
        assert p.bar_class(0) == "bar-w0"
        assert p.bar_class(3) == "bar-w10"
        assert p.bar_class(44) == "bar-w40"
        assert p.bar_class(45) == "bar-w50"
        assert p.bar_class(100) == "bar-w100"
        assert p.bar_class(250) == "bar-w100"
        assert p.bar_class(-20) == "bar-w20"
        assert p.bar_class(-2) == "bar-w10"

    def test_parse_verdict_and_refs(self):
        assert p.parse_verdict(None) is None
        assert p.parse_verdict({}) is None
        assert p.parse_verdict({"level": "nope"}) is None
        raw = {
            "level": "malicious",
            "score": 90,
            "summary": "Bad.",
            "lane": "detonate",
            "urls": [
                {"url": "https://a", "level": "malicious", "score": 90, "screenshot_ref": "local:a.png"},
                {"url": "https://b", "level": "safe", "score": 0},
            ],
            "attachments": [
                {
                    "filename": "f.pdf",
                    "sha256": "0" * 64,
                    "level": "safe",
                    "score": 0,
                    "safe_copy_ref": "local:f.pdf",
                }
            ],
        }
        assert p.parse_verdict(raw) is not None
        assert p.artifact_refs(raw) == frozenset({"local:a.png", "local:f.pdf"})
        assert p.artifact_refs({"level": "nope"}) == frozenset()

    def test_build_report_without_verdict(self):
        pending = p.build_report(message(state="pending", level=None), artifact_url=str, download_url=str)
        assert (
            not pending.verdict_available
            and "still checking" in pending.summary
            and pending.chip.label == "Checking"
        )
        failed = p.build_report(message(state="failed", level=None), artifact_url=str, download_url=str)
        assert "could not produce" in failed.summary and failed.can_release is False
        quarantined = p.build_report(
            message(state="done", level="malicious", quarantined=True, verdict={"bad": 1}),
            artifact_url=str,
            download_url=str,
        )
        assert quarantined.can_release is True and quarantined.signals == ()

    def test_build_report_with_verdict(self):
        raw = {
            "level": "suspicious",
            "score": 50,
            "summary": "Careful.",
            "lane": "trusted",
            "signals": [
                {"code": "a", "stage": "static", "weight": 10, "title": "Low"},
                {"code": "b", "stage": "intel", "weight": 40, "title": "High", "detail": "d"},
                {"code": "c", "stage": "history", "weight": -10, "title": "Trust"},
            ],
            "urls": [
                {
                    "url": "https://a",
                    "final_url": "https://a",
                    "level": "safe",
                    "score": 0,
                    "detonated": True,
                    "screenshot_ref": "local:shot.png",
                }
            ],
            "attachments": [
                {
                    "filename": "f.pdf",
                    "sha256": "0" * 64,
                    "level": "suspicious",
                    "score": 50,
                    "safe_copy_ref": "local:safe.pdf",
                }
            ],
            "needs_human_review": True,
            "override": {"note": "Analyst says fine"},
        }
        report = p.build_report(
            message(level="suspicious", verdict=raw),
            artifact_url=lambda r: f"/art/{r}",
            download_url=lambda r: f"/dl/{r}",
        )
        assert [s.title for s in report.signals] == ["High", "Low", "Trust"]
        assert report.signals[2].trust is True and report.signals[2].bar == "bar-w10"
        assert report.urls[0].final_url is None  # same as the url: not worth repeating
        assert report.urls[0].screenshot_url == "/art/local:shot.png"
        assert report.attachments[0].safe_copy_url == "/dl/local:safe.pdf"
        assert report.needs_human_review and report.override_note == "Analyst says fine"
        assert report.lane == "A sender you know, with a clean record"
        assert report.artifact_refs == frozenset({"local:shot.png", "local:safe.pdf"})

    def test_message_summary_and_list_rows(self):
        assert p.message_summary(message(verdict={"summary": "Fine."})) == "Fine."
        assert p.message_summary(message(state="pending", level=None)) == "Still checking."
        assert p.message_summary(message()) == ""
        rows = p.list_rows([(message(), mailbox())])
        assert rows[0].chip.label == "Checked" and rows[0].mailbox.address == "a@gmail.com"


class TestPushDecoder:
    def test_decode_push(self):
        data = base64.b64encode(json.dumps({"emailAddress": "a@b", "historyId": 7}).encode()).decode()
        assert decode_push({"message": {"data": data}}) == ("a@b", "7")
        assert decode_push({"message": {"data": 5}}) is None
        assert decode_push({"message": "x"}) is None
        assert decode_push([]) is None
        assert decode_push({"message": {"data": "@@@"}}) is None
        assert decode_push({"message": {"data": base64.b64encode(b"\xff\xfe").decode()}}) is None
        assert (
            decode_push(
                {"message": {"data": base64.b64encode(b'{"emailAddress": "", "historyId": 1}').decode()}}
            )
            is None
        )

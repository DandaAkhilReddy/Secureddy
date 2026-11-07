"""Presenters added for the refreshed UI, reasons and assistant replies."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from reddysec.store.models import FeedbackReasonRow, MessageRow
from reddysec.web import presenters as p
from reddysec.web.queries import DailyCounts, WeeklyCounts, clean_reason, reason_label

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)


def test_ago_short_and_short_date():
    assert p.ago_short(None) == "" and p.short_date(None) == ""
    assert p.ago_short(NOW - timedelta(seconds=10), NOW) == "just now"
    assert p.ago_short(NOW - timedelta(minutes=5), NOW) == "5 min ago"
    assert p.ago_short((NOW - timedelta(hours=2)).replace(tzinfo=None), NOW) == "2 h ago"
    assert p.ago_short(NOW - timedelta(days=3), NOW) == "3 d ago"
    assert p.ago_short(NOW + timedelta(hours=1), NOW) == p.short_date(NOW + timedelta(hours=1))
    assert p.short_date(datetime(2020, 1, 2, tzinfo=UTC)) == "2 Jan 2020"
    assert p.ago_short(datetime(2020, 1, 2, tzinfo=UTC), NOW) == "2 Jan 2020"


def test_initials_and_avatar_tone():
    assert p.initials("Ana Ruiz") == "AR" and p.initials("Walmart.com") == "WC"
    assert p.initials("walmart") == "W" and p.initials(None, "zed@example.com") == "Z"
    assert p.initials("", "") == "?" and p.initials("-- !!", "x@y") == "X"
    assert p.avatar_tone("a@b.c") == p.avatar_tone("A@B.C") and p.avatar_tone(None) == "av-0"


def test_hero():
    assert p.hero(WeeklyCounts(), has_mailboxes=False).tone == "grey"
    assert p.hero(WeeklyCounts(checked=4, safe=4), has_mailboxes=True) == p.Hero("Your inbox is safe", "ok")
    assert p.hero(WeeklyCounts(checked=3, suspicious=1), has_mailboxes=True) == p.Hero("1 email needs a look", "warn")
    # Suspicious already includes the email moved out of the inbox.
    assert p.hero(WeeklyCounts(checked=3, suspicious=2, quarantined=1), has_mailboxes=True) == p.Hero(
        "2 emails need a look", "bad")


def test_sparkline_and_stat_cards():
    days = tuple(NOW - timedelta(days=6 - i) for i in range(7))
    s = p.sparkline((0, 1, 2, 0, 0, 4, 1), days)
    assert len(s.points.split()) == 7 and s.area.startswith("M") and s.area.endswith("Z")
    assert s.label.startswith("Last 7 days: ") and "4" in s.label
    flat = p.sparkline([])
    assert flat.label == "Last 1 days: 0" and len(flat.points.split()) == 2  # one bucket draws a flat line
    hours = tuple(NOW.replace(hour=h, minute=0) for h in range(3))
    assert p.sparkline((1, 0, 2), hours, unit="hour").label == "Today, by hour: 00:00 1, 01:00 0, 02:00 2"
    months = (NOW.replace(month=10, day=1), NOW.replace(day=1))
    assert p.sparkline((4, 5), months, unit="month").label == "Last 2 months: Oct 4, Nov 5"
    daily = DailyCounts(days, (1,) * 7, (0,) * 7, (0,) * 7)
    cards = p.stat_cards(WeeklyCounts(checked=7, safe=7), daily)
    assert [c.label for c in cards] == ["Checked", "Suspicious"]
    assert all(c.spark is not None for c in cards)
    assert all(c.spark is None for c in p.stat_cards(WeeklyCounts()))


def test_chat_blocks():
    blocks = p.chat_blocks("## Hello **you**\nline two\n\n- one\n* **two**\n1. first\n2) second\n\nodd ** marker")
    assert blocks[0] == {"type": "p", "lines": [[{"b": False, "t": "Hello "}, {"b": True, "t": "you"}],
                                                [{"b": False, "t": "line two"}]]}
    assert blocks[1]["type"] == "ul" and blocks[1]["items"][1] == [{"b": True, "t": "two"}]
    assert blocks[2] == {"type": "ol", "items": [[{"b": False, "t": "first"}], [{"b": False, "t": "second"}]]}
    assert blocks[3]["lines"] == [[{"b": False, "t": "odd ** marker"}]]
    assert p.chat_blocks("") == [] and p.chat_blocks("a\n\n\nb")[1]["lines"][0][0]["t"] == "b"


def _reason(decision="safe", code="expected", text=""):
    return FeedbackReasonRow(decision=decision, reason_code=code, reason_text=text, created_at=NOW)


def test_reason_sentences():
    assert p.reason_sentence(_reason()) == "I ordered this / expected it"
    assert p.reason_sentence(_reason(code="other", text="Mine")) == "Mine"
    assert p.reason_sentence(_reason(code="known_sender", text="My dentist")) == "I know this sender. My dentist"
    assert p.reason_sentence(_reason("fake", "assistant")) == "Agreed with the assistant's suggestion"
    assert p.decision_note(_reason(), "safe") == f"You marked this safe on {p.short_date(NOW)}: I ordered this / expected it."
    assert p.decision_note(_reason(code="", text=""), "safe") == f"You marked this safe on {p.short_date(NOW)}."
    assert p.decision_note(_reason(), "fake") == "" and p.decision_note(None, "safe") == ""
    assert reason_label("fake", "money_or_codes") == "Asks for money or codes" and reason_label("safe", "zzz") == ""


def test_clean_reason():
    assert clean_reason("safe", "", "") == ("", "")
    assert clean_reason("safe", " newsletter ", " hi\x00 there\n ") == ("newsletter", "hi there")
    assert clean_reason("fake", "", "words") == ("other", "words")
    assert clean_reason("fake", "assistant", "") == ("assistant", "")
    try:
        clean_reason("fake", "newsletter", "")
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("newsletter is not a fake reason")


def test_audit_detail_with_reason():
    entry = SimpleNamespace(action="sender_trusted", details={"value": "walmart.com", "reason_code": "other", "reason": "Mine"},
                            target=None)
    assert p.detail_phrase(entry) == "walmart.com · Mine"
    entry.details = {"value": "walmart.com"}
    assert p.detail_phrase(entry) == "walmart.com"
    entry.action, entry.details = "sender_feedback_removed", {"value": "x.com"}
    assert p.detail_phrase(entry) == "x.com"
    assert p.action_phrase("assistant_question") == "Asked Secureddy a question"


def test_row_actions():
    def m(**kw):
        base = dict(state="done", level="suspicious", quarantined=False, from_address="a@b.c", verdict={})
        base.update(kw)
        return MessageRow(**base)

    assert p.row_actions(m()) == (True, True)
    assert p.row_actions(m(level="safe")) == (False, False)
    assert p.row_actions(m(level="malicious", quarantined=True)) == (True, False)
    assert p.row_actions(m(state="pending")) == (False, False)
    assert p.row_actions(m(from_address="")) == (False, False)
    assert p.row_actions(m(verdict={"client_decision": {"decision": "safe"}})) == (False, True)

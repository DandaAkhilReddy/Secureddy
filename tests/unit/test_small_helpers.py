"""Small helpers: logging filter edge cases, preferences, filling metadata
for a "Check now" row."""

from __future__ import annotations

import logging
from types import SimpleNamespace

from reddysec.core.logging import RedactingFilter
from reddysec.store.models import MailboxRow, MessageRow
from reddysec.web import preferences
from reddysec.worker.engine import fill_metadata


def test_filter_survives_odd_records():
    class Weird:
        def __iter__(self):
            raise RuntimeError("no")

    record = logging.LogRecord("x", logging.INFO, __file__, 1, 12345, None, None)
    assert RedactingFilter().filter(record) and record.msg == 12345
    record.args = ("ok",)
    record.msg = Weird()  # not a string: left alone
    assert RedactingFilter().filter(record)

    class Boom(dict):
        def items(self):
            raise RuntimeError("boom")

    record.args = Boom(a=1)
    assert RedactingFilter().filter(record)  # never raises


def test_preferences_rules():
    assert not preferences._valid("unknown", "x")
    assert not preferences._valid(preferences.SELECTED_MAILBOX, "bad id!")
    boxes = [MailboxRow(id="mbx_1", address="a@x.com", provider="gmail", status="active"),
             MailboxRow(id="mbx_2", address="b@x.com", provider="yahoo", status="disconnected")]
    assert preferences.resolve_selection(None, "mbx_1", boxes) == ("mbx_1", False)
    assert preferences.resolve_selection(None, "gone", boxes) == (None, False)
    assert preferences.resolve_selection("all", "mbx_1", boxes) == (None, True)
    assert preferences.resolve_selection("mbx_9", "", boxes) == (None, False)
    items = preferences.switcher(boxes, "mbx_1", "/messages", {"q": "x", "days": None})
    assert [i["id"] for i in items] == ["all", "mbx_1"] and items[1]["current"]
    assert items[0]["href"] == "/messages?q=x&mailbox=all"


async def test_set_preference_rejects_unknown(db):
    async with db.session() as s:
        assert not await preferences.set_preference(s, "usr_1", "colour", "red")
        assert not await preferences.set_preference(s, "usr_1", preferences.INBOX_VIEW, "sideways")


def test_fill_metadata():
    row = MessageRow(from_address="", subject="", rfc_message_id=None)
    parsed = SimpleNamespace(rfc_message_id="<a@b>", from_address="x@y.com", from_name="X", subject="Hello",
                             urls=[1, 2], real_attachments=[1])
    fill_metadata(row, parsed)
    assert (row.rfc_message_id, row.from_address, row.from_name, row.subject, row.url_count, row.attachment_count) == (
        "<a@b>", "x@y.com", "X", "Hello", 2, 1)
    keep = MessageRow(from_address="kept@y.com", subject="kept", rfc_message_id="<old>", from_name=None)
    fill_metadata(keep, SimpleNamespace(rfc_message_id="", from_address="", from_name="", subject="", urls=[],
                                        real_attachments=[]))
    assert (keep.from_address, keep.subject, keep.rfc_message_id) == ("kept@y.com", "kept", "<old>")

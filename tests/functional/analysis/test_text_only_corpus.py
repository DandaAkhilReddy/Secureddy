"""Regression corpus for "only emails with something to click or open".

* A new corpus of text-only emails (personal notes, auto-replies, signed
  plain-text mail, bounces, read receipts, link-less invites, mailto/tel-only
  signatures, tracking-pixel-only and unsubscribe-only mail) must be skipped.
* Every email of the existing corpus that has a link or a file (the false
  positive corpus that must stay SAFE and the attacks that must stay caught)
  must still be checked: the new rule may never hide an attack.
* The text-only BEC fixtures are skipped by default and caught by the
  opt-in money-scam check.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from reddysec.analysis import analyze, parse_raw
from reddysec.analysis.actionable import assess, is_actionable, text_scam_signals
from reddysec.analysis.intel import OfflineIntel
from reddysec.analysis.pipeline import AnalysisContext
from reddysec.models import PolicyConfig, VerdictLevel
from reddysec.testing.fakes import FakeDetonator

from .corpus import all_messages

RECEIVED_AT = datetime(2026, 11, 7, 9, 0, tzinfo=UTC)
# 06 (wire change) signs off with the law firm's web address: it has a link.
TEXT_ONLY_FIXTURES = {"01_plain_personal", "07_gift_card_ceo", "22_gift_card_scam_freemail"}
MONEY_SCAMS = {"07_gift_card_ceo", "22_gift_card_scam_freemail"}


def headers(sender: str, subject: str, extra: str = "") -> str:
    return (f"From: {sender}\r\nTo: client@gmail.com\r\nSubject: {subject}\r\n"
            f"Date: Sat, 07 Nov 2026 08:00:00 -0800\r\nMessage-ID: <{abs(hash(subject))}@example.com>\r\n"
            f"MIME-Version: 1.0\r\n{extra}")


def plain(sender: str, subject: str, body: str, extra: str = "") -> bytes:
    return (headers(sender, subject, extra) + 'Content-Type: text/plain; charset="utf-8"\r\n\r\n' + body).encode()


def html(sender: str, subject: str, body: str, extra: str = "") -> bytes:
    return (headers(sender, subject, extra) + 'Content-Type: text/html; charset="utf-8"\r\n\r\n' + body).encode()


def multipart(sender: str, subject: str, text: str, part_type: str, part_name: str, part_body: str,
              disposition: str = "attachment") -> bytes:
    b = "B0UNDARY"
    return (
        headers(sender, subject) + f'Content-Type: multipart/mixed; boundary="{b}"\r\n\r\n'
        f"--{b}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{text}\r\n"
        f'--{b}\r\nContent-Type: {part_type}; name="{part_name}"\r\nContent-Disposition: {disposition}; '
        f'filename="{part_name}"\r\n\r\n{part_body}\r\n--{b}--\r\n'
    ).encode()


TEXT_ONLY_CORPUS: dict[str, bytes] = {
    "personal_note": plain("Mom <mom@example.org>", "Sunday", "Dinner at 6 on Sunday. Bring the salad bowl back!"),
    "out_of_office": plain("Dr. Lee <lee@clinic.example>", "Automatic reply: question",  # "I am out of..." opener
                           "I am out of the office until Monday with limited access to email.",
                           "Auto-Submitted: auto-replied\r\n"),
    "html_note_no_links": html("Ann <ann@example.org>", "Photos",
                               "<p>Loved seeing you all. <b>Next time</b> at our place!</p>"),
    "mailto_tel_signature": html("Lawyer <jd@lawfirm.example>", "Re: documents",
                                 "<p>Received, thank you.</p><p>J. Doe<br><a href='mailto:jd@lawfirm.example'>email</a>"
                                 " | <a href='tel:+15551230000'>call</a> | <a href='sms:+15551230000'>text</a></p>"),
    "tracking_pixel_only": html("Shop <orders@shop.example>", "We received your return",
                                "<p>Your return was received.</p><img src='https://t.shop.example/o.gif?u=1' "
                                "width='1' height='1'>"),
    "cid_logo_only": html("Club <hello@club.example>", "See you Friday",
                          "<img src='cid:logo@club'><p>Doors open at 7.</p>"),
    "unsubscribe_only_newsletter": html(
        "Club <news@club.example>", "Friday schedule",
        "<p>Doors open at 7, music at 8.</p><p><a href='https://club.example/unsubscribe?u=9'>Unsubscribe</a> · "
        "<a href='https://club.example/preferences?u=9'>Manage preferences</a></p>",
        "List-Unsubscribe: <https://club.example/unsubscribe?u=9>\r\n"),
    "signed_plain_text": multipart("CFO <cfo@company.example>", "Signed: budget approved",
                                   "Budget approved as discussed.", "application/pkcs7-signature", "smime.p7s",
                                   "MIIBsignature"),
    "bounce": multipart("Mail Delivery Subsystem <mailer-daemon@googlemail.com>", "Delivery Status Notification",
                        "Your message wasn't delivered.", "message/delivery-status", "status.txt",
                        "Reporting-MTA: dns; googlemail.com\r\nStatus: 5.1.1"),
    "read_receipt": multipart("Bo <bo@example.org>", "Read: agenda", "Your message was read.",
                              "message/disposition-notification", "mdn.txt", "Disposition: manual-action/MDN-sent"),
    "invite_without_link": multipart(
        "Ann <ann@example.org>", "Invitation: Dinner", "You are invited.", "text/calendar", "invite.ics",
        "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Dinner\r\nLOCATION:Our place\r\nEND:VEVENT\r\nEND:VCALENDAR"),
}

ACTIONABLE_CORPUS: dict[str, bytes] = {
    "invite_with_meeting_link": multipart(
        "Ann <ann@example.org>", "Invitation: Call", "You are invited.", "text/calendar", "invite.ics",
        "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Call\r\nDESCRIPTION:Join https://meet.example/abc\r\n"
        "END:VEVENT\r\nEND:VCALENDAR"),
    "bare_url_in_text": plain("Bo <bo@example.org>", "Agenda", "Agenda is here: https://docs.example/agenda"),
    "button_link": html("Bank <alerts@bank.example>", "Statement", "<a class='btn' href='https://bank.example/s'>View</a>"),
    "form_in_email": html("IT <it@company.example>", "Verify", "<form action='https://evil.example/c'>"
                          "<input name='password'><button>Verify</button></form>"),
    "fake_unsubscribe_lure": html("IT <it@company.example>", "Mailbox full",
                                  "<p>Your mailbox is full.</p><a href='https://mailbox-fix.example/login'>Unsubscribe</a>"),
    "attached_file": multipart("Bo <bo@example.org>", "Contract", "See attached.", "application/pdf", "contract.pdf",
                               "%PDF-1.4 fake"),
}


def parse(raw: bytes, name: str = "x"):
    return parse_raw(raw, provider_message_id=name, mailbox_id="mbx", received_at=RECEIVED_AT)


@pytest.mark.parametrize("name", sorted(TEXT_ONLY_CORPUS))
def test_text_only_corpus_is_skipped(name):
    parsed = parse(TEXT_ONLY_CORPUS[name], name)
    assert not is_actionable(parsed), (name, [u.normalized for u in parsed.urls], assess(parsed))
    assert text_scam_signals(parsed) == [], name


@pytest.mark.parametrize("name", sorted(ACTIONABLE_CORPUS))
def test_actionable_corpus_is_checked(name):
    assert is_actionable(parse(ACTIONABLE_CORPUS[name], name)), name


@pytest.mark.parametrize("name", sorted(all_messages()))
def test_existing_corpus_with_links_or_files_is_still_checked(name):
    """The false-positive corpus (must stay SAFE) and the attack corpus (must
    stay caught) only matter if the worker still looks at them."""
    parsed = parse(all_messages()[name], name)
    if name in TEXT_ONLY_FIXTURES:
        assert not is_actionable(parsed), name
    else:
        assert is_actionable(parsed), name


@pytest.mark.parametrize("name", sorted(MONEY_SCAMS))
async def test_text_only_money_scams_are_caught_when_watched(name):
    parsed = parse(all_messages()[name], name)
    assert text_scam_signals(parsed), name
    verdict = await analyze(parsed, AnalysisContext(policy=PolicyConfig(), history=None, intel=OfflineIntel(),
                                                    detonator=FakeDetonator()))
    assert verdict.level is not VerdictLevel.SAFE, name


async def test_fake_unsubscribe_lure_is_still_analysed_like_any_link():
    det = FakeDetonator()
    parsed = parse(ACTIONABLE_CORPUS["fake_unsubscribe_lure"])
    await analyze(parsed, AnalysisContext(policy=PolicyConfig(), history=None, intel=OfflineIntel(), detonator=det))
    assert any("mailbox-fix.example" in job.url for job in det.jobs)

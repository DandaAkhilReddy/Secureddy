"""Unit tests for ``analysis.actionable``: which emails Secureddy checks.

Only email with something to click or open is checked. Every rule of the
definition has a case here, built from real MIME and parsed by the real parser.
"""

from __future__ import annotations

import io

import pytest

from reddysec.analysis import actionable
from reddysec.analysis.parser import parse_raw
from reddysec.models import (
    Attachment,
    ClientFeedback,
    ExtractedUrl,
    ParsedMessage,
    SenderHistory,
    SignalStage,
    UrlSource,
)

from .support import RECEIVED_AT, build_raw

DMARC_PASS = "mx.google.com; spf=pass smtp.mailfrom=shop.example; dkim=pass header.d=shop.example; dmarc=pass header.from=shop.example"


def parse(raw: bytes) -> ParsedMessage:
    return parse_raw(raw, provider_message_id="p1", mailbox_id="m1", received_at=RECEIVED_AT)


def qr_png(payload: str) -> bytes:
    cv2 = pytest.importorskip("cv2")
    np = pytest.importorskip("numpy")
    from PIL import Image

    encoder = cv2.QRCodeEncoder.create()
    matrix = encoder.encode(payload)
    img = Image.fromarray(np.kron(matrix, np.ones((8, 8), dtype=np.uint8)).astype("uint8")).convert("L")
    padded = Image.new("L", (img.width + 64, img.height + 64), 255)
    padded.paste(img, (32, 32))
    out = io.BytesIO()
    padded.save(out, format="PNG")
    return out.getvalue()


# --------------------------------------------------------------------------- not actionable


class TestTextOnly:
    def test_plain_text_is_not_actionable(self):
        parsed = parse(build_raw(text="Are we still on for Saturday at 7?"))
        result = actionable.assess(parsed)
        assert not result.actionable and result.reason == "text_only"
        assert not actionable.is_actionable(parsed)

    def test_html_without_links_is_not_actionable(self):
        parsed = parse(build_raw(text=None, html="<p>Hi <b>Ann</b>, see you soon.</p>"))
        assert not actionable.is_actionable(parsed)

    @pytest.mark.parametrize(
        "href",
        ["mailto:ann@example.com", "tel:+15551234567", "sms:+15551234567", "cid:logo.png", "#top", "/relative/path"],
    )
    def test_non_page_links_are_not_actionable(self, href):
        parsed = parse(build_raw(text=None, html=f'<p>Write to <a href="{href}">me</a></p>'))
        assert not actionable.is_actionable(parsed), href

    def test_tracking_pixel_and_image_src_only_is_not_actionable(self):
        html = '<p>Thanks!</p><img src="https://t.example/open.gif?u=1" width="1" height="1"><img src="cid:logo">'
        parsed = parse(build_raw(text=None, html=html))
        assert not actionable.is_actionable(parsed)

    def test_unsubscribe_only_footer_from_list_header_is_not_actionable(self):
        html = '<p>Your weekly note.</p><p><a href="https://lists.shop.example/u?id=9">Unsubscribe</a></p>'
        raw = build_raw(
            from_header="Shop <news@shop.example>",
            text=None,
            html=html,
            extra_headers={"List-Unsubscribe": "<https://lists.shop.example/u?id=9>, <mailto:u@shop.example>"},
        )
        result = actionable.assess(parse(raw))
        assert not result.actionable and result.unsubscribe_links == 1

    @pytest.mark.parametrize(
        "text",
        ["Unsubscribe", "Manage preferences", "Manage your email preferences", "Update your preferences",
         "Opt out", "Email preferences", "Stop receiving these emails"],
    )
    def test_preference_links_on_the_senders_domain_are_footers(self, text):
        html = f'<p>Hello.</p><a href="https://shop.example/account/x?u=1">{text}</a>'
        parsed = parse(build_raw(from_header="Shop <news@shop.example>", text=None, html=html))
        assert not actionable.is_actionable(parsed), text

    def test_unsubscribe_path_on_mailing_service_with_list_header(self):
        html = '<a href="https://shop.us14.list-manage.com/unsubscribe?u=1&id=2">click here</a>'
        raw = build_raw(from_header="Shop <news@shop.example>", text=None, html=html,
                        extra_headers={"List-Unsubscribe": "<mailto:u@shop.example>"})
        assert not actionable.is_actionable(parse(raw))

    def test_signed_plain_text_email_signature_is_not_a_file(self):
        raw = build_raw(text="Signed note, nothing to click.",
                        attachments=[("smime.p7s", "application/pkcs7-signature", b"\x30\x82sig", None)])
        parsed = parse(raw)
        assert parsed.real_attachments  # the parser sees a part ...
        assert not actionable.is_actionable(parsed)  # ... but it is not a file to open

    def test_bounce_report_is_not_a_file(self):
        raw = build_raw(text="Delivery failed.",
                        attachments=[("details.txt", "message/delivery-status", b"Status: 5.1.1", None)])
        assert not actionable.is_actionable(parse(raw))

    def test_calendar_invite_without_link_is_not_actionable(self):
        ics = b"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Dinner\r\nLOCATION:Our place\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        parsed = parse(build_raw(text="See you then.", attachments=[("invite.ics", "text/calendar", ics, None)]))
        assert parsed.has_calendar_invite
        assert not actionable.is_actionable(parsed)

    def test_inline_image_without_qr_is_not_actionable(self):
        from PIL import Image

        buf = io.BytesIO()
        Image.new("RGB", (60, 60), (200, 10, 10)).save(buf, format="PNG")
        raw = build_raw(text=None, html='<p>Logo</p><img src="cid:logo.png">',
                        attachments=[("logo.png", "image/png", buf.getvalue(), "inline")])
        assert not actionable.is_actionable(parse(raw))


# --------------------------------------------------------------------------- actionable


class TestActionable:
    def test_html_anchor(self):
        parsed = parse(build_raw(text=None, html='<a href="https://docs.example/x">Open</a>'))
        result = actionable.assess(parsed)
        assert result.actionable and result.reason == "links" and len(result.links) == 1

    def test_html_button_and_image_map(self):
        html = ('<a class="button" href="https://pay.example/now"><span>Pay now</span></a>'
                '<map><area href="https://map.example/a" alt="x"></map>')
        assert len(actionable.assess(parse(build_raw(text=None, html=html))).links) == 2

    def test_form_action_and_button_formaction_are_links(self):
        html = ('<form action="https://evil.example/collect" method="post"><input name="password">'
                '<button formaction="https://evil.example/alt">Verify</button></form>')
        parsed = parse(build_raw(text=None, html=html))
        hosts = {u.host for u in parsed.urls}
        assert hosts == {"evil.example"} and len(parsed.urls) == 2
        assert actionable.is_actionable(parsed)

    def test_bare_url_in_text(self):
        assert actionable.is_actionable(parse(build_raw(text="Agenda: https://docs.example/agenda")))
        assert actionable.is_actionable(parse(build_raw(text="Our site: www.acme-law.example")))

    def test_javascript_link_counts(self):
        parsed = parse(build_raw(text=None, html='<a href="javascript:alert(1)">Click</a>'))
        assert actionable.is_actionable(parsed)

    def test_real_attachment(self):
        raw = build_raw(text="Invoice attached.", attachments=[("invoice.pdf", "application/pdf", b"%PDF-1.4\n%x", None)])
        result = actionable.assess(parse(raw))
        assert result.actionable and result.reason == "files"

    def test_attached_photo_counts_as_file(self):
        raw = build_raw(text="Photo from the trip.", attachments=[("trip.jpg", "image/jpeg", b"\xff\xd8\xff\xe0jpeg", None)])
        assert actionable.is_actionable(parse(raw))

    def test_inline_image_with_qr_code_is_actionable(self):
        png = qr_png("https://evil-qr.example/login")
        raw = build_raw(text=None, html='<p>Scan to keep your account</p><img src="cid:qr.png">',
                        attachments=[("qr.png", "image/png", png, "inline")])
        parsed = parse(raw)
        assert not parsed.real_attachments
        assert any(u.source is UrlSource.QR for u in parsed.urls)
        assert actionable.is_actionable(parsed)

    def test_calendar_invite_with_link_is_actionable(self):
        ics = (b"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Call\r\nDESCRIPTION:Join https://meet.example/abc-def\r\n"
               b"END:VEVENT\r\nEND:VCALENDAR\r\n")
        parsed = parse(build_raw(text="Invite", attachments=[("invite.ics", "text/calendar", ics, None)]))
        result = actionable.assess(parsed)
        assert result.actionable and not result.files and result.links

    def test_link_inside_text_attachment(self):
        raw = build_raw(text="See attached.", attachments=[("notes.txt", "text/plain", b"go to https://x.example/y", None)])
        parsed = parse(raw)
        assert actionable.assess(parsed).reason == "links+files"

    def test_newsletter_with_content_links_is_actionable(self):
        html = ('<p><a href="https://shop.example/sale">See the sale</a></p>'
                '<p><a href="https://shop.example/unsubscribe?u=1">Unsubscribe</a></p>')
        raw = build_raw(from_header="Shop <news@shop.example>", text=None, html=html,
                        extra_headers={"List-Unsubscribe": "<https://shop.example/unsubscribe?u=1>"})
        result = actionable.assess(parse(raw))
        assert result.actionable and len(result.links) == 1 and result.unsubscribe_links == 1

    def test_fake_unsubscribe_link_to_a_stranger_is_checked(self):
        """A lure dressed as "Unsubscribe" pointing at an unrelated domain, on
        mail without a List-Unsubscribe header, is checked like any link."""
        html = '<p>Your mailbox is full.</p><a href="https://mailbox-fix.example/login">Unsubscribe</a>'
        parsed = parse(build_raw(from_header="IT <it@company.example>", text=None, html=html))
        assert actionable.is_actionable(parsed)

    def test_unsubscribe_text_with_display_mismatch_is_checked(self):
        html = '<a href="https://evil.example/u">shop.example/unsubscribe</a>'
        parsed = parse(build_raw(from_header="Shop <news@shop.example>", text=None, html=html,
                                 extra_headers={"List-Unsubscribe": "<mailto:u@shop.example>"}))
        assert actionable.is_actionable(parsed)

    def test_fixture_corpus_has_links_where_expected(self, fixtures_dir):
        for path in sorted((fixtures_dir / "emails").glob("*.eml")):
            parsed = parse(path.read_bytes())
            text_only = path.name in {"01_plain_personal.eml", "06_bec_wire_change.eml", "07_gift_card_ceo.eml",
                                      "22_gift_card_scam_freemail.eml"}
            if text_only:
                continue
            assert actionable.is_actionable(parsed) or not parsed.urls, path.name


# --------------------------------------------------------------------------- helpers


def _url(raw: str, **kw) -> ExtractedUrl:
    from reddysec.analysis.urls import build_url

    url = build_url(raw, UrlSource.HTML_HREF, kw.pop("text", None))
    assert url is not None
    return url


class TestHelpers:
    def test_unsubscribe_needs_http(self):
        parsed = ParsedMessage(provider_message_id="p", mailbox_id="m", received_at=RECEIVED_AT)
        js = ExtractedUrl(raw="javascript:x", normalized="javascript:x", source=UrlSource.HTML_HREF, display_text="Unsubscribe")
        assert not actionable.is_unsubscribe_link(js, parsed)

    def test_ip_literal_unsubscribe_is_checked(self):
        parsed = ParsedMessage(provider_message_id="p", mailbox_id="m", received_at=RECEIVED_AT,
                               from_address="a@shop.example", has_list_unsubscribe=True)
        assert not actionable.is_unsubscribe_link(_url("http://10.0.0.1/unsubscribe", text="Unsubscribe"), parsed)

    def test_list_unsubscribe_header_without_angle_brackets(self):
        parsed = ParsedMessage(provider_message_id="p", mailbox_id="m", received_at=RECEIVED_AT,
                               headers={"list-unsubscribe": "https://lists.example/u"}, has_list_unsubscribe=True)
        assert actionable.is_unsubscribe_link(_url("https://lists.example/u", text="Leave"), parsed)

    def test_openable_files_filters(self):
        def att(name: str, ctype: str, *, inline: bool = False) -> Attachment:
            return Attachment(filename=name, content_type=ctype, size=3, sha256="0" * 64,
                              declared_extension=name.rsplit(".", 1)[-1], is_inline=inline)

        files = actionable.openable_files([
            att("a.pdf", "application/pdf"), att("b.png", "image/png", inline=True), att("c.ics", "application/ics"),
            att("smime.p7s", "application/octet-stream"), att("d.asc", "application/pgp-signature"),
            att("e.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        ])
        assert [f.filename for f in files] == ["a.pdf", "e.docx"]

    def test_has_bec_signal_and_stored_verdict_rules(self):
        assert not actionable.has_bec_signal(None) and not actionable.has_bec_signal({"signals": "x"})
        assert actionable.has_bec_signal({"signals": [{"code": "bec.gift_card"}]})
        assert actionable.stored_verdict_is_text_only({"signals": [{"code": "sender.first_time"}]})
        assert not actionable.stored_verdict_is_text_only(None)
        assert not actionable.stored_verdict_is_text_only({"signals": [{"code": "bec.wire_request"}]})
        assert not actionable.stored_verdict_is_text_only({"urls": [{"url": "https://x"}]})
        assert not actionable.stored_verdict_is_text_only({"attachments": [{"filename": "a"}]})
        assert not actionable.stored_verdict_is_text_only({"signals": [{"code": "url.credential_form"}]})


# --------------------------------------------------------------------------- text-only money scams


class TestTextScams:
    def test_bec_fixtures_trip_the_text_scam_check(self, fixtures_dir):
        for name in ("06_bec_wire_change.eml", "07_gift_card_ceo.eml", "22_gift_card_scam_freemail.eml"):
            parsed = parse((fixtures_dir / "emails" / name).read_bytes())
            found = actionable.text_scam_signals(parsed)
            assert found, name
            assert all(s.stage is SignalStage.BEC and s.weight > 0 for s in found)
            assert any(s.code in actionable.MONEY_SCAM_CODES for s in found)

    def test_plain_personal_email_is_clean(self, fixtures_dir):
        parsed = parse((fixtures_dir / "emails" / "01_plain_personal.eml").read_bytes())
        assert actionable.text_scam_signals(parsed) == []

    def test_callback_scam_text_only(self):
        body = ("Your Norton subscription has been renewed and $499.99 has been charged to your account. "
                "If you did not authorize this, call our billing department at +1 (808) 555-0147 to cancel.")
        parsed = parse(build_raw(from_header="Billing <billing.dept7@gmail.com>", subject="Order #88231", text=body))
        assert not actionable.is_actionable(parsed)
        assert any(s.code == "bec.callback_scam" for s in actionable.text_scam_signals(parsed))

    def test_trusted_sender_is_not_flagged(self):
        body = "Please wire the escrow funds today to the new account details below. Routing number changed."
        raw = build_raw(from_header="Title Co <closing@shop.example>", text=body, auth=DMARC_PASS)
        parsed = parse(raw)
        assert actionable.text_scam_signals(parsed)
        trusted = ClientFeedback(trusted_domains=["shop.example"])
        assert actionable.text_scam_signals(parsed, feedback=trusted) == []
        weak = ClientFeedback(trusted_addresses=["closing@shop.example"])
        assert actionable.text_scam_signals(parsed, feedback=weak) == []

    def test_known_correspondent_is_still_checked(self):
        """Hacked accounts of real contacts are how BEC arrives: history alone is no pass."""
        body = "Quick favour: buy 5 Apple gift cards and send me photos of the codes. Keep this between us."
        parsed = parse(build_raw(from_header="Boss <boss@company.example>", text=body))
        history = SenderHistory(address="boss@company.example", message_count=20, replied_to=True)
        assert actionable.text_scam_signals(parsed, history)

    def test_soft_tells_count_only_together(self):
        ooo = parse(build_raw(from_header="Dr Lee <lee@clinic.example>", subject="Automatic reply",
                              text="I am out of the office until Monday with limited access to email."))
        assert actionable.text_scam_signals(ooo) == []
        opener = parse(build_raw(from_header="CEO <ceo.office.mail@gmail.com>", subject="Quick one",
                                 text="Are you at your desk? I need a favour. Text me on my cell, I'm in meetings. "
                                      "Keep this between us, it is urgent."))
        found = actionable.text_scam_signals(opener)
        assert found and not any(s.code in actionable.MONEY_SCAM_CODES for s in found)
        assert sum(s.weight for s in found) >= actionable.TEXT_SCAM_COMBINED_WEIGHT

    def test_heuristic_failure_is_swallowed(self, monkeypatch):
        import reddysec.analysis.bec as bec

        def boom(*a, **k):
            raise RuntimeError("bug")

        monkeypatch.setattr(bec, "bec_signals", boom)
        parsed = parse(build_raw(text="buy gift cards"))
        assert actionable.text_scam_signals(parsed) == []

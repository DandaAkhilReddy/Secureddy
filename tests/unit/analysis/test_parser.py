"""Parser edge cases: addresses, encoded words, multiple auth headers, broken MIME."""

from __future__ import annotations

from datetime import datetime

from reddysec.analysis.parser import html_to_text, parse_authentication_results, parse_raw
from reddysec.models import AuthResults

from .support import RECEIVED_AT, build_raw


def _parse(raw: bytes, **kw):
    kw.setdefault("provider_message_id", "pm1")
    kw.setdefault("mailbox_id", "mbx")
    kw.setdefault("received_at", RECEIVED_AT)
    return parse_raw(raw, **kw)


class TestAddresses:
    def test_basic_from_and_recipients(self):
        raw = build_raw(from_header="Alice Smith <alice@example.com>", to="client@gmail.com, Bob <bob@x.org>",
                        extra_headers={"Cc": "carol@y.net"})
        p = _parse(raw)
        assert p.from_address == "alice@example.com"
        assert p.from_name == "Alice Smith"
        assert p.from_domain == "example.com"
        assert "bob@x.org" in p.to and "client@gmail.com" in p.to
        assert p.cc == ["carol@y.net"]

    def test_encoded_word_display_name(self):
        raw = build_raw(from_header="=?UTF-8?B?RG9jdVNpZ24gU2VydmljZQ==?= <dse@docusign.net>")
        p = _parse(raw)
        assert p.from_name == "DocuSign Service"
        assert p.from_address == "dse@docusign.net"

    def test_encoded_word_subject(self):
        raw = build_raw(subject="=?utf-8?q?Action_required_=E2=80=94_verify?=")
        p = _parse(raw)
        assert "Action required" in p.subject and "verify" in p.subject

    def test_missing_from_falls_back_to_sender(self):
        raw = build_raw(from_header="").replace(b"From: \r\n", b"Sender: real@x.com\r\n")
        p = _parse(raw)
        assert p.from_address == "real@x.com"

    def test_odd_quoting_is_tolerated(self):
        raw = build_raw(from_header='"Smith, John (Finance)" <john.smith@corp.example>')
        p = _parse(raw)
        assert p.from_address == "john.smith@corp.example"
        assert "Smith" in (p.from_name or "")

    def test_reply_to_list(self):
        raw = build_raw(extra_headers={"Reply-To": '"ceo@company.com" <x@gmail.com>, Bob <bob@y.org>'})
        p = _parse(raw)
        assert p.reply_to == ["x@gmail.com", "bob@y.org"]

    def test_from_domain_lowercased(self):
        raw = build_raw(from_header="A <A@Example.COM>")
        p = _parse(raw)
        assert p.from_domain == "example.com"


class TestDates:
    def test_timezone_aware(self):
        p = _parse(build_raw(date="Wed, 05 Nov 2026 09:00:00 -0800"))
        assert p.date is not None and p.date.tzinfo is not None
        assert p.date.utcoffset().total_seconds() == -8 * 3600

    def test_bad_date_is_none(self):
        p = _parse(build_raw(date="not a date at all"))
        assert p.date is None


class TestBodies:
    def test_prefers_plain_text(self):
        p = _parse(build_raw(text="The plain part.", html="<p>The <b>html</b> part.</p>"))
        assert p.text_body == "The plain part."
        assert p.html_body is not None and "html" in p.html_body

    def test_derives_text_from_html_when_no_plain(self):
        p = _parse(build_raw(text=None, html="<html><body><p>Only&nbsp;HTML here.</p><script>x()</script></body></html>"))
        assert "Only" in p.text_body and "HTML here" in p.text_body
        assert "x()" not in p.text_body

    def test_html_to_text_strips_scripts_and_tags(self):
        text = html_to_text("<html><head><style>a{}</style></head><body>Hi <a href='#'>there</a><script>bad()</script></body></html>")
        assert "Hi" in text and "there" in text and "bad()" not in text and "<" not in text


class TestAttachments:
    def test_attachment_metadata_and_bytes(self):
        raw = build_raw(attachments=[("report.pdf", "application/pdf", b"%PDF-1.4\n%fake\n", None)])
        p = _parse(raw)
        assert len(p.attachments) == 1
        att = p.attachments[0]
        assert att.filename == "report.pdf"
        assert att.declared_extension == "pdf"
        assert att.sniffed_type == "pdf"
        assert att.size == len(b"%PDF-1.4\n%fake\n")
        assert att.data == b"%PDF-1.4\n%fake\n"
        assert not att.is_inline
        assert p.has_attachments

    def test_inline_cid_image_is_inline_and_not_counted(self):
        html = '<html><body><img src="cid:logo.png">hello</body></html>'
        raw = build_raw(text=None, html=html,
                        attachments=[("logo.png", "image/png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 20, "inline")])
        p = _parse(raw)
        assert p.attachments[0].is_inline
        assert not p.has_attachments  # inline images don't count as real attachments
        assert p.real_attachments == []

    def test_cid_referenced_in_html_marked_inline(self):
        # Declared as attachment, but referenced by cid: in the HTML -> inline.
        html = '<html><body>see <img src="cid:sig.png"></body></html>'
        raw = build_raw(text=None, html=html,
                        attachments=[("sig.png", "image/png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 10, None)])
        p = _parse(raw)
        assert p.attachments[0].is_inline

    def test_calendar_invite_detected(self):
        raw = build_raw(attachments=[("invite.ics", "text/calendar", b"BEGIN:VCALENDAR\nEND:VCALENDAR\n", None)])
        p = _parse(raw)
        assert p.has_calendar_invite

    def test_filename_from_content_type_name(self):
        raw = build_raw(attachments=[("data.bin", "application/octet-stream", b"\x00\x01\x02", None)])
        p = _parse(raw)
        assert p.attachments[0].filename == "data.bin"


class TestRawAndHeaders:
    def test_raw_size_and_sha(self):
        raw = build_raw()
        p = _parse(raw)
        assert p.raw_size == len(raw)
        assert len(p.raw_sha256) == 64

    def test_headers_lowercased_first_value(self):
        raw = build_raw(extra_headers={"X-Custom": "first"})
        p = _parse(raw)
        assert p.headers["x-custom"] == "first"
        assert "from" in p.headers and "subject" in p.headers

    def test_thread_id_carried_in_headers(self):
        p = _parse(build_raw(), thread_id="thread-99")
        assert p.headers["x-reddysec-thread-id"] == "thread-99"

    def test_list_unsubscribe_flag(self):
        raw = build_raw(extra_headers={"List-Unsubscribe": "<https://x.test/unsub>"})
        p = _parse(raw)
        assert p.has_list_unsubscribe

    def test_message_id_stripped_of_brackets(self):
        p = _parse(build_raw(message_id="<abc@host>"))
        assert p.rfc_message_id == "abc@host"


class TestRobustness:
    def test_empty_bytes_never_raises(self):
        p = parse_raw(b"", provider_message_id="x", mailbox_id="m", received_at=RECEIVED_AT)
        assert p.provider_message_id == "x"
        assert p.from_address == ""
        assert p.urls == []

    def test_garbage_bytes_degrade_gracefully(self):
        p = parse_raw(b"\xff\xfe\x00not a real email", provider_message_id="x", mailbox_id="m", received_at=RECEIVED_AT)
        assert p.raw_size > 0
        assert isinstance(p.text_body, str)

    def test_headers_only_no_body(self):
        raw = b"From: a@b.com\r\nSubject: hi\r\n\r\n"
        p = _parse(raw)
        assert p.from_address == "a@b.com"
        assert p.subject == "hi"

    def test_broken_mime_boundary_degrades(self):
        raw = b'From: a@b.com\r\nContent-Type: multipart/mixed; boundary="X"\r\n\r\nno parts here at all'
        p = _parse(raw)
        assert p.from_address == "a@b.com"  # did not raise

    def test_nested_multipart(self):
        raw = build_raw(text="plain", html="<p>html body with <a href='https://nested.example/x'>link</a></p>",
                        attachments=[("a.txt", "text/plain", b"attachment text https://intxt.example/y", None)])
        p = _parse(raw)
        normalized = {u.normalized for u in p.urls}
        assert "https://nested.example/x" in normalized
        assert any("intxt.example" in u for u in normalized)

    def test_urls_populated_from_bodies(self):
        p = _parse(build_raw(text="Visit https://plain.example/path now."))
        assert any("plain.example" in u.normalized for u in p.urls)


class TestAuthenticationResults:
    def test_gmail_format(self):
        raw = build_raw(
            from_header="x@docusign.net",
            auth="mx.google.com; dkim=pass header.i=@docusign.net header.s=s1; "
                 "spf=pass smtp.mailfrom=x@docusign.net; dmarc=pass (p=REJECT) header.from=docusign.net",
        )
        p = _parse(raw)
        assert p.auth.spf == "pass" and p.auth.dkim == "pass" and p.auth.dmarc == "pass"
        assert p.auth.dkim_domain == "docusign.net"
        assert p.auth.aligned is True

    def test_comments_with_nested_parens_stripped(self):
        auth = ("mx.google.com; spf=pass (google.com: domain of x@a.com designates (really) 1.2.3.4 as permitted) "
                "smtp.mailfrom=x@a.com; dkim=fail header.i=@a.com; dmarc=fail header.from=a.com")
        result = parse_authentication_results([auth], "a.com")
        assert result.spf == "pass" and result.dkim == "fail" and result.dmarc == "fail"

    def test_multiple_headers_prefers_receiving_provider(self):
        headers = [
            "mx.google.com; dkim=pass header.i=@sender.com; spf=pass smtp.mailfrom=x@sender.com; "
            "dmarc=pass header.from=sender.com",
            "forwarder.example; dkim=fail; dmarc=fail header.from=sender.com",
        ]
        result = parse_authentication_results(headers, "sender.com")
        assert result.dmarc == "pass"  # google header wins

    def test_multiple_dkim_keeps_passing_one(self):
        auth = ("mx.google.com; dkim=fail header.i=@bounce.mcsv.net; dkim=pass header.i=@brand.com header.s=k1; "
                "spf=pass smtp.mailfrom=bounce@mcsv.net; dmarc=pass header.from=brand.com")
        result = parse_authentication_results([auth], "brand.com")
        assert result.dkim == "pass"
        assert result.dkim_domain == "brand.com"

    def test_yahoo_format(self):
        auth = ("atlas.mail.yahoo.com; dkim=pass header.i=@brand.com header.s=sel; "
                "spf=pass smtp.mailfrom=brand.com; dmarc=pass(p=REJECT) header.from=brand.com")
        result = parse_authentication_results([auth], "brand.com")
        assert result.dkim == "pass" and result.dmarc == "pass"

    def test_alignment_via_spf_when_no_dmarc(self):
        auth = "mx.google.com; spf=pass smtp.mailfrom=newsletter@brand.com; dkim=none"
        result = parse_authentication_results([auth], "brand.com")
        assert result.aligned is True

    def test_alignment_false_when_dkim_domain_differs(self):
        auth = "mx.google.com; dkim=pass header.i=@sendgrid.net; spf=pass smtp.mailfrom=bounce@sendgrid.net; dmarc=fail header.from=brand.com"
        result = parse_authentication_results([auth], "brand.com")
        assert result.aligned is False

    def test_no_headers_gives_empty(self):
        result = parse_authentication_results([], "brand.com")
        assert result == AuthResults()
        assert result.aligned is None

    def test_subdomain_alignment_uses_registrable_domain(self):
        auth = "mx.google.com; dkim=pass header.i=@mail.brand.com; spf=pass smtp.mailfrom=x@brand.com; dmarc=pass header.from=news.brand.com"
        result = parse_authentication_results([auth], "news.brand.com")
        assert result.aligned is True

    def test_parse_raw_tz_naive_received_at_ok(self):
        # received_at without tzinfo must not crash date-skew handling.
        raw = build_raw(date="Wed, 05 Nov 2026 09:00:00 -0800")
        p = parse_raw(raw, provider_message_id="x", mailbox_id="m", received_at=datetime(2026, 11, 5, 17, 0))
        assert p.date is not None

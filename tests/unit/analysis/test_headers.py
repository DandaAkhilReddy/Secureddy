"""Sender and header signals, with their negatives."""

from __future__ import annotations

from reddysec.analysis.headers import sender_signals
from reddysec.analysis.parser import parse_raw
from reddysec.models import SenderHistory

from .support import RECEIVED_AT, build_raw

GMAIL_AUTH = ("mx.google.com; dkim=pass header.i=@gmail.com; spf=pass smtp.mailfrom=x@gmail.com; "
              "dmarc=pass header.from=gmail.com")


def parse(**kw):
    return parse_raw(build_raw(**kw), provider_message_id="pm", mailbox_id="mbx", received_at=RECEIVED_AT)


def codes(signals) -> set[str]:
    return {s.code for s in signals}


def weight(signals, code: str) -> int:
    return max((s.weight for s in signals if s.code == code), default=0)


class TestDisplayName:
    def test_brand_impersonation_from_freemail(self):
        p = parse(from_header="DocuSign <docusign.notices@gmail.com>", auth=GMAIL_AUTH)
        s = sender_signals(p, None)
        assert "sender.display_brand_impersonation" in codes(s)

    def test_display_contains_other_address(self):
        p = parse(from_header='"ceo@bigcorp.com" <attacker@gmail.com>', auth=GMAIL_AUTH)
        s = sender_signals(p, None)
        assert "sender.display_contains_other_address" in codes(s)

    def test_freemail_company_name(self):
        p = parse(from_header="Acme Billing Department <acme.billing@gmail.com>", auth=GMAIL_AUTH)
        s = sender_signals(p, None)
        assert "sender.freemail_company_name" in codes(s)

    def test_person_named_chase_not_flagged(self):
        p = parse(from_header="Chase Williams <chase.williams@gmail.com>", auth=GMAIL_AUTH)
        s = sender_signals(p, None)
        assert "sender.display_brand_impersonation" not in codes(s)

    def test_legit_brand_from_own_domain_not_flagged(self):
        auth = ("mx.google.com; dkim=pass header.i=@docusign.net; spf=pass smtp.mailfrom=x@docusign.net; "
                "dmarc=pass header.from=docusign.net")
        p = parse(from_header="DocuSign <dse@docusign.net>", auth=auth)
        s = sender_signals(p, None)
        assert "sender.display_brand_impersonation" not in codes(s)


class TestDomainSignals:
    def test_lookalike_domain(self):
        auth = ("mx.google.com; dkim=pass header.i=@docusign-secure.com; spf=pass smtp.mailfrom=x@docusign-secure.com; "
                "dmarc=pass header.from=docusign-secure.com")
        p = parse(from_header="DocuSign <dse@docusign-secure.com>", auth=auth)
        s = sender_signals(p, None)
        assert "sender.domain_lookalike" in codes(s)

    def test_reply_to_mismatch(self):
        auth = ("mx.google.com; dkim=pass header.i=@corp.example; spf=pass smtp.mailfrom=x@corp.example; "
                "dmarc=pass header.from=corp.example")
        p = parse(from_header="Vendor <ap@corp.example>", extra_headers={"Reply-To": "ap.vendor@gmail.com"}, auth=auth)
        s = sender_signals(p, None)
        assert "sender.reply_to_mismatch" in codes(s)

    def test_reply_to_mismatch_ignored_for_bulk(self):
        p = parse(
            from_header="News <news@brand.com>",
            extra_headers={"Reply-To": "replies@mailer.com", "List-Unsubscribe": "<https://brand.com/unsub>"},
            auth="mx.google.com; dkim=pass header.i=@brand.com; spf=pass smtp.mailfrom=brand.com; dmarc=pass header.from=brand.com",
        )
        s = sender_signals(p, None)
        assert "sender.reply_to_mismatch" not in codes(s)

    def test_return_path_mismatch(self):
        auth = ("mx.google.com; dkim=pass header.i=@corp.example; spf=pass smtp.mailfrom=corp.example; "
                "dmarc=pass header.from=corp.example")
        p = parse(from_header="X <x@corp.example>", extra_headers={"Return-Path": "<bounce@sketchy.example>"}, auth=auth)
        s = sender_signals(p, None)
        assert "sender.return_path_mismatch" in codes(s)

    def test_missing_from(self):
        p = parse_raw(b"Subject: no sender\r\n\r\nbody", provider_message_id="x", mailbox_id="m", received_at=RECEIVED_AT)
        s = sender_signals(p, None)
        assert "sender.missing_from" in codes(s)


class TestAuth:
    def test_dmarc_fail(self):
        auth = "mx.google.com; dkim=fail; spf=fail smtp.mailfrom=x@brand.com; dmarc=fail header.from=brand.com"
        p = parse(from_header="X <x@brand.com>", auth=auth)
        s = sender_signals(p, None)
        assert "auth.dmarc_fail" in codes(s)
        assert weight(s, "auth.dmarc_fail") > weight(s, "auth.dkim_fail")

    def test_auth_missing(self):
        p = parse(from_header="X <x@brand.com>")  # no Authentication-Results
        s = sender_signals(p, None)
        assert "auth.missing" in codes(s)

    def test_dmarc_pass_aligned_is_trust(self):
        auth = ("mx.google.com; dkim=pass header.i=@brand.com; spf=pass smtp.mailfrom=brand.com; "
                "dmarc=pass header.from=brand.com")
        p = parse(from_header="X <x@brand.com>", auth=auth)
        s = sender_signals(p, None)
        assert weight(s, "auth.dmarc_pass_aligned") < 0

    def test_none_scaled_below_fail(self):
        auth_none = "mx.google.com; spf=none; dkim=none; dmarc=none header.from=brand.com"
        p = parse(from_header="X <x@brand.com>", auth=auth_none)
        s = sender_signals(p, None)
        assert weight(s, "auth.dmarc_none") < 40


class TestHistory:
    def test_first_seen(self):
        p = parse(from_header="X <x@brand.com>", auth=GMAIL_AUTH)
        s = sender_signals(p, None)
        assert "sender.first_seen" in codes(s)

    def test_known_contact_is_trust(self):
        p = parse(from_header="Maria <maria@friend.com>",
                  auth="mx.google.com; dkim=pass header.i=@friend.com; spf=pass smtp.mailfrom=friend.com; dmarc=pass header.from=friend.com")
        hist = SenderHistory(address="maria@friend.com", message_count=10, replied_to=True)
        s = sender_signals(p, hist)
        assert weight(s, "sender.known_contact") < 0

    def test_contact_name_different_address(self):
        p = parse(from_header="Maria Lindqvist <maria.l.urgent@gmail.com>", auth=GMAIL_AUTH)
        hist = SenderHistory(address="maria@friend.com", display_names=["Maria Lindqvist"], message_count=5, replied_to=True)
        s = sender_signals(p, hist)
        assert "sender.display_contact_impersonation" in codes(s)


class TestSubjectAndDate:
    def test_urgency_subject(self):
        p = parse(subject="URGENT: verify your account immediately", from_header="X <x@brand.com>", auth=GMAIL_AUTH)
        s = sender_signals(p, None)
        assert "subject.urgency" in codes(s)

    def test_date_skew(self):
        p = parse(date="Mon, 01 Jan 2035 00:00:00 +0000", from_header="X <x@brand.com>", auth=GMAIL_AUTH)
        s = sender_signals(p, None)
        assert "header.date_skew" in codes(s)

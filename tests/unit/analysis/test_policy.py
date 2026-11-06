"""Triage lanes and detonation selection, including magic-link protection."""

from __future__ import annotations

from reddysec.analysis.parser import parse_raw
from reddysec.analysis.policy import (
    choose_lane,
    select_attachments_to_detonate,
    select_urls_to_detonate,
)
from reddysec.models import PolicyConfig, SenderHistory, Signal, SignalStage, TriageLane

from .support import RECEIVED_AT, build_raw

ALIGNED = ("mx.google.com; dkim=pass header.i=@{d}; spf=pass smtp.mailfrom={d}; dmarc=pass header.from={d}")


def parse(**kw):
    return parse_raw(build_raw(**kw), provider_message_id="pm", mailbox_id="mbx", received_at=RECEIVED_AT)


def sig(code: str, weight: int) -> Signal:
    return Signal(code=code, stage=SignalStage.STATIC, weight=weight, title=code)


class TestChooseLane:
    def test_release_fast_no_links_no_attachments(self):
        p = parse(text="Just a note, nothing attached.")
        lane = choose_lane(p, None, PolicyConfig(), {}, {})
        assert lane is TriageLane.RELEASE_FAST

    def test_block_on_strong_signal(self):
        p = parse(html='<a href="https://evil.example/x">x</a>', text=None)
        url_static = {p.urls[0].normalized: [sig("url.known_bad", 100)]}
        assert choose_lane(p, None, PolicyConfig(), url_static, {}) is TriageLane.BLOCK

    def test_block_on_blocked_sender(self):
        p = parse(from_header="Spammer <spam@baddomain.example>", text="hello")
        policy = PolicyConfig(blocked_senders=["baddomain.example"])
        assert choose_lane(p, None, PolicyConfig().model_copy(update={"blocked_senders": ["baddomain.example"]}), {}, {}) is TriageLane.BLOCK
        assert choose_lane(p, None, policy, {}, {}) is TriageLane.BLOCK

    def test_trusted_known_correspondent_clean(self):
        p = parse(from_header="Maria <maria@friend.example>",
                  html='<a href="https://www.google.com/doc">doc</a>', text=None,
                  auth=ALIGNED.format(d="friend.example"))
        hist = SenderHistory(address="maria@friend.example", message_count=10, replied_to=True)
        lane = choose_lane(p, hist, PolicyConfig(), {p.urls[0].normalized: []}, {})
        assert lane is TriageLane.TRUSTED

    def test_trusted_domain_from_policy(self):
        p = parse(from_header="Advisor <a@trusted-advisor.example>",
                  html='<a href="https://www.nytimes.com/x">news</a>', text=None,
                  auth=ALIGNED.format(d="trusted-advisor.example"))
        policy = PolicyConfig(trusted_domains=["trusted-advisor.example"])
        lane = choose_lane(p, None, policy, {p.urls[0].normalized: []}, {})
        assert lane is TriageLane.TRUSTED

    def test_not_trusted_when_url_to_unknown_domain(self):
        p = parse(from_header="Maria <maria@friend.example>",
                  html='<a href="https://sketchy-unknown.example/x">x</a>', text=None,
                  auth=ALIGNED.format(d="friend.example"))
        hist = SenderHistory(address="maria@friend.example", message_count=10, replied_to=True)
        lane = choose_lane(p, hist, PolicyConfig(), {p.urls[0].normalized: []}, {})
        assert lane is TriageLane.DETONATE

    def test_not_trusted_when_unauthenticated(self):
        p = parse(from_header="Maria <maria@friend.example>",
                  html='<a href="https://www.google.com/x">x</a>', text=None)  # no auth
        hist = SenderHistory(address="maria@friend.example", message_count=10, replied_to=True)
        assert choose_lane(p, hist, PolicyConfig(), {p.urls[0].normalized: []}, {}) is TriageLane.DETONATE

    def test_detonate_default(self):
        p = parse(html='<a href="https://unknown.example/x">x</a>', text=None,
                  from_header="X <x@unknown-sender.example>")
        assert choose_lane(p, None, PolicyConfig(), {p.urls[0].normalized: []}, {}) is TriageLane.DETONATE

    def test_not_trusted_with_dangerous_attachment(self):
        p = parse(from_header="Maria <maria@friend.example>", text="file attached",
                  attachments=[("x.pdf", "application/pdf", b"%PDF-1.4\n", None)],
                  auth=ALIGNED.format(d="friend.example"))
        hist = SenderHistory(address="maria@friend.example", message_count=10, replied_to=True)
        att_signals = {"k": [sig("attachment.dangerous_type", 70)]}
        assert choose_lane(p, hist, PolicyConfig(), {}, att_signals) is TriageLane.DETONATE


class TestSelectUrls:
    def test_drops_unsubscribe_and_mailto(self):
        html = ('<a href="https://brand.example/offer">Offer</a>'
                '<a href="https://brand.example/unsubscribe?u=1">Unsubscribe</a>'
                '<a href="mailto:x@y.com">mail</a>')
        p = parse(html=html, text=None)
        selected = select_urls_to_detonate(p, PolicyConfig(), {})
        normals = {u.normalized for u in selected}
        assert any("offer" in u for u in normals)
        assert not any("unsubscribe" in u for u in normals)
        assert not any(u.startswith("mailto") for u in normals)

    def test_drops_tracking_pixel(self):
        html = '<a href="https://track.example/open.gif">x</a><a href="https://real.example/page">y</a>'
        p = parse(html=html, text=None)
        selected = {u.normalized for u in select_urls_to_detonate(p, PolicyConfig(), {})}
        assert not any(u.endswith(".gif") for u in selected)

    def test_never_detonate_domains(self):
        p = parse(html='<a href="https://internal-portal.example/x">x</a>', text=None)
        policy = PolicyConfig(never_detonate_domains=["internal-portal.example"])
        assert select_urls_to_detonate(p, policy, {}) == []

    def test_magic_link_from_popular_sender_protected(self):
        # Long-token link from accounts.google.com, DMARC-aligned -> never detonated.
        p = parse(
            from_header="Google <no-reply@accounts.google.com>",
            html='<a href="https://accounts.google.com/signin/v2/challenge?token=aB3dEf9hJ2kL4mN6oP8qR0sT2uV4wX6yZ">continue</a>',
            text=None,
            auth=ALIGNED.format(d="accounts.google.com"),
        )
        assert p.urls[0].has_opaque_token
        selected = select_urls_to_detonate(p, PolicyConfig(), {})
        assert selected == []

    def test_opaque_token_from_unknown_sender_still_detonated(self):
        p = parse(
            from_header="X <x@sketchy-unknown.example>",
            html='<a href="https://sketchy-unknown.example/r?token=aB3dEf9hJ2kL4mN6oP8qR0sT2uV">go</a>',
            text=None,
            auth=ALIGNED.format(d="sketchy-unknown.example"),
        )
        selected = select_urls_to_detonate(p, PolicyConfig(), {})
        assert len(selected) == 1

    def test_dedup_by_domain_and_path(self):
        html = ('<a href="https://x.example/a?u=1">one</a>'
                '<a href="https://x.example/a?u=2">two</a>'
                '<a href="https://x.example/b">three</a>')
        p = parse(html=html, text=None)
        selected = select_urls_to_detonate(p, PolicyConfig(), {})
        paths = {u.normalized.split("?")[0] for u in selected}
        assert paths == {"https://x.example/a", "https://x.example/b"}

    def test_cap_at_eight(self):
        links = "".join(f'<a href="https://x.example/p{i}">l{i}</a>' for i in range(20))
        p = parse(html=links, text=None)
        selected = select_urls_to_detonate(p, PolicyConfig(), {})
        assert len(selected) <= 8

    def test_ranked_by_static_risk(self):
        html = '<a href="https://low.example/a">a</a><a href="https://high.example/b">b</a>'
        p = parse(html=html, text=None)
        url_static = {}
        for u in p.urls:
            url_static[u.normalized] = [sig("url.lookalike", 60)] if "high" in u.normalized else [sig("url.insecure_http", 10)]
        selected = select_urls_to_detonate(p, PolicyConfig(), url_static)
        assert "high.example" in selected[0].normalized


class TestSelectAttachments:
    def test_skips_images(self):
        p = parse(text="x", attachments=[("logo.png", "image/png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 10, None)])
        assert select_attachments_to_detonate(p) == []

    def test_selects_documents(self):
        p = parse(text="x", attachments=[("doc.pdf", "application/pdf", b"%PDF-1.4\n" + b"x" * 50, None)])
        selected = select_attachments_to_detonate(p)
        assert len(selected) == 1 and selected[0].filename == "doc.pdf"

    def test_skips_calendar_and_text(self):
        p = parse(text="x", attachments=[("invite.ics", "text/calendar", b"BEGIN:VCALENDAR\n", None),
                                         ("note.txt", "text/plain", b"hello", None)])
        assert select_attachments_to_detonate(p) == []

    def test_selects_svg(self):
        svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>x</script></svg>'
        p = parse(text="x", attachments=[("image.svg", "image/svg+xml", svg, None)])
        selected = select_attachments_to_detonate(p)
        assert len(selected) == 1

    def test_skips_oversized(self):
        big = parse(text="x")
        from reddysec.models import Attachment
        big.attachments.append(Attachment(filename="huge.zip", content_type="application/zip",
                                           size=30 * 1024 * 1024, sha256="0" * 64, declared_extension="zip", data=b"PK"))
        assert select_attachments_to_detonate(big) == []

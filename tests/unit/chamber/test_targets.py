"""Unit tests for target policy: the one decision made on the host before a
URL is handed to a sandbox."""

from __future__ import annotations

import ipaddress

import pytest

from reddysec.chamber import targets
from reddysec.chamber.targets import (
    _resolve_blocking,
    decide_target,
    is_public_address,
    parse_ip_literal,
    resolve_host,
)


class TestIsPublicAddress:
    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.1", "10.0.0.1", "172.16.5.4", "192.168.1.1", "169.254.169.254",
            "0.0.0.0", "::1", "fe80::1", "fc00::1", "192.0.0.1", "198.18.0.1",
            "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::7f00:1",  # NAT64-wrapped 127.0.0.1
        ],
    )
    def test_non_public_rejected(self, ip):
        assert not is_public_address(ipaddress.ip_address(ip))

    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "64:ff9b::8.8.8.8"])
    def test_public_allowed(self, ip):
        assert is_public_address(ipaddress.ip_address(ip))

    def test_nat64_wraps_private_v4(self):
        # 64:ff9b::/96 embedding 10.0.0.1 must be refused
        embedded = ipaddress.ip_address("64:ff9b::0a00:0001")
        assert not is_public_address(embedded)

    def test_6to4_and_teredo_unwrapped(self):
        # 6to4 (2002::/16) embedding a private v4 is refused...
        assert not is_public_address(ipaddress.ip_address("2002:0a00:0001::1"))  # 10.0.0.1
        # ...and a 6to4 embedding a public v4 is allowed.
        assert is_public_address(ipaddress.ip_address("2002:0808:0808::1"))  # 8.8.8.8
        # Teredo (2001:0000::/32) carries the client v4 in the last 32 bits (inverted).
        teredo_private = ipaddress.ip_address("2001:0000:4136:e378:8000:63bf:3fff:fdd2")
        assert is_public_address(teredo_private) == teredo_private.is_global


class TestResolveHost:
    async def test_literal_short_circuits(self):
        addrs = await resolve_host("127.0.0.1")
        assert [str(a) for a in addrs] == ["127.0.0.1"]

    async def test_resolves_localhost(self):
        # getaddrinfo works offline for localhost.
        addrs = await resolve_host("localhost")
        assert any(str(a) in ("127.0.0.1", "::1") for a in addrs)

    def test_resolve_blocking_localhost(self):
        addrs = _resolve_blocking("localhost")
        assert addrs  # at least one A/AAAA


class TestParseIpLiteral:
    @pytest.mark.parametrize(
        "host,expected",
        [
            ("127.0.0.1", "127.0.0.1"),
            ("[::1]", "::1"),
            ("2130706433", "127.0.0.1"),  # decimal shorthand
            ("0x7f.0.0.1", "127.0.0.1"),  # hex octet
            ("example.com", None),
            ("", None),
        ],
    )
    def test_parse(self, host, expected):
        got = parse_ip_literal(host)
        assert (str(got) if got is not None else None) == expected


class TestDecideTarget:
    async def test_public_name_allowed_when_resolves_public(self, monkeypatch):
        async def fake_resolve(host, timeout_s=5.0):
            return [ipaddress.ip_address("93.184.216.34")]

        monkeypatch.setattr(targets, "resolve_host", fake_resolve)
        decision = await decide_target("https://example.com/path")
        assert decision.allowed and decision.reason is None
        assert "93.184.216.34" in decision.addresses

    @pytest.mark.parametrize(
        "url,reason",
        [
            (None, "no_url"),
            ("ftp://example.com", "bad_scheme"),
            ("file:///etc/passwd", "bad_scheme"),
            ("javascript:alert(1)", "bad_scheme"),
            ("https://", "no_host"),
            ("https://paypal.com@evil.example/", "userinfo"),
        ],
    )
    async def test_rejections_without_dns(self, url, reason):
        decision = await decide_target(url)
        assert not decision.allowed and decision.reason == reason

    async def test_loopback_literal_blocked(self):
        decision = await decide_target("http://127.0.0.1:8000/x")
        assert not decision.allowed and decision.reason == "private_address"

    async def test_metadata_ip_blocked(self):
        decision = await decide_target("http://169.254.169.254/latest/meta-data/")
        assert not decision.allowed and decision.reason == "private_address"

    async def test_internal_name_blocked_before_dns(self):
        for host in ("http://metadata.google.internal/", "http://db.svc.local/"):
            decision = await decide_target(host)
            assert not decision.allowed and decision.reason == "private_address"

    async def test_private_resolution_blocked(self, monkeypatch):
        async def fake_resolve(host, timeout_s=5.0):
            return [ipaddress.ip_address("10.1.2.3")]

        monkeypatch.setattr(targets, "resolve_host", fake_resolve)
        decision = await decide_target("https://intranet.example.com/")
        assert not decision.allowed and decision.reason == "private_address"

    async def test_any_private_answer_blocks(self, monkeypatch):
        # DNS rebinding defence: a mix of public and private answers is refused.
        async def fake_resolve(host, timeout_s=5.0):
            return [ipaddress.ip_address("8.8.8.8"), ipaddress.ip_address("127.0.0.1")]

        monkeypatch.setattr(targets, "resolve_host", fake_resolve)
        decision = await decide_target("https://rebind.example.com/")
        assert not decision.allowed and decision.reason == "private_address"

    async def test_dns_failure(self, monkeypatch):
        async def fake_resolve(host, timeout_s=5.0):
            raise OSError("NXDOMAIN")

        monkeypatch.setattr(targets, "resolve_host", fake_resolve)
        decision = await decide_target("https://nope.invalid/")
        assert not decision.allowed and decision.reason == "dns_failure"

    async def test_allow_private_bypasses_everything(self):
        decision = await decide_target("http://127.0.0.1:9000/x", allow_private=True)
        assert decision.allowed

    async def test_no_addresses_is_dns_failure(self, monkeypatch):
        async def empty(host, timeout_s=5.0):
            return []

        monkeypatch.setattr(targets, "resolve_host", empty)
        decision = await decide_target("https://example.com/")
        assert not decision.allowed and decision.reason == "dns_failure"

    async def test_malformed_url_rejected(self):
        # An unterminated IPv6 bracket makes urlsplit raise on host access.
        decision = await decide_target("http://[::1")
        assert not decision.allowed and decision.reason in ("bad_url", "no_host")

    async def test_public_literal_allowed(self):
        decision = await decide_target("https://8.8.8.8/")
        assert decision.allowed and decision.addresses == ("8.8.8.8",)

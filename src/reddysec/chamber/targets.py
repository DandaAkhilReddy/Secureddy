"""Which URLs the chamber is allowed to open.

The sandbox fetches whatever the page tells it to, so the one decision we
make on the host is *where the first request may go*. Anything that is not a
globally routable address is refused: loopback, RFC1918, link-local (which
includes the cloud metadata service at 169.254.169.254), multicast, reserved
and unspecified addresses, IPv4 addresses hidden inside IPv6 (mapped or
NAT64) and the usual special-purpose blocks.

This is a first line of defence only. The browser resolves the name again a
moment later, so a hostile DNS server can answer differently (rebinding) or a
redirect can point at a private address. The production backends therefore
also block private ranges at the network layer (the Docker "dirty" network and
the ACI subnet NSG); see the backend docstrings.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})

_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")
_METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata", "instance-data"})


@dataclass(frozen=True)
class TargetDecision:
    allowed: bool
    reason: str | None = None  # machine-readable: bad_scheme, no_host, private_address, dns_failure ...
    detail: str = ""
    addresses: tuple[str, ...] = ()


def is_public_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for an address the public internet can route to."""
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped
        if mapped is not None:
            return is_public_address(mapped)
        if ip in _NAT64_PREFIX:
            embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
            return is_public_address(embedded)
        if ip.sixtofour is not None:
            return is_public_address(ip.sixtofour)
        if ip.teredo is not None:
            return is_public_address(ip.teredo[1])
    if ip.is_multicast or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_reserved:
        return False
    if ip.is_private:
        return False
    return ip.is_global


def parse_ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return the address when ``host`` is an IP literal (bracketed IPv6 ok)."""
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        pass
    # Chromium accepts shorthand IPv4 forms ("0x7f.1", "2130706433", "127.1").
    # Treat anything numeric-looking as an IPv4 literal via inet_aton so these
    # cannot slip past the private-range check.
    if candidate and all(c in "0123456789abcdefxX." for c in candidate):
        try:
            return ipaddress.IPv4Address(socket.inet_aton(candidate))
        except OSError:
            return None
    return None


def _resolve_blocking(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    addresses = []
    for family, _type, _proto, _canon, sockaddr in infos:
        if family in (socket.AF_INET, socket.AF_INET6):
            addresses.append(ipaddress.ip_address(sockaddr[0]))
    return addresses


async def resolve_host(host: str, timeout_s: float = 5.0) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """All A/AAAA answers for ``host``. Raises ``OSError`` on failure."""
    literal = parse_ip_literal(host)
    if literal is not None:
        return [literal]
    return await asyncio.wait_for(asyncio.to_thread(_resolve_blocking, host), timeout=timeout_s)


async def decide_target(url: str | None, *, allow_private: bool = False, dns_timeout_s: float = 5.0) -> TargetDecision:
    """Decide whether the chamber may open ``url``.

    ``allow_private`` exists for development and tests that run their own
    "evil site" on 127.0.0.1; production never sets it.
    """
    if not url:
        return TargetDecision(False, "no_url", "job has no url")
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        return TargetDecision(False, "bad_url", f"unparsable url: {exc}")
    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return TargetDecision(False, "bad_scheme", f"scheme {scheme or '(none)'!r} is not http/https")
    try:
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError as exc:
        return TargetDecision(False, "bad_url", f"invalid host: {exc}")
    if not host:
        return TargetDecision(False, "no_host", "url has no host")
    if parts.username or parts.password:
        # "https://paypal.com@evil.example/" - the browser would happily go to
        # evil.example. Refuse rather than guess what the sender meant.
        return TargetDecision(False, "userinfo", "url contains credentials / userinfo")
    if not allow_private and (host in _METADATA_HOSTS or host.endswith(".internal") or host.endswith(".local")):
        return TargetDecision(False, "private_address", f"{host} is an internal name")
    try:
        addresses = await resolve_host(host, timeout_s=dns_timeout_s)
    except (OSError, TimeoutError, UnicodeError) as exc:
        return TargetDecision(False, "dns_failure", f"could not resolve {host}: {exc}")
    if not addresses:
        return TargetDecision(False, "dns_failure", f"no addresses for {host}")
    text = tuple(str(a) for a in addresses)
    if not allow_private:
        bad = [str(a) for a in addresses if not is_public_address(a)]
        if bad:
            return TargetDecision(False, "private_address", f"{host} resolves to non-public {', '.join(bad)}", text)
    return TargetDecision(True, None, "", text)

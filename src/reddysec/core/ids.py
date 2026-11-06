"""Identifiers. Prefixed, URL-safe, sortable by creation time."""

from __future__ import annotations

import os
import time

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32


def _encode(n: int, length: int) -> str:
    out = []
    for _ in range(length):
        out.append(_ALPHABET[n & 31])
        n >>= 5
    return "".join(reversed(out))


def new_id(prefix: str) -> str:
    """ULID-like: 10 chars of millisecond time + 16 chars of randomness."""
    ts = _encode(int(time.time() * 1000), 10)
    rnd = _encode(int.from_bytes(os.urandom(10), "big"), 16)
    return f"{prefix}_{ts}{rnd}"


def is_id(value: str, prefix: str) -> bool:
    if not value.startswith(prefix + "_"):
        return False
    body = value[len(prefix) + 1 :]
    return len(body) == 26 and all(c in _ALPHABET for c in body)

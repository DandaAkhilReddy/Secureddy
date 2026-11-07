"""Keep secrets out of logs, error pages and ``repr``.

Two layers:

* :func:`redact_text` replaces anything that *looks* like a credential in a
  string: Anthropic keys (``sk-ant-...``), Google OAuth client secrets
  (``GOCSPX-...``), GitHub tokens (``ghp_...``, ``github_pat_...``), bearer
  tokens in an ``Authorization`` value, JWTs, and ``user:password@`` in URLs.
* :func:`redact_mapping` walks dicts and lists and blanks the *value* of any
  key that names a secret (``access_token``, ``refresh_token``,
  ``app_password``, ``password``, ``client_secret``, ``api_key``,
  ``authorization``, ``assertion`` ...), whatever it looks like.

:func:`structlog_processor` applies both to every log event; it is installed
by ``core.logging.configure_logging``. Redaction is a safety net, not a
licence: code still must not log secrets on purpose.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, MutableMapping
from typing import Any

MASK = "[redacted]"

# Keys whose values are always secret, compared case-insensitively after
# removing "-" and "_" (so "Access-Token", "access_token" and "accessToken"
# all match).
SECRET_KEYS = frozenset(
    k.replace("_", "").replace("-", "").lower()
    for k in (
        "access_token",
        "refresh_token",
        "id_token",
        "token",
        "oauth_access_token",
        "app_password",
        "password",
        "passwd",
        "secret",
        "client_secret",
        "api_key",
        "x-api-key",
        "authorization",
        "assertion",
        "client_assertion",
        "cookie",
        "set-cookie",
        "secret_key",
        "token_kek",
        "private_key",
        "pin",
        "code_verifier",
    )
)

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"), MASK),
    (re.compile(r"GOCSPX-[A-Za-z0-9_\-]{8,}"), MASK),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}"), MASK),
    (re.compile(r"\bgho_[A-Za-z0-9]{20,}"), MASK),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), MASK),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9\-._~+/]{8,}=*"), r"\1 " + MASK),
    # Three base64url segments starting with a JSON header: a JWT.
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), MASK),
    # user:password@host in URLs (database URLs, proxies).
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+):[^\s@/]+@"), r"\1:" + MASK + "@"),
)


def _normal_key(key: Any) -> str:
    return str(key).replace("_", "").replace("-", "").lower()


def is_secret_key(key: Any) -> bool:
    normal = _normal_key(key)
    return normal in SECRET_KEYS or normal.endswith(("token", "password", "secret", "apikey"))


def redact_text(value: str) -> str:
    for pattern, replacement in _PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def redact_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 8:
        return value
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return redact_mapping(value, depth=depth + 1)
    if isinstance(value, list | tuple):
        items = [redact_value(v, depth=depth + 1) for v in value]
        return type(value)(items) if isinstance(value, tuple) else items
    return value


def redact_mapping(data: Mapping[str, Any], *, depth: int = 0) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in data.items():
        if is_secret_key(key) and value not in (None, "", [], {}):
            out[key] = MASK
        else:
            out[key] = redact_value(value, depth=depth)
    return out


# structlog's own fields that must stay untouched.
_EVENT_FIELDS = frozenset({"level", "timestamp", "logger"})


def structlog_processor(_logger: Any, _method: str, event_dict: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    """A structlog processor: redacts every field of the event in place."""
    for key in list(event_dict.keys()):
        if key in _EVENT_FIELDS:
            continue
        value = event_dict[key]
        if key != "event" and is_secret_key(key) and value not in (None, ""):
            event_dict[key] = MASK
        else:
            event_dict[key] = redact_value(value)
    return event_dict


__all__ = [
    "MASK",
    "SECRET_KEYS",
    "is_secret_key",
    "redact_mapping",
    "redact_text",
    "redact_value",
    "structlog_processor",
]

"""Credentials for the Claude API: keyless (Workload Identity Federation) or an API key.

Keyless is the default whenever it is configured. The flow, on Azure
Container Apps::

    managed identity ──(1) Entra access token, aud = api://<app id>──▶ us
    us ──(2) POST https://api.anthropic.com/v1/oauth/token (RFC 7523 jwt-bearer)──▶ Anthropic
    Anthropic ──▶ short-lived "sk-ant-oat01-..." access token (expires_in seconds)
    us ──(3) Messages API with  Authorization: Bearer <token>──▶ Anthropic

1. ``$IDENTITY_ENDPOINT?api-version=2019-08-01&resource=<audience>&client_id=<id>``
   with header ``X-IDENTITY-HEADER: $IDENTITY_HEADER`` (the Container Apps
   managed-identity endpoint). Outside Container Apps (a VM) the Azure
   Instance Metadata Service is used instead.
2. JSON body ``grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer``,
   ``assertion``, ``federation_rule_id``, ``organization_id``,
   ``service_account_id`` and optional ``workspace_id``, with
   ``anthropic-beta: oauth-2025-04-20,oidc-federation-2026-04-01``. The wire
   format matches the official SDK (``anthropic.lib.credentials``) and the
   WIF reference; the SDK's provider is synchronous, so the async exchange
   lives here instead.
3. API calls send ``Authorization: Bearer <token>`` and
   ``anthropic-beta: oauth-2025-04-20``.

The token is cached and refreshed 120 seconds before it expires (and at once
after a 401, see :meth:`AnthropicCredentials.invalidate`). Nothing here is a
long-lived secret: the Entra token lives for minutes in memory, the Claude
token likewise, and neither is ever logged (errors carry status codes and the
OAuth ``error`` field only).

Precedence: keyless when ``RS_ANTHROPIC_FEDERATION_RULE_ID``,
``RS_ANTHROPIC_ORGANIZATION_ID`` and ``RS_ANTHROPIC_SERVICE_ACCOUNT_ID`` are
set; otherwise ``RS_ANTHROPIC_API_KEY`` (``x-api-key``), with a one-time
warning in the log that a static key is in use.

Both Claude callers use this module: the "Ask Secureddy" assistant
(``assistant.llm.AnthropicChat``) and the background BEC reviewer
(``analysis.bec.AnthropicAssessor``, through :func:`get_anthropic_auth_headers`
and :func:`invalidate_default_credentials` after a 401).
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx

from .logging import get_logger

log = get_logger(__name__)

TOKEN_PATH = "/v1/oauth/token"
GRANT_TYPE_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
OAUTH_API_BETA = "oauth-2025-04-20"
FEDERATION_BETA = "oidc-federation-2026-04-01"
REFRESH_BEFORE_S = 120
IDENTITY_API_VERSION = "2019-08-01"
IMDS_ENDPOINT = "http://169.254.169.254/metadata/identity/oauth2/token"
IMDS_API_VERSION = "2018-02-01"
DEFAULT_TIMEOUT_S = 15.0
MAX_ASSERTION_BYTES = 16 * 1024

Clock = Callable[[], float]
IdentityTokenSource = Callable[[], Awaitable[str]]


class AnthropicAuthError(Exception):
    """Keyless sign-in to the Claude API failed (no identity, a rule mismatch,
    a network error). The message never contains a token."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class _Token:
    value: str
    expires_at: float


def _oauth_error(resp: httpx.Response) -> str:
    """The RFC 6749 ``error`` code only: token endpoints sometimes echo the
    assertion back in their error bodies."""
    try:
        body = resp.json()
    except ValueError:
        return ""
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):  # Anthropic API error envelope
            return str(err.get("type", ""))[:80]
        return str(err or "")[:80]
    return ""


class ManagedIdentityToken:
    """An Entra access token for ``audience`` from the Azure managed identity.

    Container Apps (and App Service) expose ``IDENTITY_ENDPOINT`` and
    ``IDENTITY_HEADER``; a VM has the Instance Metadata Service. ``client_id``
    picks a user-assigned identity; empty means the system-assigned one.
    """

    def __init__(
        self,
        audience: str,
        *,
        client_id: str = "",
        http: httpx.AsyncClient | None = None,
        environ: dict[str, str] | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        if not audience:
            raise ValueError("an audience (api://<app id>) is required for keyless Claude")
        self.audience = audience
        self.client_id = client_id
        self._http = http
        self._environ = environ if environ is not None else os.environ
        self._timeout = timeout_s

    async def __call__(self) -> str:
        endpoint = self._environ.get("IDENTITY_ENDPOINT", "")
        header = self._environ.get("IDENTITY_HEADER", "")
        if endpoint and header:
            params = {"api-version": IDENTITY_API_VERSION, "resource": self.audience}
            headers = {"X-IDENTITY-HEADER": header}
            url = endpoint
        else:
            params = {"api-version": IMDS_API_VERSION, "resource": self.audience}
            headers = {"Metadata": "true"}
            url = IMDS_ENDPOINT
        if self.client_id:
            params["client_id"] = self.client_id
        http = self._http or httpx.AsyncClient()
        try:
            resp = await http.get(url, params=params, headers=headers, timeout=self._timeout)
        except httpx.HTTPError as exc:
            raise AnthropicAuthError(f"managed identity endpoint unreachable ({type(exc).__name__})") from None
        finally:
            if self._http is None:
                await http.aclose()
        if resp.status_code != 200:
            raise AnthropicAuthError(
                f"managed identity refused a token (HTTP {resp.status_code} {_oauth_error(resp)})".strip(),
                status=resp.status_code,
            )
        try:
            token = resp.json().get("access_token")
        except (ValueError, AttributeError):
            token = None
        if not isinstance(token, str) or not token:
            raise AnthropicAuthError("managed identity returned no access token")
        return token


class AnthropicCredentials:
    """Headers for one Claude API request. Thread-safe within one event loop."""

    def __init__(
        self,
        *,
        api_key: str = "",
        federation_rule_id: str = "",
        organization_id: str = "",
        service_account_id: str = "",
        workspace_id: str = "",
        identity_token: IdentityTokenSource | None = None,
        base_url: str = "https://api.anthropic.com",
        http: httpx.AsyncClient | None = None,
        clock: Clock = time.time,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        self.keyless = bool(federation_rule_id and organization_id and service_account_id)
        if self.keyless and identity_token is None:
            raise ValueError("keyless Claude needs an identity token source")
        if not self.keyless and not api_key:
            raise ValueError("no Claude credentials: set the federation ids or an API key")
        self._api_key = api_key
        self._rule = federation_rule_id
        self._org = organization_id
        self._service_account = service_account_id
        self._workspace = workspace_id
        self._identity_token = identity_token
        self.base_url = base_url.rstrip("/")
        self._http = http
        self._clock = clock
        self._timeout = timeout_s
        self._token: _Token | None = None
        self._lock = asyncio.Lock()
        self.exchanges = 0  # how many token exchanges ran (tests and metrics)

    @property
    def mode(self) -> str:
        return "workload_identity" if self.keyless else "api_key"

    def __repr__(self) -> str:  # never show the key or the token
        return f"AnthropicCredentials(mode={self.mode!r})"

    def invalidate(self) -> None:
        """Drop the cached token (after the API answered 401)."""
        self._token = None

    async def headers(self) -> dict[str, str]:
        if not self.keyless:
            return {"x-api-key": self._api_key}
        token = await self._access_token()
        return {"Authorization": f"Bearer {token}", "anthropic-beta": OAUTH_API_BETA}

    async def _access_token(self) -> str:
        now = self._clock()
        cached = self._token
        if cached is not None and now < cached.expires_at - REFRESH_BEFORE_S:
            return cached.value
        async with self._lock:
            cached = self._token
            if cached is not None and self._clock() < cached.expires_at - REFRESH_BEFORE_S:
                return cached.value
            self._token = await self._exchange()
            return self._token.value

    async def _exchange(self) -> _Token:
        assert self._identity_token is not None
        assertion = await self._identity_token()
        if len(assertion.encode()) > MAX_ASSERTION_BYTES:
            raise AnthropicAuthError("the identity token is too large to be a JWT")
        body: dict[str, Any] = {
            "grant_type": GRANT_TYPE_JWT_BEARER,
            "assertion": assertion,
            "federation_rule_id": self._rule,
            "organization_id": self._org,
            "service_account_id": self._service_account,
        }
        if self._workspace:
            body["workspace_id"] = self._workspace
        http = self._http or httpx.AsyncClient()
        try:
            resp = await http.post(
                f"{self.base_url}{TOKEN_PATH}",
                json=body,
                headers={"anthropic-beta": f"{OAUTH_API_BETA},{FEDERATION_BETA}", "content-type": "application/json"},
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            raise AnthropicAuthError(f"Claude token endpoint unreachable ({type(exc).__name__})") from None
        finally:
            if self._http is None:
                await http.aclose()
        self.exchanges += 1
        if resp.status_code != 200:
            hint = " (check the federation rule's audience and claims)" if resp.status_code in (400, 401, 403) else ""
            raise AnthropicAuthError(
                f"Claude token exchange failed: HTTP {resp.status_code} {_oauth_error(resp)}{hint}".strip(),
                status=resp.status_code,
            )
        try:
            data = resp.json()
            token = data["access_token"]
            expires_in = int(data["expires_in"])
        except (ValueError, KeyError, TypeError):
            raise AnthropicAuthError("Claude token exchange returned an unexpected answer") from None
        token_type = str(data.get("token_type") or "bearer").lower()
        if not isinstance(token, str) or not token or token_type != "bearer":
            raise AnthropicAuthError("Claude token exchange returned an unusable token")
        log.info("anthropic.token_exchanged", expires_in=expires_in)
        return _Token(token, self._clock() + expires_in)


# --------------------------------------------------------------------------- settings


_warned_static_key = False


def credentials_from_settings(settings: Any, http: httpx.AsyncClient | None = None) -> AnthropicCredentials | None:
    """Keyless when the federation ids are set, else the API key, else None."""
    global _warned_static_key
    base_url = getattr(settings, "anthropic_base_url", "") or "https://api.anthropic.com"
    if getattr(settings, "anthropic_wif_enabled", False):
        audience = settings.anthropic_wif_audience
        if not audience:
            log.error("anthropic.wif_missing_audience")
            return None
        source = ManagedIdentityToken(audience, client_id=settings.azure_identity_client_id, http=http)
        return AnthropicCredentials(
            federation_rule_id=settings.anthropic_federation_rule_id,
            organization_id=settings.anthropic_organization_id,
            service_account_id=settings.anthropic_service_account_id,
            workspace_id=settings.anthropic_workspace_id,
            identity_token=source,
            base_url=base_url,
            http=http,
        )
    key = settings.anthropic_api_key.get_secret_value()
    if not key:
        return None
    if not _warned_static_key:
        _warned_static_key = True
        log.warning(
            "anthropic.static_api_key_in_use",
            hint="switch to keyless Workload Identity Federation (docs/claude-keyless-setup.md)",
        )
    return AnthropicCredentials(api_key=key, base_url=base_url, http=http)


_default: AnthropicCredentials | None = None
_default_key: tuple[Any, ...] | None = None


async def get_anthropic_auth_headers(settings: Any = None) -> dict[str, str]:
    """Headers that authenticate one Claude API request (keyless if
    configured, else ``x-api-key``). Raises :class:`AnthropicAuthError` when
    nothing is configured or the exchange fails. The credential object, and
    with it the cached token, is shared by the whole process."""
    global _default, _default_key
    if settings is None:
        from reddysec.config import get_settings

        settings = get_settings()
    key = (
        settings.anthropic_federation_rule_id,
        settings.anthropic_organization_id,
        settings.anthropic_service_account_id,
        settings.anthropic_workspace_id,
        settings.anthropic_wif_audience,
        settings.azure_identity_client_id,
        settings.anthropic_api_key.get_secret_value(),
    )
    if _default is None or _default_key != key:
        _default = credentials_from_settings(settings)
        _default_key = key
    if _default is None:
        raise AnthropicAuthError("Claude is not configured")
    return await _default.headers()


def invalidate_default_credentials() -> None:
    """Drop the shared credential's cached token (the API answered 401)."""
    if _default is not None:
        _default.invalidate()


def reset_default_credentials() -> None:
    """Tests call this to forget the shared credential."""
    global _default, _default_key, _warned_static_key
    _default = None
    _default_key = None
    _warned_static_key = False


__all__ = [
    "FEDERATION_BETA",
    "OAUTH_API_BETA",
    "AnthropicAuthError",
    "AnthropicCredentials",
    "ManagedIdentityToken",
    "credentials_from_settings",
    "get_anthropic_auth_headers",
    "invalidate_default_credentials",
    "reset_default_credentials",
]

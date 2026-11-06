"""Small OpenID Connect helpers shared by the Microsoft and Yahoo sign-ins.

* :class:`JwksCache` fetches a provider's signing keys (JWKS) through an
  injectable async fetcher and caches them, refetching once when a token
  names a key id we have not seen (providers rotate keys without notice).
* :func:`verify_id_token` checks an ID token's signature with those keys
  (PyJWT on ``cryptography``) and returns its claims. Audience, expiry,
  issuer and nonce are checked by the caller against its own clock, so tests
  can pin time.
* :func:`client_assertion` builds the RFC 7523 JWT a confidential client
  signs with its certificate instead of sending a client secret.

Why verify signatures at all when the ID token came straight from the token
endpoint over TLS (OIDC Core 3.1.3.7 allows skipping it then)? Because it is
cheap, and it keeps working if a future change ever accepts an ID token from
the front channel.
"""

from __future__ import annotations

import base64
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from reddysec.mail.base import ConnectorError
from reddysec.mail.oauth_google import IdTokenError

JwksFetcher = Callable[[str], Awaitable[dict[str, Any]]]

JWKS_TTL_S = 24 * 60 * 60
JWKS_MIN_REFETCH_S = 300  # an unknown kid may refetch at most this often
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
ASSERTION_LIFETIME_S = 600  # Entra accepts up to 10 minutes


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def http_jwks_fetcher(http_getter: Callable[[], httpx.AsyncClient]) -> JwksFetcher:
    """A fetcher that GETs the JWKS URL with the caller's shared client."""

    async def fetch(url: str) -> dict[str, Any]:
        try:
            resp = await http_getter().get(url, headers={"Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise ConnectorError(f"signing keys unreachable: {exc}", retryable=True) from exc
        if resp.status_code != 200:
            raise ConnectorError(f"signing keys: HTTP {resp.status_code}", retryable=True)
        try:
            body = resp.json()
        except ValueError as exc:
            raise ConnectorError("signing keys: not JSON", retryable=True) from exc
        if not isinstance(body, dict):
            raise ConnectorError("signing keys: unexpected shape", retryable=True)
        return body

    return fetch


class JwksCache:
    """Signing keys by ``kid``, refreshed after ``ttl_s`` or on an unknown kid."""

    def __init__(
        self,
        url: str,
        fetcher: JwksFetcher,
        *,
        ttl_s: int = JWKS_TTL_S,
        min_refetch_s: int = JWKS_MIN_REFETCH_S,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.url = url
        self._fetch = fetcher
        self._ttl_s = ttl_s
        self._min_refetch_s = min_refetch_s
        self._monotonic = monotonic
        self._keys: dict[str, dict[str, Any]] = {}
        self._fetched_at: float | None = None
        self.fetches = 0

    async def _refresh(self) -> None:
        body = await self._fetch(self.url)
        keys = body.get("keys") if isinstance(body.get("keys"), list) else []
        self._keys = {str(k["kid"]): k for k in keys if isinstance(k, dict) and k.get("kid")}
        self._fetched_at = self._monotonic()
        self.fetches += 1

    async def key(self, kid: str) -> dict[str, Any]:
        now = self._monotonic()
        stale = self._fetched_at is None or now - self._fetched_at > self._ttl_s
        if stale:
            await self._refresh()
        elif kid not in self._keys and now - (self._fetched_at or 0) >= self._min_refetch_s:
            await self._refresh()
        try:
            return self._keys[kid]
        except KeyError:
            raise IdTokenError("ID token is signed with a key the provider does not publish") from None


async def verify_id_token(token: str, keys: JwksCache, *, algorithms: list[str]) -> dict[str, Any]:
    """Check the signature and return the claims. Time and audience checks are
    left to the caller (``options`` below), which uses its injectable clock."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise IdTokenError("malformed ID token") from exc
    alg = str(header.get("alg", ""))
    if alg not in algorithms:
        raise IdTokenError(f"ID token uses an unexpected algorithm {alg!r}")
    jwk = await keys.key(str(header.get("kid", "")))
    try:
        signing_key = jwt.PyJWK(jwk, algorithm=alg)
        claims = jwt.decode(
            token,
            key=signing_key,
            algorithms=[alg],
            options={
                "verify_signature": True,
                "verify_aud": False,
                "verify_iss": False,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
            },
        )
    except jwt.PyJWTError as exc:
        raise IdTokenError("ID token signature is not valid") from exc
    if not isinstance(claims, dict):
        raise IdTokenError("ID token payload is not an object")
    return claims


def check_time_claims(claims: dict[str, Any], now: datetime, *, leeway_s: int = 120) -> None:
    ts = int(now.timestamp())
    try:
        exp = int(claims.get("exp", 0))
    except (TypeError, ValueError) as exc:
        raise IdTokenError("ID token has no usable expiry") from exc
    if exp <= ts - leeway_s:
        raise IdTokenError("ID token has expired")
    for name in ("nbf", "iat"):
        value = claims.get(name)
        if value is not None:
            try:
                if int(value) > ts + leeway_s:
                    raise IdTokenError(f"ID token {name} is in the future")
            except (TypeError, ValueError) as exc:
                raise IdTokenError(f"ID token has a malformed {name}") from exc


# --------------------------------------------------------------------------- certificates


@dataclass(frozen=True)
class ClientCertificate:
    """The private key that signs client assertions, and its SHA-1 thumbprint."""

    private_key: RSAPrivateKey
    thumbprint_hex: str  # uppercase hex, 40 characters
    certificate: x509.Certificate | None = None

    @property
    def x5t(self) -> str:
        return b64url(bytes.fromhex(self.thumbprint_hex))


def _normalise_thumbprint(value: str) -> str:
    cleaned = "".join(ch for ch in value if ch not in ": \t\r\n").upper()
    if cleaned and (len(cleaned) != 40 or any(ch not in "0123456789ABCDEF" for ch in cleaned)):
        raise ValueError("the certificate thumbprint must be 40 hex characters (SHA-1)")
    return cleaned


def load_client_certificate(pem_bundle: str, thumbprint: str = "") -> ClientCertificate:
    """Parse a PEM bundle (private key + certificate). When both a certificate
    and a configured thumbprint are present they must agree, so a wrong Key
    Vault secret fails at start-up instead of at the first sign-in."""
    data = pem_bundle.replace("\\n", "\n").encode()
    if b"PRIVATE KEY" not in data:
        raise ValueError("the client certificate bundle has no private key")
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as exc:
        raise ValueError("the client certificate's private key cannot be read") from exc
    if not isinstance(key, RSAPrivateKey):
        raise ValueError("the client certificate must use an RSA key (RS256)")
    cert: x509.Certificate | None = None
    if b"BEGIN CERTIFICATE" in data:
        try:
            cert = x509.load_pem_x509_certificate(data)
        except ValueError as exc:
            raise ValueError("the client certificate cannot be read") from exc
    configured = _normalise_thumbprint(thumbprint)
    actual = cert.fingerprint(hashes.SHA1()).hex().upper() if cert is not None else ""  # noqa: S303 - x5t is SHA-1 by definition
    if configured and actual and configured != actual:
        raise ValueError("the configured thumbprint does not match the client certificate")
    final = configured or actual
    if not final:
        raise ValueError("a certificate thumbprint is required when the bundle has no certificate")
    return ClientCertificate(private_key=key, thumbprint_hex=final, certificate=cert)


def client_assertion(cert: ClientCertificate, *, client_id: str, audience: str, now: datetime) -> str:
    """RFC 7523 client assertion, signed RS256 with the certificate's key.

    Header ``{"alg": "RS256", "typ": "JWT", "x5t": base64url(sha1 thumbprint)}``;
    claims ``aud`` (the token endpoint), ``iss`` = ``sub`` = client id, a fresh
    ``jti``, ``nbf`` and an ``exp`` ten minutes later.
    """
    ts = int(now.timestamp())
    claims = {
        "aud": audience,
        "iss": client_id,
        "sub": client_id,
        "jti": str(uuid.uuid4()),
        "nbf": ts,
        "iat": ts,
        "exp": ts + ASSERTION_LIFETIME_S,
    }
    return jwt.encode(claims, cert.private_key, algorithm="RS256", headers={"typ": "JWT", "x5t": cert.x5t})

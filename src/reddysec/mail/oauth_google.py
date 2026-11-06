"""Google OAuth 2.0 for a *Web application* client: Authorization Code + PKCE.

Why both a client secret and PKCE? Google's Web client type requires the
secret at the token endpoint, and PKCE additionally binds the authorization
code to the browser session that started the flow, so a code stolen from a
redirect log cannot be redeemed by anyone else. The ``state`` value is a
signed, time-limited payload (itsdangerous) carrying a nonce, the page to
return to, and a hash of the PKCE verifier: the callback can therefore prove
that the ``state`` it received belongs to the ``code_verifier`` it kept in the
session cookie, which stops login-CSRF and mix-up attacks.

Everything network-facing goes through an injectable ``httpx.AsyncClient`` so
the unit tests run against ``httpx.MockTransport`` and never touch Google.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

import httpx
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from pydantic import BaseModel, Field

from reddysec.mail.base import AuthExpired, ConnectorError

AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
TOKENINFO_ENDPOINT = "https://oauth2.googleapis.com/tokeninfo"
REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke"
ALLOWED_ISSUERS = frozenset({"accounts.google.com", "https://accounts.google.com"})

# gmail.modify covers read / label / move (the connector never deletes mail);
# gmail.settings.basic is required to create the HOLD-mode filter;
# gmail.labels lets us create our own labels without the broader scopes.
SCOPES = [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.settings.basic",
    "https://www.googleapis.com/auth/gmail.labels",
]

_STATE_SALT = "reddysec.google.oauth.state"
_REQUEST_TIMEOUT_S = 20.0


class OAuthError(ConnectorError):
    """A permanent OAuth failure (bad request, bad state, bad token)."""

    def __init__(self, message: str):
        super().__init__(message, retryable=False)


class OAuthStateError(OAuthError):
    """The ``state`` is tampered, expired, or does not match the PKCE verifier."""


class IdTokenError(OAuthError):
    """The ID token failed verification (audience, expiry, issuer, subject)."""


class AuthStart(BaseModel):
    """What ``begin`` hands to the web layer. ``code_verifier`` must be kept
    server-side (session cookie) and presented again to ``finish``."""

    url: str
    state: str
    code_verifier: str


class TokenSet(BaseModel):
    """Tokens plus the verified identity claims from the ID token."""

    access_token: str
    refresh_token: str | None = None
    expires_at: datetime
    id_claims: dict[str, Any] = Field(default_factory=dict)
    scopes: list[str] = Field(default_factory=list)

    def to_secret(self) -> dict[str, Any]:
        """The JSON-serialisable shape stored in the credential vault."""
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_at": self.expires_at.isoformat(),
            "scopes": list(self.scopes),
            "sub": self.id_claims.get("sub"),
            "email": self.id_claims.get("email"),
        }


IdTokenVerifier = Callable[[str], Awaitable[dict[str, Any]]]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded)


def pkce_pair() -> tuple[str, str]:
    """A fresh (code_verifier, S256 code_challenge) pair per RFC 7636."""
    verifier = _b64url(os.urandom(64))  # 86 chars, within the 43..128 limit
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def decode_jwt_payload(token: str) -> dict[str, Any]:
    """Decode (without verifying) the payload segment of a JWT.

    We never trust this alone: ``GoogleOAuth.finish`` cross-checks it against
    Google's tokeninfo endpoint. Decoding locally gives us the claims even when
    tokeninfo returns a reduced set, and lets us detect a swapped token.
    """
    try:
        _header, payload, _signature = token.split(".")
        return json.loads(_b64url_decode(payload))
    except (ValueError, json.JSONDecodeError) as exc:
        raise IdTokenError("malformed ID token") from exc


def _safe_return_to(return_to: str) -> str:
    """Only same-origin relative paths; anything else becomes '/'. Prevents the
    sign-in flow from being used as an open redirect."""
    if not return_to.startswith("/") or return_to.startswith("//") or "\\" in return_to:
        return "/"
    return return_to


class GoogleOAuth:
    """Authorization Code + PKCE flow against Google for a Web client.

    Parameters
    ----------
    http:
        Shared ``httpx.AsyncClient``. Tests pass one built on ``MockTransport``.
    id_token_verifier:
        Overrides how an ID token is verified. The default asks Google's
        tokeninfo endpoint (also through ``http``), which validates the
        signature server-side; an alternative could verify locally with
        cached certificates.
    clock:
        Returns the current UTC time; injectable so tests can pin ``expires_at``.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        *,
        state_signer_secret: str,
        http: httpx.AsyncClient | None = None,
        id_token_verifier: IdTokenVerifier | None = None,
        clock: Callable[[], datetime] | None = None,
        scopes: list[str] | None = None,
    ):
        if not client_id:
            raise ValueError("client_id is required")
        self.client_id = client_id
        self._client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = list(scopes or SCOPES)
        self._http = http
        self._owns_http = http is None
        self._verify_id_token = id_token_verifier or self._verify_via_tokeninfo
        self._clock = clock or (lambda: datetime.now(UTC))
        self._signer = URLSafeTimedSerializer(state_signer_secret, salt=_STATE_SALT)

    # ------------------------------------------------------------------ http
    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=_REQUEST_TIMEOUT_S)
        return self._http

    async def aclose(self) -> None:
        if self._owns_http and self._http is not None:
            await self._http.aclose()
            self._http = None

    # ------------------------------------------------------------------ begin
    def begin(self, return_to: str = "/", *, login_hint: str | None = None, link: str | None = None) -> AuthStart:
        """Build the consent URL. ``access_type=offline`` + ``prompt=consent``
        guarantee a refresh token even if the user consented before;
        ``include_granted_scopes`` keeps previously granted scopes when we add new ones."""
        verifier, challenge = pkce_pair()
        payload: dict[str, Any] = {
            "n": _b64url(os.urandom(16)),
            "r": _safe_return_to(return_to),
            "v": hashlib.sha256(verifier.encode("ascii")).hexdigest(),
        }
        if link:
            # "Connect another mailbox": the signed-in account that started the flow.
            payload["l"] = link
        state = self._signer.dumps(payload)
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.scopes),
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "access_type": "offline",
            "prompt": "consent",
            "include_granted_scopes": "true",
        }
        if login_hint:
            params["login_hint"] = login_hint
        return AuthStart(url=f"{AUTH_ENDPOINT}?{urlencode(params)}", state=state, code_verifier=verifier)

    def read_state(self, state: str, max_age_s: int = 600) -> dict[str, Any]:
        """Validate the signed state and return its payload (``r`` is return_to).

        Raises ``OAuthStateError`` when the signature is bad or older than
        ``max_age_s``: a consent screen left open for longer must be restarted.
        """
        try:
            payload = self._signer.loads(state, max_age=max_age_s)
        except SignatureExpired as exc:
            raise OAuthStateError("sign-in took too long; please start again") from exc
        except BadSignature as exc:
            raise OAuthStateError("sign-in state is invalid") from exc
        if not isinstance(payload, dict) or {"n", "r", "v"} - payload.keys():
            raise OAuthStateError("sign-in state is malformed")
        return payload

    def return_to(self, state: str, max_age_s: int = 600) -> str:
        return _safe_return_to(str(self.read_state(state, max_age_s)["r"]))

    def link_of(self, state: str, max_age_s: int = 600) -> str | None:
        """The account id a "Connect another mailbox" flow was started by, if any."""
        link = self.read_state(state, max_age_s).get("l")
        return str(link) if link else None

    # ----------------------------------------------------------------- finish
    async def finish(self, state: str, code: str, code_verifier: str, max_age_s: int = 600) -> TokenSet:
        """Redeem the authorization code. Validates state, verifier binding and
        the ID token before anything is returned."""
        payload = self.read_state(state, max_age_s)
        if hashlib.sha256(code_verifier.encode("ascii")).hexdigest() != payload["v"]:
            raise OAuthStateError("sign-in state does not belong to this browser session")
        data = await self._post_token(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": self.client_id,
                "client_secret": self._client_secret,
                "redirect_uri": self.redirect_uri,
                "code_verifier": code_verifier,
            }
        )
        id_token = data.get("id_token")
        if not id_token:
            raise IdTokenError("token response did not include an ID token")
        claims = await self._verified_claims(id_token)
        return self._token_set(data, claims, refresh_token=data.get("refresh_token"))

    async def refresh(self, refresh_token: str) -> TokenSet:
        """Exchange a refresh token for a new access token. Google does not echo
        the refresh token back, so the input one is carried into the result."""
        if not refresh_token:
            raise AuthExpired("no refresh token on file; the mailbox must be reconnected")
        data = await self._post_token(
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": self.client_id,
                "client_secret": self._client_secret,
            }
        )
        claims: dict[str, Any] = {}
        if data.get("id_token"):
            # Informational only: identity was verified at sign-in and the
            # response arrived from Google's token endpoint over TLS.
            try:
                claims = self._public_claims(decode_jwt_payload(data["id_token"]))
            except IdTokenError:
                claims = {}
        return self._token_set(data, claims, refresh_token=data.get("refresh_token") or refresh_token)

    async def revoke(self, token: str) -> None:
        """Revoke an access or refresh token. A 400 means it was already invalid,
        which is the state we wanted, so it is not an error."""
        try:
            resp = await self.http.post(
                REVOKE_ENDPOINT,
                data={"token": token},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.HTTPError as exc:
            raise ConnectorError(f"token revocation failed: {exc}", retryable=True) from exc
        if resp.status_code >= 500:
            raise ConnectorError(f"token revocation failed: HTTP {resp.status_code}", retryable=True)

    # --------------------------------------------------------------- internals
    async def _post_token(self, form: dict[str, str]) -> dict[str, Any]:
        try:
            resp = await self.http.post(
                TOKEN_ENDPOINT, data=form, headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
        except httpx.HTTPError as exc:
            raise ConnectorError(f"Google token endpoint unreachable: {exc}", retryable=True) from exc
        if resp.status_code >= 500:
            raise ConnectorError(f"Google token endpoint error: HTTP {resp.status_code}", retryable=True)
        try:
            body = resp.json()
        except json.JSONDecodeError as exc:
            raise ConnectorError("Google token endpoint returned a non-JSON body", retryable=True) from exc
        if resp.status_code != 200 or "error" in body:
            error = str(body.get("error", f"http_{resp.status_code}"))
            description = str(body.get("error_description", ""))
            if error == "invalid_grant":
                # Code already used / expired, or the refresh token was revoked
                # (password change, user removed access, 6-month inactivity).
                raise AuthExpired(f"Google rejected the grant: {description or error}")
            raise OAuthError(f"Google token error {error}: {description}".strip())
        if "access_token" not in body:
            raise OAuthError("Google token response lacks access_token")
        return body

    def _token_set(
        self, data: dict[str, Any], claims: dict[str, Any], *, refresh_token: str | None
    ) -> TokenSet:
        expires_in = int(data.get("expires_in", 3600))
        scopes = str(data.get("scope", "")).split()
        return TokenSet(
            access_token=data["access_token"],
            refresh_token=refresh_token,
            expires_at=self._clock() + timedelta(seconds=expires_in),
            id_claims=claims,
            scopes=scopes,
        )

    async def _verified_claims(self, id_token: str) -> dict[str, Any]:
        local = decode_jwt_payload(id_token)
        verified = await self._verify_id_token(id_token)
        if str(verified.get("aud", "")) != self.client_id:
            raise IdTokenError("ID token was issued for a different client")
        if str(verified.get("iss", "")) not in ALLOWED_ISSUERS:
            raise IdTokenError("ID token issuer is not Google")
        try:
            exp = int(verified.get("exp", 0))
        except (TypeError, ValueError) as exc:
            raise IdTokenError("ID token has no usable expiry") from exc
        if exp <= int(self._clock().timestamp()):
            raise IdTokenError("ID token has expired")
        if local.get("sub") and str(verified.get("sub", "")) != str(local["sub"]):
            raise IdTokenError("ID token subject mismatch")
        merged = {**local, **verified}
        return self._public_claims(merged)

    @staticmethod
    def _public_claims(claims: dict[str, Any]) -> dict[str, Any]:
        verified = claims.get("email_verified", False)
        if isinstance(verified, str):
            verified = verified.lower() == "true"
        return {
            "sub": str(claims.get("sub", "")),
            "email": str(claims.get("email", "")).lower(),
            "email_verified": bool(verified),
            "name": claims.get("name"),
            "picture": claims.get("picture"),
        }

    async def _verify_via_tokeninfo(self, id_token: str) -> dict[str, Any]:
        """Google validates the signature for us; we validate aud/exp/iss/sub."""
        try:
            resp = await self.http.get(TOKENINFO_ENDPOINT, params={"id_token": id_token})
        except httpx.HTTPError as exc:
            raise ConnectorError(f"Google tokeninfo unreachable: {exc}", retryable=True) from exc
        if resp.status_code >= 500:
            raise ConnectorError(f"Google tokeninfo error: HTTP {resp.status_code}", retryable=True)
        if resp.status_code != 200:
            raise IdTokenError("Google rejected the ID token")
        try:
            return resp.json()
        except json.JSONDecodeError as exc:
            raise IdTokenError("Google tokeninfo returned a non-JSON body") from exc

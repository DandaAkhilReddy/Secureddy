"""Sign in with Microsoft (personal Outlook.com/Hotmail and work Microsoft 365
accounts) for the Graph mail connector: Authorization Code + PKCE, with a
certificate instead of a client secret.

The Entra app "Secureddy" is multi-tenant plus personal accounts
(``signInAudience = AzureADandPersonalMicrosoftAccount``), so the authority is
``https://login.microsoftonline.com/common``. The tenant forbids client
secrets: the app proves who it is with an RFC 7523 *client assertion*, a short
JWT signed RS256 with the certificate's private key and carrying the
certificate's SHA-1 thumbprint as ``x5t`` (see ``mail.oidc.client_assertion``).

The ``state`` parameter works exactly like Google's (``mail.oauth_google``):
a signed, time-limited payload with a nonce, the page to return to, a hash of
the PKCE verifier and, in "link" mode, the id of the signed-in account that
started the flow. The nonce doubles as the OIDC ``nonce`` and must come back
inside the ID token.

ID token checks: the signature against Microsoft's published keys
(``https://login.microsoftonline.com/common/discovery/v2.0/keys``, cached),
``aud`` equal to our client id, ``iss`` equal to
``https://login.microsoftonline.com/{tid}/v2.0`` for the token's own ``tid``
(the multi-tenant issuer rule), expiry, and the nonce.

Email and account linking: Microsoft's ``email`` claim is *not* guaranteed to
be verified (a work tenant's admin can set it to anything, and personal
accounts are treated the same way here). ``email_verified`` in our claims is
therefore ``True`` only for work accounts whose token carries the optional
``xms_edov`` claim ("email domain owner verified"). The web layer never links
a sign-in to an existing account by an unverified email (see
``web.queries.resolve_identity``).

Revocation: Microsoft has no endpoint that revokes a single refresh token for
a v2 app, so ``revoke`` is a documented no-op. Disconnecting a mailbox deletes
our copy of the token; the client can also remove the app at
https://account.live.com/consent/Manage (personal) or https://myapps.microsoft.com (work).
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

import httpx
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from reddysec.core.logging import get_logger
from reddysec.mail.base import AuthExpired, ConnectorError
from reddysec.mail.oauth_google import (
    AuthStart,
    IdTokenError,
    OAuthError,
    OAuthStateError,
    TokenSet,
    _safe_return_to,
    pkce_pair,
)
from reddysec.mail.oidc import (
    CLIENT_ASSERTION_TYPE,
    ClientCertificate,
    JwksCache,
    b64url,
    check_time_claims,
    client_assertion,
    http_jwks_fetcher,
    load_client_certificate,
    verify_id_token,
)

log = get_logger(__name__)

DEFAULT_AUTHORITY = "https://login.microsoftonline.com/common"
JWKS_URL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
PERSONAL_TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad"
SCOPES = [
    "openid",
    "email",
    "profile",
    "offline_access",
    "User.Read",
    "Mail.ReadWrite",
    "MailboxSettings.ReadWrite",
]
# Errors that mean "the person must sign in again": a revoked or expired
# refresh token, a password change, or a new MFA / consent requirement.
REAUTH_ERRORS = frozenset({"invalid_grant", "interaction_required", "consent_required", "login_required"})

_STATE_SALT = "reddysec.microsoft.oauth.state"
_REQUEST_TIMEOUT_S = 20.0


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes")
    return value is True or value == 1


class MicrosoftOAuth:
    """Authorization Code + PKCE against the Microsoft identity platform (v2).

    ``certificate`` is the PEM bundle (private key + certificate) or an already
    loaded :class:`ClientCertificate`. ``http`` and ``jwks`` are injectable so
    tests run against ``httpx.MockTransport`` and their own signing keys.
    """

    provider = "microsoft"

    def __init__(
        self,
        client_id: str,
        certificate: str | ClientCertificate,
        redirect_uri: str,
        *,
        state_signer_secret: str,
        thumbprint: str = "",
        authority: str = DEFAULT_AUTHORITY,
        http: httpx.AsyncClient | None = None,
        jwks: JwksCache | None = None,
        clock: Callable[[], datetime] | None = None,
        scopes: list[str] | None = None,
    ):
        if not client_id:
            raise ValueError("client_id is required")
        self.client_id = client_id
        self.cert = (
            certificate
            if isinstance(certificate, ClientCertificate)
            else load_client_certificate(certificate, thumbprint)
        )
        self.redirect_uri = redirect_uri
        self.authority = authority.rstrip("/")
        self.scopes = list(scopes or SCOPES)
        self._http = http
        self._owns_http = http is None
        self._clock = clock or (lambda: datetime.now(UTC))
        self._signer = URLSafeTimedSerializer(state_signer_secret, salt=_STATE_SALT)
        self.jwks = jwks or JwksCache(JWKS_URL, http_jwks_fetcher(lambda: self.http))

    @property
    def authorize_endpoint(self) -> str:
        return f"{self.authority}/oauth2/v2.0/authorize"

    @property
    def token_endpoint(self) -> str:
        return f"{self.authority}/oauth2/v2.0/token"

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
    def begin(self, return_to: str = "/", *, link: str | None = None, login_hint: str | None = None) -> AuthStart:
        """The consent URL. ``prompt=select_account`` lets a person with both a
        personal and a work account choose; ``link`` (the signed-in account's
        id) marks a "Connect another mailbox" flow and travels in the state."""
        verifier, challenge = pkce_pair()
        payload: dict[str, Any] = {
            "n": b64url(os.urandom(16)),
            "r": _safe_return_to(return_to),
            "v": hashlib.sha256(verifier.encode("ascii")).hexdigest(),
        }
        if link:
            payload["l"] = link
        state = self._signer.dumps(payload)
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "response_mode": "query",
            "scope": " ".join(self.scopes),
            "state": state,
            "nonce": payload["n"],
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "prompt": "select_account",
        }
        if login_hint:
            params["login_hint"] = login_hint
        return AuthStart(url=f"{self.authorize_endpoint}?{urlencode(params)}", state=state, code_verifier=verifier)

    def read_state(self, state: str, max_age_s: int = 600) -> dict[str, Any]:
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
        link = self.read_state(state, max_age_s).get("l")
        return str(link) if link else None

    # ----------------------------------------------------------------- finish
    async def finish(self, state: str, code: str, code_verifier: str, max_age_s: int = 600) -> TokenSet:
        payload = self.read_state(state, max_age_s)
        if hashlib.sha256(code_verifier.encode("ascii")).hexdigest() != payload["v"]:
            raise OAuthStateError("sign-in state does not belong to this browser session")
        data = await self._post_token(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
                "code_verifier": code_verifier,
                "scope": " ".join(self.scopes),
            }
        )
        id_token = data.get("id_token")
        if not id_token:
            raise IdTokenError("token response did not include an ID token")
        claims = await self._verified_claims(str(id_token), nonce=str(payload["n"]))
        return self._token_set(data, claims, refresh_token=data.get("refresh_token"))

    async def refresh(self, refresh_token: str) -> TokenSet:
        """Microsoft rotates refresh tokens: the response carries a new one,
        which the caller must persist (the old one keeps working for a while)."""
        if not refresh_token:
            raise AuthExpired("no refresh token on file; the mailbox must be reconnected")
        data = await self._post_token(
            {"grant_type": "refresh_token", "refresh_token": refresh_token, "scope": " ".join(self.scopes)}
        )
        return self._token_set(data, {}, refresh_token=data.get("refresh_token") or refresh_token)

    async def revoke(self, token: str) -> None:
        """Not supported by Microsoft for v2 apps; see the module docstring."""
        log.info("microsoft.revoke_not_supported")

    # --------------------------------------------------------------- internals
    def assertion(self) -> str:
        return client_assertion(self.cert, client_id=self.client_id, audience=self.token_endpoint, now=self._clock())

    async def _post_token(self, form: dict[str, str]) -> dict[str, Any]:
        body = {
            **form,
            "client_id": self.client_id,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": self.assertion(),
        }
        try:
            resp = await self.http.post(
                self.token_endpoint, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
        except httpx.HTTPError as exc:
            raise ConnectorError(f"Microsoft token endpoint unreachable: {exc}", retryable=True) from exc
        if resp.status_code >= 500 or resp.status_code == 429:
            raise ConnectorError(f"Microsoft token endpoint error: HTTP {resp.status_code}", retryable=True)
        try:
            parsed = resp.json()
        except json.JSONDecodeError as exc:
            raise ConnectorError("Microsoft token endpoint returned a non-JSON body", retryable=True) from exc
        if not isinstance(parsed, dict):
            raise OAuthError("Microsoft token response has an unexpected shape")
        if resp.status_code != 200 or "error" in parsed:
            error = str(parsed.get("error", f"http_{resp.status_code}"))
            description = str(parsed.get("error_description", "")).split("\r\n", 1)[0]
            if error in REAUTH_ERRORS:
                raise AuthExpired(f"Microsoft rejected the grant: {description or error}")
            raise OAuthError(f"Microsoft token error {error}: {description}".strip())
        if "access_token" not in parsed:
            raise OAuthError("Microsoft token response lacks access_token")
        return parsed

    def _token_set(self, data: dict[str, Any], claims: dict[str, Any], *, refresh_token: Any) -> TokenSet:
        expires_in = int(data.get("expires_in", 3600))
        return TokenSet(
            access_token=str(data["access_token"]),
            refresh_token=str(refresh_token) if refresh_token else None,
            expires_at=self._clock() + timedelta(seconds=expires_in),
            id_claims=claims,
            scopes=str(data.get("scope", "")).split(),
        )

    async def _verified_claims(self, id_token: str, *, nonce: str) -> dict[str, Any]:
        claims = await verify_id_token(id_token, self.jwks, algorithms=["RS256"])
        if str(claims.get("aud", "")) != self.client_id:
            raise IdTokenError("ID token was issued for a different client")
        tid = str(claims.get("tid", ""))
        if not tid or str(claims.get("iss", "")) != f"https://login.microsoftonline.com/{tid}/v2.0":
            raise IdTokenError("ID token issuer does not match its tenant")
        check_time_claims(claims, self._clock())
        if str(claims.get("nonce", "")) != nonce:
            raise IdTokenError("ID token nonce does not match this sign-in")
        return self.public_claims(claims)

    @staticmethod
    def public_claims(claims: dict[str, Any]) -> dict[str, Any]:
        oid = str(claims.get("oid") or claims.get("sub") or "")
        tid = str(claims.get("tid", ""))
        email = str(claims.get("email") or "").strip().lower()
        if not email:
            username = str(claims.get("preferred_username") or "").strip().lower()
            email = username if "@" in username else ""
        personal = tid == PERSONAL_TENANT
        return {
            "sub": oid,
            "oid": oid,
            "tid": tid,
            "personal": personal,
            "email": email,
            # See the module docstring: only a work tenant that vouches for the
            # email's domain counts as verified.
            "email_verified": (not personal) and _truthy(claims.get("xms_edov")),
            "name": claims.get("name"),
        }

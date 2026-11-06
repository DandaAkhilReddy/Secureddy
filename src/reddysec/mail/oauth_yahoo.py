"""Sign in with Yahoo (OpenID Connect), for *signing in* only.

Yahoo's sign-in is open to any developer, but OAuth access to Yahoo Mail over
IMAP needs Yahoo's commercial Mail API approval, which we do not have yet. So
a Yahoo sign-in identifies the person; their mailbox is then connected with a
Yahoo *app password* on the "Connect your Yahoo Mail" step
(``/mailboxes/connect-yahoo``), tested with a real IMAP login before it is
saved.

If Yahoo approves us for mail access, switch it on like this (the hook is
already in place): add ``mail-r`` / ``mail-w`` to ``scopes``, store the token
set from :meth:`YahooOAuth.finish` in the vault with ``kind=imap_oauth`` and
``oauth_access_token`` set, and ``mail.imap.ImapConnector`` authenticates with
SASL XOAUTH2 (``xoauth2_string``) instead of the app password. A refresh hook
like Gmail's would then keep the access token fresh.

Client authentication uses HTTP Basic with the client secret (Yahoo's
documented method). PKCE (S256) is sent as well; the ``state`` is signed and
bound to the PKCE verifier as for Google and Microsoft, and its nonce is the
OIDC ``nonce`` that must come back in the ID token. The ID token's signature
is checked against Yahoo's published keys (RS256 or ES256).
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
from reddysec.mail.oidc import JwksCache, b64url, check_time_claims, http_jwks_fetcher, verify_id_token

AUTH_ENDPOINT = "https://api.login.yahoo.com/oauth2/request_auth"
TOKEN_ENDPOINT = "https://api.login.yahoo.com/oauth2/get_token"
JWKS_URL = "https://api.login.yahoo.com/openid/v1/certs"
ISSUER = "https://api.login.yahoo.com"
SCOPES = ["openid", "email", "profile"]
IMAP_HOST = "imap.mail.yahoo.com"
IMAP_PORT = 993

_STATE_SALT = "reddysec.yahoo.oauth.state"
_REQUEST_TIMEOUT_S = 20.0


class YahooOAuth:
    provider = "yahoo"

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        *,
        state_signer_secret: str,
        http: httpx.AsyncClient | None = None,
        jwks: JwksCache | None = None,
        clock: Callable[[], datetime] | None = None,
        scopes: list[str] | None = None,
        use_pkce: bool = True,
    ):
        if not client_id:
            raise ValueError("client_id is required")
        self.client_id = client_id
        self._client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = list(scopes or SCOPES)
        self.use_pkce = use_pkce
        self._http = http
        self._owns_http = http is None
        self._clock = clock or (lambda: datetime.now(UTC))
        self._signer = URLSafeTimedSerializer(state_signer_secret, salt=_STATE_SALT)
        self.jwks = jwks or JwksCache(JWKS_URL, http_jwks_fetcher(lambda: self.http))

    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=_REQUEST_TIMEOUT_S)
        return self._http

    async def aclose(self) -> None:
        if self._owns_http and self._http is not None:
            await self._http.aclose()
            self._http = None

    def begin(self, return_to: str = "/", *, link: str | None = None) -> AuthStart:
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
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.scopes),
            "state": state,
            "nonce": payload["n"],
        }
        if self.use_pkce:
            params["code_challenge"] = challenge
            params["code_challenge_method"] = "S256"
        return AuthStart(url=f"{AUTH_ENDPOINT}?{urlencode(params)}", state=state, code_verifier=verifier)

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

    def link_of(self, state: str, max_age_s: int = 600) -> str | None:
        link = self.read_state(state, max_age_s).get("l")
        return str(link) if link else None

    async def finish(self, state: str, code: str, code_verifier: str, max_age_s: int = 600) -> TokenSet:
        payload = self.read_state(state, max_age_s)
        if hashlib.sha256(code_verifier.encode("ascii")).hexdigest() != payload["v"]:
            raise OAuthStateError("sign-in state does not belong to this browser session")
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.redirect_uri}
        if self.use_pkce:
            form["code_verifier"] = code_verifier
        data = await self._post_token(form)
        id_token = data.get("id_token")
        if not id_token:
            raise IdTokenError("token response did not include an ID token")
        claims = await verify_id_token(str(id_token), self.jwks, algorithms=["RS256", "ES256"])
        if str(claims.get("aud", "")) != self.client_id:
            raise IdTokenError("ID token was issued for a different client")
        if str(claims.get("iss", "")).rstrip("/") != ISSUER:
            raise IdTokenError("ID token issuer is not Yahoo")
        check_time_claims(claims, self._clock())
        if str(claims.get("nonce", "")) != str(payload["n"]):
            raise IdTokenError("ID token nonce does not match this sign-in")
        expires_in = int(data.get("expires_in", 3600))
        return TokenSet(
            access_token=str(data["access_token"]),
            refresh_token=data.get("refresh_token"),
            expires_at=self._clock() + timedelta(seconds=expires_in),
            id_claims=self.public_claims(claims),
            scopes=list(self.scopes),
        )

    async def _post_token(self, form: dict[str, str]) -> dict[str, Any]:
        try:
            resp = await self.http.post(
                TOKEN_ENDPOINT,
                data=form,
                auth=(self.client_id, self._client_secret),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.HTTPError as exc:
            raise ConnectorError(f"Yahoo token endpoint unreachable: {exc}", retryable=True) from exc
        if resp.status_code >= 500:
            raise ConnectorError(f"Yahoo token endpoint error: HTTP {resp.status_code}", retryable=True)
        try:
            body = resp.json()
        except json.JSONDecodeError as exc:
            raise ConnectorError("Yahoo token endpoint returned a non-JSON body", retryable=True) from exc
        if not isinstance(body, dict):
            raise OAuthError("Yahoo token response has an unexpected shape")
        if resp.status_code != 200 or "error" in body:
            error = str(body.get("error", f"http_{resp.status_code}"))
            if error == "invalid_grant":
                raise AuthExpired(f"Yahoo rejected the grant: {body.get('error_description', error)}")
            raise OAuthError(f"Yahoo token error {error}: {body.get('error_description', '')}".strip())
        if "access_token" not in body:
            raise OAuthError("Yahoo token response lacks access_token")
        return body

    @staticmethod
    def public_claims(claims: dict[str, Any]) -> dict[str, Any]:
        verified = claims.get("email_verified", False)
        if isinstance(verified, str):
            verified = verified.lower() == "true"
        return {
            "sub": str(claims.get("sub", "")),
            "email": str(claims.get("email", "")).strip().lower(),
            "email_verified": verified is True,
            "name": claims.get("name") or claims.get("given_name"),
        }

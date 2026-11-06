"""Sign in with Yahoo (sign-in only): basic auth, PKCE, ID token checks."""

from __future__ import annotations

import base64
from datetime import timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from reddysec.mail.base import AuthExpired, ConnectorError
from reddysec.mail.oauth_google import IdTokenError, OAuthError, OAuthStateError
from reddysec.mail.oauth_yahoo import ISSUER, JWKS_URL, TOKEN_ENDPOINT, YahooOAuth

from .oidc_support import FIXED_NOW, Signer

CLIENT_ID = "yahoo-client"
SECRET = "yahoo-secret"
REDIRECT = "http://localhost:8000/auth/yahoo/callback"


class FakeYahoo:
    def __init__(self, signer: Signer) -> None:
        self.signer = signer
        self.requests: list[httpx.Request] = []
        self.nonce = ""
        self.claims: dict[str, Any] = {}
        self.status = 200
        self.body: Any = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        if str(request.url) == JWKS_URL:
            return httpx.Response(200, json=self.signer.jwks())
        assert str(request.url) == TOKEN_ENDPOINT
        self.requests.append(request)
        if self.body is not None:
            return httpx.Response(self.status, json=self.body)
        claims = {
            "iss": ISSUER, "aud": CLIENT_ID, "sub": "YSUB123", "email": "Avery.L@Yahoo.com", "email_verified": True,
            "name": "Avery", "nonce": self.nonce, "exp": int((FIXED_NOW + timedelta(hours=1)).timestamp()),
            **self.claims,
        }
        return httpx.Response(200, json={"access_token": "at", "refresh_token": "rt", "expires_in": 3600,
                                         "id_token": self.signer.token(claims)})


@pytest.fixture(params=["RS256", "ES256"])
def yahoo(request) -> FakeYahoo:
    return FakeYahoo(Signer("y1", alg=request.param))


def _client(fake: FakeYahoo, **kw: Any) -> YahooOAuth:
    return YahooOAuth(CLIENT_ID, SECRET, REDIRECT, state_signer_secret="s", clock=lambda: FIXED_NOW,
                      http=httpx.AsyncClient(transport=httpx.MockTransport(fake.handler)), **kw)


def _start(oauth: YahooOAuth, fake: FakeYahoo, **kw: Any):
    start = oauth.begin("/after", **kw)
    params = {k: v[0] for k, v in parse_qs(urlsplit(start.url).query).items()}
    fake.nonce = params["nonce"]
    return start, params


async def test_happy_path_with_basic_auth_and_pkce(yahoo):
    oauth = _client(yahoo)
    start, params = _start(oauth, yahoo, link="usr_9")
    assert params["scope"] == "openid email profile" and params["code_challenge_method"] == "S256"
    assert oauth.link_of(start.state) == "usr_9"
    tokens = await oauth.finish(start.state, "code", start.code_verifier)
    assert tokens.id_claims == {"sub": "YSUB123", "email": "avery.l@yahoo.com", "email_verified": True, "name": "Avery"}
    req = yahoo.requests[0]
    expected = "Basic " + base64.b64encode(f"{CLIENT_ID}:{SECRET}".encode()).decode()
    assert req.headers["authorization"] == expected
    form = parse_qs(req.content.decode())
    assert form["code_verifier"] == [start.code_verifier] and "client_secret" not in form


async def test_without_pkce(yahoo):
    oauth = _client(yahoo, use_pkce=False)
    start, params = _start(oauth, yahoo)
    assert "code_challenge" not in params
    await oauth.finish(start.state, "code", start.code_verifier)
    assert "code_verifier" not in parse_qs(yahoo.requests[0].content.decode())


async def test_unverified_email_string_claim(yahoo):
    yahoo.claims = {"email_verified": "false"}
    oauth = _client(yahoo)
    start, _ = _start(oauth, yahoo)
    assert (await oauth.finish(start.state, "c", start.code_verifier)).id_claims["email_verified"] is False


@pytest.mark.parametrize(
    ("claims", "message"),
    [({"aud": "x"}, "different client"), ({"iss": "https://evil"}, "not Yahoo"), ({"nonce": "n"}, "nonce"),
     ({"exp": int((FIXED_NOW - timedelta(hours=2)).timestamp())}, "expired")],
)
async def test_bad_id_tokens(yahoo, claims, message):
    yahoo.claims = claims
    oauth = _client(yahoo)
    start, _ = _start(oauth, yahoo)
    with pytest.raises(IdTokenError, match=message):
        await oauth.finish(start.state, "c", start.code_verifier)


async def test_state_and_token_errors(yahoo):
    oauth = _client(yahoo)
    with pytest.raises(OAuthStateError):
        oauth.read_state("x")
    with pytest.raises(OAuthStateError, match="malformed"):
        oauth.read_state(oauth._signer.dumps([1]))
    with pytest.raises(OAuthStateError, match="too long"):
        oauth.read_state(oauth.begin().state, max_age_s=-1)
    start, _ = _start(oauth, yahoo)
    with pytest.raises(OAuthStateError):
        await oauth.finish(start.state, "c", "wrong")
    yahoo.status, yahoo.body = 400, {"error": "invalid_grant"}
    with pytest.raises(AuthExpired):
        await oauth.finish(start.state, "c", start.code_verifier)
    yahoo.body = {"error": "invalid_client"}
    with pytest.raises(OAuthError):
        await oauth.finish(start.state, "c", start.code_verifier)
    yahoo.status, yahoo.body = 200, {"x": 1}
    with pytest.raises(OAuthError, match="access_token"):
        await oauth.finish(start.state, "c", start.code_verifier)
    yahoo.body = {"access_token": "a"}
    with pytest.raises(IdTokenError, match="did not include"):
        await oauth.finish(start.state, "c", start.code_verifier)
    yahoo.body = [1]
    with pytest.raises(OAuthError, match="shape"):
        await oauth.finish(start.state, "c", start.code_verifier)
    yahoo.status, yahoo.body = 502, {}
    with pytest.raises(ConnectorError):
        await oauth.finish(start.state, "c", start.code_verifier)


async def test_transport_errors():
    def boom(request):
        raise httpx.ConnectError("down", request=request)

    oauth = YahooOAuth(CLIENT_ID, SECRET, REDIRECT, state_signer_secret="s",
                       http=httpx.AsyncClient(transport=httpx.MockTransport(boom)))
    start = oauth.begin()
    with pytest.raises(ConnectorError, match="unreachable"):
        await oauth.finish(start.state, "c", start.code_verifier)
    html = YahooOAuth(CLIENT_ID, SECRET, REDIRECT, state_signer_secret="s",
                      http=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, text="<"))))
    with pytest.raises(ConnectorError, match="non-JSON"):
        await html.finish(start.state, "c", start.code_verifier)


async def test_requires_client_id_and_closes_own_client():
    with pytest.raises(ValueError):
        YahooOAuth("", SECRET, REDIRECT, state_signer_secret="s")
    oauth = YahooOAuth(CLIENT_ID, SECRET, REDIRECT, state_signer_secret="s")
    assert oauth.http is oauth.http
    await oauth.aclose()
    assert oauth._http is None

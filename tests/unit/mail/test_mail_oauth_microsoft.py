"""Sign in with Microsoft: certificate client assertion, PKCE, ID token checks."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest

from reddysec.mail.base import AuthExpired, ConnectorError
from reddysec.mail.oauth_google import IdTokenError, OAuthError, OAuthStateError
from reddysec.mail.oauth_microsoft import JWKS_URL, PERSONAL_TENANT, MicrosoftOAuth
from reddysec.mail.oidc import (
    CLIENT_ASSERTION_TYPE,
    JwksCache,
    check_time_claims,
    client_assertion,
    http_jwks_fetcher,
    load_client_certificate,
    verify_id_token,
)

from .oidc_support import FIXED_NOW, Signer, rsa_key, self_signed_bundle, thumbprint

CLIENT_ID = "8cc0907f-7f8e-45ec-9758-102eea8c1a00"
REDIRECT = "http://localhost:8000/auth/microsoft/callback"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
WORK_TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"


class FakeEntra:
    """login.microsoftonline.com: token endpoint + JWKS."""

    def __init__(self, signer: Signer) -> None:
        self.signer = signer
        self.forms: list[dict[str, str]] = []
        self.jwks_calls = 0
        self.nonce = ""
        self.claims: dict[str, Any] = {}
        self.token_status = 200
        self.token_body: dict[str, Any] | None = None
        self.raise_network = False

    def id_token(self, **overrides: Any) -> str:
        claims = {
            "aud": CLIENT_ID,
            "iss": f"https://login.microsoftonline.com/{PERSONAL_TENANT}/v2.0",
            "tid": PERSONAL_TENANT,
            "oid": "00000000-0000-0000-aaaa-000000000001",
            "sub": "pairwise-sub",
            "email": "Avery@Outlook.com",
            "name": "Avery Lawson",
            "nonce": self.nonce,
            "iat": int(FIXED_NOW.timestamp()),
            "nbf": int(FIXED_NOW.timestamp()),
            "exp": int((FIXED_NOW + timedelta(hours=1)).timestamp()),
            **self.claims,
            **overrides,
        }
        return self.signer.token({k: v for k, v in claims.items() if v is not None})

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.raise_network:
            raise httpx.ConnectError("down", request=request)
        url = str(request.url)
        if url == JWKS_URL:
            self.jwks_calls += 1
            return httpx.Response(200, json=self.signer.jwks())
        assert url == TOKEN_URL, url
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        self.forms.append(form)
        if self.token_body is not None:
            return httpx.Response(self.token_status, json=self.token_body)
        body: dict[str, Any] = {
            "access_token": f"at-{len(self.forms)}",
            "refresh_token": f"rt-{len(self.forms)}",
            "expires_in": 3600,
            "scope": "openid email profile offline_access User.Read Mail.ReadWrite MailboxSettings.ReadWrite",
        }
        if form["grant_type"] == "authorization_code":
            body["id_token"] = self.id_token()
        return httpx.Response(200, json=body)


@pytest.fixture(scope="module")
def cert_bundle():
    key = rsa_key()
    pem, cert = self_signed_bundle(key)
    return pem, cert, key


@pytest.fixture
def entra() -> FakeEntra:
    return FakeEntra(Signer("ms-key-1"))


@pytest.fixture
def ms(cert_bundle, entra) -> MicrosoftOAuth:
    pem, cert, _key = cert_bundle
    http = httpx.AsyncClient(transport=httpx.MockTransport(entra.handler))
    return MicrosoftOAuth(
        CLIENT_ID, pem, REDIRECT, thumbprint=thumbprint(cert), state_signer_secret="state-secret", http=http,
        clock=lambda: FIXED_NOW,
    )


def _start(ms: MicrosoftOAuth, entra: FakeEntra, **kw: Any):
    start = ms.begin("/mailboxes", **kw)
    params = {k: v[0] for k, v in parse_qs(urlsplit(start.url).query).items()}
    entra.nonce = params["nonce"]
    return start, params


class TestBegin:
    def test_url_has_pkce_nonce_scopes_and_state(self, ms, entra):
        start, params = _start(ms, entra)
        assert start.url.startswith("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?")
        assert params["client_id"] == CLIENT_ID and params["redirect_uri"] == REDIRECT
        assert params["code_challenge_method"] == "S256"
        expected = base64.urlsafe_b64encode(hashlib.sha256(start.code_verifier.encode()).digest()).rstrip(b"=")
        assert params["code_challenge"] == expected.decode()
        assert params["scope"].split() == [
            "openid", "email", "profile", "offline_access", "User.Read", "Mail.ReadWrite", "MailboxSettings.ReadWrite",
        ]
        assert params["prompt"] == "select_account" and params["response_mode"] == "query"
        assert ms.return_to(start.state) == "/mailboxes" and ms.link_of(start.state) is None

    def test_link_and_login_hint_travel(self, ms, entra):
        start, params = _start(ms, entra, link="usr_1", login_hint="a@outlook.com")
        assert ms.link_of(start.state) == "usr_1" and params["login_hint"] == "a@outlook.com"

    def test_open_redirect_is_neutralised(self, ms):
        assert ms.return_to(ms.begin("https://evil.example").state) == "/"

    def test_bad_state(self, ms):
        with pytest.raises(OAuthStateError):
            ms.read_state("garbage")
        good = ms.begin("/").state
        with pytest.raises(OAuthStateError, match="too long"):
            ms.read_state(good, max_age_s=-1)

    def test_malformed_state_payload(self, ms):
        state = ms._signer.dumps({"n": "x"})
        with pytest.raises(OAuthStateError, match="malformed"):
            ms.read_state(state)

    def test_requires_client_id(self, cert_bundle):
        with pytest.raises(ValueError):
            MicrosoftOAuth("", cert_bundle[0], REDIRECT, state_signer_secret="s")


class TestClientAssertion:
    async def test_token_request_carries_a_valid_signed_assertion(self, ms, entra, cert_bundle):
        _pem, cert, key = cert_bundle
        start, _ = _start(ms, entra)
        await ms.finish(start.state, "code-1", start.code_verifier)
        form = entra.forms[0]
        assert form["client_assertion_type"] == CLIENT_ASSERTION_TYPE and "client_secret" not in form
        assert form["code_verifier"] == start.code_verifier and form["grant_type"] == "authorization_code"
        assertion = form["client_assertion"]
        header = jwt.get_unverified_header(assertion)
        assert header["alg"] == "RS256" and header["typ"] == "JWT"
        x5t = base64.urlsafe_b64encode(bytes.fromhex(thumbprint(cert))).rstrip(b"=").decode()
        assert header["x5t"] == x5t
        claims = jwt.decode(assertion, key.public_key(), algorithms=["RS256"], audience=TOKEN_URL,
                            options={"verify_exp": False, "verify_nbf": False, "verify_iat": False})
        assert claims["iss"] == claims["sub"] == CLIENT_ID and claims["aud"] == TOKEN_URL
        assert claims["exp"] - claims["nbf"] <= 600 and claims["jti"]

    def test_each_assertion_has_a_fresh_jti(self, ms):
        a, b = ms.assertion(), ms.assertion()
        assert jwt.decode(a, options={"verify_signature": False})["jti"] != jwt.decode(
            b, options={"verify_signature": False})["jti"]

    def test_certificate_loading_rules(self, cert_bundle):
        pem, cert, _ = cert_bundle
        assert load_client_certificate(pem).thumbprint_hex == thumbprint(cert)  # computed from the cert
        colons = ":".join(thumbprint(cert)[i:i + 2] for i in range(0, 40, 2)).lower()
        assert load_client_certificate(pem, colons).thumbprint_hex == thumbprint(cert)
        assert load_client_certificate(pem.replace("\n", "\\n")).certificate is not None  # Key Vault one-liner
        with pytest.raises(ValueError, match="does not match"):
            load_client_certificate(pem, "00" * 20)
        with pytest.raises(ValueError, match="40 hex"):
            load_client_certificate(pem, "abc")
        with pytest.raises(ValueError, match="no private key"):
            load_client_certificate(cert.public_bytes(__import__("cryptography.hazmat.primitives.serialization",
                                                                  fromlist=["Encoding"]).Encoding.PEM).decode())
        key_only = pem.split("-----BEGIN CERTIFICATE-----")[0]
        with pytest.raises(ValueError, match="thumbprint is required"):
            load_client_certificate(key_only)
        assert load_client_certificate(key_only, thumbprint(cert)).certificate is None
        with pytest.raises(ValueError, match="cannot be read"):
            load_client_certificate("-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n")

    def test_ec_keys_are_refused(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
        with pytest.raises(ValueError, match="RSA"):
            load_client_certificate(pem, "AB" * 20)

    def test_bad_certificate_section(self, cert_bundle):
        key_only = cert_bundle[0].split("-----BEGIN CERTIFICATE-----")[0]
        broken = key_only + "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        with pytest.raises(ValueError, match="cannot be read"):
            load_client_certificate(broken)

    def test_client_assertion_helper(self, cert_bundle):
        cert = load_client_certificate(cert_bundle[0])
        token = client_assertion(cert, client_id="c", audience="https://aud", now=FIXED_NOW)
        assert jwt.decode(token, options={"verify_signature": False})["aud"] == "https://aud"


class TestFinish:
    async def test_personal_account_claims(self, ms, entra):
        start, _ = _start(ms, entra)
        tokens = await ms.finish(start.state, "code-1", start.code_verifier)
        assert tokens.access_token == "at-1" and tokens.refresh_token == "rt-1"
        assert tokens.expires_at == FIXED_NOW + timedelta(hours=1)
        c = tokens.id_claims
        assert c["oid"] == c["sub"] == "00000000-0000-0000-aaaa-000000000001"
        assert c["email"] == "avery@outlook.com" and c["personal"] is True
        assert c["email_verified"] is False  # personal accounts never count as verified
        assert tokens.to_secret()["sub"] == c["oid"]

    async def test_work_account_with_xms_edov_is_verified(self, ms, entra):
        entra.claims = {"tid": WORK_TENANT, "iss": f"https://login.microsoftonline.com/{WORK_TENANT}/v2.0",
                        "xms_edov": "1", "email": None, "preferred_username": "Avery@Contoso.com"}
        start, _ = _start(ms, entra)
        c = (await ms.finish(start.state, "c", start.code_verifier)).id_claims
        assert c["email"] == "avery@contoso.com" and c["email_verified"] is True and c["tid"] == WORK_TENANT

    async def test_work_account_without_xms_edov_is_unverified(self, ms, entra):
        entra.claims = {"tid": WORK_TENANT, "iss": f"https://login.microsoftonline.com/{WORK_TENANT}/v2.0"}
        start, _ = _start(ms, entra)
        assert (await ms.finish(start.state, "c", start.code_verifier)).id_claims["email_verified"] is False

    def test_preferred_username_without_at_is_not_an_email(self):
        claims = MicrosoftOAuth.public_claims({"oid": "o", "tid": "t", "preferred_username": "+15551234567"})
        assert claims["email"] == ""

    @pytest.mark.parametrize(
        ("override", "message"),
        [
            ({"aud": "someone-else"}, "different client"),
            ({"iss": "https://login.microsoftonline.com/other-tenant/v2.0"}, "issuer"),
            ({"tid": ""}, "issuer"),
            ({"exp": int((FIXED_NOW - timedelta(hours=1)).timestamp())}, "expired"),
            ({"nbf": int((FIXED_NOW + timedelta(hours=1)).timestamp())}, "future"),
            ({"nonce": "replayed"}, "nonce"),
        ],
    )
    async def test_rejects_bad_id_tokens(self, ms, entra, override, message):
        entra.claims = override
        start, _ = _start(ms, entra)
        with pytest.raises(IdTokenError, match=message):
            await ms.finish(start.state, "c", start.code_verifier)

    async def test_rejects_a_token_signed_by_someone_else(self, ms, entra):
        start, _ = _start(ms, entra)
        forger = Signer("ms-key-1")  # same kid, different key
        entra.token_body = {"access_token": "a", "id_token": forger.token({"aud": CLIENT_ID})}
        with pytest.raises(IdTokenError, match="signature"):
            await ms.finish(start.state, "c", start.code_verifier)

    async def test_unknown_kid_refetches_once_then_fails(self, ms, entra):
        start, _ = _start(ms, entra)
        entra.token_body = {"access_token": "a", "id_token": entra.signer.token({"aud": CLIENT_ID}, kid="rotated")}
        with pytest.raises(IdTokenError, match="does not publish"):
            await ms.finish(start.state, "c", start.code_verifier)
        assert entra.jwks_calls == 1  # min refetch interval keeps a flood of bad kids cheap

    async def test_verifier_must_match_state(self, ms, entra):
        start, _ = _start(ms, entra)
        with pytest.raises(OAuthStateError, match="browser session"):
            await ms.finish(start.state, "c", "another-verifier")

    async def test_missing_id_token(self, ms, entra):
        start, _ = _start(ms, entra)
        entra.token_body = {"access_token": "a"}
        with pytest.raises(IdTokenError, match="did not include"):
            await ms.finish(start.state, "c", start.code_verifier)

    async def test_wrong_algorithm(self, ms, entra):
        start, _ = _start(ms, entra)
        entra.token_body = {"access_token": "a", "id_token": jwt.encode({"aud": CLIENT_ID}, "k" * 32, algorithm="HS256")}
        with pytest.raises(IdTokenError, match="unexpected algorithm"):
            await ms.finish(start.state, "c", start.code_verifier)


class TestRefreshAndErrors:
    async def test_refresh_rotates_and_sends_assertion(self, ms, entra):
        tokens = await ms.refresh("rt-old")
        assert tokens.refresh_token == "rt-1" and tokens.id_claims == {}
        assert entra.forms[0]["grant_type"] == "refresh_token" and entra.forms[0]["client_assertion"]

    async def test_refresh_keeps_old_token_when_none_returned(self, ms, entra):
        entra.token_body = {"access_token": "a", "expires_in": 60}
        assert (await ms.refresh("rt-old")).refresh_token == "rt-old"

    async def test_no_refresh_token(self, ms):
        with pytest.raises(AuthExpired):
            await ms.refresh("")

    @pytest.mark.parametrize("error", ["invalid_grant", "interaction_required", "consent_required"])
    async def test_reauth_errors_are_auth_expired(self, ms, entra, error):
        entra.token_status, entra.token_body = 400, {"error": error, "error_description": "AADSTS70008: expired\r\nTrace"}
        with pytest.raises(AuthExpired, match="AADSTS70008: expired$"):
            await ms.refresh("rt")

    async def test_other_errors(self, ms, entra):
        entra.token_status, entra.token_body = 400, {"error": "invalid_client"}
        with pytest.raises(OAuthError, match="invalid_client"):
            await ms.refresh("rt")
        entra.token_status, entra.token_body = 200, {"token_type": "Bearer"}
        with pytest.raises(OAuthError, match="lacks access_token"):
            await ms.refresh("rt")
        entra.token_status, entra.token_body = 200, ["not", "a", "dict"]
        with pytest.raises(OAuthError, match="shape"):
            await ms.refresh("rt")

    @pytest.mark.parametrize("status", [429, 500, 503])
    async def test_server_errors_are_retryable(self, ms, entra, status):
        entra.token_status, entra.token_body = status, {}
        with pytest.raises(ConnectorError) as exc:
            await ms.refresh("rt")
        assert exc.value.retryable

    async def test_network_error_and_non_json(self, cert_bundle, entra):
        entra.raise_network = True
        ms = MicrosoftOAuth(CLIENT_ID, cert_bundle[0], REDIRECT, state_signer_secret="s",
                            http=httpx.AsyncClient(transport=httpx.MockTransport(entra.handler)))
        with pytest.raises(ConnectorError, match="unreachable"):
            await ms.refresh("rt")
        bad = MicrosoftOAuth(CLIENT_ID, cert_bundle[0], REDIRECT, state_signer_secret="s",
                             http=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, text="<html>"))))
        with pytest.raises(ConnectorError, match="non-JSON"):
            await bad.refresh("rt")

    async def test_revoke_is_a_documented_no_op(self, ms, entra):
        await ms.revoke("anything")
        assert entra.forms == []

    async def test_owned_http_client_is_closed(self, cert_bundle):
        ms = MicrosoftOAuth(CLIENT_ID, load_client_certificate(cert_bundle[0]), REDIRECT, state_signer_secret="s")
        assert ms.http is ms.http
        await ms.aclose()
        assert ms._http is None


class TestJwks:
    async def test_cache_ttl_and_fetch_errors(self):
        signer = Signer("k1")
        calls: list[str] = []

        async def fetch(url: str) -> dict[str, Any]:
            calls.append(url)
            return signer.jwks()

        now = [0.0]
        cache = JwksCache("https://keys", fetch, ttl_s=100, min_refetch_s=10, monotonic=lambda: now[0])
        await cache.key("k1")
        await cache.key("k1")
        assert len(calls) == 1
        now[0] = 50
        with pytest.raises(IdTokenError):
            await cache.key("unknown")  # refetched once (past min interval), still unknown
        assert len(calls) == 2
        now[0] = 200
        await cache.key("k1")
        assert len(calls) == 3 and cache.fetches == 3

    @pytest.mark.parametrize(
        "response",
        [httpx.Response(500), httpx.Response(200, text="x"), httpx.Response(200, json=[1])],
    )
    async def test_http_fetcher_errors(self, response):
        client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: response))
        with pytest.raises(ConnectorError):
            await http_jwks_fetcher(lambda: client)("https://keys")

    async def test_http_fetcher_network_error(self):
        def boom(request):
            raise httpx.ConnectError("x", request=request)

        client = httpx.AsyncClient(transport=httpx.MockTransport(boom))
        with pytest.raises(ConnectorError, match="unreachable"):
            await http_jwks_fetcher(lambda: client)("https://keys")

    async def test_verify_rejects_garbage(self):
        cache = JwksCache("u", lambda url: None)  # never called
        with pytest.raises(IdTokenError, match="malformed"):
            await verify_id_token("not-a-jwt", cache, algorithms=["RS256"])

    async def test_verify_rejects_non_object_payload(self):
        signer = Signer("k1")

        async def fetch(url):
            return signer.jwks()

        header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "kid": "k1"}).encode()).rstrip(b"=")
        body = base64.urlsafe_b64encode(b"[1,2]").rstrip(b"=")
        signing_input = header + b"." + body
        from cryptography.hazmat.primitives import hashes as h
        from cryptography.hazmat.primitives.asymmetric import padding

        sig = base64.urlsafe_b64encode(signer.key.sign(signing_input, padding.PKCS1v15(), h.SHA256())).rstrip(b"=")
        with pytest.raises(IdTokenError):
            await verify_id_token((signing_input + b"." + sig).decode(), JwksCache("u", fetch), algorithms=["RS256"])

    def test_time_claims(self):
        with pytest.raises(IdTokenError, match="expiry"):
            check_time_claims({"exp": "soon"}, FIXED_NOW)
        with pytest.raises(IdTokenError, match="malformed iat"):
            check_time_claims({"exp": int(FIXED_NOW.timestamp()) + 60, "iat": "x"}, FIXED_NOW)
        check_time_claims({"exp": int(FIXED_NOW.timestamp()) + 60}, FIXED_NOW)

"""GoogleOAuth: begin/finish/refresh/revoke against a MockTransport Google."""

from __future__ import annotations

import hashlib
import time
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from itsdangerous import URLSafeTimedSerializer

from reddysec.mail.base import AuthExpired, ConnectorError
from reddysec.mail.oauth_google import (
    SCOPES,
    GoogleOAuth,
    IdTokenError,
    OAuthError,
    OAuthStateError,
    decode_jwt_payload,
    pkce_pair,
)

from .conftest import (
    CLIENT_ID,
    CLIENT_SECRET,
    FIXED_NOW,
    REDIRECT_URI,
    STATE_SECRET,
    FakeGoogleAuthServer,
    make_id_token,
)


@pytest.fixture
async def oauth(google_auth: FakeGoogleAuthServer):
    http = httpx.AsyncClient(transport=httpx.MockTransport(google_auth.handle))
    yield GoogleOAuth(
        CLIENT_ID,
        CLIENT_SECRET,
        REDIRECT_URI,
        state_signer_secret=STATE_SECRET,
        http=http,
        clock=lambda: FIXED_NOW,
    )
    await http.aclose()


class TestBegin:
    def test_url_carries_pkce_offline_consent_and_signed_state(self, oauth: GoogleOAuth):
        start = oauth.begin("/dashboard?tab=1")
        parts = urlsplit(start.url)
        assert parts.scheme == "https" and parts.netloc == "accounts.google.com"
        q = parse_qs(parts.query)
        assert q["client_id"] == [CLIENT_ID]
        assert q["redirect_uri"] == [REDIRECT_URI]
        assert q["response_type"] == ["code"]
        assert q["access_type"] == ["offline"]
        assert q["prompt"] == ["consent"]
        assert q["include_granted_scopes"] == ["true"]
        assert q["code_challenge_method"] == ["S256"]
        assert q["scope"][0].split() == SCOPES
        assert q["state"] == [start.state]
        # S256 challenge matches the verifier we hand back to the web layer.
        _v, challenge = pkce_pair()
        assert len(challenge) == 43
        expected = hashlib.sha256(start.code_verifier.encode()).digest()
        import base64

        assert q["code_challenge"] == [base64.urlsafe_b64encode(expected).rstrip(b"=").decode()]
        payload = oauth.read_state(start.state)
        assert payload["r"] == "/dashboard?tab=1"
        assert payload["v"] == hashlib.sha256(start.code_verifier.encode()).hexdigest()
        assert oauth.return_to(start.state) == "/dashboard?tab=1"

    @pytest.mark.parametrize("bad", ["https://evil.example/", "//evil.example", "no-slash", "/ok\\evil"])
    def test_return_to_is_sanitised_against_open_redirect(self, oauth: GoogleOAuth, bad: str):
        assert oauth.return_to(oauth.begin(bad).state) == "/"

    def test_login_hint_is_optional(self, oauth: GoogleOAuth):
        q = parse_qs(urlsplit(oauth.begin(login_hint="client@gmail.com").url).query)
        assert q["login_hint"] == ["client@gmail.com"]
        assert "login_hint" not in parse_qs(urlsplit(oauth.begin().url).query)

    def test_requires_client_id(self):
        with pytest.raises(ValueError):
            GoogleOAuth("", CLIENT_SECRET, REDIRECT_URI, state_signer_secret=STATE_SECRET)


class TestFinish:
    async def test_happy_path(self, oauth: GoogleOAuth, google_auth: FakeGoogleAuthServer):
        start = oauth.begin("/after")
        tokens = await oauth.finish(start.state, "good-code", start.code_verifier)
        assert tokens.access_token == "access-1"
        assert tokens.refresh_token == "refresh-1"
        assert tokens.expires_at == FIXED_NOW + timedelta(seconds=3599)
        assert tokens.id_claims == {
            "sub": "sub-123",
            "email": "client@gmail.com",
            "email_verified": True,
            "name": "The Client",
            "picture": "https://example.com/p.png",
        }
        assert "https://www.googleapis.com/auth/gmail.modify" in tokens.scopes
        secret = tokens.to_secret()
        assert secret["refresh_token"] == "refresh-1" and secret["email"] == "client@gmail.com"
        # Exactly one token exchange with PKCE verifier + one tokeninfo check.
        token_calls = [c for c in google_auth.calls if c.path == "/token"]
        assert len(token_calls) == 1
        assert token_calls[0].json["code_verifier"] == [start.code_verifier]
        assert token_calls[0].json["grant_type"] == ["authorization_code"]
        assert [c.path for c in google_auth.calls if c.path == "/tokeninfo"] == ["/tokeninfo"]

    async def test_tampered_state_rejected(self, oauth: GoogleOAuth):
        start = oauth.begin()
        forged = URLSafeTimedSerializer("other-secret", salt="reddysec.google.oauth.state").dumps(
            {"n": "x", "r": "/", "v": "y"}
        )
        with pytest.raises(OAuthStateError, match="invalid"):
            await oauth.finish(forged, "good-code", start.code_verifier)
        with pytest.raises(OAuthStateError):
            await oauth.finish(start.state[:-3] + "abc", "good-code", start.code_verifier)

    async def test_malformed_state_payload_rejected(self, oauth: GoogleOAuth):
        bad = URLSafeTimedSerializer(STATE_SECRET, salt="reddysec.google.oauth.state").dumps({"n": "x"})
        with pytest.raises(OAuthStateError, match="malformed"):
            oauth.read_state(bad)

    async def test_expired_state_rejected(self, oauth: GoogleOAuth, monkeypatch: pytest.MonkeyPatch):
        start = oauth.begin()
        real_time = time.time
        monkeypatch.setattr(time, "time", lambda: real_time() + 601)
        with pytest.raises(OAuthStateError, match="too long"):
            await oauth.finish(start.state, "good-code", start.code_verifier, max_age_s=600)

    async def test_verifier_mismatch_rejected(self, oauth: GoogleOAuth, google_auth: FakeGoogleAuthServer):
        start = oauth.begin()
        other = oauth.begin()
        with pytest.raises(OAuthStateError, match="browser session"):
            await oauth.finish(start.state, "good-code", other.code_verifier)
        assert not google_auth.calls  # rejected before any network call

    async def test_bad_audience_rejected(self, oauth: GoogleOAuth, google_auth: FakeGoogleAuthServer):
        google_auth.tokeninfo_override = {**google_auth.id_claims, "aud": "someone-else"}
        start = oauth.begin()
        with pytest.raises(IdTokenError, match="different client"):
            await oauth.finish(start.state, "good-code", start.code_verifier)

    async def test_expired_id_token_rejected(self, oauth: GoogleOAuth, google_auth: FakeGoogleAuthServer):
        google_auth.tokeninfo_override = {**google_auth.id_claims, "exp": str(int(FIXED_NOW.timestamp()) - 1)}
        start = oauth.begin()
        with pytest.raises(IdTokenError, match="expired"):
            await oauth.finish(start.state, "good-code", start.code_verifier)

    async def test_bad_issuer_and_subject_mismatch_rejected(
        self, oauth: GoogleOAuth, google_auth: FakeGoogleAuthServer
    ):
        google_auth.tokeninfo_override = {**google_auth.id_claims, "iss": "https://evil.example"}
        start = oauth.begin()
        with pytest.raises(IdTokenError, match="issuer"):
            await oauth.finish(start.state, "good-code", start.code_verifier)
        google_auth.tokeninfo_override = {**google_auth.id_claims, "sub": "sub-999"}
        start = oauth.begin()
        with pytest.raises(IdTokenError, match="subject"):
            await oauth.finish(start.state, "good-code", start.code_verifier)

    async def test_unusable_exp_rejected(self, oauth: GoogleOAuth, google_auth: FakeGoogleAuthServer):
        google_auth.tokeninfo_override = {**google_auth.id_claims, "exp": "not-a-number"}
        start = oauth.begin()
        with pytest.raises(IdTokenError, match="expiry"):
            await oauth.finish(start.state, "good-code", start.code_verifier)

    async def test_tokeninfo_rejection_and_outage(
        self, oauth: GoogleOAuth, google_auth: FakeGoogleAuthServer
    ):
        google_auth.tokeninfo_status = 400
        start = oauth.begin()
        with pytest.raises(IdTokenError, match="rejected"):
            await oauth.finish(start.state, "good-code", start.code_verifier)
        google_auth.tokeninfo_status = 503
        start = oauth.begin()
        with pytest.raises(ConnectorError) as info:
            await oauth.finish(start.state, "good-code", start.code_verifier)
        assert info.value.retryable

    async def test_invalid_grant_raises_auth_expired(self, oauth: GoogleOAuth):
        start = oauth.begin()
        with pytest.raises(AuthExpired):
            await oauth.finish(start.state, "used-code", start.code_verifier)

    async def test_other_oauth_errors_are_permanent(
        self, oauth: GoogleOAuth, google_auth: FakeGoogleAuthServer
    ):
        oauth_wrong = GoogleOAuth(
            CLIENT_ID,
            "wrong",
            REDIRECT_URI,
            state_signer_secret=STATE_SECRET,
            http=oauth.http,
            clock=lambda: FIXED_NOW,
        )
        start = oauth_wrong.begin()
        with pytest.raises(OAuthError, match="invalid_client") as info:
            await oauth_wrong.finish(start.state, "good-code", start.code_verifier)
        assert not info.value.retryable

    async def test_missing_id_token_rejected(self, oauth: GoogleOAuth, google_auth: FakeGoogleAuthServer):
        google_auth.token_extra = {"id_token": ""}
        start = oauth.begin()
        with pytest.raises(IdTokenError, match="ID token"):
            await oauth.finish(start.state, "good-code", start.code_verifier)

    async def test_network_error_is_retryable(self, oauth: GoogleOAuth, google_auth: FakeGoogleAuthServer):
        google_auth.fail_next.append(httpx.ConnectError("dns failure"))
        start = oauth.begin()
        with pytest.raises(ConnectorError) as info:
            await oauth.finish(start.state, "good-code", start.code_verifier)
        assert info.value.retryable

    async def test_5xx_and_garbage_are_retryable(self, oauth: GoogleOAuth, google_auth: FakeGoogleAuthServer):
        google_auth.token_status = 502
        start = oauth.begin()
        with pytest.raises(ConnectorError) as info:
            await oauth.finish(start.state, "good-code", start.code_verifier)
        assert info.value.retryable
        google_auth.token_status = 200
        google_auth.fail_next.append(httpx.Response(200, text="<html>not json</html>"))
        start = oauth.begin()
        with pytest.raises(ConnectorError, match="non-JSON") as info:
            await oauth.finish(start.state, "good-code", start.code_verifier)
        assert info.value.retryable

    async def test_token_body_without_access_token(
        self, oauth: GoogleOAuth, google_auth: FakeGoogleAuthServer
    ):
        google_auth.fail_next.append(httpx.Response(200, json={"token_type": "Bearer"}))
        start = oauth.begin()
        with pytest.raises(OAuthError, match="access_token"):
            await oauth.finish(start.state, "good-code", start.code_verifier)

    async def test_custom_verifier_is_used(self, google_auth: FakeGoogleAuthServer):
        seen: list[str] = []

        async def verifier(token: str) -> dict:
            seen.append(token)
            return google_auth.id_claims

        http = httpx.AsyncClient(transport=httpx.MockTransport(google_auth.handle))
        oauth = GoogleOAuth(
            CLIENT_ID,
            CLIENT_SECRET,
            REDIRECT_URI,
            state_signer_secret=STATE_SECRET,
            http=http,
            id_token_verifier=verifier,
            clock=lambda: FIXED_NOW,
        )
        start = oauth.begin()
        tokens = await oauth.finish(start.state, "good-code", start.code_verifier)
        assert tokens.id_claims["sub"] == "sub-123" and seen
        assert all(c.path != "/tokeninfo" for c in google_auth.calls)
        await http.aclose()


class TestRefreshAndRevoke:
    async def test_refresh_keeps_refresh_token_and_decodes_claims(
        self, oauth: GoogleOAuth, google_auth: FakeGoogleAuthServer
    ):
        google_auth.token_extra = {
            "id_token": make_id_token({"sub": "sub-123", "email": "client@gmail.com", "email_verified": True})
        }
        tokens = await oauth.refresh("refresh-1")
        assert tokens.access_token == "access-1"
        assert tokens.refresh_token == "refresh-1"
        assert tokens.id_claims["email"] == "client@gmail.com" and tokens.id_claims["email_verified"] is True
        form = [c for c in google_auth.calls if c.path == "/token"][0].json
        assert form["grant_type"] == ["refresh_token"] and form["refresh_token"] == ["refresh-1"]

    async def test_refresh_with_unparseable_id_token_still_succeeds(
        self, oauth: GoogleOAuth, google_auth: FakeGoogleAuthServer
    ):
        google_auth.token_extra = {"id_token": "garbage"}
        tokens = await oauth.refresh("refresh-1")
        assert tokens.id_claims == {}

    async def test_refresh_invalid_grant_is_auth_expired(
        self, oauth: GoogleOAuth, google_auth: FakeGoogleAuthServer
    ):
        google_auth.refresh_error = "invalid_grant"
        with pytest.raises(AuthExpired, match="revoked"):
            await oauth.refresh("refresh-1")

    async def test_refresh_without_token(self, oauth: GoogleOAuth):
        with pytest.raises(AuthExpired):
            await oauth.refresh("")

    async def test_revoke(self, oauth: GoogleOAuth, google_auth: FakeGoogleAuthServer):
        await oauth.revoke("access-1")
        google_auth.revoke_status = 400  # already invalid: still fine
        await oauth.revoke("access-1")
        google_auth.revoke_status = 500
        with pytest.raises(ConnectorError) as info:
            await oauth.revoke("access-1")
        assert info.value.retryable
        google_auth.revoke_status = 200
        google_auth.fail_next.append(httpx.ConnectError("boom"))
        with pytest.raises(ConnectorError) as info:
            await oauth.revoke("access-1")
        assert info.value.retryable

    async def test_owns_http_client_when_none_given(self):
        oauth = GoogleOAuth(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, state_signer_secret=STATE_SECRET)
        assert isinstance(oauth.http, httpx.AsyncClient)
        await oauth.aclose()
        await oauth.aclose()  # idempotent


def test_decode_jwt_payload_rejects_garbage():
    with pytest.raises(IdTokenError):
        decode_jwt_payload("nope")
    assert decode_jwt_payload(make_id_token({"a": 1}))["a"] == 1


class TestTokeninfoTransport:
    async def test_tokeninfo_network_error_is_retryable(
        self, oauth: GoogleOAuth, google_auth: FakeGoogleAuthServer
    ):
        google_auth.tokeninfo_raise = httpx.ConnectError("dns")
        start = oauth.begin()
        with pytest.raises(ConnectorError, match="unreachable") as info:
            await oauth.finish(start.state, "good-code", start.code_verifier)
        assert info.value.retryable

    async def test_tokeninfo_non_json_is_rejected(
        self, oauth: GoogleOAuth, google_auth: FakeGoogleAuthServer
    ):
        google_auth.tokeninfo_text = "<html>maintenance</html>"
        start = oauth.begin()
        with pytest.raises(IdTokenError, match="non-JSON"):
            await oauth.finish(start.state, "good-code", start.code_verifier)

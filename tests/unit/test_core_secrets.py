"""Secret redaction (logs, repr) and keyless Claude credentials (WIF)."""

from __future__ import annotations

import json
import logging

import httpx
import pytest
from pydantic import SecretStr

from reddysec.config import Settings
from reddysec.core import anthropic_auth as aa
from reddysec.core.logging import RedactingFilter, configure_logging
from reddysec.core.redact import (
    MASK,
    is_secret_key,
    redact_mapping,
    redact_text,
    redact_value,
    structlog_processor,
)

# Built at run time so secret scanners do not flag this file.
KEY = "sk-ant-" + "api03-" + "A" * 30
GOOGLE = "GOCSPX-" + "b" * 20
GH = "ghp_" + "c" * 36
PAT = "github_pat_" + "d" * 40
JWT = "eyJ" + "a" * 20 + "." + "b" * 20 + "." + "c" * 20


class TestRedact:
    @pytest.mark.parametrize("secret", [KEY, GOOGLE, GH, PAT, JWT])
    def test_patterns(self, secret):
        assert secret not in redact_text(f"value={secret} tail")
        assert MASK in redact_text(secret)

    def test_bearer_and_url_credentials(self):
        assert redact_text("Authorization: Bearer abcdefghijklmnop") == f"Authorization: Bearer {MASK}"
        assert redact_text("postgresql://user:hunter2@db/x") == f"postgresql://user:{MASK}@db/x"
        assert redact_text("plain words stay") == "plain words stay"

    def test_keys(self):
        for key in ("access_token", "Refresh-Token", "refreshToken", "app_password", "client_secret", "X-Api-Key",
                    "authorization", "pin", "my_secret", "rs_token"):
            assert is_secret_key(key), key
        for key in ("token_type", "max_tokens", "email", "subject", "level"):
            assert not is_secret_key(key), key

    def test_nested_structures(self):
        data = {"user": "a", "access_token": "x", "refresh_token": "", "nested": {"password": "p", "list": [KEY, ("t", GH)]}}
        out = redact_mapping(data)
        assert out["access_token"] == MASK and out["refresh_token"] == "" and out["user"] == "a"
        assert out["nested"]["password"] == MASK and out["nested"]["list"][0] == MASK
        assert out["nested"]["list"][1] == ("t", MASK)
        deep: dict = {}
        cur = deep
        for _ in range(12):
            cur["n"] = {}
            cur = cur["n"]
        assert redact_value(deep)  # deep nesting stops instead of recursing forever
        assert redact_value(42) == 42

    def test_structlog_processor(self):
        event = {"event": f"called with {KEY}", "access_token": "abc", "level": "info", "app_password": None,
                 "details": {"refresh_token": "r"}}
        out = structlog_processor(None, "info", event)
        assert KEY not in out["event"] and out["access_token"] == MASK and out["app_password"] is None
        assert out["details"]["refresh_token"] == MASK and out["level"] == "info"

    def test_stdlib_filter(self):
        record = logging.LogRecord("x", logging.INFO, __file__, 1, "token %s and %s", (KEY, {"password": "p"}), None)
        assert RedactingFilter().filter(record)
        assert KEY not in record.getMessage() and "'password': '[redacted]'" in record.getMessage()
        rec2 = logging.LogRecord("x", logging.INFO, __file__, 1, "x %(a)s", ({"a": GH},), None)
        RedactingFilter().filter(rec2)
        assert GH not in rec2.getMessage()

    def test_configure_logging_installs_filter_once(self, capsys):
        configure_logging("INFO", json=True)
        configure_logging("INFO", json=True)
        root = logging.getLogger()
        assert all(sum(isinstance(f, RedactingFilter) for f in h.filters) == 1 for h in root.handlers)
        from reddysec.core.logging import get_logger

        get_logger("t").info("leak_test", access_token="zzz", note=f"key {KEY}")
        out = capsys.readouterr().out
        assert "zzz" not in out and KEY not in out
        configure_logging("INFO", json=False)

    def test_settings_repr_hides_secrets(self):
        s = Settings(database_url="postgresql+asyncpg://u:hunter2@h/db", anthropic_api_key=SecretStr(KEY),
                     secret_key=SecretStr("s3cr3t-value"), google_client_secret=SecretStr(GOOGLE))
        text = repr(s) + str(s)
        assert "hunter2" not in text and KEY not in text and "s3cr3t-value" not in text and GOOGLE not in text
        assert "u:" in text  # the user name is not a secret


# --------------------------------------------------------------------------- keyless Claude


class Clock:
    def __init__(self, t: float = 1_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def anthropic_server(log: list[httpx.Request], *, status: int = 200, body: dict | None = None, expires_in: int = 600):
    counter = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        log.append(request)
        if request.url.path == "/v1/oauth/token":
            counter["n"] += 1
            if status != 200:
                return httpx.Response(status, json=body or {"error": "invalid_grant", "error_description": "assertion echo"})
            return httpx.Response(200, json=body or {"access_token": f"sk-ant-oat01-{counter['n']}", "token_type": "Bearer",
                                                     "expires_in": expires_in, "scope": "workspace:inference"})
        return httpx.Response(404)

    return httpx.MockTransport(handler)


async def identity() -> str:
    return "entra.jwt.token"


def creds(log, clock=None, **kw) -> aa.AnthropicCredentials:
    transport = kw.pop("transport", None) or anthropic_server(log, **{k: kw.pop(k) for k in list(kw) if k in ("status", "body", "expires_in")})
    return aa.AnthropicCredentials(
        federation_rule_id="fdrl_1", organization_id="org-uuid", service_account_id="svac_1",
        identity_token=kw.pop("identity_token", identity), http=httpx.AsyncClient(transport=transport),
        clock=clock or Clock(), **kw,
    )


class TestKeyless:
    async def test_exchange_request_and_headers(self):
        log: list[httpx.Request] = []
        c = creds(log, workspace_id="wrkspc_1")
        assert c.keyless and c.mode == "workload_identity" and "sk-ant" not in repr(c)
        headers = await c.headers()
        assert headers == {"Authorization": "Bearer sk-ant-oat01-1", "anthropic-beta": aa.OAUTH_API_BETA}
        (req,) = log
        assert req.url == "https://api.anthropic.com/v1/oauth/token"
        assert req.headers["anthropic-beta"] == "oauth-2025-04-20,oidc-federation-2026-04-01"
        assert json.loads(req.content) == {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": "entra.jwt.token",
            "federation_rule_id": "fdrl_1", "organization_id": "org-uuid", "service_account_id": "svac_1",
            "workspace_id": "wrkspc_1",
        }

    async def test_cached_until_120s_before_expiry_then_refreshed(self):
        log: list[httpx.Request] = []
        clock = Clock()
        c = creds(log, clock)
        await c.headers()
        clock.t += 600 - 121
        assert (await c.headers())["Authorization"].endswith("-1") and c.exchanges == 1
        clock.t += 2
        assert (await c.headers())["Authorization"].endswith("-2") and c.exchanges == 2
        c.invalidate()
        assert (await c.headers())["Authorization"].endswith("-3")

    async def test_failures_never_echo_the_body(self):
        log: list[httpx.Request] = []
        c = creds(log, status=401)
        with pytest.raises(aa.AnthropicAuthError) as err:
            await c.headers()
        assert "invalid_grant" in str(err.value) and "assertion echo" not in str(err.value)
        assert err.value.status == 401 and "federation rule" in str(err.value)

    @pytest.mark.parametrize("body", [
        {"token_type": "Bearer", "expires_in": 60},
        {"access_token": "x", "expires_in": "soon"},
        {"access_token": "x", "expires_in": 60, "token_type": "mac"},
    ])
    async def test_bad_answers(self, body):
        with pytest.raises(aa.AnthropicAuthError):
            await creds([], body=body).headers()

    async def test_non_json_and_network_and_huge_assertion(self):
        transport = httpx.MockTransport(lambda r: httpx.Response(200, text="<html>"))
        with pytest.raises(aa.AnthropicAuthError, match="unexpected"):
            await creds([], transport=transport).headers()

        def boom(request):
            raise httpx.ConnectError("down")

        with pytest.raises(aa.AnthropicAuthError, match="unreachable"):
            await creds([], transport=httpx.MockTransport(boom)).headers()

        async def huge() -> str:
            return "x" * 20000

        with pytest.raises(aa.AnthropicAuthError, match="too large"):
            await creds([], identity_token=huge).headers()

    async def test_owned_http_client_is_used_and_closed(self, monkeypatch):
        transport = anthropic_server([])
        real = httpx.AsyncClient
        monkeypatch.setattr(aa.httpx, "AsyncClient", lambda *a, **k: real(transport=transport))
        c = aa.AnthropicCredentials(federation_rule_id="f", organization_id="o", service_account_id="s",
                                    identity_token=identity)
        assert (await c.headers())["Authorization"].startswith("Bearer ")

    def test_constructor_rules(self):
        with pytest.raises(ValueError):
            aa.AnthropicCredentials(federation_rule_id="f", organization_id="o", service_account_id="s")
        with pytest.raises(ValueError):
            aa.AnthropicCredentials()

    async def test_api_key_mode(self):
        c = aa.AnthropicCredentials(api_key=KEY)
        assert c.mode == "api_key" and await c.headers() == {"x-api-key": KEY} and KEY not in repr(c)


class TestManagedIdentity:
    async def test_container_apps_endpoint(self):
        seen: list[httpx.Request] = []

        def handler(request):
            seen.append(request)
            return httpx.Response(200, json={"access_token": "entra-token", "expires_on": "1"})

        env = {"IDENTITY_ENDPOINT": "http://localhost:42356/msi/token", "IDENTITY_HEADER": "hdr"}
        source = aa.ManagedIdentityToken("api://app", client_id="cid", environ=env,
                                         http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        assert await source() == "entra-token"
        (req,) = seen
        assert req.headers["X-IDENTITY-HEADER"] == "hdr"
        assert dict(req.url.params) == {"api-version": "2019-08-01", "resource": "api://app", "client_id": "cid"}

    async def test_imds_fallback_and_errors(self):
        seen: list[httpx.Request] = []

        def handler(request):
            seen.append(request)
            return httpx.Response(400, json={"error": "invalid_resource", "error_description": "secret stuff"})

        source = aa.ManagedIdentityToken("api://app", environ={}, http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        with pytest.raises(aa.AnthropicAuthError) as err:
            await source()
        assert seen[0].url.host == "169.254.169.254" and seen[0].headers["Metadata"] == "true"
        assert "invalid_resource" in str(err.value) and "secret stuff" not in str(err.value)
        for body in ({}, ["x"]):
            empty = aa.ManagedIdentityToken("api://a", environ={}, http=httpx.AsyncClient(
                transport=httpx.MockTransport(lambda r, b=body: httpx.Response(200, json=b))))
            with pytest.raises(aa.AnthropicAuthError, match="no access token"):
                await empty()

        def down(request):
            raise httpx.ConnectTimeout("t")

        with pytest.raises(aa.AnthropicAuthError, match="unreachable"):
            await aa.ManagedIdentityToken("api://a", environ={}, http=httpx.AsyncClient(transport=httpx.MockTransport(down)))()
        with pytest.raises(ValueError):
            aa.ManagedIdentityToken("")

    async def test_owned_client(self, monkeypatch):
        real = httpx.AsyncClient
        transport = httpx.MockTransport(lambda r: httpx.Response(200, json={"access_token": "t"}))
        monkeypatch.setattr(aa.httpx, "AsyncClient", lambda *a, **k: real(transport=transport))
        assert await aa.ManagedIdentityToken("api://a", environ={})() == "t"


class TestFromSettings:
    def setup_method(self):
        aa.reset_default_credentials()

    def teardown_method(self):
        aa.reset_default_credentials()

    def test_precedence(self):
        wif = Settings(anthropic_federation_rule_id="fdrl", anthropic_organization_id="org",
                       anthropic_service_account_id="svac", anthropic_wif_audience="api://x",
                       anthropic_api_key=SecretStr(KEY), azure_identity_client_id="cid")
        assert wif.anthropic_wif_enabled and wif.anthropic_configured
        c = aa.credentials_from_settings(wif)
        assert c is not None and c.keyless
        assert aa.credentials_from_settings(wif.model_copy(update={"anthropic_wif_audience": ""})) is None
        key = Settings(anthropic_api_key=SecretStr(KEY))
        assert aa.credentials_from_settings(key).mode == "api_key"
        assert aa.credentials_from_settings(Settings()) is None and not Settings().anthropic_configured

    async def test_shared_headers(self, monkeypatch):
        with pytest.raises(aa.AnthropicAuthError):
            await aa.get_anthropic_auth_headers(Settings())
        s = Settings(anthropic_api_key=SecretStr(KEY))
        assert await aa.get_anthropic_auth_headers(s) == {"x-api-key": KEY}
        first = aa._default
        assert await aa.get_anthropic_auth_headers(s) == {"x-api-key": KEY} and aa._default is first
        from reddysec import config

        monkeypatch.setattr(config, "get_settings", lambda: s)
        assert await aa.get_anthropic_auth_headers() == {"x-api-key": KEY}

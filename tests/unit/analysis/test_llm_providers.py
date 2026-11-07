"""Claude (Anthropic) and Azure AI Foundry assessors, and the settings factory."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest

from reddysec.analysis.bec import (
    AnthropicAssessor,
    AzureFoundryAssessor,
    AzureOpenAiAssessor,
    LlmAssessment,
    NoopLlm,
    llm_from_settings,
)
from reddysec.config import Settings
from reddysec.models import ParsedMessage

GOOD = {
    "is_bec_likely": True,
    "confidence": 0.9,
    "intent": "wire fraud via changed bank details",
    "plain_summary": "The email asks to send money to a new account. Call the sender first.",
}


def message() -> ParsedMessage:
    return ParsedMessage(
        provider_message_id="m1",
        mailbox_id="mbx",
        received_at=datetime.now(UTC),
        from_address="attorney@example.com",
        subject="Updated wiring instructions",
        text_body="Please use the new account for closing funds.",
    )


def client_with(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class TestAnthropic:
    async def test_happy_path_and_request_shape(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["headers"] = dict(request.headers)
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"content": [{"type": "text", "text": json.dumps(GOOD)}]})

        assessor = AnthropicAssessor(client_with(handler), "sk-test", "claude-haiku-5-5")
        result = await assessor.assess(message(), "reply-to mismatch")
        assert isinstance(result, LlmAssessment) and result.is_bec_likely and result.confidence == 0.9
        assert seen["url"] == "https://api.anthropic.com/v1/messages"
        assert seen["headers"]["x-api-key"] == "sk-test" and seen["headers"]["anthropic-version"] == "2023-06-01"
        body = seen["body"]
        assert body["model"] == "claude-haiku-5-5" and body["max_tokens"] == 300 and body["temperature"] == 0
        assert "fraud analyst" in body["system"]
        assert body["messages"][0]["role"] == "user"
        assert "Updated wiring instructions" in body["messages"][0]["content"]
        assert "reply-to mismatch" in body["messages"][0]["content"]

    async def test_code_fence_is_tolerated(self):
        fenced = "```json\n" + json.dumps(GOOD) + "\n```"

        def handler(request):
            return httpx.Response(200, json={"content": [{"type": "text", "text": fenced}]})

        result = await AnthropicAssessor(client_with(handler), "k", "m").assess(message(), "")
        assert result is not None and result.intent.startswith("wire fraud")

    @pytest.mark.parametrize(
        "response",
        [
            httpx.Response(429, json={"error": "rate"}),
            httpx.Response(200, json={"content": [{"type": "text", "text": "not json"}]}),
            httpx.Response(200, json={"content": [{"type": "text", "text": json.dumps({"is_bec_likely": "maybe"})}]}),
            httpx.Response(200, json={"unexpected": 1}),
            httpx.Response(200, content=b"\xff"),
        ],
    )
    async def test_bad_responses_return_none(self, response):
        def handler(request):
            return response

        assert await AnthropicAssessor(client_with(handler), "k", "m").assess(message(), "") is None

    async def test_network_error_and_unconfigured(self):
        def handler(request):
            raise httpx.ConnectError("down")

        assert await AnthropicAssessor(client_with(handler), "k", "m").assess(message(), "") is None
        assert await AnthropicAssessor(client_with(handler), "", "m").assess(message(), "") is None

    async def test_unexpected_exception_is_contained(self):
        class Boom(httpx.AsyncClient):
            async def post(self, *a, **k):
                raise RuntimeError("weird")

        assert await AnthropicAssessor(Boom(), "k", "m").assess(message(), "") is None


class TestFoundry:
    async def test_url_and_model_in_body(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["body"] = json.loads(request.content)
            seen["key"] = request.headers.get("api-key")
            return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(GOOD)}}]})

        assessor = AzureFoundryAssessor(
            client_with(handler), "https://res.services.ai.azure.com", "fk", "Phi-4"
        )
        result = await assessor.assess(message(), "")
        assert result is not None and result.is_bec_likely
        assert seen["url"] == "https://res.services.ai.azure.com/models/chat/completions?api-version=2024-05-01-preview"
        assert seen["body"]["model"] == "Phi-4" and seen["body"]["response_format"] == {"type": "json_object"}
        assert seen["key"] == "fk"

    def test_azure_openai_has_no_extra_payload(self):
        plain = AzureOpenAiAssessor(httpx.AsyncClient(), "https://x", "k", "dep")
        assert plain.extra_payload() == {}
        assert "/openai/deployments/dep/chat/completions" in plain.url


class TestFactory:
    def test_none_and_unknown(self):
        assert isinstance(llm_from_settings(Settings(llm_provider="none")), NoopLlm)

        class Odd:
            llm_provider = "something-else"

        assert isinstance(llm_from_settings(Odd()), NoopLlm)

    def test_each_provider(self):
        http = httpx.AsyncClient()
        a = llm_from_settings(Settings(llm_provider="anthropic", anthropic_api_key="k", anthropic_model="m"), http)
        assert isinstance(a, AnthropicAssessor) and a.url.endswith("/v1/messages")
        f = llm_from_settings(
            Settings(
                llm_provider="azure_foundry",
                azure_foundry_endpoint="https://r.services.ai.azure.com",
                azure_foundry_api_key="k",
                azure_foundry_model="Phi-4",
            ),
            http,
        )
        assert isinstance(f, AzureFoundryAssessor)
        o = llm_from_settings(
            Settings(
                llm_provider="azure_openai",
                azure_openai_endpoint="https://o.openai.azure.com",
                azure_openai_api_key="k",
                azure_openai_deployment="gpt",
            ),
            http,
        )
        assert isinstance(o, AzureOpenAiAssessor) and not isinstance(o, AzureFoundryAssessor)
        default_client = llm_from_settings(Settings(llm_provider="anthropic", anthropic_api_key="k"))
        assert isinstance(default_client, AnthropicAssessor)


class TestAnthropicKeyless:
    """The background reviewer authenticates through core.anthropic_auth:
    keyless (Workload Identity Federation) when configured, else the key."""

    async def test_auth_headers_provider_is_used_per_request(self):
        seen = []

        async def auth():
            return {"Authorization": "Bearer oat-1", "anthropic-beta": "oauth-2025-04-20"}

        def handler(request):
            seen.append(dict(request.headers))
            return httpx.Response(200, json={"content": [{"type": "text", "text": json.dumps(GOOD)}]})

        assessor = AnthropicAssessor(client_with(handler), model="claude-haiku-5-5", auth_headers=auth)
        assert assessor.configured
        assert (await assessor.assess(message(), "")) is not None
        assert seen[0]["authorization"] == "Bearer oat-1" and "x-api-key" not in seen[0]
        assert seen[0]["anthropic-beta"] == "oauth-2025-04-20" and seen[0]["anthropic-version"] == "2023-06-01"

    async def test_401_with_keyless_invalidates_and_retries_once(self):
        tokens = iter(["old", "new", "newer"])
        dropped = []
        statuses = iter([401, 200])

        async def auth():
            return {"Authorization": f"Bearer {next(tokens)}"}

        def handler(request):
            status = next(statuses)
            if status == 401:
                return httpx.Response(401, json={"error": {"type": "authentication_error"}})
            assert request.headers["authorization"] == "Bearer new"
            return httpx.Response(200, json={"content": [{"type": "text", "text": json.dumps(GOOD)}]})

        assessor = AnthropicAssessor(
            client_with(handler), model="m", auth_headers=auth, on_unauthorized=lambda: dropped.append(1)
        )
        assert await assessor.assess(message(), "") is not None
        assert dropped == [1]

    async def test_401_twice_gives_none(self):
        async def auth():
            return {"Authorization": "Bearer t"}

        def handler(request):
            return httpx.Response(401)

        assessor = AnthropicAssessor(client_with(handler), model="m", auth_headers=auth, on_unauthorized=lambda: None)
        assert await assessor.assess(message(), "") is None

    async def test_401_with_api_key_is_not_retried(self):
        calls = []

        def handler(request):
            calls.append(1)
            return httpx.Response(401)

        assessor = AnthropicAssessor(client_with(handler), "k", "m", on_unauthorized=lambda: None)
        assert await assessor.assess(message(), "") is None and calls == [1]

    async def test_auth_failure_is_contained(self):
        from reddysec.core.anthropic_auth import AnthropicAuthError

        async def auth():
            raise AnthropicAuthError("exchange failed", status=403)

        def handler(request):  # pragma: no cover - never reached
            raise AssertionError("no request without credentials")

        assert await AnthropicAssessor(client_with(handler), model="m", auth_headers=auth).assess(message(), "") is None

    async def test_factory_goes_through_get_anthropic_auth_headers(self, monkeypatch):
        from reddysec.analysis import bec

        seen = []

        async def fake(settings):
            seen.append(settings)
            return {"Authorization": "Bearer wif"}

        monkeypatch.setattr(bec, "get_anthropic_auth_headers", fake)

        def handler(request):
            assert request.headers["authorization"] == "Bearer wif"
            return httpx.Response(200, json={"content": [{"type": "text", "text": json.dumps(GOOD)}]})

        settings = Settings(
            llm_provider="anthropic",
            anthropic_federation_rule_id="fdrl_1",
            anthropic_organization_id="org",
            anthropic_service_account_id="svac_1",
            anthropic_wif_audience="api://x",
        )
        assessor = llm_from_settings(settings, client_with(handler))
        assert isinstance(assessor, AnthropicAssessor)
        assert await assessor.assess(message(), "") is not None and seen == [settings]

    def test_factory_without_any_claude_credentials_is_a_noop(self):
        assert isinstance(llm_from_settings(Settings(llm_provider="anthropic")), NoopLlm)

    def test_default_models(self):
        s = Settings()
        assert s.anthropic_model == "claude-haiku-5-5"
        assert Settings(assistant_provider="anthropic", anthropic_api_key="k").effective_assistant_model == "claude-sonnet-5-5"

    async def test_invalidate_default_credentials(self):
        from reddysec.core import anthropic_auth

        anthropic_auth.reset_default_credentials()
        anthropic_auth.invalidate_default_credentials()  # nothing cached: no error
        headers = await anthropic_auth.get_anthropic_auth_headers(Settings(anthropic_api_key="sk-x"))
        assert headers == {"x-api-key": "sk-x"}
        anthropic_auth.invalidate_default_credentials()
        anthropic_auth.reset_default_credentials()

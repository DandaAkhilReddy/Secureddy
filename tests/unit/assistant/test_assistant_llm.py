"""Chat clients with tool use, against httpx.MockTransport."""

from __future__ import annotations

import json

import httpx
import pytest
from pydantic import SecretStr

from reddysec.assistant.llm import (
    AnthropicChat,
    AzureFoundryChat,
    AzureOpenAiChat,
    ChatError,
    ToolSpec,
    _arguments,
    chat_model_from_settings,
)
from reddysec.config import Settings

TOOLS = [ToolSpec("get_stats", "Counts.", {"type": "object", "properties": {"days": {"type": "integer"}}})]
HISTORY = [
    {"role": "user", "text": "What's suspicious?"},
    {"role": "assistant", "text": "Let me look.", "tool_calls": [{"id": "t1", "name": "get_stats", "arguments": {"days": 7}}]},
    {"role": "tool", "results": [{"id": "t1", "name": "get_stats", "content": '{"suspicious": 2}'}]},
]


def client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class TestAnthropic:
    async def test_tool_use_round_trip(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["headers"] = request.headers
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"content": [
                {"type": "text", "text": "Checking. "},
                {"type": "tool_use", "id": "tu_2", "name": "list_messages", "input": {"level": "suspicious"}},
            ]})

        chat = AnthropicChat(client(handler), "sk-key", "claude-sonnet-5-5")
        reply = await chat.complete("SYSTEM", HISTORY, TOOLS)
        assert reply.text == "Checking." and reply.tool_calls[0].name == "list_messages"
        assert reply.tool_calls[0].arguments == {"level": "suspicious"} and reply.tool_calls[0].id == "tu_2"
        body = seen["body"]
        assert seen["url"] == "https://api.anthropic.com/v1/messages"
        assert seen["headers"]["x-api-key"] == "sk-key" and seen["headers"]["anthropic-version"] == "2023-06-01"
        assert body["system"] == "SYSTEM" and body["model"] == "claude-sonnet-5-5"
        assert body["tools"][0]["input_schema"]["properties"]["days"]["type"] == "integer"
        roles = [m["role"] for m in body["messages"]]
        assert roles == ["user", "assistant", "user"]
        assert body["messages"][1]["content"][1] == {"type": "tool_use", "id": "t1", "name": "get_stats", "input": {"days": 7}}
        assert body["messages"][2]["content"][0] == {"type": "tool_result", "tool_use_id": "t1", "content": '{"suspicious": 2}'}

    async def test_final_text_only(self):
        chat = AnthropicChat(client(lambda r: httpx.Response(200, json={"content": [{"type": "text", "text": "All quiet."}, "junk"]})), "k", "m")
        reply = await chat.complete("S", [{"role": "user", "text": "hi"}], [])
        assert reply.text == "All quiet." and reply.tool_calls == ()

    def test_wire_merges_consecutive_roles_and_skips_empty(self):
        wire = AnthropicChat.to_wire([
            {"role": "user", "text": "a"}, {"role": "user", "text": "b"},
            {"role": "assistant", "text": ""}, {"role": "system", "text": "ignored"},
        ])
        assert wire == [{"role": "user", "content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]}]

    @pytest.mark.parametrize("response", [
        httpx.Response(500, json={"error": "boom"}),
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, json={"content": "nope"}),
        httpx.Response(200, json=["list"]),
    ])
    async def test_bad_responses_raise_chat_error(self, response):
        chat = AnthropicChat(client(lambda r: response), "k", "m")
        with pytest.raises(ChatError):
            await chat.complete("S", [{"role": "user", "text": "hi"}], TOOLS)

    async def test_timeout_and_network_errors(self):
        def timeout(request):
            raise httpx.ReadTimeout("slow", request=request)

        def broken(request):
            raise httpx.ConnectError("down", request=request)

        for handler, word in ((timeout, "timeout"), (broken, "network")):
            with pytest.raises(ChatError, match=word):
                await AnthropicChat(client(handler), "k", "m").complete("S", [{"role": "user", "text": "x"}], [])


class TestOpenAiShaped:
    async def test_azure_openai_function_calling_round_trip(self):
        seen = {}

        def handler(request):
            seen["url"] = str(request.url)
            seen["key"] = request.headers["api-key"]
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"choices": [{"message": {"content": None, "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "get_stats", "arguments": '{"days": 30}'}},
                {"id": "", "function": {"name": "skipped"}},
                "junk",
            ]}}]})

        chat = AzureOpenAiChat(client(handler), "https://res.openai.azure.com/", "az-key", "gpt-dep")
        reply = await chat.complete("SYSTEM", HISTORY, TOOLS)
        assert reply.tool_calls[0].arguments == {"days": 30} and len(reply.tool_calls) == 1 and reply.text == ""
        assert seen["url"] == "https://res.openai.azure.com/openai/deployments/gpt-dep/chat/completions?api-version=2024-10-21"
        assert seen["key"] == "az-key"
        msgs = seen["body"]["messages"]
        assert msgs[0] == {"role": "system", "content": "SYSTEM"}
        assert msgs[2]["tool_calls"][0]["function"] == {"name": "get_stats", "arguments": '{"days": 7}'}
        assert msgs[3] == {"role": "tool", "tool_call_id": "t1", "content": '{"suspicious": 2}'}
        assert seen["body"]["tools"][0]["type"] == "function" and "model" not in seen["body"]

    async def test_foundry_url_model_and_content_parts(self):
        seen = {}

        def handler(request):
            seen["url"] = str(request.url)
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"choices": [{"message": {"content": [{"text": "Hello"}, {"text": " there"}, 3]}}]})

        chat = AzureFoundryChat(client(handler), "https://x.services.ai.azure.com", "k", "Llama-4")
        reply = await chat.complete("S", [{"role": "user", "text": "hi"}], [])
        assert reply.text == "Hello there"
        assert seen["url"] == "https://x.services.ai.azure.com/models/chat/completions?api-version=2024-05-01-preview"
        assert seen["body"]["model"] == "Llama-4" and "tools" not in seen["body"]

    @pytest.mark.parametrize("payload", [{"choices": []}, {"choices": [{"message": "text"}]}, {"nothing": 1}])
    async def test_malformed_choices(self, payload):
        chat = AzureOpenAiChat(client(lambda r: httpx.Response(200, json=payload)), "https://e", "k", "d")
        with pytest.raises(ChatError):
            await chat.complete("S", [{"role": "user", "text": "x"}], [])

    async def test_timeout(self):
        def handler(request):
            raise httpx.ConnectTimeout("slow", request=request)

        with pytest.raises(ChatError, match="timeout"):
            await AzureOpenAiChat(client(handler), "https://e", "k", "d").complete("S", [], [])


def test_arguments_parsing():
    assert _arguments({"a": 1}) == {"a": 1}
    assert _arguments('{"a": 1}') == {"a": 1}
    assert _arguments("not json") == {} and _arguments("[1]") == {} and _arguments("") == {} and _arguments(None) == {}


class TestFactory:
    def settings(self, **kw) -> Settings:
        return Settings(env="test", **kw)

    def test_off_by_default(self):
        assert chat_model_from_settings(self.settings()) is None

    def test_follows_llm_provider_and_default_model(self):
        s = self.settings(llm_provider="anthropic", anthropic_api_key=SecretStr("k"))
        assert s.effective_assistant_provider == "anthropic" and s.effective_assistant_model == "claude-sonnet-5-5"
        model = chat_model_from_settings(s, httpx.AsyncClient())
        assert isinstance(model, AnthropicChat)

    def test_openai_alias_and_explicit_override(self):
        s = self.settings(llm_provider="openai", azure_openai_endpoint="https://e", azure_openai_api_key=SecretStr("k"),
                          azure_openai_deployment="dep")
        assert s.effective_assistant_provider == "azure_openai"
        assert isinstance(chat_model_from_settings(s, httpx.AsyncClient()), AzureOpenAiChat)
        s2 = self.settings(llm_provider="anthropic", assistant_provider="none")
        assert chat_model_from_settings(s2) is None

    def test_foundry_and_missing_keys(self):
        s = self.settings(assistant_provider="azure_foundry", azure_foundry_endpoint="https://f",
                          azure_foundry_api_key=SecretStr("k"), azure_foundry_model="phi")
        assert isinstance(chat_model_from_settings(s, httpx.AsyncClient()), AzureFoundryChat)
        assert s.effective_assistant_model == "phi"
        assert chat_model_from_settings(self.settings(assistant_provider="azure_foundry")) is None
        assert chat_model_from_settings(self.settings(assistant_provider="azure_openai")) is None
        assert chat_model_from_settings(self.settings(assistant_provider="anthropic")) is None
        custom = self.settings(assistant_provider="anthropic", assistant_model="claude-opus-x")
        assert custom.effective_assistant_model == "claude-opus-x"

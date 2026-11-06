"""Provider-agnostic chat with tool use, for the "Ask Secureddy" assistant.

The agent speaks one small neutral format; each client translates it to its
provider's wire shape and back:

* ``{"role": "user", "text": str}``
* ``{"role": "assistant", "text": str, "tool_calls": [{"id", "name", "arguments"}]}``
* ``{"role": "tool", "results": [{"id", "name", "content": str}]}``

:class:`AnthropicChat` uses the Messages API (``tools`` + ``tool_use`` /
``tool_result`` content blocks). :class:`AzureOpenAiChat` and
:class:`AzureFoundryChat` use the OpenAI-compatible chat-completions
function-calling shape, against an Azure OpenAI deployment or the Foundry
``/models/chat/completions`` endpoint. All of them take an injected
``httpx.AsyncClient`` (tests use ``httpx.MockTransport``) and turn every
failure into :class:`ChatError`, which the agent turns into a calm reply: a
broken model never becomes a 500 on the client's screen.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import httpx

from reddysec.core.logging import get_logger

log = get_logger(__name__)

DEFAULT_TIMEOUT_S = 30.0
DEFAULT_MAX_TOKENS = 1024


class ChatError(Exception):
    """The model could not answer (network, status, malformed reply)."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]  # JSON schema of the arguments object


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class ChatReply:
    text: str
    tool_calls: tuple[ToolCall, ...] = field(default_factory=tuple)


@runtime_checkable
class ChatModel(Protocol):
    async def complete(
        self, system: str, messages: list[dict[str, Any]], tools: list[ToolSpec]
    ) -> ChatReply: ...


def _arguments(raw: Any) -> dict[str, Any]:
    """Tool arguments arrive as an object (Anthropic) or a JSON string (OpenAI)."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            value = json.loads(raw)
        except ValueError:
            return {}
        return value if isinstance(value, dict) else {}
    return {}


async def _post(http: httpx.AsyncClient, url: str, payload: dict[str, Any], headers: dict[str, str],
                timeout: float) -> dict[str, Any]:
    try:
        resp = await http.post(url, json=payload, headers=headers, timeout=timeout)
    except httpx.TimeoutException as exc:
        log.warning("assistant_llm_timeout")
        raise ChatError("timeout") from exc
    except httpx.HTTPError as exc:
        log.warning("assistant_llm_request_failed", error=type(exc).__name__)
        raise ChatError("network") from exc
    if resp.status_code != 200:
        log.warning("assistant_llm_bad_status", status=resp.status_code)
        raise ChatError(f"status {resp.status_code}")
    try:
        data = resp.json()
    except ValueError as exc:
        raise ChatError("invalid json") from exc
    if not isinstance(data, dict):
        raise ChatError("invalid json")
    return data


# --------------------------------------------------------------------------- Anthropic


class AnthropicChat:
    """Claude via ``POST /v1/messages`` with tool use."""

    def __init__(
        self,
        http: httpx.AsyncClient,
        api_key: str,
        model: str,
        *,
        base_url: str = "https://api.anthropic.com",
        api_version: str = "2023-06-01",
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> None:
        self._http = http
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._api_version = api_version
        self._timeout = timeout_s
        self._max_tokens = max_tokens

    @property
    def url(self) -> str:
        return f"{self._base_url}/v1/messages"

    @staticmethod
    def to_wire(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Neutral turns to Anthropic messages. Consecutive turns of the same
        role are merged, because the API wants user and assistant to alternate."""
        out: list[dict[str, Any]] = []
        for m in messages:
            role = m.get("role")
            blocks: list[dict[str, Any]] = []
            if role == "user":
                blocks.append({"type": "text", "text": str(m.get("text", ""))})
                wire_role = "user"
            elif role == "assistant":
                if m.get("text"):
                    blocks.append({"type": "text", "text": str(m["text"])})
                for c in m.get("tool_calls") or []:
                    blocks.append({"type": "tool_use", "id": c["id"], "name": c["name"], "input": c.get("arguments") or {}})
                wire_role = "assistant"
            elif role == "tool":
                for r in m.get("results") or []:
                    blocks.append({"type": "tool_result", "tool_use_id": r["id"], "content": str(r.get("content", ""))})
                wire_role = "user"
            else:
                continue
            if not blocks:
                continue
            if out and out[-1]["role"] == wire_role:
                out[-1]["content"].extend(blocks)
            else:
                out.append({"role": wire_role, "content": blocks})
        return out

    async def complete(self, system: str, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> ChatReply:
        payload: dict[str, Any] = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "system": system,
            "messages": self.to_wire(messages),
        }
        if tools:
            payload["tools"] = [
                {"name": t.name, "description": t.description, "input_schema": t.parameters} for t in tools
            ]
        headers = {"x-api-key": self._api_key, "anthropic-version": self._api_version, "content-type": "application/json"}
        data = await _post(self._http, self.url, payload, headers, self._timeout)
        content = data.get("content")
        if not isinstance(content, list):
            raise ChatError("no content")
        texts: list[str] = []
        calls: list[ToolCall] = []
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text":
                texts.append(str(block.get("text", "")))
            elif block.get("type") == "tool_use" and block.get("id") and block.get("name"):
                calls.append(ToolCall(str(block["id"]), str(block["name"]), _arguments(block.get("input"))))
        return ChatReply("".join(texts).strip(), tuple(calls))


# --------------------------------------------------------------------------- OpenAI-shaped


class AzureOpenAiChat:
    """An Azure OpenAI deployment's chat completions with function calling."""

    def __init__(
        self,
        http: httpx.AsyncClient,
        endpoint: str,
        api_key: str,
        deployment: str,
        *,
        api_version: str = "2024-10-21",
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> None:
        self._http = http
        self._endpoint = endpoint.rstrip("/")
        self._api_key = api_key
        self._deployment = deployment
        self._api_version = api_version
        self._timeout = timeout_s
        self._max_tokens = max_tokens

    @property
    def url(self) -> str:
        return f"{self._endpoint}/openai/deployments/{self._deployment}/chat/completions?api-version={self._api_version}"

    def extra_payload(self) -> dict[str, Any]:
        return {}

    @staticmethod
    def to_wire(system: str, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = [{"role": "system", "content": system}]
        for m in messages:
            role = m.get("role")
            if role == "user":
                out.append({"role": "user", "content": str(m.get("text", ""))})
            elif role == "assistant":
                entry: dict[str, Any] = {"role": "assistant", "content": m.get("text") or None}
                calls = m.get("tool_calls") or []
                if calls:
                    entry["tool_calls"] = [
                        {
                            "id": c["id"],
                            "type": "function",
                            "function": {"name": c["name"], "arguments": json.dumps(c.get("arguments") or {})},
                        }
                        for c in calls
                    ]
                out.append(entry)
            elif role == "tool":
                for r in m.get("results") or []:
                    out.append({"role": "tool", "tool_call_id": r["id"], "content": str(r.get("content", ""))})
        return out

    async def complete(self, system: str, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> ChatReply:
        payload: dict[str, Any] = {
            "messages": self.to_wire(system, messages),
            "max_tokens": self._max_tokens,
            "temperature": 0.2,
            **self.extra_payload(),
        }
        if tools:
            payload["tools"] = [
                {"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.parameters}}
                for t in tools
            ]
        data = await _post(self._http, self.url, payload, {"api-key": self._api_key}, self._timeout)
        try:
            message = data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ChatError("no choices") from exc
        if not isinstance(message, dict):
            raise ChatError("no message")
        content = message.get("content") or ""
        if isinstance(content, list):  # content parts
            content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
        calls: list[ToolCall] = []
        for c in message.get("tool_calls") or []:
            fn = c.get("function") if isinstance(c, dict) else None
            if isinstance(fn, dict) and c.get("id") and fn.get("name"):
                calls.append(ToolCall(str(c["id"]), str(fn["name"]), _arguments(fn.get("arguments"))))
        return ChatReply(str(content).strip(), tuple(calls))


class AzureFoundryChat(AzureOpenAiChat):
    """Azure AI Foundry model inference: the same JSON at
    ``<endpoint>/models/chat/completions`` with the model name in the body."""

    def __init__(self, http: httpx.AsyncClient, endpoint: str, api_key: str, model: str, **kw: Any) -> None:
        kw.setdefault("api_version", "2024-05-01-preview")
        super().__init__(http, endpoint, api_key, model, **kw)

    @property
    def url(self) -> str:
        return f"{self._endpoint}/models/chat/completions?api-version={self._api_version}"

    def extra_payload(self) -> dict[str, Any]:
        return {"model": self._deployment}


# --------------------------------------------------------------------------- factory


def chat_model_from_settings(settings: Any, http: httpx.AsyncClient | None = None) -> ChatModel | None:
    """The configured chat model, or ``None`` when the assistant is off or a
    required key, endpoint or model is missing (the page then says so calmly)."""
    provider = settings.effective_assistant_provider
    model = settings.effective_assistant_model
    if provider == "anthropic":
        key = settings.anthropic_api_key.get_secret_value()
        if not key or not model:
            return None
        return AnthropicChat(http or httpx.AsyncClient(), key, model)
    if provider == "azure_foundry":
        key = settings.azure_foundry_api_key.get_secret_value()
        if not key or not model or not settings.azure_foundry_endpoint:
            return None
        return AzureFoundryChat(http or httpx.AsyncClient(), settings.azure_foundry_endpoint, key, model)
    if provider == "azure_openai":
        key = settings.azure_openai_api_key.get_secret_value()
        if not key or not model or not settings.azure_openai_endpoint:
            return None
        return AzureOpenAiChat(http or httpx.AsyncClient(), settings.azure_openai_endpoint, key, model)
    return None

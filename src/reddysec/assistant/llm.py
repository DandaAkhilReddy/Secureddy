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
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import httpx

from reddysec.core.anthropic_auth import AnthropicAuthError, AnthropicCredentials, credentials_from_settings
from reddysec.core.logging import get_logger

log = get_logger(__name__)

DEFAULT_TIMEOUT_S = 30.0
DEFAULT_MAX_TOKENS = 1024
DEFAULT_ANTHROPIC_URL = "https://api.anthropic.com"


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
    """``complete`` is required. A model may also offer
    ``stream(system, messages, tools)``: an async iterator of text pieces that
    ends with the whole :class:`ChatReply`; the agent uses it when present to
    show the answer as it is written."""

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
    """Claude via ``POST /v1/messages`` with tool use.

    ``credentials`` is an API key string or a
    :class:`~reddysec.core.anthropic_auth.AnthropicCredentials` (keyless
    Workload Identity Federation, or a key). With keyless credentials a 401
    drops the cached token and the request is tried once more.
    """

    def __init__(
        self,
        http: httpx.AsyncClient,
        credentials: str | AnthropicCredentials,
        model: str,
        *,
        base_url: str | None = None,
        api_version: str = "2023-06-01",
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> None:
        self._http = http
        if isinstance(credentials, str):
            credentials = AnthropicCredentials(api_key=credentials, base_url=base_url or DEFAULT_ANTHROPIC_URL)
        self._credentials = credentials
        self._model = model
        self._base_url = (base_url or credentials.base_url).rstrip("/")
        self._api_version = api_version
        self._timeout = timeout_s
        self._max_tokens = max_tokens

    @property
    def url(self) -> str:
        return f"{self._base_url}/v1/messages"

    @property
    def auth_mode(self) -> str:
        return self._credentials.mode

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

    def _payload(self, system: str, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> dict[str, Any]:
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
        return payload

    async def _headers(self) -> dict[str, str]:
        try:
            auth = await self._credentials.headers()
        except AnthropicAuthError as exc:
            log.warning("assistant_llm_auth_failed", error=str(exc), status=exc.status)
            raise ChatError("auth") from None
        return {**auth, "anthropic-version": self._api_version, "content-type": "application/json"}

    async def complete(self, system: str, messages: list[dict[str, Any]], tools: list[ToolSpec]) -> ChatReply:
        payload = self._payload(system, messages, tools)
        for attempt in range(2):
            try:
                data = await _post(self._http, self.url, payload, await self._headers(), self._timeout)
                break
            except ChatError as exc:
                if str(exc) == "status 401" and self._credentials.keyless and attempt == 0:
                    self._credentials.invalidate()
                    continue
                raise
        return _anthropic_reply(data)

    async def stream(
        self, system: str, messages: list[dict[str, Any]], tools: list[ToolSpec]
    ) -> AsyncIterator[str | ChatReply]:
        """Server-sent events from the Messages API: yields text pieces as they
        arrive and, last, the whole :class:`ChatReply` (text and tool calls)."""
        payload = {**self._payload(system, messages, tools), "stream": True}
        for attempt in range(2):
            headers = await self._headers()
            try:
                async with self._http.stream(
                    "POST", self.url, json=payload, headers=headers, timeout=self._timeout
                ) as resp:
                    if resp.status_code == 401 and self._credentials.keyless and attempt == 0:
                        self._credentials.invalidate()
                        continue
                    if resp.status_code != 200:
                        log.warning("assistant_llm_bad_status", status=resp.status_code)
                        raise ChatError(f"status {resp.status_code}")
                    async for item in _anthropic_events(resp):
                        yield item
                    return
            except httpx.TimeoutException as exc:
                log.warning("assistant_llm_timeout")
                raise ChatError("timeout") from exc
            except httpx.HTTPError as exc:
                log.warning("assistant_llm_request_failed", error=type(exc).__name__)
                raise ChatError("network") from exc
        raise ChatError("status 401")  # pragma: no cover - the loop returns or raises


def _anthropic_reply(data: dict[str, Any]) -> ChatReply:
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


async def _anthropic_events(resp: httpx.Response) -> AsyncIterator[str | ChatReply]:
    """Parse the Messages API event stream into text deltas and a final reply."""
    blocks: dict[int, dict[str, Any]] = {}
    data_lines: list[str] = []

    def handle(event: dict[str, Any]) -> str | None:
        kind = event.get("type")
        if kind == "error":
            raise ChatError("stream error")
        index = event.get("index")
        if kind == "content_block_start" and isinstance(index, int):
            block = event.get("content_block") or {}
            blocks[index] = {"type": block.get("type"), "id": block.get("id"), "name": block.get("name"),
                             "text": str(block.get("text") or ""), "json": ""}
        elif kind == "content_block_delta" and isinstance(index, int):
            delta = event.get("delta") or {}
            block = blocks.setdefault(index, {"type": "text", "text": "", "json": ""})
            if delta.get("type") == "text_delta":
                piece = str(delta.get("text") or "")
                block["text"] += piece
                return piece
            if delta.get("type") == "input_json_delta":
                block["json"] += str(delta.get("partial_json") or "")
        return None

    async for line in resp.aiter_lines():
        if line.startswith("data:"):
            data_lines.append(line[5:].strip())
            continue
        if line.strip() or not data_lines:
            continue
        raw = "\n".join(data_lines)
        data_lines = []
        try:
            event = json.loads(raw)
        except ValueError:
            continue
        if isinstance(event, dict):
            piece = handle(event)
            if piece:
                yield piece
    if data_lines:  # a stream that ended without a blank line
        try:
            event = json.loads("\n".join(data_lines))
        except ValueError:
            event = None
        if isinstance(event, dict):
            piece = handle(event)
            if piece:
                yield piece
    texts: list[str] = []
    calls: list[ToolCall] = []
    for index in sorted(blocks):
        block = blocks[index]
        if block.get("type") == "text":
            texts.append(block["text"])
        elif block.get("type") == "tool_use" and block.get("id") and block.get("name"):
            calls.append(ToolCall(str(block["id"]), str(block["name"]), _arguments(block["json"] or "{}")))
    yield ChatReply("".join(texts).strip(), tuple(calls))


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
        if not model:
            return None
        http = http or httpx.AsyncClient()
        credentials = credentials_from_settings(settings, http)
        if credentials is None:
            return None
        return AnthropicChat(http, credentials, model)
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

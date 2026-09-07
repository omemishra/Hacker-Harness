from __future__ import annotations

import json
import os
import uuid
from abc import ABC, abstractmethod
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .models import ModelReply, ProviderConfig, ToolCall, ToolResult
from .tools import parse_tool_arguments


class ProviderError(RuntimeError):
    pass


INTERRUPTED_TOOL_RESULT = "tool call was interrupted before a result was recorded"


def repair_tool_pairing(messages: list[dict], reason: str = INTERRUPTED_TOOL_RESULT) -> list[dict]:
    """Ensure every assistant tool_use is followed by a matching tool_result.

    Anthropic (and OpenAI) reject history where a later user/system turn lands
    immediately after tool_use. Loop-stop and crashes used to leave that gap.
    """
    stub = ToolResult(ok=False, output=reason).model_dump_json()
    index = 0
    while index < len(messages):
        message = messages[index]
        calls = message.get("tool_calls") if message.get("role") == "assistant" else None
        if not calls:
            index += 1
            continue
        needed = [str(call.get("id") or "") for call in calls if call.get("id")]
        collected: dict[str, dict] = {}
        extras: list[dict] = []
        systems: list[dict] = []
        cursor = index + 1
        while cursor < len(messages) and messages[cursor].get("role") in {"tool", "system"}:
            block = messages[cursor]
            if block.get("role") == "system":
                systems.append(block)
            else:
                tool_id = str(block.get("tool_call_id") or "")
                if tool_id and tool_id not in collected:
                    collected[tool_id] = block
                else:
                    extras.append(block)
            cursor += 1
        ordered = []
        for tool_id in needed:
            ordered.append(collected.pop(tool_id, {"role": "tool", "tool_call_id": tool_id, "content": stub}))
        ordered.extend(collected.values())
        ordered.extend(extras)
        messages[index + 1 : cursor] = ordered + systems
        index = index + 1 + len(ordered) + len(systems)
    return messages


class ModelProvider(ABC):
    @abstractmethod
    def complete(self, messages: list[dict], tools: list[dict]) -> ModelReply: ...


def post_json(url: str, headers: dict[str, str], payload: dict) -> dict:
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urlopen(request, timeout=120) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise ProviderError(f"provider returned {exc.code}: {body[:500]}") from exc
    except URLError as exc:
        raise ProviderError(f"provider connection failed: {exc.reason}") from exc


class OpenAIProvider(ModelProvider):
    def __init__(self, config: ProviderConfig):
        self.config = config
        self.api_key = os.environ.get(config.api_key_env, "")
        self.base_url = (config.base_url or "https://api.openai.com/v1").rstrip("/")

    def complete(self, messages: list[dict], tools: list[dict]) -> ModelReply:
        if not self.api_key:
            raise ProviderError(f"missing API key environment variable: {self.config.api_key_env}")
        repair_tool_pairing(messages)
        payload = {
            "model": self.config.model,
            "messages": messages,
            "tools": [{"type": "function", "function": tool} for tool in tools],
            "tool_choice": "auto",
            "temperature": self.config.temperature,
        }
        data = post_json(
            f"{self.base_url}/chat/completions",
            {"Authorization": f"Bearer {self.api_key}"},
            payload,
        )
        message = data["choices"][0]["message"]
        calls = []
        for call in message.get("tool_calls") or []:
            function = call.get("function") or {}
            arguments = parse_tool_arguments(function.get("arguments"))
            calls.append(ToolCall(id=call["id"], name=function.get("name", ""), arguments=arguments))
        usage = data.get("usage") or {}
        return ModelReply(text=message.get("content") or "", tool_calls=calls, input_tokens=usage.get("prompt_tokens", 0), output_tokens=usage.get("completion_tokens", 0))


class AnthropicProvider(ModelProvider):
    def __init__(self, config: ProviderConfig):
        self.config = config
        self.api_key = os.environ.get(config.api_key_env, "")
        self.base_url = (config.base_url or "https://api.anthropic.com/v1").rstrip("/")

    def complete(self, messages: list[dict], tools: list[dict]) -> ModelReply:
        if not self.api_key:
            raise ProviderError(f"missing API key environment variable: {self.config.api_key_env}")
        repair_tool_pairing(messages)
        system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
        anthropic_messages = []
        index = 0
        while index < len(messages):
            message = messages[index]
            if message["role"] == "system":
                index += 1
                continue
            if message["role"] == "tool":
                results = []
                while index < len(messages) and messages[index]["role"] == "tool":
                    tool_message = messages[index]
                    results.append({"type": "tool_result", "tool_use_id": tool_message["tool_call_id"], "content": tool_message["content"]})
                    index += 1
                anthropic_messages.append({"role": "user", "content": results})
                continue
            elif message["role"] == "assistant" and message.get("tool_calls"):
                content: list[dict[str, Any]] = []
                if message.get("content"):
                    content.append({"type": "text", "text": message["content"]})
                for call in message["tool_calls"]:
                    raw_args = call["function"].get("arguments") or "{}"
                    parsed = parse_tool_arguments(raw_args)
                    content.append({"type": "tool_use", "id": call["id"], "name": call["function"]["name"], "input": parsed})
                anthropic_messages.append({"role": "assistant", "content": content})
            else:
                anthropic_messages.append({"role": message["role"], "content": message.get("content", "")})
            index += 1
        payload = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "system": system,
            "messages": anthropic_messages,
            "tools": [{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]} for t in tools],
        }
        data = post_json(
            f"{self.base_url}/messages",
            {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
            payload,
        )
        text_parts, calls = [], []
        for block in data.get("content", []):
            if block["type"] == "text":
                text_parts.append(block["text"])
            elif block["type"] == "tool_use":
                raw_input = block.get("input")
                if not raw_input:
                    raw_input = {key: value for key, value in block.items() if key not in {"type", "id", "name", "input", "index", "caller"}}
                if not raw_input:
                    raw_input = block.get("partial_json") or {}
                calls.append(ToolCall(id=block.get("id", str(uuid.uuid4())), name=block["name"], arguments=parse_tool_arguments(raw_input)))
        usage = data.get("usage") or {}
        return ModelReply(text="\n".join(text_parts), tool_calls=calls, input_tokens=usage.get("input_tokens", 0), output_tokens=usage.get("output_tokens", 0))


def make_provider(config: ProviderConfig) -> ModelProvider:
    if config.kind == "anthropic":
        return AnthropicProvider(config)
    return OpenAIProvider(config)

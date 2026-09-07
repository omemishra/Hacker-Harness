from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
import os

from pydantic import BaseModel, Field, field_validator, model_validator


class ProviderConfig(BaseModel):
    kind: Literal["openai", "anthropic", "openai-compatible"] = "openai"
    model: str = "gpt-5-mini"
    base_url: str | None = None
    api_key_env: str = "OPENAI_API_KEY"
    max_tokens: int = 4096
    temperature: float = 0.1
    context_window: int = 128_000


class PolicyConfig(BaseModel):
    command_mode: Literal["strict", "standard", "engagement"] = "strict"
    max_tool_rounds: int = 60
    max_failed_tool_rounds: int = 20
    command_timeout_seconds: int = 120
    max_output_chars: int = 50_000
    allow_file_writes: bool = True
    max_subagents: int = 4
    subagent_timeout_seconds: int = 600
    auto_compact_percent: float = 50.0


class HarnessConfig(BaseModel):
    api_profile: str | None = None
    provider: ProviderConfig = Field(default_factory=ProviderConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    system_prompt_file: str = ".hacker-harness/SYSTEM.md"


class ScopeTarget(BaseModel):
    value: str
    notes: str = ""


class ScopeDocument(BaseModel):
    engagement: str = "UNCONFIGURED"
    authorized: bool = False
    owner: str = ""
    expires_at: datetime | None = None
    targets: list[ScopeTarget] = Field(default_factory=list)
    excluded: list[ScopeTarget] = Field(default_factory=list)
    rules: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def expand_host_lists(cls, data: Any) -> Any:
        """Accept value as a string or a list of hosts on targets/excluded entries."""
        if not isinstance(data, dict):
            return data
        for key in ("targets", "excluded"):
            items = data.get(key)
            if not isinstance(items, list):
                continue
            expanded: list[Any] = []
            for item in items:
                if isinstance(item, str):
                    expanded.append({"value": item})
                    continue
                if not isinstance(item, dict):
                    expanded.append(item)
                    continue
                value = item.get("value")
                if isinstance(value, list):
                    notes = item.get("notes", "")
                    for entry in value:
                        host = str(entry).strip()
                        if host:
                            expanded.append({"value": host, "notes": notes})
                    continue
                expanded.append(item)
            data[key] = expanded
        return data

    def is_active(self) -> bool:
        if not self.authorized:
            return False
        if self.expires_at is None:
            return False
        expiry = self.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return expiry > datetime.now(timezone.utc)


class WorkflowNode(BaseModel):
    id: str
    description: str = ""
    depends_on: list[str] = Field(default_factory=list)
    prompt: str | None = None
    command: str | None = None
    approval: str | None = None
    save_output: str | None = None
    continue_on_error: bool = False

    @model_validator(mode="after")
    def one_action(self) -> "WorkflowNode":
        actions = [self.prompt is not None, self.command is not None, self.approval is not None]
        if sum(actions) != 1:
            raise ValueError("node must define exactly one of prompt, command, or approval")
        return self


class Workflow(BaseModel):
    name: str
    description: str = ""
    version: int = 1
    inputs: dict[str, str] = Field(default_factory=dict)
    nodes: list[WorkflowNode]

    @field_validator("nodes")
    @classmethod
    def unique_ids(cls, nodes: list[WorkflowNode]) -> list[WorkflowNode]:
        ids = [node.id for node in nodes]
        if len(ids) != len(set(ids)):
            raise ValueError("workflow node IDs must be unique")
        known = set(ids)
        for node in nodes:
            missing = set(node.depends_on) - known
            if missing:
                raise ValueError(f"node {node.id} depends on missing nodes: {sorted(missing)}")
            if node.id in node.depends_on:
                raise ValueError(f"node {node.id} cannot depend on itself")
        return nodes


class ToolCall(BaseModel):
    id: str
    name: str
    arguments: dict[str, Any]


class ModelReply(BaseModel):
    text: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0


class ToolResult(BaseModel):
    ok: bool
    output: str
    metadata: dict[str, Any] = Field(default_factory=dict)


def project_root(start: Path | None = None) -> Path:
    env = os.environ.get("HACKER_HARNESS_PROJECT", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    current = (start or Path.cwd()).resolve()
    home = Path.home().resolve()
    for candidate in [current, *current.parents]:
        if not (candidate / ".hacker-harness").is_dir():
            continue
        # ~/.hacker-harness is a personal default, not the engagement Hermes is in.
        if candidate == home and current != home:
            continue
        return candidate
    return current

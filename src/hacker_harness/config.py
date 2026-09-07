from __future__ import annotations

import os
import json
import re
from pathlib import Path

import yaml

from .models import HarnessConfig, ProviderConfig, ScopeDocument


def _read_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data or {}


def _read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return data


def deep_merge(base: dict, override: dict) -> dict:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(root: Path) -> HarnessConfig:
    global_path = Path(os.environ.get("HACKER_HARNESS_CONFIG", "~/.config/hacker-harness/config.yaml")).expanduser()
    project_path = root / ".hacker-harness" / "config.yaml"
    data = deep_merge(_read_yaml(global_path), _read_yaml(project_path))
    settings = load_settings(root)
    if settings:
        selected = (os.environ.get("HACKER_HARNESS_PROVIDER_PROFILE") or os.environ.get("HACKER_HARNESS_API_PROFILE") or settings.get("activeProvider"))
        profiles = settings.get("providers", {})
        if not selected or selected not in profiles:
            raise ValueError(f"active provider '{selected}' was not found in .hacker-harness/settings.json")
        data["provider"] = normalize_provider(profiles[selected])
        data["api_profile"] = selected
        permissions = settings.get("permissions", {})
        agent = settings.get("agent", {})
        data["policy"] = deep_merge(data.get("policy", {}), {
            "command_mode": permissions.get("commandMode", data.get("policy", {}).get("command_mode", "strict")),
            "allow_file_writes": permissions.get("allowFileWrites", data.get("policy", {}).get("allow_file_writes", True)),
            "max_tool_rounds": agent.get("maxToolRounds", data.get("policy", {}).get("max_tool_rounds", 60)),
            "max_failed_tool_rounds": agent.get("maxFailedToolRounds", data.get("policy", {}).get("max_failed_tool_rounds", 20)),
            "command_timeout_seconds": agent.get("commandTimeoutSeconds", data.get("policy", {}).get("command_timeout_seconds", 120)),
            "max_output_chars": agent.get("maxOutputChars", data.get("policy", {}).get("max_output_chars", 50_000)),
            "max_subagents": agent.get("maxSubagents", data.get("policy", {}).get("max_subagents", 4)),
            "subagent_timeout_seconds": agent.get("subagentTimeoutSeconds", data.get("policy", {}).get("subagent_timeout_seconds", 600)),
            "auto_compact_percent": agent.get("autoCompactPercent", data.get("policy", {}).get("auto_compact_percent", 50)),
        })
        if settings.get("systemPromptFile"):
            data["system_prompt_file"] = settings["systemPromptFile"]
    else:
        api_data = load_api_file(root)
        selected = os.environ.get("HACKER_HARNESS_API_PROFILE") or data.get("api_profile") or api_data.get("active")
        if selected:
            profiles = api_data.get("profiles", {})
            if selected not in profiles:
                raise ValueError(f"API profile '{selected}' was not found in .hacker-harness/apis.yaml")
            profile = profiles[selected]
            if "api_key" in profile:
                raise ValueError("raw api_key values are forbidden; use api_key_env and an environment variable")
            data["provider"] = deep_merge(profile, data.get("provider", {}))
            data["api_profile"] = selected
    if model := os.environ.get("HACKER_HARNESS_MODEL"):
        data.setdefault("provider", {})["model"] = model
    if kind := os.environ.get("HACKER_HARNESS_PROVIDER"):
        data.setdefault("provider", {})["kind"] = kind
    return HarnessConfig.model_validate(data)


ENV_REFERENCE = re.compile(r"^\$\{([A-Z_][A-Z0-9_]*)\}$")
GENERIC_CONTEXT_WINDOW = 128_000
# Longest prefix match. DeepSeek V4 Pro/Flash are 1M; older DeepSeek chat models stay at 128k.
MODEL_CONTEXT_WINDOWS = (
    ("deepseek-v4", 1_000_000),
    ("deepseek-chat", 128_000),
    ("deepseek-reasoner", 128_000),
    ("gpt-5", 128_000),
    ("gpt-4o", 128_000),
    ("claude-opus", 200_000),
    ("claude-sonnet", 200_000),
    ("claude-haiku", 200_000),
    ("kimi", 128_000),
    ("moonshot", 128_000),
)


def known_context_window(model: str | None) -> int | None:
    name = str(model or "").strip().lower()
    if not name:
        return None
    matches = [(prefix, window) for prefix, window in MODEL_CONTEXT_WINDOWS if name.startswith(prefix) or prefix in name]
    if not matches:
        return None
    return max(matches, key=lambda item: len(item[0]))[1]


def resolve_context_window(model: str | None, declared) -> int:
    """Use an explicit operator window, except stale 128k defaults on larger known models."""
    known = known_context_window(model)
    if declared is None:
        return known or GENERIC_CONTEXT_WINDOW
    try:
        value = int(declared)
    except (TypeError, ValueError):
        return known or GENERIC_CONTEXT_WINDOW
    if known and value == GENERIC_CONTEXT_WINDOW and known > GENERIC_CONTEXT_WINDOW:
        return known
    return value


def normalize_provider(profile: dict) -> dict:
    if not isinstance(profile, dict):
        raise ValueError("provider definition must be a JSON object")
    wire_format = profile.get("format")
    if wire_format not in {"openai", "anthropic"}:
        raise ValueError("provider format must be 'openai' or 'anthropic'")
    api_key_env = profile.get("apiKeyEnv")
    if "apiKey" in profile:
        match = ENV_REFERENCE.fullmatch(str(profile["apiKey"]))
        if not match:
            raise ValueError("apiKey must be an environment reference such as ${DEEPSEEK_API_KEY}, never a literal key")
        api_key_env = match.group(1)
    if not api_key_env:
        raise ValueError("provider requires apiKey or apiKeyEnv")
    normalized = {
        "kind": "anthropic" if wire_format == "anthropic" else ("openai-compatible" if profile.get("baseUrl") else "openai"),
        "model": profile.get("model"),
        "base_url": profile.get("baseUrl"),
        "api_key_env": api_key_env,
        "max_tokens": profile.get("maxTokens", 4096),
        "temperature": profile.get("temperature", 0.1),
        "context_window": resolve_context_window(profile.get("model"), profile.get("contextWindow")),
    }
    return {key: value for key, value in normalized.items() if value is not None}


def save_mcp_document(root: Path, servers: dict, *, version: int = 1) -> Path:
    path = root / ".hacker-harness" / "mcp.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not isinstance(servers, dict):
        raise ValueError("mcp.json mcpServers must be a JSON object")
    payload = {"version": version, "mcpServers": servers}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def load_mcp_servers(root: Path) -> dict:
    path = root / ".hacker-harness" / "mcp.json"
    data = _read_json(path)
    if not data:
        return {}
    servers = data.get("mcpServers", data)
    if not isinstance(servers, dict):
        raise ValueError("mcp.json mcpServers must be a JSON object")
    return dict(servers)


def load_settings(root: Path) -> dict:
    base = _read_json(root / ".hacker-harness" / "settings.json")
    local = _read_json(root / ".hacker-harness" / "settings.local.json")
    settings = deep_merge(base, local)
    if not settings:
        return {}
    providers = settings.get("providers", {})
    if not isinstance(providers, dict):
        raise ValueError("settings.json providers must be a JSON object")
    for name, profile in providers.items():
        try:
            ProviderConfig.model_validate(normalize_provider(profile))
        except ValueError as exc:
            raise ValueError(f"invalid provider '{name}': {exc}") from exc
    legacy = settings.get("mcpServers") if isinstance(settings.get("mcpServers"), dict) else {}
    settings["mcpServers"] = deep_merge(legacy, load_mcp_servers(root))
    return settings


def save_settings(root: Path, data: dict) -> None:
    path = root / ".hacker-harness" / "settings.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(data)
    servers = payload.pop("mcpServers", None)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if servers is not None:
        save_mcp_document(root, servers)


def load_knowledge_paths(root: Path, raw_paths: list | None = None) -> list[Path]:
    """Resolve read-only knowledge roots (shared methodology/skill libraries).

    These live outside the project root and are readable by model file tools,
    but never writable. Entries must exist as directories.
    """
    settings = load_settings(root)
    raw = raw_paths if raw_paths is not None else (settings.get("knowledgePaths", []) or [])
    resolved: list[Path] = []
    for item in raw:
        path = Path(str(item)).expanduser().resolve()
        if not path.is_dir():
            raise ValueError(f"knowledge path is not a directory: {item}")
        if path not in resolved:
            resolved.append(path)
    return resolved


def _read_env_value(path: Path, key: str) -> str:
    if not path.is_file():
        return ""
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, _, value = stripped.partition("=")
        if name.strip() != key:
            continue
        return value.strip().strip("'\"")
    return ""


def load_obsidian_vault(settings: dict | None, root: Path | None = None) -> Path | None:
    """Resolve the obsidian-wiki vault (settings → project .env → ~/.obsidian-wiki/config)."""
    candidates: list[str] = []
    if settings:
        candidates.append(str(settings.get("obsidianVault") or "").strip())
    if root is not None:
        candidates.append(_read_env_value(root / ".env", "OBSIDIAN_VAULT_PATH"))
        candidates.append(_read_env_value(root / ".hacker-harness" / ".env", "OBSIDIAN_VAULT_PATH"))
    candidates.append(_read_env_value(Path("~/.obsidian-wiki/config").expanduser(), "OBSIDIAN_VAULT_PATH"))
    for raw in candidates:
        if not raw:
            continue
        path = Path(raw).expanduser().resolve()
        if not path.is_dir():
            raise ValueError(f"obsidianVault is not a directory: {raw}")
        return path
    return None


def load_api_file(root: Path) -> dict:
    data = _read_yaml(root / ".hacker-harness" / "apis.yaml")
    profiles = data.get("profiles", {})
    if not isinstance(profiles, dict):
        raise ValueError("apis.yaml profiles must be a mapping")
    for name, profile in profiles.items():
        if not isinstance(profile, dict):
            raise ValueError(f"API profile '{name}' must be a mapping")
        if "api_key" in profile:
            raise ValueError(f"API profile '{name}' contains a raw api_key; use api_key_env instead")
        ProviderConfig.model_validate(profile)
    return data


def save_api_file(root: Path, data: dict) -> None:
    path = root / ".hacker-harness" / "apis.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def load_scope(root: Path) -> ScopeDocument:
    return ScopeDocument.model_validate(_read_yaml(root / ".hacker-harness" / "scope.yaml"))

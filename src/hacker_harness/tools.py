from __future__ import annotations

import inspect
import json
import os
import re
import subprocess
import threading
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .config import load_knowledge_paths, load_obsidian_vault, load_scope
from .memory import MEMORY_RELATIVE, ensure_memory_file
from .skills import (
    discover_skill_entries,
    load_skill_body,
    promote_skill,
    resolve_skill_entry,
    save_playbook,
    search_playbooks,
)
from .models import HarnessConfig, ToolResult
from .mcp import MCPManager
from .scope import ScopeDocument, ScopeError, _hostname, target_allowed, validate_command
from .state import StateStore


TOOL_SPECS = [
    {"name": "read_file", "description": "Read a UTF-8 text file inside the project.", "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "start_line": {"type": "integer"}, "end_line": {"type": "integer"}}, "required": ["path"]}},
    {"name": "list_files", "description": "List project files matching a glob pattern.", "parameters": {"type": "object", "properties": {"pattern": {"type": "string"}}, "required": ["pattern"]}},
    {"name": "search_text", "description": "Search project text with a regular expression.", "parameters": {"type": "object", "properties": {"pattern": {"type": "string"}, "glob": {"type": "string"}}, "required": ["pattern"]}},
    {"name": "write_file", "description": "Create or replace a UTF-8 file inside the project. You must put both path and the complete file contents in the tool input object. Do not call write_file with an empty input.", "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}},
    {"name": "replace_text", "description": "Replace one exact text occurrence inside a project file.", "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "old": {"type": "string"}, "new": {"type": "string"}}, "required": ["path", "old", "new"]}},
    {"name": "run_command", "description": "Run a shell command in the project. Network security tools require active target authorization.", "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}},
    {"name": "remember", "description": "Persist a distilled lesson to .hacker-harness/memory.md after you decide what is worth keeping. Use when the operator asks to remember, corrects you, or sets a standing preference. Write declarative third-person lessons — never copy the operator verbatim. Mirrors to obsidianVault when configured.", "parameters": {"type": "object", "properties": {"content": {"type": "string"}, "kind": {"type": "string", "enum": ["preference", "lesson", "procedure", "profile"]}}, "required": ["content"]}},
    {"name": "memory_search", "description": "Search prior distilled lessons and preferences from project memory (FTS). Use before repeating a mistake or when recalling operator preferences.", "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}},
    {"name": "skill_load", "description": "Load the full SKILL.md body for a cataloged skill by name or skill_id. Use when the current task matches a skill description.", "parameters": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    {"name": "playbook_save", "description": "Save a reusable attack-chain playbook with triggers, steps, dead ends, and payloads. Use when the operator asks to save a chain or confirms after you suggest it. Writes to obsidianVault/concepts/patterns when configured, else .hacker-harness/playbooks/. Also stores a short procedure pointer in memory.md.", "parameters": {"type": "object", "properties": {"title": {"type": "string"}, "content": {"type": "string"}, "observables": {"type": "array", "items": {"type": "string"}}, "tags": {"type": "array", "items": {"type": "string"}}, "procedure_summary": {"type": "string"}}, "required": ["title", "content"]}},
    {"name": "playbook_search", "description": "Search saved playbooks for similar techniques, observables, or stack signals.", "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}},
    {"name": "skill_promote", "description": "Create a new SKILL.md from a proven playbook. Only when the operator explicitly asks to promote a technique to a reusable skill — never auto-promote from a chain save.", "parameters": {"type": "object", "properties": {"name": {"type": "string"}, "description": {"type": "string"}, "content": {"type": "string"}}, "required": ["name", "description", "content"]}},
    {"name": "task_create", "description": "Create a persistent task.", "parameters": {"type": "object", "properties": {"title": {"type": "string"}, "description": {"type": "string"}, "priority": {"type": "integer"}}, "required": ["title"]}},
    {"name": "task_ready", "description": "List unblocked persistent tasks.", "parameters": {"type": "object", "properties": {}}},
    {"name": "scope_check", "description": "Check whether a target is inside the active authorization scope.", "parameters": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}},
    {"name": "finding_create", "description": "Record a structured authorized-testing finding with detailed technical description, reproduction steps (PoC), impact statement, and developer remediation. Creates a confirmed finding.", "parameters": {"type": "object", "properties": {"title": {"type": "string"}, "severity": {"type": "string", "enum": ["informational", "low", "medium", "high", "critical"]}, "target": {"type": "string"}, "evidence": {"type": "string"}, "description": {"type": "string"}, "impact": {"type": "string"}, "steps": {"type": "string"}, "remediation": {"type": "string"}}, "required": ["title", "severity", "target"]}},
    {"name": "signal_record", "description": "Record an unconfirmed security lead as a signal. Does not claim a vulnerability until advanced with evidence via finding_advance.", "parameters": {"type": "object", "properties": {"title": {"type": "string"}, "target": {"type": "string"}, "notes": {"type": "string"}, "severity": {"type": "string", "enum": ["informational", "low", "medium", "high", "critical"]}}, "required": ["title", "target"]}},
    {"name": "finding_advance", "description": "Advance a signal/confirmed finding after evidence review. signal→confirmed requires evidence; confirmed→ready requires evidence and preferably remediation.", "parameters": {"type": "object", "properties": {"finding_id": {"type": "string"}, "status": {"type": "string", "enum": ["confirmed", "ready"]}, "evidence": {"type": "string"}, "remediation": {"type": "string"}}, "required": ["finding_id", "status"]}},
    {"name": "finding_dismiss", "description": "Dismiss a signal or confirmed finding that does not hold up under review.", "parameters": {"type": "object", "properties": {"finding_id": {"type": "string"}, "reason": {"type": "string"}}, "required": ["finding_id"]}},
    {"name": "finding_archive", "description": "Archive a finding when it no longer applies or was superseded.", "parameters": {"type": "object", "properties": {"finding_id": {"type": "string"}}, "required": ["finding_id"]}},
    {"name": "finding_list", "description": "List engagement findings. Optional status filter: signal, confirmed, ready, dismissed, archived.", "parameters": {"type": "object", "properties": {"status": {"type": "string", "enum": ["signal", "confirmed", "ready", "dismissed", "archived"]}}}},
    {"name": "http_request", "description": "Send one approved HTTP request to an explicitly authorized target. Redirects are not followed automatically.", "parameters": {"type": "object", "properties": {"url": {"type": "string"}, "method": {"type": "string", "enum": ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]}, "headers": {"type": "object", "additionalProperties": {"type": "string"}}, "body": {"type": "string"}, "timeout": {"type": "integer", "minimum": 1, "maximum": 120}}, "required": ["url"]}},
    {"name": "goal_create", "description": "Create a persistent engagement goal.", "parameters": {"type": "object", "properties": {"title": {"type": "string"}, "description": {"type": "string"}}, "required": ["title"]}},
    {"name": "goal_list", "description": "List persistent engagement goals.", "parameters": {"type": "object", "properties": {"status": {"type": "string"}}}},
    {"name": "goal_update", "description": "Update an engagement goal status.", "parameters": {"type": "object", "properties": {"goal_id": {"type": "string"}, "status": {"type": "string", "enum": ["pending", "in_progress", "completed", "blocked", "failed", "cancelled"]}}, "required": ["goal_id", "status"]}},
    {"name": "skill_pivot", "description": "Suggest or chain tactical next-step skills based on a finding or technique. Evaluates finding evidence/title to return high-impact pivot paths.", "parameters": {"type": "object", "properties": {"finding_id": {"type": "string"}, "skill_name": {"type": "string"}}, "required": []}},
    {"name": "methodology_advance", "description": "Advance the active methodology to the next stage only after this stage's required files exist and are non-empty. Fails if required writes are missing.", "parameters": {"type": "object", "properties": {}}},
    {"name": "spawn_agent", "description": "Run a subagent with the same authorized tools, scope, and approval gates. For GenPentest, pass a plan file path (for example GenPentest/plans/P5_Plan.md) as instructions, not the whole methodology. Every spawn requires operator approval.", "parameters": {"type": "object", "properties": {"instructions": {"type": "string"}, "agent_id": {"type": "string"}}, "required": ["instructions"]}},
]


SENSITIVE_ARGUMENT_NAMES = {"authorization", "cookie", "set-cookie", "api_key", "apikey", "token", "password", "secret"}
PROTECTED_READ_PATHS = {
    ".hacker-harness/scope.yaml", ".hacker-harness/settings.json", ".hacker-harness/settings.local.json",
    ".hacker-harness/config.yaml", ".hacker-harness/apis.yaml", ".hacker-harness/mcp.json", ".hacker-harness/state.db",
    ".hacker-harness/history", ".hacker-harness/SYSTEM.md",
}

# Models often send write_file with file/filename/text instead of path/content.
TOOL_ARGUMENT_ALIASES = {
    "write_file": {
        "file": "path", "filename": "path", "filepath": "path", "file_path": "path",
        "text": "content", "body": "content", "data": "content", "contents": "content",
    },
    "replace_text": {"file": "path", "filename": "path", "filepath": "path"},
    "read_file": {"file": "path", "filename": "path", "filepath": "path", "file_path": "path"},
}


def parse_tool_arguments(raw) -> dict:
    """Parse tool arguments from a dict, JSON object, or broken JSON (HTML reports)."""
    if isinstance(raw, dict):
        return dict(raw)
    if raw is None:
        return {}
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", "replace")
    if not isinstance(raw, str):
        return {}
    text = raw.strip()
    if not text:
        return {}
    candidates = [text]
    start, end = text.find("{"), text.rfind("}")
    if start >= 0 and end > start:
        candidates.append(text[start : end + 1])
    for candidate in candidates:
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return _parse_relaxed_object(text)


def _json_unescape(fragment: str) -> str:
    try:
        return json.loads(f'"{fragment}"')
    except json.JSONDecodeError:
        return fragment.replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"').replace("\\\\", "\\")


def _parse_relaxed_object(text: str) -> dict:
    """Recover path/content when the model emits invalid JSON (raw newlines, HTML quotes)."""
    out: dict = {}
    path = re.search(r'"(?:path|filename|file|filepath|file_path)"\s*:\s*"((?:\\.|[^"\\])*)"', text)
    if path:
        out["path"] = _json_unescape(path.group(1))
    content_key = re.search(r'"(?:content|text|body|data|contents)"\s*:\s*"', text)
    if content_key:
        body = text[content_key.end() :].rstrip()
        if body.endswith("}"):
            body = body[:-1].rstrip()
        if body.endswith('"'):
            body = body[:-1]
        if "\\n" in body and "\n" not in body:
            out["content"] = _json_unescape(body.replace('"', '\\"'))
        else:
            out["content"] = body.replace('\\"', '"').replace("\\\\", "\\")
    return out


def _fill_write_file_from_commentary(arguments: dict, commentary: str) -> dict:
    args = dict(arguments)
    text = commentary or ""
    if not args.get("content"):
        fence = re.search(r"```(?:html|htm|xml|markdown|md)?\s*\n([\s\S]+?)```", text, re.I)
        if fence:
            args["content"] = fence.group(1)
        else:
            marker = re.search(r"(?i)(?:<!DOCTYPE html|<html[\s>])", text)
            if marker:
                args["content"] = text[marker.start() :]
    if not args.get("path"):
        named = re.search(r"([A-Za-z0-9_./-]+\.(?:html|htm|md|txt|css))", text)
        if named:
            args["path"] = named.group(1)
        elif args.get("content"):
            args["path"] = "report.html"
    return args


def enrich_tool_arguments(name: str, arguments, commentary: str = "") -> dict:
    parsed = _normalize_tool_arguments(name, parse_tool_arguments(arguments))
    if name == "write_file":
        parsed = _fill_write_file_from_commentary(parsed, commentary)
    return parsed


def _normalize_tool_arguments(name: str, arguments) -> dict:
    """Coerce provider payloads into kwargs the tool methods can bind."""
    arguments = parse_tool_arguments(arguments)
    if not isinstance(arguments, dict):
        arguments = {}
    if set(arguments) <= {"input", "arguments"}:
        nested = arguments.get("input", arguments.get("arguments"))
        nested = parse_tool_arguments(nested)
        if nested:
            arguments = nested
    aliases = TOOL_ARGUMENT_ALIASES.get(name, {})
    normalized = {}
    for key, value in arguments.items():
        normalized[aliases.get(str(key), str(key))] = value
    return normalized



def redact_arguments(value, key: str = ""):
    if key.lower() in SENSITIVE_ARGUMENT_NAMES or any(word in key.lower() for word in ("token", "secret", "password", "api_key")):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {item_key: redact_arguments(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [redact_arguments(item) for item in value]
    return value


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _run_with_timeout(fn, timeout: float):
    """Run ``fn`` on a daemon thread; raise TimeoutError after ``timeout`` seconds."""
    holder: dict = {}

    def target() -> None:
        try:
            holder["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - propagated to the caller
            holder["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise TimeoutError(f"operation exceeded {timeout:.0f}s")
    if "error" in holder:
        raise holder["error"]
    return holder["value"]


class ToolRegistry:
    def __init__(self, root: Path, config: HarnessConfig, scope: ScopeDocument, state: StateStore, approve: Callable[[str], bool] | None = None, settings: dict | None = None, provider=None, spawn_depth: int = 0):
        self.root = root.resolve()
        self.config = config
        self.scope = scope
        self.state = state
        self.approve = approve or (lambda _: False)
        self.provider = provider
        self.spawn_depth = spawn_depth
        self.methodology_session = None
        self.methodology_bundle = ""
        self.settings = settings or {}
        self.knowledge_roots = load_knowledge_paths(root, self.settings.get("knowledgePaths"))
        self.obsidian_vault = load_obsidian_vault(self.settings, self.root)
        ensure_memory_file(self.root)
        self.skill_entries = discover_skill_entries(self.root)
        self.passive_domains = tuple(self.settings.get("passiveDomains", []) or [])
        self.mcp = MCPManager(self.root, self.settings.get("mcpServers", {}), self.approve, scope)

    def _request_approval(self, question: str, session_key: str | None = None) -> bool:
        if session_key is None:
            return self.approve(question)
        try:
            return self.approve(question, session_key=session_key)
        except TypeError:
            return self.approve(question)

    def engagement_root(self) -> Path | None:
        """Operator-configured root that holds per-scope engagement folders."""
        raw = self.settings.get("engagementRoot", "")
        if not raw:
            return None
        return Path(str(raw)).expanduser().resolve()

    def engagement_dirs(self) -> list[Path]:
        """The writable per-scope folders: engagementRoot/<hostname> for each in-scope host target."""
        base = self.engagement_root()
        if base is None:
            return []
        dirs: list[Path] = []
        for item in self.scope.targets:
            host = _hostname(item.value)
            if host and "." in host:
                candidate = (base / host).resolve()
                if candidate not in dirs:
                    dirs.append(candidate)
        return dirs

    def specs(self) -> list[dict]:
        return [*TOOL_SPECS, *self.mcp.discover()]

    def _path(self, raw: str) -> Path:
        path = (self.root / raw).resolve() if not Path(raw).is_absolute() else Path(raw).resolve()
        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise PermissionError("path escapes the project root") from exc
        return path

    def _view_roots(self) -> list[Path]:
        """Readable roots: project, knowledge libraries, optional Obsidian vault, and engagement folders."""
        roots = [self.root, *self.knowledge_roots, *self.engagement_dirs()]
        if self.obsidian_vault is not None:
            roots.append(self.obsidian_vault)
        return roots

    def _read_path(self, raw: str) -> Path:
        path = Path(raw).expanduser().resolve() if Path(raw).is_absolute() else (self.root / raw).resolve()
        for root in self._view_roots():
            try:
                path.relative_to(root)
                return path
            except ValueError:
                continue
        raise PermissionError(f"path escapes the project root, knowledge paths, and engagement folder: {raw}")

    def _write_path(self, raw: str) -> Path:
        path = Path(raw).expanduser().resolve() if Path(raw).is_absolute() else (self.root / raw).resolve()
        allowed = False
        for root in [self.root, *self.engagement_dirs()]:
            try:
                path.relative_to(root)
                allowed = True
                break
            except ValueError:
                continue
        if not allowed:
            raise PermissionError("path escapes the project root and the engagement folder")
        relative = str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path)
        if relative in {".hacker-harness/scope.yaml", ".hacker-harness/settings.json", ".hacker-harness/settings.local.json", ".hacker-harness/mcp.json", ".hacker-harness/config.yaml", ".hacker-harness/apis.yaml", ".hacker-harness/history"} or relative.startswith(".hacker-harness/state.db"):
            raise PermissionError("harness scope, policy, and state files are operator-controlled")
        return path

    def _view_pattern(self, pattern: str) -> tuple[Path, str] | None:
        """If an absolute glob targets a knowledge, Obsidian, or engagement root, return (root, relative_glob)."""
        if not pattern.startswith("/"):
            return None
        expanded = Path(pattern).expanduser().resolve()
        for root in [*self.knowledge_roots, *([self.obsidian_vault] if self.obsidian_vault else []), *self.engagement_dirs()]:
            try:
                relative = expanded.relative_to(root)
            except ValueError:
                continue
            return root, str(relative) or "**/*"
        return None

    def execute(self, name: str, arguments: dict) -> ToolResult:
        try:
            self.refresh_scope()
        except Exception as exc:
            self.state.audit(name, False, {"arguments": redact_arguments(arguments), "error": f"scope reload failed: {exc}"})
            return ToolResult(ok=False, output=f"ScopeError: could not reload .hacker-harness/scope.yaml: {exc}")
        if name.startswith("mcp__"):
            try:
                result = self.mcp.call(name, arguments)
                self.state.audit(name, True, {"arguments": redact_arguments(arguments)})
                return ToolResult(ok=True, output=str(result))
            except Exception as exc:
                self.state.audit(name, False, {"arguments": redact_arguments(arguments), "error": str(exc)})
                return ToolResult(ok=False, output=f"{type(exc).__name__}: {exc}")
        try:
            method = getattr(self, f"tool_{name}")
        except AttributeError:
            return ToolResult(ok=False, output=f"unknown tool: {name}")
        arguments = _normalize_tool_arguments(name, arguments)
        spec = next((item for item in TOOL_SPECS if item["name"] == name), None)
        required = list((spec or {}).get("parameters", {}).get("required") or [])
        missing = [key for key in required if key not in arguments or arguments[key] is None or (isinstance(arguments.get(key), str) and key != "content" and not str(arguments[key]).strip())]
        if missing:
            hint = f"{name} requires {', '.join(required)}. Missing: {', '.join(missing)}. Call again with those fields populated."
            self.state.audit(name, False, {"arguments": redact_arguments(arguments), "error": hint})
            return ToolResult(ok=False, output=hint)
        try:
            signature = inspect.signature(method)
            allowed = {key: value for key, value in arguments.items() if key in signature.parameters}
            result = method(**allowed)
            self.state.audit(name, True, {"arguments": redact_arguments(allowed)})
            return ToolResult(ok=True, output=str(result))
        except TypeError as exc:
            hint = f"{name} argument error: {exc}. Required fields: {', '.join(required) or 'see tool spec'}."
            self.state.audit(name, False, {"arguments": redact_arguments(arguments), "error": hint})
            return ToolResult(ok=False, output=hint)
        except Exception as exc:
            self.state.audit(name, False, {"arguments": redact_arguments(arguments), "error": str(exc)})
            return ToolResult(ok=False, output=f"{type(exc).__name__}: {exc}")

    def refresh_scope(self) -> ScopeDocument:
        """Hot-reload the operator scope before every gated tool invocation."""
        scope_path = self.root / ".hacker-harness" / "scope.yaml"
        if scope_path.exists():
            self.scope = load_scope(self.root)
            self.mcp.scope = self.scope
        return self.scope

    def recreate_mcp(self) -> None:
        """Reload MCP policy code and reconnect configured servers (e.g. after ``uv tool install``)."""
        import importlib
        from . import mcp as mcp_module

        importlib.reload(mcp_module)
        try:
            self.mcp.close()
        except Exception:
            pass
        self.mcp = mcp_module.MCPManager(
            self.root,
            self.settings.get("mcpServers", {}),
            self.approve,
            self.scope,
        )

    def tool_read_file(self, path: str, start_line: int = 1, end_line: int = 400) -> str:
        target = self._read_path(path)
        relative = str(target.relative_to(self.root)) if target.is_relative_to(self.root) else str(target)
        if relative in PROTECTED_READ_PATHS or relative.startswith(".hacker-harness/state.db"):
            raise PermissionError("harness control files are operator-only; use the sanitized runtime context or a dedicated slash command")
        lines = target.read_text(encoding="utf-8").splitlines()
        start = max(1, start_line)
        end = min(len(lines), end_line)
        return "\n".join(f"{i}: {lines[i-1]}" for i in range(start, end + 1))

    def tool_list_files(self, pattern: str) -> str:
        knowledge = self._view_pattern(pattern)
        if knowledge:
            base, relative = knowledge
        elif pattern.startswith("/"):
            raise PermissionError("absolute pattern escapes the project root, knowledge paths, and engagement folder")
        else:
            base, relative = self.root, pattern.lstrip("/")
        files = [str(p.relative_to(self.root)) if base == self.root else str(p) for p in base.glob(relative) if p.is_file()]
        return "\n".join(sorted(files)[:1000])

    def tool_search_text(self, pattern: str, glob: str = "**/*") -> str:
        knowledge = self._view_pattern(glob)
        if knowledge:
            search_root, search_glob = knowledge
        elif glob.startswith("/"):
            raise PermissionError("absolute glob escapes the project root, knowledge paths, and engagement folder")
        else:
            search_root, search_glob = self.root, glob
        command = ["rg", "--line-number", "--color", "never", "--glob", search_glob, pattern, str(search_root)]
        proc = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if proc.returncode not in (0, 1):
            raise RuntimeError(proc.stderr.strip())
        return proc.stdout[: self.config.policy.max_output_chars]

    def _relative(self, target: Path) -> str:
        return str(target.relative_to(self.root)) if target.is_relative_to(self.root) else str(target)

    def tool_write_file(self, path: str, content: str) -> str:
        if not self.config.policy.allow_file_writes:
            raise PermissionError("file writes are disabled by policy")
        target = self._write_path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return f"wrote {len(content)} characters to {self._relative(target)}"

    def tool_replace_text(self, path: str, old: str, new: str) -> str:
        target = self._write_path(path)
        content = target.read_text(encoding="utf-8")
        count = content.count(old)
        if count != 1:
            raise ValueError(f"expected exactly one match, found {count}")
        target.write_text(content.replace(old, new, 1), encoding="utf-8")
        return f"updated {self._relative(target)}"

    def tool_run_command(self, command: str) -> str:
        validate_command(command, self.scope, self.passive_domains)
        if self.config.policy.command_mode == "strict":
            # Every command is gated; session-memory is the approve callback's
            # job (the TUI remembers exact questions for "allow for session").
            if not self.approve(command):
                raise PermissionError("command was not approved")
        env = os.environ.copy()
        env["HACKER_HARNESS_PROJECT"] = str(self.root)
        proc = subprocess.run(command, cwd=self.root, shell=True, capture_output=True, text=True, timeout=self.config.policy.command_timeout_seconds, env=env)
        output = (proc.stdout + ("\n" + proc.stderr if proc.stderr else ""))[: self.config.policy.max_output_chars]
        if proc.returncode != 0:
            raise RuntimeError(f"command exited {proc.returncode}\n{output}")
        return output or "command completed successfully"

    def tool_remember(self, content: str, kind: str = "lesson") -> str:
        normalized_kind = kind if kind in {"preference", "lesson", "procedure", "profile"} else "lesson"
        saved = self.state.remember(content, kind=normalized_kind, obsidian_vault=self.obsidian_vault)
        if not saved:
            return "memory unchanged (duplicate lesson)"
        if self.obsidian_vault is not None:
            return f"memory stored in {MEMORY_RELATIVE} and staged to {self.obsidian_vault / '_raw'}"
        return f"memory stored in {MEMORY_RELATIVE}"

    def tool_memory_search(self, query: str) -> str:
        matches = self.state.search_memories(query)
        if not matches:
            return "no matching memories"
        return json.dumps(matches, indent=2)

    def tool_skill_load(self, name: str) -> str:
        entry = resolve_skill_entry(self.skill_entries, name)
        body = load_skill_body(entry.path)
        return f"# Skill: {entry.name}\n\n{body}"

    def tool_playbook_save(
        self,
        title: str,
        content: str,
        observables: list[str] | None = None,
        tags: list[str] | None = None,
        procedure_summary: str = "",
    ) -> str:
        path, summary = save_playbook(
            self.root,
            title=title,
            content=content,
            observables=observables,
            tags=tags,
            procedure_summary=procedure_summary,
            vault=self.obsidian_vault,
        )
        return json.dumps({"path": str(path), "procedure": summary}, indent=2)

    def tool_playbook_search(self, query: str) -> str:
        matches = search_playbooks(self.root, query, vault=self.obsidian_vault)
        if not matches:
            return "no matching playbooks"
        return json.dumps(matches, indent=2)

    def tool_skill_promote(self, name: str, description: str, content: str) -> str:
        path = promote_skill(self.root, name=name, description=description, content=content)
        self.skill_entries = discover_skill_entries(self.root)
        return f"skill promoted at {path.relative_to(self.root)} — call skill_load on next turn; restart session to refresh catalog in system prompt"

    def tool_task_create(self, title: str, description: str = "", priority: int = 2) -> str:
        return self.state.create_task(title, description, priority)

    def tool_task_ready(self) -> str:
        return json.dumps(self.state.ready_tasks(), indent=2)

    def tool_scope_check(self, target: str) -> str:
        return "authorized" if target_allowed(target, self.scope) else "not authorized"

    def tool_finding_create(self, title: str, severity: str, target: str, evidence: str = "", remediation: str = "", description: str = "", impact: str = "", steps: str = "") -> str:
        if not target_allowed(target, self.scope):
            raise PermissionError(f"finding target is not in the active authorization scope: {target}")
        merged_evidence = evidence or steps
        if description or impact:
            desc_block = f"Description: {description}\nImpact: {impact}\n\n{merged_evidence}".strip()
            merged_evidence = desc_block
        return self.state.create_finding(title, severity, target, merged_evidence, remediation, status="confirmed")

    def tool_signal_record(self, title: str, target: str, notes: str = "", severity: str = "informational") -> str:
        if not target_allowed(target, self.scope):
            raise PermissionError(f"signal target is not in the active authorization scope: {target}")
        return self.state.create_signal(title, target, notes, severity=severity)

    def tool_finding_advance(self, finding_id: str, status: str, evidence: str = "", remediation: str = "") -> str:
        if not self.state.advance_finding(finding_id, status, evidence=evidence, remediation=remediation):
            raise ValueError(f"finding not found: {finding_id}")
        return f"{finding_id} → {status}"

    def tool_finding_dismiss(self, finding_id: str, reason: str = "") -> str:
        if not self.state.dismiss_finding(finding_id, reason):
            raise ValueError(f"finding not found: {finding_id}")
        return f"{finding_id} → dismissed"

    def tool_finding_archive(self, finding_id: str) -> str:
        if not self.state.archive_finding(finding_id):
            raise ValueError(f"finding not found or cannot archive: {finding_id}")
        return f"{finding_id} → archived"

    def tool_finding_list(self, status: str | None = None) -> str:
        return json.dumps(self.state.list_findings(status=status), indent=2)

    def tool_http_request(self, url: str, method: str = "GET", headers: dict[str, str] | None = None, body: str = "", timeout: int = 30) -> str:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("url must use http or https and include a hostname")
        if not target_allowed(parsed.hostname, self.scope):
            raise PermissionError(f"HTTP target is not in the active authorization scope: {parsed.hostname}")
        method = method.upper()
        if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError(f"unsupported HTTP method: {method}")
        if self.config.policy.command_mode == "strict":
            if not self._request_approval(f"HTTP {method} {parsed.hostname}{parsed.path or '/'}", session_key=f"HTTP {parsed.hostname}"):
                raise PermissionError("HTTP request was not approved")
        request = Request(url, data=body.encode("utf-8") if body else None, headers=headers or {}, method=method)
        opener = build_opener(NoRedirect)
        try:
            response = opener.open(request, timeout=max(1, min(timeout, 120)))
        except HTTPError as exc:
            response = exc
        except URLError as exc:
            raise RuntimeError(f"HTTP connection failed: {exc.reason}") from exc
        with response:
            response_body = response.read(self.config.policy.max_output_chars).decode("utf-8", errors="replace")
            response_headers = "\n".join(f"{key}: {value}" for key, value in response.headers.items())
            location = response.headers.get("Location")
            redirect_note = f"\nRedirect not followed: {location}" if location else ""
            status = getattr(response, "status", getattr(response, "code", 0))
            return f"HTTP {status}\n{response_headers}{redirect_note}\n\n{response_body}"

    def tool_goal_create(self, title: str, description: str = "") -> str:
        return self.state.create_goal(title, description)

    def tool_goal_list(self, status: str | None = None) -> str:
        return json.dumps(self.state.list_goals(status=status), indent=2)

    def tool_goal_update(self, goal_id: str, status: str) -> str:
        if not self.state.update_goal(goal_id, status):
            raise ValueError(f"goal not found: {goal_id}")
        return f"{goal_id} → {status}"

    def tool_skill_pivot(self, finding_id: str = "", skill_name: str = "") -> str:
        from .skills import suggest_pivots_for_finding
        if finding_id:
            finding = self.state.get_finding(finding_id)
            if not finding:
                raise ValueError(f"finding not found: {finding_id}")
            pivots = suggest_pivots_for_finding(self.root, finding)
        elif skill_name:
            pivots = suggest_pivots_for_finding(self.root, skill_name)
        else:
            findings = self.state.list_findings()
            if not findings:
                return "No findings recorded to evaluate pivots. Pass a skill_name or record findings first."
            pivots = suggest_pivots_for_finding(self.root, findings[-1])
        if not pivots:
            return "No direct attack pivots identified for this input."
        lines = ["Suggested attack pivots:"]
        for p in pivots:
            lines.append(f"- **{p['name']}** (`{p['skill_id']}`): {p['reason']} — {p['description']}")
        return "\n".join(lines)

    def tool_methodology_advance(self) -> str:
        agent = getattr(self, "agent", None)
        if agent is None or not hasattr(agent, "advance_methodology"):
            raise PermissionError("no active methodology session")
        return agent.advance_methodology()

    def tool_spawn_agent(self, instructions: str, agent_id: str = "") -> str:
        """Run a subagent with the same tools, scope, approvals, and state."""
        from .agent import Agent

        if self.spawn_depth >= 2:
            raise PermissionError("spawn depth exceeded: subagents may not spawn further subagents")
        label = f" {agent_id}" if agent_id else ""
        if not self.approve(f"Spawn subagent{label}: {instructions[:200]}"):
            raise PermissionError("subagent spawn was not approved")
        timeout = float(getattr(self.config.policy, "subagent_timeout_seconds", 600))
        subagent = Agent(
            self.root,
            provider=self.provider,
            approve=self.approve,
            spawn_depth=self.spawn_depth + 1,
            methodology_session=self.methodology_session,
            methodology_bundle=self.methodology_bundle,
        )
        try:
            return _run_with_timeout(lambda: subagent.run(instructions), timeout)
        except TimeoutError as exc:
            raise TimeoutError(f"subagent exceeded {timeout:.0f}s") from exc

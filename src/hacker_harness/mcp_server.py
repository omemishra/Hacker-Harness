from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Callable, TextIO

from . import __version__
from .config import load_config, load_scope, load_settings
from .models import project_root
from .state import StateStore
from .tools import TOOL_SPECS, ToolRegistry
from .workflows import WorkflowRunner, load_workflow, workflow_catalog, workflow_files

MCP_PROTOCOL_VERSION = "2025-06-18"
# Handshake-era versions Hermes/Claude still speak. Do not advertise 2026-07-28 (stateless).
SUPPORTED_PROTOCOL_VERSIONS = frozenset({"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"})
# Nested autonomy and nested MCP clients stay inside hh chat, not the executor surface.
EXCLUDED_EXECUTOR_TOOLS = frozenset({"spawn_agent"})
EXECUTOR_EXTRA_SPECS = [
    {
        "name": "scope_show",
        "description": "Show the active authorization scope (engagement, expiry, targets, exclusions, rules).",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "workflow_list",
        "description": "List YAML DAG workflows available in this engagement.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "workflow_run",
        "description": "Run a named YAML DAG workflow. Requires an explicit target. Human approval nodes still apply unless mcpServe.allowActive or engagement command mode is set.",
        "parameters": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "target": {"type": "string"},
                "inputs": {"type": "object", "additionalProperties": {"type": "string"}},
            },
            "required": ["name", "target"],
        },
    },
]


def mcp_active_allowed(settings: dict, command_mode: str) -> bool:
    env = os.environ.get("HACKER_HARNESS_MCP_ALLOW_ACTIVE", "").strip().lower()
    if env in {"1", "true", "yes"}:
        return True
    serve = settings.get("mcpServe") or {}
    if command_mode == "engagement":
        return True
    return bool(serve.get("allowActive", False))


def make_mcp_approve(settings: dict, command_mode: str) -> Callable[[str], bool]:
    allowed = mcp_active_allowed(settings, command_mode)

    def approve(question: str, session_key: str | None = None) -> bool:
        return allowed

    return approve


def _spec_to_mcp_tool(spec: dict) -> dict:
    return {
        "name": spec["name"],
        "description": spec.get("description", ""),
        "inputSchema": spec.get("parameters") or {"type": "object", "properties": {}},
    }


def executor_tool_specs() -> list[dict]:
    native = [spec for spec in TOOL_SPECS if spec["name"] not in EXCLUDED_EXECUTOR_TOOLS]
    return [*native, *EXECUTOR_EXTRA_SPECS]


class MCPExecutor:
    """JSON-RPC MCP server: other harnesses call HH tools; scope stays in the tool layer."""

    def __init__(
        self,
        root: Path | None = None,
        *,
        settings: dict | None = None,
        config=None,
        scope=None,
    ):
        self.root = (root or project_root()).resolve()
        self._load_from_disk = settings is None and config is None and scope is None
        self.settings = dict(settings if settings is not None else load_settings(self.root))
        self.settings["mcpServers"] = {}
        self.config = config or load_config(self.root)
        self.scope = scope or load_scope(self.root)
        self.state = StateStore(self.root)
        self.approve = make_mcp_approve(self.settings, self.config.policy.command_mode)
        self.tools = ToolRegistry(
            self.root,
            self.config,
            self.scope,
            self.state,
            approve=self.approve,
            settings=self.settings,
        )
        if self._load_from_disk:
            print(
                "hacker-harness executor "
                f"root={self.root} authorized={self.scope.is_active()} "
                f"commandMode={self.config.policy.command_mode} "
                f"allowActive={mcp_active_allowed(self.settings, self.config.policy.command_mode)}",
                file=sys.stderr,
            )

    def reload_operator_state(self) -> None:
        if not self._load_from_disk:
            return
        self.settings = dict(load_settings(self.root))
        self.settings["mcpServers"] = {}
        self.config = load_config(self.root)
        self.scope = load_scope(self.root)
        self.approve = make_mcp_approve(self.settings, self.config.policy.command_mode)
        self.tools.config = self.config
        self.tools.settings = self.settings
        self.tools.approve = self.approve
        self.tools.scope = self.scope
        self.tools.passive_domains = tuple(self.settings.get("passiveDomains") or [])

    def handle(self, message: dict) -> dict | None:
        if message.get("jsonrpc") != "2.0":
            return self._error(message.get("id"), -32600, "invalid JSON-RPC version")
        method = message.get("method")
        msg_id = message.get("id")
        if msg_id is None:
            return None
        try:
            if method == "initialize":
                params = message.get("params") or {}
                requested = str(params.get("protocolVersion") or MCP_PROTOCOL_VERSION)
                protocol = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else MCP_PROTOCOL_VERSION
                result = {
                    "protocolVersion": protocol,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "hacker-harness", "version": __version__},
                    "instructions": (
                        f"Hacker-Harness executor root={self.root}. "
                        "Scope still gates every HTTP/command/finding. "
                        "allowActive/commandMode=engagement only skip TTY approval, never scope. "
                        "Do not kill this process or start a second hh mcp serve. "
                        "workflow_run requires an explicit target."
                    ),
                }
            elif method == "ping":
                result = {}
            elif method == "logging/setLevel":
                result = {}
            elif method == "tools/list":
                result = {"tools": [_spec_to_mcp_tool(spec) for spec in executor_tool_specs()]}
            elif method == "tools/call":
                self.reload_operator_state()
                params = message.get("params") or {}
                result = self.call_tool(str(params.get("name") or ""), params.get("arguments") or {})
            else:
                return self._error(msg_id, -32601, f"method not found: {method}")
        except Exception as exc:
            return self._error(msg_id, -32603, str(exc))
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict:
        if not isinstance(arguments, dict):
            arguments = {}
        try:
            output = self._dispatch(name, arguments)
            return {"content": [{"type": "text", "text": output}], "isError": False}
        except Exception as exc:
            return {"content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}], "isError": True}

    def _dispatch(self, name: str, arguments: dict[str, Any]) -> str:
        if name == "scope_show":
            return self._scope_show()
        if name == "workflow_list":
            return self._workflow_list()
        if name == "workflow_run":
            return self._workflow_run(arguments)
        if name in EXCLUDED_EXECUTOR_TOOLS:
            raise PermissionError(f"{name} is not available on the MCP executor surface")
        result = self.tools.execute(name, arguments)
        if not result.ok:
            raise RuntimeError(result.output)
        return result.output

    def _scope_show(self) -> str:
        scope = self.tools.refresh_scope()
        payload = {
            "active": scope.is_active(),
            "authorized": scope.authorized,
            "engagement": scope.engagement,
            "expires_at": scope.expires_at.isoformat() if scope.expires_at else None,
            "targets": [item.value for item in scope.targets],
            "excluded": [item.value for item in scope.excluded],
            "rules": scope.rules,
            "project_root": str(self.root),
            "command_mode": self.config.policy.command_mode,
            "mcp_allow_active": mcp_active_allowed(self.settings, self.config.policy.command_mode),
        }
        return json.dumps(payload, indent=2)

    def _workflow_list(self) -> str:
        entries = [
            {
                "name": item["name"],
                "description": item["description"],
                "path": str(item["path"].relative_to(self.root)),
                "inputs": item["inputs"],
                "nodes": item["nodes"],
            }
            for item in workflow_catalog(self.root)
        ]
        return json.dumps(entries, indent=2)

    def _workflow_run(self, arguments: dict[str, Any]) -> str:
        name = str(arguments.get("name") or "").strip()
        target = str(arguments.get("target") or "").strip()
        extra = arguments.get("inputs") or {}
        if not name:
            raise ValueError("workflow_run requires name")
        if not target:
            raise ValueError("workflow_run requires an explicit target")
        inputs = {"target": target}
        if isinstance(extra, dict):
            inputs.update({str(key): str(value) for key, value in extra.items()})
        matches = [path for path in workflow_files(self.root) if load_workflow(path).name == name or path.stem == name]
        if len(matches) != 1:
            raise ValueError(f"expected one workflow named {name}, found {len(matches)}")
        workflow = load_workflow(matches[0])
        notes: list[str] = []
        runner = WorkflowRunner(self.root, approve=self.approve, emit=notes.append)
        run_id, outputs = runner.run(workflow, inputs)
        return json.dumps({"run_id": run_id, "nodes": list(outputs), "log": notes}, indent=2)

    def _error(self, msg_id: Any, code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def read_stdio_message(stream: TextIO) -> dict | None:
    first = stream.readline()
    if first == "":
        return None
    if first.lower().startswith("content-length:"):
        length = int(first.split(":", 1)[1].strip())
        while True:
            line = stream.readline()
            if line in ("", "\n", "\r\n"):
                break
        body = stream.read(length)
        return json.loads(body)
    line = first.strip()
    if not line:
        return read_stdio_message(stream)
    return json.loads(line)


TTY_USAGE = """\
hh mcp serve is stdin/stdout JSON-RPC for Hermes/Claude Code. It is not a TCP
server and has no port.

You do not run this yourself. After `hermes mcp add`, Hermes spawns
hh-mcp-serve in the background. Start a new Hermes session to use the tools.

Hand probe:  printf '%s\\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | hh mcp serve
Stay on this TTY:  hh mcp serve --foreground
"""


def write_stdio_message(stream: TextIO, message: dict) -> None:
    # Hermes (mcp Python SDK) and hh's own MCP client speak NDJSON, not HTTP-style
    # Content-Length frames. A Content-Length first line is parsed as JSON and
    # the client reports "Connection closed".
    line = json.dumps(message, separators=(",", ":")) + "\n"
    buf = getattr(stream, "buffer", None)
    if buf is not None:
        buf.write(line.encode("utf-8"))
        buf.flush()
        return
    stream.write(line)
    stream.flush()


def serve_stdio(root: Path | None = None, stdin: TextIO | None = None, stdout: TextIO | None = None, *, foreground: bool = False) -> int:
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    incoming = stdin or sys.stdin
    outgoing = stdout or sys.stdout
    if not foreground and incoming is sys.stdin and getattr(incoming, "isatty", lambda: False)():
        print(TTY_USAGE.rstrip(), file=sys.stderr)
        return 0
    executor: MCPExecutor | None = None
    while True:
        try:
            message = read_stdio_message(incoming)
        except json.JSONDecodeError:
            continue
        if message is None:
            return 0
        try:
            if executor is None:
                executor = MCPExecutor(root)
            reply = executor.handle(message)
        except Exception as exc:
            msg_id = message.get("id") if isinstance(message, dict) else None
            if msg_id is None:
                print(f"hacker-harness mcp serve: {type(exc).__name__}: {exc}", file=sys.stderr)
                continue
            reply = {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32603, "message": str(exc)}}
        if reply is not None:
            write_stdio_message(outgoing, reply)


def main() -> None:
    raise SystemExit(serve_stdio())

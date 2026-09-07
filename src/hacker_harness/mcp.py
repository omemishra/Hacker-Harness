from __future__ import annotations

import atexit
import json
import os
import re
import selectors
import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from .models import ScopeDocument
from .scope import _hostname, target_allowed


ENV_REF = re.compile(r"^\$\{([A-Z_][A-Z0-9_]*)\}$")
URL_REF = re.compile(r"https?://[^\s'\"]+")
# Playwright MCP uses ``target`` for snapshot element refs (e.g. e28), not URLs.
MCP_SCOPE_KEYS = frozenset({"url", "host", "hostname", "domain", "endpoint"})
MCP_ARGUMENT_ALIASES = {"ref": "target", "selector": "target", "locator": "target", "elementRef": "target"}
# Playwright element/DOM tools use ``target`` for snapshot refs (e28, f8e27) and CSS (#id), not hosts.
MCP_DOM_TOOLS = frozenset({
    "browser_type", "browser_click", "browser_drag", "browser_hover", "browser_select_option",
    "browser_fill_form", "browser_press_key", "browser_file_upload", "browser_drop", "browser_find",
    "browser_handle_dialog", "browser_evaluate", "browser_snapshot", "browser_take_screenshot",
    "browser_wait_for", "browser_tabs", "browser_resize", "browser_console_messages",
    "browser_navigate_back", "browser_close", "browser_network_requests",
})
MCP_NETWORK_TOOLS = frozenset({"browser_navigate", "browser_network_request"})
# Playwright element parameters are never hostnames; skip even if a caller recurses into them.
MCP_DOM_ARGUMENT_KEYS = frozenset({
    "target", "element", "text", "ref", "selector", "locator", "elementref",
    "starttarget", "endtarget", "startelement", "endelement",
    "fields", "name", "value", "submit", "key", "keys", "file", "files",
    "elementdescription", "description", "values",
})
MCP_SCOPE_POLICY_ID = "dom-tools-exempt-v2"
LOCAL_CONTROL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
ELEMENT_REF = re.compile(r"^#?[\w-]+$", re.I)
PLAYWRIGHT_SELECTOR_PREFIXES = ("xpath=", "css=", "text=", "role=", "id=", "nth=", "internal:")


class MCPError(RuntimeError):
    pass


class MCPClient:
    def __init__(self, name: str, config: dict, project: Path, approve: Callable[[str], bool]):
        self.name, self.config, self.project, self.approve = name, config, project, approve
        self.process: subprocess.Popen | None = None
        self.request_id = 0
        self.protocol_version = config.get("protocolVersion", "2025-06-18")

    def start(self) -> None:
        if self.process and self.process.poll() is None:
            return
        command = self.config.get("command")
        if not command:
            raise MCPError(f"MCP server '{self.name}' has no command")
        executable = command if Path(command).is_file() else shutil.which(command)
        if not executable:
            raise MCPError(f"MCP server '{self.name}' executable not found: {command}")
        args = [str(item) for item in self.config.get("args", [])]
        if self.config.get("requireStartupApproval", False) and not self.approve(
            f"MCP {self.name}: start server",
            session_key=f"MCP {self.name}",
        ):
            raise PermissionError(f"MCP server startup denied: {self.name}")
        env = os.environ.copy()
        for key, raw in self.config.get("env", {}).items():
            match = ENV_REF.fullmatch(str(raw))
            if match:
                if match.group(1) not in os.environ:
                    raise MCPError(f"MCP server '{self.name}' requires environment variable {match.group(1)}")
                env[key] = os.environ[match.group(1)]
            else:
                if any(marker in key.upper() for marker in ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "APIKEY")):
                    raise MCPError(f"MCP server '{self.name}' sensitive environment value {key} must use a reference such as ${{{key}}}")
                env[key] = str(raw)
        self.process = subprocess.Popen(
            [str(executable), *args], cwd=self.project, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", bufsize=1,
        )
        result = self.request("initialize", {
            "protocolVersion": self.protocol_version,
            "capabilities": {},
            "clientInfo": {"name": "hacker-harness", "version": "1.0.0"},
        })
        self.protocol_version = result.get("protocolVersion", self.protocol_version)
        self.notify("notifications/initialized", {})

    def _send(self, message: dict) -> None:
        if not self.process or not self.process.stdin:
            raise MCPError(f"MCP server is not running: {self.name}")
        self.process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.process.stdin.flush()

    def _read(self, timeout: float = 30.0) -> dict:
        if not self.process or not self.process.stdout:
            raise MCPError(f"MCP server is not running: {self.name}")
        selector = selectors.DefaultSelector()
        selector.register(self.process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise MCPError(f"MCP server '{self.name}' exited with {self.process.returncode}")
                if not selector.select(max(0.05, deadline - time.monotonic())):
                    continue
                line = self.process.stdout.readline()
                if not line:
                    continue
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        finally:
            selector.close()
        raise MCPError(f"MCP server '{self.name}' timed out")

    def request(self, method: str, params: dict) -> dict:
        self.request_id += 1
        request_id = self.request_id
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        while True:
            message = self._read(float(self.config.get("timeoutSeconds", 30)))
            if message.get("id") != request_id:
                if "id" in message and "method" in message:
                    self._send({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "Client method not supported"}})
                continue
            if "error" in message:
                error = message["error"]
                raise MCPError(f"{self.name} {method}: {error.get('message', error)}")
            return message.get("result") or {}

    def notify(self, method: str, params: dict) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def list_tools(self) -> list[dict]:
        self.start()
        tools, cursor = [], None
        while True:
            result = self.request("tools/list", {"cursor": cursor} if cursor else {})
            tools.extend(result.get("tools", []))
            cursor = result.get("nextCursor")
            if not cursor:
                return tools

    def call_tool(self, name: str, arguments: dict) -> str:
        self.start()
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        blocks = []
        for block in result.get("content", []):
            if block.get("type") == "text":
                blocks.append(block.get("text", ""))
            else:
                blocks.append(f"[{block.get('type', 'content')} content]")
        if result.get("structuredContent") is not None:
            blocks.append(json.dumps(result["structuredContent"], indent=2, default=str))
        text = "\n".join(item for item in blocks if item)
        if result.get("isError"):
            raise MCPError(text or f"MCP tool failed: {name}")
        return text or "MCP tool completed"

    def close(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()


class MCPManager:
    def __init__(self, project: Path, servers: dict, approve: Callable[[str], bool], scope: ScopeDocument):
        self.project, self.approve, self.scope = project, approve, scope
        self.clients = {name: MCPClient(name, config, project, approve) for name, config in servers.items() if isinstance(config, dict) and config.get("enabled", True)}
        self.tool_map: dict[str, tuple[str, str]] = {}
        self.cached_specs: list[dict] | None = None
        self.errors: dict[str, str] = {}
        atexit.register(self.close)

    def discover(self, refresh: bool = False) -> list[dict]:
        if self.cached_specs is not None and not refresh:
            return self.cached_specs
        self.cached_specs, self.tool_map, self.errors = [], {}, {}
        for server_name, client in self.clients.items():
            try:
                for tool in client.list_tools():
                    original = tool.get("name", "tool")
                    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", original)
                    exposed = f"mcp__{server_name}__{safe}"
                    self.tool_map[exposed] = (server_name, original)
                    self.cached_specs.append({"name": exposed, "description": f"MCP {server_name}: {tool.get('description', original)}", "parameters": tool.get("inputSchema") or {"type": "object", "properties": {}}})
            except Exception as exc:
                self.errors[server_name] = str(exc)
        return self.cached_specs

    def handles(self, name: str) -> bool:
        return name in self.tool_map

    def call(self, exposed_name: str, arguments: dict) -> str:
        if exposed_name not in self.tool_map:
            self.discover()
        if exposed_name not in self.tool_map:
            raise MCPError(f"unknown MCP tool: {exposed_name}")
        server_name, original = self.tool_map[exposed_name]
        config = self.clients[server_name].config
        arguments = self._normalize_arguments(arguments)
        self._apply_mcp_scope_policy(original, arguments)
        if config.get("requireToolApproval", True):
            prompt = self._tool_prompt(server_name, original, arguments)
            if not self.approve(prompt, session_key=f"MCP {server_name}"):
                raise PermissionError(f"MCP tool call denied: {server_name}/{original}")
        return self.clients[server_name].call_tool(original, arguments)

    def _apply_mcp_scope_policy(self, original: str, arguments: dict) -> None:
        """Validate only network-bearing MCP calls; never treat DOM refs/selectors as hosts."""
        if original in MCP_DOM_TOOLS:
            return
        if original in MCP_NETWORK_TOOLS:
            self._validate_targets(arguments)
            return
        if original == "browser_run_code_unsafe" or any(
            key in arguments for key in ("code", "expression", "script")
        ):
            self._validate_embedded_urls(arguments)
            return
        self._validate_targets(arguments)

    def _normalize_arguments(self, arguments: dict) -> dict:
        if not isinstance(arguments, dict):
            return arguments
        return self._normalize_argument_tree(arguments)

    def _normalize_argument_tree(self, value):
        if isinstance(value, dict):
            normalized = dict(value)
            for alias, canonical in MCP_ARGUMENT_ALIASES.items():
                if alias in normalized and canonical not in normalized:
                    normalized[canonical] = normalized.pop(alias)
            return {key: self._normalize_argument_tree(item) for key, item in normalized.items()}
        if isinstance(value, list):
            return [self._normalize_argument_tree(item) for item in value]
        return value

    def _looks_like_network_target(self, value: str) -> bool:
        text = value.strip()
        lower = text.lower()
        if not text or text.startswith(("#", ".", "[", "(", "/")):
            return False
        if any(lower.startswith(prefix) for prefix in PLAYWRIGHT_SELECTOR_PREFIXES):
            return False
        if lower.startswith("//") and "://" not in lower:
            return False
        if "://" in text:
            return lower.startswith(("http://", "https://"))
        if ELEMENT_REF.fullmatch(text) and "." not in text:
            return False
        if re.fullmatch(r"[a-f]?\w*\d+\w*", text, re.I) and "." not in text and "/" not in text:
            return False
        return "." in text and "=" not in text.split(".", 1)[0]

    def _scope_host_from_url(self, raw: str) -> str:
        if not raw.lower().startswith(("http://", "https://")):
            return ""
        try:
            host = _hostname(raw)
        except ValueError:
            return ""
        if not host or "=" in host:
            return ""
        return host

    def _network_host(self, value: str, key: str) -> str:
        if key.lower() not in MCP_SCOPE_KEYS:
            return ""
        if not self._looks_like_network_target(value):
            return ""
        try:
            host = _hostname(value)
        except ValueError:
            return ""
        if host.lower() in LOCAL_CONTROL_HOSTS:
            return ""
        return host

    def _deny_host(self, host: str) -> None:
        if not host or host.lower() in LOCAL_CONTROL_HOSTS:
            return
        if not target_allowed(host, self.scope):
            raise PermissionError(
                f"MCP target is not in the active authorization scope: {host} "
                f"[policy={MCP_SCOPE_POLICY_ID}]"
            )

    def _validate_embedded_urls(self, value, key: str = "") -> None:
        if isinstance(value, dict):
            for item_key, item_value in value.items():
                self._validate_embedded_urls(item_value, str(item_key))
        elif isinstance(value, list):
            for item in value:
                self._validate_embedded_urls(item, key)
        elif isinstance(value, str):
            for raw in URL_REF.findall(value):
                self._deny_host(self._scope_host_from_url(raw))

    def _tool_prompt(self, server_name: str, tool_name: str, arguments: dict) -> str:
        host = self._argument_host(arguments)
        if host:
            return f"MCP {server_name} · {tool_name} · {host}"
        return f"MCP {server_name} · {tool_name}"

    def _argument_host(self, value, key: str = "") -> str:
        if isinstance(value, dict):
            for item_key, item_value in value.items():
                found = self._argument_host(item_value, str(item_key))
                if found:
                    return found
        elif isinstance(value, list):
            for item in value:
                found = self._argument_host(item, key)
                if found:
                    return found
        elif isinstance(value, str):
            if key.lower() in MCP_DOM_ARGUMENT_KEYS:
                return ""
            host = self._network_host(value, key)
            if host:
                return host
            for raw in URL_REF.findall(value):
                host = self._scope_host_from_url(raw)
                if host:
                    return host
        return ""

    def _validate_targets(self, value, key: str = "") -> None:
        if isinstance(value, dict):
            for item_key, item_value in value.items():
                self._validate_targets(item_value, str(item_key))
        elif isinstance(value, list):
            for item in value:
                self._validate_targets(item, key)
        elif isinstance(value, str):
            if key.lower() in MCP_DOM_ARGUMENT_KEYS:
                return
            host = self._network_host(value, key)
            if host:
                self._deny_host(host)
            for raw in URL_REF.findall(value):
                self._deny_host(self._scope_host_from_url(raw))

    def status(self) -> list[dict]:
        return [{"name": name, "connected": bool(client.process and client.process.poll() is None), "tools": sum(1 for server, _tool in self.tool_map.values() if server == name), "error": self.errors.get(name, "")} for name, client in self.clients.items()]

    def close(self) -> None:
        for client in self.clients.values():
            client.close()

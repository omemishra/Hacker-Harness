from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Callable

from .skills import PLAYBOOK_VAULT_DIR

InputFn = Callable[[str], str]

PLAYWRIGHT_MCP_CONFIG = {
    "enabled": True,
    "command": "npx",
    "args": [
        "-y",
        "@playwright/mcp@latest",
        "--headless",
        "--browser",
        "chromium",
        "--isolated",
    ],
    "env": {},
    "protocolVersion": "2025-06-18",
    "timeoutSeconds": 30,
    "requireStartupApproval": False,
    "requireToolApproval": True,
}

PLAYWRIGHT_INSTALL_HINT = """\
Playwright MCP browser binaries (run once per machine):
  npx @playwright/mcp install-browser chrome-for-testing"""

OBSIDIAN_WIKI_HINT = """\
Obsidian wiki (optional, recommended for playbook RAG):
  git clone https://github.com/ar9av/obsidian-wiki ~/obsidian-wiki
  Set OBSIDIAN_VAULT_PATH in ~/obsidian-wiki/config to your vault folder.
  Playbooks are stored under concepts/patterns/ inside the vault."""

def caido_mcp_config() -> dict:
    command = os.environ.get("HACKER_HARNESS_CAIDO_MCP", "").strip() or shutil.which("caido-mcp-server") or "caido-mcp-server"
    return {
        "enabled": True,
        "command": command,
        "args": ["serve"],
        "env": {"CAIDO_URL": "http://127.0.0.1:8080"},
        "protocolVersion": "2025-06-18",
        "timeoutSeconds": 60,
        "requireStartupApproval": False,
        "requireToolApproval": True,
    }


CAIDO_INSTALL_HINT = """\
Caido MCP (community server, not affiliated with Caido):
  git clone --branch v1.1.0 https://github.com/c0tton-fluff/caido-mcp-server.git
  cd caido-mcp-server && go build -o caido-mcp-server .
  ./caido-mcp-server login -u http://127.0.0.1:8080
  Put the binary on PATH, or set HACKER_HARNESS_CAIDO_MCP to its path.
  Docs: https://docs.caido.io/app/tutorials/mcp"""


def default_vault_candidates() -> list[str]:
    candidates: list[str] = []
    wiki_config = Path("~/.obsidian-wiki/config").expanduser()
    if wiki_config.is_file():
        for line in wiki_config.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("OBSIDIAN_VAULT_PATH="):
                raw = stripped.split("=", 1)[1].strip().strip("'\"")
                if raw:
                    candidates.append(str(Path(raw).expanduser()))
    candidates.append(str(Path("~/Targets").expanduser()))
    seen: set[str] = set()
    unique: list[str] = []
    for item in candidates:
        key = str(Path(item).expanduser().resolve()) if Path(item).expanduser().exists() else item
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def bootstrap_obsidian_vault(vault: Path) -> list[str]:
    """Create minimal obsidian-wiki-friendly layout for playbooks and ingest."""
    vault = vault.expanduser().resolve()
    vault.mkdir(parents=True, exist_ok=True)
    created: list[str] = []
    layout = {
        "index.md": "# Engagement knowledge\n\nRouter index for the Hacker-Harness vault. Add target notes under `concepts/`.\n",
        f"{PLAYBOOK_VAULT_DIR}/.gitkeep": "",
        "_raw/.gitkeep": "",
        "concepts/.gitkeep": "",
    }
    for relative, content in layout.items():
        path = vault / relative
        if path.exists():
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        created.append(str(path.relative_to(vault)))
    return created


def default_mcp_document() -> dict:
    return {
        "version": 1,
        "mcpServers": {
            "playwright": dict(PLAYWRIGHT_MCP_CONFIG),
            "caido": caido_mcp_config(),
        },
    }


def configure_obsidian_vault(settings: dict, vault: Path) -> dict:
    updated = dict(settings)
    updated["obsidianVault"] = str(vault.expanduser().resolve())
    return updated


def configure_caido_mcp(settings: dict) -> dict:
    updated = dict(settings)
    servers = dict(updated.get("mcpServers") or {})
    servers["caido"] = caido_mcp_config()
    updated["mcpServers"] = servers
    return updated


def configure_playwright_mcp(settings: dict) -> dict:
    updated = dict(settings)
    servers = dict(updated.get("mcpServers") or {})
    servers["playwright"] = dict(PLAYWRIGHT_MCP_CONFIG)
    updated["mcpServers"] = servers
    return updated


def _parse_yes_no(answer: str, *, default: bool) -> bool:
    text = answer.strip().lower()
    if not text:
        return default
    return text in {"y", "yes"}


def run_project_setup(
    project: Path,
    settings: dict,
    *,
    input_fn: InputFn,
    interactive: bool = True,
) -> tuple[dict, list[str]]:
    """Interactive post-init setup for vault, playbooks, and Playwright MCP."""
    messages: list[str] = []
    if not interactive:
        return settings, messages

    updated = dict(settings)
    print("\nOptional project setup (API keys and scope.yaml stay manual).\n")

    candidates = default_vault_candidates()
    default_path = candidates[0] if candidates else str(Path("~/Targets").expanduser())
    print("Obsidian vault — stores playbooks (concepts/patterns/) and wiki knowledge for search.")
    print(OBSIDIAN_WIKI_HINT)
    vault_answer = input_fn(f"Vault folder path [{default_path}] (Enter=use, -=skip): ").strip()
    if vault_answer == "-":
        messages.append("skipped obsidian vault")
    else:
        raw = vault_answer or default_path
        vault = Path(raw).expanduser()
        if not vault.is_dir():
            create = _parse_yes_no(
                input_fn(f"  {vault} does not exist. Create vault skeleton? [Y/n]: "),
                default=True,
            )
            if not create:
                messages.append("skipped obsidian vault (path missing)")
            else:
                created = bootstrap_obsidian_vault(vault)
                if created:
                    messages.append(f"created vault layout: {', '.join(created)}")
        if vault.is_dir():
            updated = configure_obsidian_vault(updated, vault)
            bootstrap_obsidian_vault(vault)
            messages.append(f"obsidianVault → {vault.resolve()}")
            messages.append(f"playbooks → {vault.resolve() / PLAYBOOK_VAULT_DIR}")

    playwright_answer = input_fn("Enable Playwright MCP for browser testing? [Y/n]: ")
    servers = dict(updated.get("mcpServers") or default_mcp_document()["mcpServers"])
    updated["mcpServers"] = servers
    if _parse_yes_no(playwright_answer, default=True):
        updated = configure_playwright_mcp(updated)
        messages.append("enabled mcpServers.playwright")
        print(PLAYWRIGHT_INSTALL_HINT)
    else:
        servers.setdefault("playwright", dict(PLAYWRIGHT_MCP_CONFIG))
        servers["playwright"]["enabled"] = False
        messages.append("mcpServers.playwright disabled")

    caido_answer = input_fn("Enable Caido MCP (proxy at 127.0.0.1:8080)? [y/N]: ")
    servers = dict(updated.get("mcpServers") or {})
    updated["mcpServers"] = servers
    if _parse_yes_no(caido_answer, default=False):
        updated = configure_caido_mcp(updated)
        messages.append("enabled mcpServers.caido")
        print(CAIDO_INSTALL_HINT)
    elif "caido" in servers:
        servers["caido"]["enabled"] = False
        messages.append("mcpServers.caido disabled")

    print("\nSetup complete. Still edit scope.yaml and provider API keys before active testing.\n")
    return updated, messages


def save_settings(project: Path, settings: dict) -> Path:
    from .config import save_settings as persist

    persist(project, settings)
    return project / ".hacker-harness" / "settings.json"

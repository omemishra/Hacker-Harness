from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from . import __version__
from .agent import Agent, conversation_turns
from .config import deep_merge, load_config, load_obsidian_vault, load_mcp_servers, load_scope, load_settings, resolve_context_window, save_mcp_document, save_settings
from .models import Workflow, project_root
from .methodology import STAGE_HEADING, MethodologyRunner, chat_methodology_bundle, discover_documents, discover_workflows, init_methodology, load_methodology, missing_requirements, validate_methodology
from .line_editor import LineEditor
from .providers import ProviderError
from .mcp import MCP_SCOPE_POLICY_ID
from .scope import target_allowed
from .memory import MEMORY_RELATIVE, curate_operator_memory, ensure_memory_file
from .project_seed import seed_methodology_library, seed_skill_library, seed_stage_manifests, seed_workflow_library
from .project_setup import default_mcp_document, run_project_setup, save_settings as save_project_settings
from .skills import discover_skill_entries, init_skill, resolve_skill_entry, validate_skill
from .state import StateStore
from .tui import TerminalUI
from .tools import TOOL_SPECS
from .workflows import WorkflowRunner, init_workflow, load_workflow, parse_workflow_invocation, resolve_yaml_workflow_name, topological, workflow_catalog, workflow_files, yaml_workflow_names

SETTINGS_TEMPLATE = {
    "version": 4,
    "activeProvider": "openai",
    "providers": {
        "openai": {"format": "openai", "model": "gpt-5-mini", "apiKey": "${OPENAI_API_KEY}", "contextWindow": 128000},
        "deepseek-openai": {"format": "openai", "baseUrl": "https://api.deepseek.com", "model": "deepseek-v4-pro", "apiKey": "${DEEPSEEK_API_KEY}", "contextWindow": 1000000},
        "deepseek-anthropic": {"format": "anthropic", "baseUrl": "https://api.deepseek.com/anthropic", "model": "deepseek-v4-pro", "apiKey": "${DEEPSEEK_API_KEY}", "contextWindow": 1000000},
        "kimi-openai": {"format": "openai", "baseUrl": "https://YOUR-KIMI-ENDPOINT.example/v1", "model": "YOUR-KIMI-MODEL", "apiKey": "${KIMI_API_KEY}"},
        "kimi-anthropic": {"format": "anthropic", "baseUrl": "https://YOUR-KIMI-ANTHROPIC-ENDPOINT.example", "model": "YOUR-KIMI-MODEL", "apiKey": "${KIMI_API_KEY}"},
    },
    "permissions": {"commandMode": "strict", "allowFileWrites": True},
    "agent": {"maxToolRounds": 60, "maxFailedToolRounds": 20, "commandTimeoutSeconds": 120, "maxOutputChars": 50000, "maxSubagents": 4, "subagentTimeoutSeconds": 600, "autoCompactPercent": 50},
    "systemPromptFile": ".hacker-harness/SYSTEM.md",
    "skillPaths": [".hacker-harness/skills"],
    "knowledgePaths": [],
    "obsidianVault": "",
    "passiveDomains": ["web.archive.org", "crt.sh", "api.preview.is", "otx.alienvault.com", "urlscan.io", "api.github.com", "raw.githubusercontent.com", "gist.githubusercontent.com", "securitytrails.com", "dns.google", "cloudflare-dns.com", "one.one.one.one", "interactsh.com", "interact.sh", "oastify.com", "burpcollaborator.net", "canarytokens.org", "github.com"],
    "engagementRoot": "",
    "methodologyPaths": ["methodology"],
    "workflowPaths": ["workflows"],
    "methodologies": {"strictByDefault": True, "offerInstallMissing": True, "autoRoute": True},
    "mcpServe": {"allowActive": False},
    "ui": {
        "theme": "hacker",
        "largeBanner": True,
        "toolCards": True,
        "toolCardMode": "summary",
        "showToolOutput": True,
        "maxToolOutputLines": 12,
        "methodologyProgress": True,
        "showContext": True,
        "fullscreen": True,
    },
}
SCOPE_TEMPLATE = {"engagement": "UNCONFIGURED - replace before testing", "authorized": False, "owner": "", "expires_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(), "targets": [{"value": "example.com", "notes": "Replace with an authorized target"}], "excluded": [], "rules": ["Only test assets explicitly listed above", "Respect rate limits and program rules"]}
SYSTEM_TEMPLATE = """# Hacker-Harness Instructions

You are a full-capability offensive-security agent for authorized penetration tests, bug bounty programs, and secure engineering.
Confirm scope before active network actions. Never target excluded assets, expand beyond authorization,
persist on systems, disrupt availability, or expose real user data. Use the minimum requests needed to
validate a finding. Within scope, actively perform reconnaissance, web/API and access-control testing,
business-logic review, evidence capture, triage, and reporting. Preserve exact evidence and produce
reproducible, remediation-focused reports.
Use the supplied sanitized runtime context instead of reading `.hacker-harness` control files. Load only the
workflow or framework selected by the operator; do not inventory every methodology document.
Prefer http_request for in-scope HTTP fetches. Do not use curl/wget unless the hostname is in the active scope;
the harness blocks out-of-scope network commands on purpose.
"""
WORKFLOW_TEMPLATE = """name: authorized-web-review
description: Plan, approve, and document a scoped web security review
version: 1
inputs:
  target: example.com
nodes:
  - id: plan
    description: Build a scope-aware test plan
    prompt: >-
      Create a concise, non-destructive security test plan for {{ target }}. Read the scope manifest first.
      Do not execute network requests. Include stop conditions and evidence requirements.
    save_output: .hacker-harness/artifacts/test-plan.md
  - id: authorize
    description: Human authorization gate
    depends_on: [plan]
    approval: "Confirm that {{ target }} is authorized and approve the planned active testing?"
  - id: review
    description: Review existing local evidence
    depends_on: [authorize]
    prompt: >-
      Review local evidence and the test plan for {{ target }}. Identify gaps and prioritize safe validation.
    save_output: .hacker-harness/artifacts/review.md
"""
SCOPED_WEB_TRIAGE_WORKFLOW = """name: scoped-web-triage
description: Authorized web triage with signal tracking and human approval gates
version: 1
inputs:
  target: example.com
nodes:
  - id: scope_review
    description: Confirm authorization boundaries
    prompt: >-
      Review the active authorization scope for {{ target }}. Use scope_check on the target.
      Summarize allowed assets, exclusions, and rate-limit rules. Do not run active attacks yet.
      Narrate what you are checking as you work so the operator can follow along.
    save_output: .hacker-harness/artifacts/scope-review-{{ target }}.md
  - id: authorize
    description: Human authorization gate for active triage
    depends_on: [scope_review]
    approval: "Approve active web triage against {{ target }} within the current scope?"
  - id: surface_map
    description: Map attack surface with minimal requests
    depends_on: [authorize]
    prompt: >-
      Perform scoped surface mapping for {{ target }}: routes, auth flows, APIs, headers, cookies.
      Prefer passive review and low-impact requests. Record unconfirmed leads with signal_record only.
      Do not claim vulnerabilities without evidence. Narrate live: say what endpoint or behavior you
      are probing, what you observe, and why it might matter (e.g. reflected input, verbose errors)
      before recording a signal.
    save_output: .hacker-harness/artifacts/surface-map-{{ target }}.md
  - id: triage
    description: Triage signals into evidence-backed findings
    depends_on: [surface_map]
    prompt: >-
      Review signal findings for {{ target }}. Advance only evidence-backed items using
      finding_advance (signal→confirmed→ready). Dismiss false positives with finding_dismiss.
      Use finding_create only when you already have confirmed evidence and remediation guidance.
      Explain each triage decision out loud: what you are validating, exploit attempts you make,
      and whether it holds up.
  - id: summarize
    description: Engagement triage summary
    depends_on: [triage]
    prompt: >-
      Summarize the triage for {{ target }}: signals, confirmed, ready, dismissed, and gaps.
      List safe next steps the operator can approve.
    save_output: .hacker-harness/artifacts/triage-summary-{{ target }}.md
"""


def approve(question: str) -> bool:
    try:
        return input(f"\nAPPROVAL REQUIRED: {question}\nApprove? [y/N] ").strip().lower() in {"y", "yes"}
    except EOFError:
        return False


def enqueue_chat_followup(pending: list[str], text: str) -> str | None:
    """Queue text typed while a run is in progress as the next chat message.

    Returns a short operator notice, or None when there is nothing to queue.
    Does not create persistent tasks — those remain an explicit ``/comment``.
    """
    value = text.strip()
    if value.startswith("/comment "):
        value = value[len("/comment "):].strip()
    if not value:
        return None
    pending.append(value)
    preview = value if len(value) <= 72 else value[:69] + "..."
    return f"Queued next message ({len(pending)}): {preview}"


def resolve_provider_profile(requested: str | None, profiles: dict) -> str | None:
    """Map picker / ``/model`` input onto an existing provider profile name."""
    if not requested:
        return None
    value = requested.strip()
    if value in profiles:
        return value
    lowered = {name.lower(): name for name in profiles}
    if value.lower() in lowered:
        return lowered[value.lower()]
    if value.isdigit():
        names = list(profiles)
        index = int(value)
        if 1 <= index <= len(names):
            return names[index - 1]
    prefixes = [name for name in profiles if name.lower().startswith(value.lower())]
    if len(prefixes) == 1:
        return prefixes[0]
    hits = [name for name in profiles if name.lower() in value.lower().replace("●", " ").replace("○", " ")]
    if len(hits) == 1:
        return hits[0]
    return None


def replay_session_transcript(ui, messages: list[dict], context: dict | None = None) -> int:
    """Redraw saved user/assistant turns into the live conversation surface.

    Historic You turns are drawn without a live context meter so resume does
    not stamp current token usage onto every prior prompt. ``context`` is
    accepted for call-site compatibility and ignored.
    """
    count = 0
    ui._instant_assistant = True
    try:
        for role, content in conversation_turns(messages):
            if role == "user":
                ui.user(content)
            else:
                ui.assistant(content)
            count += 1
    finally:
        ui._instant_assistant = False
    return count


SAFE_SETTINGS_KEYS = ("skillPaths", "knowledgePaths", "obsidianVault", "passiveDomains", "engagementRoot", "methodologyPaths", "workflowPaths", "methodologies", "ui", "permissions", "agent", "systemPromptFile", "mcpServe")


def migrate_settings(project: Path) -> None:
    """Merge newly introduced settings keys into an existing project without touching
    operator-owned values (activeProvider, providers, scope, SYSTEM.md)."""
    path = project / ".hacker-harness" / "settings.json"
    if not path.exists():
        return
    existing = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(existing, dict):
        return
    defaults = {key: SETTINGS_TEMPLATE[key] for key in SAFE_SETTINGS_KEYS if key in SETTINGS_TEMPLATE}
    merged = deep_merge(defaults, existing)
    paths = list(merged.get("methodologyPaths", []))
    if paths == [".hacker-harness/methodologies"]:
        merged["methodologyPaths"] = ["methodology"]
    if not merged.get("workflowPaths"):
        merged["workflowPaths"] = ["workflows"]
    legacy_servers = merged.pop("mcpServers", None) if isinstance(merged.get("mcpServers"), dict) else None
    mcp_path = project / ".hacker-harness" / "mcp.json"
    if not mcp_path.exists():
        servers = legacy_servers if legacy_servers else default_mcp_document()["mcpServers"]
        save_mcp_document(project, servers)
    elif legacy_servers:
        save_mcp_document(project, deep_merge(legacy_servers, load_mcp_servers(project)))
    if isinstance(existing.get("version"), int) and existing["version"] >= SETTINGS_TEMPLATE["version"] and merged == existing and mcp_path.exists() and "mcpServers" not in existing:
        return
    merged["version"] = SETTINGS_TEMPLATE["version"]
    merged.pop("mcpServers", None)
    if merged != existing or (legacy_servers is not None and "mcpServers" in existing):
        save_settings(project, merged)

def print_table(headers: list[str], rows: list[list[str]]) -> None:
    widths = [len(h) for h in headers]
    for row in rows:
        widths = [max(widths[i], len(str(v))) for i, v in enumerate(row)]
    print("  ".join(headers[i].ljust(widths[i]) for i in range(len(headers))))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print("  ".join(str(row[i]).ljust(widths[i]) for i in range(len(headers))))


def cmd_init(args) -> int:
    project, hh = Path(args.path).resolve(), Path(args.path).resolve() / ".hacker-harness"
    if hh.exists() and not args.force:
        print(f"error: {hh} already exists; use --force", file=sys.stderr)
        return 2
    (hh / "artifacts").mkdir(parents=True, exist_ok=True)
    (hh / "skills").mkdir(parents=True, exist_ok=True)
    seed_methodology_library(project, force=args.force)
    seed_workflow_library(project, force=args.force)
    seed_skill_library(project, force=args.force)
    seed_stage_manifests(project, force=args.force)
    settings = json.loads(json.dumps(SETTINGS_TEMPLATE))
    mcp_doc = default_mcp_document()
    files = {
        hh / "settings.json": json.dumps(settings, indent=2) + "\n",
        hh / "mcp.json": json.dumps(mcp_doc, indent=2) + "\n",
        hh / "scope.yaml": yaml.safe_dump(SCOPE_TEMPLATE, sort_keys=False),
        hh / "SYSTEM.md": SYSTEM_TEMPLATE,
    }
    for target, content in files.items():
        if args.force or not target.exists():
            target.write_text(content, encoding="utf-8")
    ensure_memory_file(project)
    StateStore(project)
    interactive = not args.no_setup and sys.stdin.isatty()
    settings["mcpServers"] = dict(mcp_doc["mcpServers"])
    settings, notes = run_project_setup(project, settings, input_fn=input, interactive=interactive)
    save_project_settings(project, settings)
    print(f"Hacker-Harness initialized in {project}")
    for note in notes:
        print(f"  • {note}")
    print("Edit .hacker-harness/scope.yaml and provider API keys before active testing.")
    return 0


def cmd_setup(args) -> int:
    project = Path(args.path).resolve()
    hh = project / ".hacker-harness"
    if not hh.is_dir():
        print(f"error: {hh} not found; run `hh init` first", file=sys.stderr)
        return 2
    settings = load_settings(project)
    interactive = not args.no_setup and sys.stdin.isatty()
    settings, notes = run_project_setup(project, settings, input_fn=input, interactive=interactive)
    save_project_settings(project, settings)
    print(f"Updated setup in {project}")
    for note in notes:
        print(f"  • {note}")
    return 0


def show_ready(project: Path) -> None:
    rows = [[t["id"], str(t["priority"]), t["status"], t["title"]] for t in StateStore(project).ready_tasks()]
    print_table(["ID", "P", "Status", "Title"], rows)


def show_scope(project: Path) -> None:
    scope = load_scope(project)
    print(f"Source: {(project / '.hacker-harness' / 'scope.yaml').resolve()}")
    print(f"Authorization scope: {'ACTIVE' if scope.is_active() else 'INACTIVE'}")
    print(f"Engagement: {scope.engagement}\nExpires: {scope.expires_at}\nTargets:")
    for target in scope.targets:
        print(f"  - {target.value}")


BUILTIN_SLASH_COMMANDS = [
    "help", "commands", "scope", "skills", "methodologies", "workflows", "workflow", "use", "advance",
    "pivot", "report", "retest", "tree", "model", "provider", "version", "context", "compact",
    "sessions", "resume", "new", "tools", "mcp", "goals", "goal", "comment", "remember",
    "findings", "validate", "vulns", "settings", "tasks", "clear", "quit", "exit"
]
OFFENSIVE_TOOL_NAMES = ["nmap", "nuclei", "httpx", "subfinder", "amass", "naabu", "katana", "gau", "ffuf", "sqlmap", "dalfox", "masscan", "gobuster", "feroxbuster"]


def session_rows(store: StateStore) -> str:
    sessions = store.list_sessions()
    if not sessions:
        return "No saved sessions."
    return "\n".join(
        f"{item['id']}  ·  {item['message_count']} messages  ·  {item['provider']}/{item['model']}  ·  {item['title'] or 'Untitled'}"
        for item in sessions
    )


def activate_methodology_context(project: Path, ui: TerminalUI, agent: Agent, command: str, contexts: dict[str, tuple[Path, Path]]) -> bool:
    folder, document = contexts[command]
    methodology = load_methodology(project, folder, document.name)
    runner = MethodologyRunner(project, emit=ui.methodology, approve=ui.approve, event_handler=ui.event)
    runner.preflight(methodology)
    required_mcp = {item.name for item in methodology.requirements if item.kind == "mcp"}
    if required_mcp:
        agent.tools.mcp.discover(refresh=True)
        connected = {item["name"] for item in agent.tools.mcp.status() if item["connected"]}
        unavailable = sorted(required_mcp - connected)
        if unavailable:
            raise PermissionError(f"required MCP server connection failed: {', '.join(unavailable)}")
    bundle, session = chat_methodology_bundle(methodology, project, command)
    loaded = agent.apply_methodology(f"methodology /{command}", bundle, session)
    ui.notice(f"{'Loaded' if loaded else 'Already active'} {methodology_short_name(command)}: stage 1/{len(methodology.stages)} · {'strict' if methodology.strict else 'advisory'} · current-stage context only", "ok")
    return loaded


def route_methodology(prompt: str, contexts: dict[str, tuple[Path, Path]], agent: Agent) -> str | None:
    lowered = prompt.lower()
    active = "\n".join(str(message.get("content", "")) for message in agent.messages if message.get("role") == "system")
    scored = []
    for command in contexts:
        if f"methodology /{command}" in active:
            continue
        tokens = [token for token in command.split("-") if token not in {"workflow", "framework", "methodology"} and len(token) >= 4]
        score = sum(1 for token in tokens if token in lowered)
        if score:
            preference = 1 if command.endswith("-workflow") else 0
            scored.append((score, preference, command))
    if not scored:
        return None
    scored.sort(reverse=True)
    if len(scored) > 1 and scored[0][:2] == scored[1][:2]:
        return None
    return scored[0][2]


def cmd_chat(args) -> int:
    project = project_root()
    migrate_settings(project)
    settings, config, scope = load_settings(project), load_config(project), load_scope(project)
    from .fullscreen import ChatOutput, LinearChat, SpinnerStream, is_fullscreen_available

    def interactive_terminal() -> bool:
        try:
            return bool(sys.stdin.isatty()) and bool(sys.stdout.isatty())
        except Exception:
            return False

    use_fullscreen = is_fullscreen_available(settings)
    use_linear = not use_fullscreen and LinearChat.available() and interactive_terminal()
    fullscreen = None
    linear = None
    output = None
    spinner = None
    if use_fullscreen:
        output = ChatOutput()
        ui = TerminalUI(project, settings, stream=output)
    elif use_linear:
        # Wraps stdout so the thinking animation yields to real output.
        spinner = SpinnerStream(sys.stdout)
        ui = TerminalUI(project, settings, stream=spinner)
    else:
        ui = TerminalUI(project, settings)
    store = StateStore(project)
    resume_id = getattr(args, "resume", None)
    restored = store.get_session(resume_id) if resume_id else None
    if resume_id and not restored:
        raise ValueError(f"session not found: {resume_id}")
    agent = Agent(project, approve=ui.approve, event_handler=ui.event, restored_messages=restored["messages"] if restored else None)
    if restored:
        session_id = restored["id"]
        agent.input_tokens = restored["input_tokens"]
        agent.output_tokens = restored["output_tokens"]
    else:
        session_id = store.create_session(config.api_profile or config.provider.kind, config.provider.model, agent.messages)
    recent_sessions = [item.get("title") or item["id"] for item in store.list_sessions(limit=5)]
    ui.header(__version__, config.api_profile or config.provider.kind, config.provider.model, scope.is_active(), session_id, len(TOOL_SPECS), len(agent.loaded_skills), bool(restored), recent_sessions=recent_sessions)
    ui.write()  # gap between the banner and the conversation area
    ui.write()
    if restored:
        # Agent already holds the full message list for the next prompt; redraw
        # prior user/assistant turns so resume is not a blank conversation pane.
        replay_session_transcript(ui, agent.messages, agent.context_status())

    def command_names() -> list[str]:
        return sorted(set(BUILTIN_SLASH_COMMANDS + list(methodology_commands(project))))

    history_path = project / ".hacker-harness" / "history"

    # LinearChat (prompt_toolkit) handles its own history/completion. The GNU
    # readline LineEditor is only for the plain input() fallback, so the two
    # never write the same history file.
    editor = None if use_linear else LineEditor(project, command_names, lambda: sorted(load_settings(project).get("providers", {})), lambda: [item["id"] for item in store.list_sessions()], lambda: methodology_use_names(project), lambda: yaml_workflow_names(project), lambda: [item.value for item in load_scope(project).targets])

    def save_session(title: str | None = None) -> None:
        store.save_session(session_id, agent.messages, config.api_profile or config.provider.kind, config.provider.model, agent.input_tokens, agent.output_tokens, title)

    def status_line() -> list:
        pct = agent.context_status()["percent"]
        try:
            cwd = "~/" + str(project.relative_to(Path.home()))
        except ValueError:
            cwd = str(project)
        return [
            ("muted", "Model: "),
            ("cyan", f"{config.provider.model}   "),
            ("muted", "Working Directory: "),
            ("green", f"{cwd}   "),
            ("muted", "Context Utilization: "),
            ("yellow", f"{pct:.0f}%"),
            *ui.phase_status_fragments(),
        ]

    # Messages typed while a run is in progress wait here and run next,
    # like other coding-agent CLIs — not as persistent /tasks entries.
    pending_prompts: list[str] = []

    if output is not None:
        from .fullscreen import FullScreenChat, HarnessAutoSuggest, HarnessCompleter

        def queue_followup(text: str) -> None:
            notice = enqueue_chat_followup(pending_prompts, text)
            if notice:
                ui.notice(notice, "ok")

        completer = HarnessCompleter(
            command_names,
            lambda: sorted(load_settings(project).get("providers", {})),
            lambda: [item["id"] for item in store.list_sessions()],
            lambda: methodology_use_names(project),
            lambda: yaml_workflow_names(project),
            lambda: [item.value for item in load_scope(project).targets],
        )
        auto_suggest = HarnessAutoSuggest(
            command_names,
            lambda: sorted(load_settings(project).get("providers", {})),
            lambda: [item["id"] for item in store.list_sessions()],
            lambda: methodology_use_names(project),
            lambda: yaml_workflow_names(project),
            lambda: [item.value for item in load_scope(project).targets],
        )

        fullscreen = FullScreenChat(
            output=output,
            history_path=history_path,
            completer=completer,
            get_status=status_line,
            busy_comment=queue_followup,
            auto_suggest=auto_suggest,
        )
        ui.input_fn = fullscreen.sub_input

    if use_linear:
        from .fullscreen import HarnessAutoSuggest, HarnessCompleter

        completer = HarnessCompleter(
            command_names,
            lambda: sorted(load_settings(project).get("providers", {})),
            lambda: [item["id"] for item in store.list_sessions()],
            lambda: methodology_use_names(project),
            lambda: yaml_workflow_names(project),
            lambda: [item.value for item in load_scope(project).targets],
        )
        auto_suggest = HarnessAutoSuggest(
            command_names,
            lambda: sorted(load_settings(project).get("providers", {})),
            lambda: [item["id"] for item in store.list_sessions()],
            lambda: methodology_use_names(project),
            lambda: yaml_workflow_names(project),
            lambda: [item.value for item in load_scope(project).targets],
        )

        linear = LinearChat(
            history_path=history_path,
            completer=completer,
            auto_suggest=auto_suggest,
            get_status=status_line,
            stream=spinner,
            spinner=spinner,
        )
        ui.input_fn = linear.sub_input

    def sub_input(prompt_text: str) -> str:
        if fullscreen is not None:
            return fullscreen.sub_input(prompt_text)
        if linear is not None:
            return linear.sub_input(prompt_text)
        return input(prompt_text)

    def handle_input(prompt: str) -> bool:
        nonlocal agent, session_id, config
        if _handle_one_input(prompt):
            return True
        while pending_prompts:
            next_prompt = pending_prompts.pop(0)
            ui.notice(f"Running queued message ({len(pending_prompts)} remaining)…", "ok")
            if _handle_one_input(next_prompt):
                return True
        return False

    def _handle_one_input(prompt: str) -> bool:
        nonlocal agent, session_id, config
        if prompt in {"/quit", "/exit"}:
            save_session()
            if editor is not None:
                editor.save()
            return True
        if not prompt:
            return False
        workflows = methodology_commands(project)
        contexts = methodology_contexts(project)
        if prompt == "/help": ui.help(sorted(workflows))
        elif prompt == "/commands":
            executable = [f"/{name} <target>  ·  executable workflow  ·  {path.relative_to(project)}" for name, (_folder, path) in sorted(workflows.items())]
            load_only = [f"/use {methodology_short_name(name)}  ·  context framework  ·  {path.relative_to(project)}" for name, (_folder, path) in sorted(contexts.items()) if name.endswith("-framework")]
            body = "\n".join([*executable, *load_only])
            ui.card("Imported workflow commands", body or "No workflow commands. Import a methodology folder first.", line_limit=100)
        elif prompt == "/scope": show_scope(project)
        elif prompt == "/skills":
            body = "\n".join(str(path.relative_to(project)) for path in agent.loaded_skills) or "No SKILL.md files loaded."
            ui.card("Loaded skills", body)
        elif prompt == "/methodologies":
            lines = []
            for command, (folder, document) in sorted(contexts.items()):
                methodology = load_methodology(project, folder, document.name)
                missing = missing_requirements(project, methodology)
                role = "executable" if command.endswith("-workflow") else "loadable"
                lines.append(f"{methodology_short_name(command)}  ·  {role}  ·  {len(methodology.stages)} sections  ·  {'STRICT' if methodology.strict else 'advisory'}  ·  {'ready' if not missing else f'{len(missing)} missing'}")
            ui.card("Methodology deck", "\n".join(lines) or "No methodology folders found.", line_limit=100)
        elif prompt == "/workflows":
            lines = []
            for entry in workflow_catalog(project):
                input_keys = ", ".join(entry["inputs"]) or "none"
                rel = entry["path"].relative_to(project)
                line = f"{entry['name']}  ·  {entry['nodes']} nodes  ·  inputs: {input_keys}  ·  {rel}"
                if entry["description"]:
                    line += f"\n  {entry['description']}"
                lines.append(line)
            footer = "Run: /workflow <name> <target>   or   /workflow <name> -i key=value"
            body = "\n\n".join(lines) if lines else "No YAML workflows found in workflows/."
            ui.card("YAML workflows", f"{body}\n\n{footer}", line_limit=100)
        elif prompt == "/workflow" or prompt.startswith("/workflow "):
            rest = prompt[len("/workflow"):].strip()
            if not rest:
                ui.notice("Usage: /workflow <name> [target]  or  /workflow <name> -i key=value; use /workflows to list.", "warn")
            else:
                try:
                    requested_name, inputs = parse_workflow_invocation(rest)
                    workflow_name = resolve_yaml_workflow_name(requested_name, project) or requested_name
                    workflow_path = resolve_workflow(project, workflow_name)
                    workflow = load_workflow(workflow_path)
                    for key in workflow.inputs:
                        if key not in inputs:
                            if key == "target":
                                try:
                                    target = sub_input("  Target ❯ ").strip()
                                except (EOFError, KeyboardInterrupt):
                                    ui.write()
                                    return False
                                if not target:
                                    ui.notice("Usage: /workflow <name> <target>", "warn")
                                    return False
                                inputs[key] = target
                            else:
                                try:
                                    value = sub_input(f"  {key} ❯ ").strip()
                                except (EOFError, KeyboardInterrupt):
                                    ui.write()
                                    return False
                                if value:
                                    inputs[key] = value
                    run_yaml_workflow_command(project, ui, workflow, inputs)
                    agent.messages.append({"role": "user", "content": prompt})
                    agent.messages.append({"role": "assistant", "content": f"Completed YAML workflow {workflow.name} with inputs {inputs}."})
                    save_session(title=f"/workflow {workflow.name}" if len(agent.messages) <= 3 else None)
                except Exception as exc:
                    ui.notice(f"{type(exc).__name__}: {exc}", "error")
        elif prompt == "/use" or prompt.startswith("/use "):
            requested = prompt.split(maxsplit=1)[1].strip().lstrip("/") if " " in prompt else ""
            command = resolve_methodology_context(requested, contexts) if requested else None
            if not command:
                ui.notice("Usage: /use <methodology>; use /methodologies for markdown frameworks. YAML DAG workflows: /workflows and /workflow <name>.", "warn")
            else:
                try:
                    activate_methodology_context(project, ui, agent, command, contexts)
                    save_session()
                except Exception as exc:
                    ui.notice(f"{type(exc).__name__}: {exc}", "error")
        elif prompt == "/advance":
            try:
                ui.notice(agent.advance_methodology(), "ok")
                save_session()
            except Exception as exc:
                ui.notice(f"{type(exc).__name__}: {exc}", "error")
        elif prompt == "/provider":
            config = load_config(project)
            ui.card("Provider", f"Profile: {config.api_profile or 'default'}\nFormat: {config.provider.kind}\nModel: {config.provider.model}\nContext window: {config.provider.context_window:,}")
        elif prompt == "/version":
            ui.card("Version", f"Hacker-Harness v{__version__}\nMCP scope policy: {MCP_SCOPE_POLICY_ID}\nSession: {session_id}\nProject: {project}", "ok", "green")
        elif prompt == "/model" or prompt.startswith("/model "):
            profiles = settings.get("providers", {})
            raw = prompt.split(maxsplit=1)[1].strip() if " " in prompt else ui.model_picker(profiles, settings.get("activeProvider", ""))
            if not raw:
                ui.notice("Model selection cancelled.", "warn")
            else:
                requested = resolve_provider_profile(raw, profiles)
                if not requested:
                    ui.notice(f"Unknown model profile: {raw}", "error")
                else:
                    save_session()
                    settings["activeProvider"] = requested
                    save_settings(project, settings)
                    config = load_config(project)
                    prior_input_tokens, prior_output_tokens = agent.input_tokens, agent.output_tokens
                    agent = Agent(project, approve=ui.approve, event_handler=ui.event, restored_messages=agent.messages)
                    agent.input_tokens, agent.output_tokens = prior_input_tokens, prior_output_tokens
                    ui.notice(f"Model switched to {requested} · {config.provider.model} [{config.provider.kind}]", "ok")
                    save_session()
        elif prompt == "/context":
            status = agent.context_status()
            ui.context(status)
            ui.card("Context details", f"Estimated/current input: {status['used']:,} tokens\nWindow: {status['window']:,} tokens\nUtilization: {status['percent']:.1f}%\nGenerated this session: {status['output_tokens']:,} tokens")
        elif prompt == "/sessions":
            ui.card("Saved sessions", session_rows(store), line_limit=50)
        elif prompt == "/resume" or prompt.startswith("/resume "):
            requested = prompt.split(maxsplit=1)[1].strip() if " " in prompt else ""
            if not requested:
                ui.card("Saved sessions", session_rows(store), "select", line_limit=50)
                try: requested = sub_input("  Session ID or latest ❯ ").strip()
                except (EOFError, KeyboardInterrupt): ui.write(); return False
            selected = store.get_session(requested or "latest")
            if not selected:
                ui.notice(f"Session not found: {requested}", "error")
            else:
                save_session()
                session_id = selected["id"]
                agent = Agent(project, approve=ui.approve, event_handler=ui.event, restored_messages=selected["messages"])
                agent.input_tokens, agent.output_tokens = selected["input_tokens"], selected["output_tokens"]
                if output is not None:
                    output.clear()
                    ui.header(__version__, config.api_profile or config.provider.kind, config.provider.model, scope.is_active(), session_id, len(TOOL_SPECS), len(agent.loaded_skills), True)
                    ui.write()
                    ui.write()
                replay_session_transcript(ui, agent.messages, agent.context_status())
                ui.notice(f"Resumed {session_id} · {selected['title'] or 'Untitled'} · {len(selected['messages'])} messages", "ok")
                ui.context(agent.context_status())
        elif prompt == "/new":
            save_session()
            agent = Agent(project, approve=ui.approve, event_handler=ui.event)
            session_id = store.create_session(config.api_profile or config.provider.kind, config.provider.model, agent.messages)
            if output is not None:
                output.clear()
                ui.header(__version__, config.api_profile or config.provider.kind, config.provider.model, scope.is_active(), session_id, len(TOOL_SPECS), len(agent.loaded_skills), False)
                ui.write()
                ui.write()
            ui.notice(f"New session {session_id}", "ok")
        elif prompt == "/tools":
            installed = [f"✓ {name}  {shutil.which(name)}" if shutil.which(name) else f"○ {name}  not found" for name in OFFENSIVE_TOOL_NAMES]
            ui.card("Offensive tool deck", f"{len(TOOL_SPECS)} native agent tools\n\n" + "\n".join(installed), line_limit=100)
        elif prompt == "/mcp" or prompt == "/mcp status":
            status = agent.tools.mcp.status()
            body = "\n".join(f"{'✓' if item['connected'] else '○'} {item['name']} · {item['tools']} tools" + (f" · {item['error']}" if item['error'] else "") for item in status) or "No MCP servers configured in .hacker-harness/mcp.json."
            ui.card("MCP servers", body, line_limit=100)
        elif prompt == "/mcp connect":
            agent.tools.recreate_mcp()
            specs = agent.tools.mcp.discover(refresh=True)
            status = agent.tools.mcp.status()
            body = "\n".join(f"{'✓' if item['connected'] else '×'} {item['name']} · {item['tools']} tools" + (f" · {item['error']}" if item['error'] else "") for item in status) or "No MCP servers configured."
            ui.card("MCP connection", body, f"{len(specs)} tools", "green" if specs else "yellow", 100)
        elif prompt in ("/goals", "/goal"):
            goals = store.list_goals()
            body = "\n".join(f"{item['id']}  [{item['status']}] {item['title']}" for item in goals) or "No engagement goals."
            body += "\n\nUsage: /goal add <text> · /goal current · /goal set <id> <status> · /goal done <id> · /goal remove <id>"
            ui.card("Engagement goals", body, line_limit=100)
        elif prompt == "/goal current":
            active = [item for item in store.list_goals() if item["status"] not in {"completed", "cancelled", "failed"}]
            if not active:
                ui.notice("No active goal. Set one with /goal add <text>.", "warn")
            else:
                goal = active[-1]
                ui.card("Current goal", f"{goal['id']}  [{goal['status']}] {goal['title']}\n{goal.get('description') or ''}".rstrip(), line_limit=100)
        elif prompt.startswith("/goal add "):
            title = prompt[len("/goal add "):].strip()
            goal_id = store.create_goal(title, session_id=session_id)
            ui.notice(f"Created {goal_id}: {title}", "ok")
        elif prompt.startswith("/goal set "):
            parts = prompt[len("/goal set "):].split(maxsplit=1)
            if len(parts) != 2:
                ui.notice("Usage: /goal set <id> <status>", "warn")
            else:
                goal_id, status = parts[0].strip(), parts[1].strip()
                if store.update_goal(goal_id, status): ui.notice(f"{goal_id} → {status}", "ok")
                else: ui.notice(f"Goal not found: {goal_id}", "error")
        elif prompt.startswith("/goal done "):
            goal_id = prompt[len("/goal done "):].strip()
            if store.update_goal(goal_id, "completed"): ui.notice(f"Completed {goal_id}", "ok")
            else: ui.notice(f"Goal not found: {goal_id}", "error")
        elif prompt.startswith("/goal remove "):
            goal_id = prompt[len("/goal remove "):].strip()
            if store.remove_goal(goal_id): ui.notice(f"Removed {goal_id}", "ok")
            else: ui.notice(f"Goal not found: {goal_id}", "error")
        elif prompt == "/pivot" or prompt.startswith("/pivot "):
            from .skills import suggest_pivots_for_finding
            arg = prompt[len("/pivot"):].strip()
            findings = store.list_findings()
            if arg:
                match = next((f for f in findings if f["id"] == arg or arg.lower() in f["title"].lower()), None)
                pivots = suggest_pivots_for_finding(project, match or arg)
            elif findings:
                pivots = suggest_pivots_for_finding(project, findings[-1])
            else:
                pivots = []
            if not pivots:
                ui.notice("No pivot paths identified. Supply a finding ID or skill name (e.g. /pivot finding-123).", "warn")
            else:
                body = "\n".join(f"• {p['name']} ({p['skill_id']})\n  Reason: {p['reason']}\n  {p['description']}" for p in pivots)
                ui.card("Suggested Attack Pivots", body, line_limit=100)
        elif prompt == "/report" or prompt.startswith("/report "):
            from .reports import build_report, gather_target_findings
            rest = prompt[len("/report"):].strip()
            target, fmt = "", "html"
            for token in rest.split():
                if token.startswith("--"):
                    fmt = token.lstrip("-")
                elif not target:
                    target = token
            if not target:
                scope = load_scope(project)
                target = scope.domains[0] if scope.domains else "all"
            raw_findings = gather_target_findings(project, target, store.list_findings())
            if not raw_findings:
                ui.notice(f"No findings located for target '{target}'.", "warn")
            else:
                ui.notice(f"Processing and synthesizing findings for {target} with LLM...", "hint")
                content, filename, _ = build_report(target, raw_findings, fmt=fmt, project=project, provider=agent.provider)
                out_path = project / filename
                out_path.write_text(content, encoding="utf-8")
                ui.notice(f"Generated {fmt.upper()} report for {target} -> {out_path.resolve()}", "ok")
                if fmt.lower() in ("markdown", "md", "hackerone", "bugcrowd", "intigriti", "yeswehack"):
                    ui.card(f"Pentest Report Summary ({fmt.upper()})", content[:2000] + ("\n... (truncated)" if len(content) > 2000 else ""), line_limit=100)
        elif prompt == "/retest" or prompt.startswith("/retest "):
            from .retest import format_retest_summary, run_retest
            rest = prompt[len("/retest"):].strip().split()
            target = rest[0] if rest else ""
            finding_filter = rest[1] if len(rest) > 1 else "all"
            if not target:
                scope = load_scope(project)
                target = scope.domains[0] if scope.domains else "all"
            results = run_retest(project, target, finding_filter=finding_filter, store_findings=store.list_findings())
            if not results:
                ui.notice(f"No matching findings to retest for target '{target}' and selector '{finding_filter}'.", "warn")
            else:
                summary = format_retest_summary(target, results)
                ui.card(f"Retest Results ({target})", summary, line_limit=100)
        elif prompt == "/tree" or prompt.startswith("/tree "):
            arg = prompt[len("/tree"):].strip().lower()
            current = settings.get("ui", {}).get("attackTree", False)
            if arg in ("on", "true", "enable", "1"):
                settings.setdefault("ui", {})["attackTree"] = True
                save_settings(project, settings)
                ui.notice("Live Attack Tree visualization: ENABLED", "ok")
            elif arg in ("off", "false", "disable", "0"):
                settings.setdefault("ui", {})["attackTree"] = False
                save_settings(project, settings)
                ui.notice("Live Attack Tree visualization: DISABLED", "ok")
            else:
                status_text = "ENABLED" if current else "DISABLED"
                ui.card("Live Attack Tree", f"Status: {status_text}\n\nToggle: /tree on  ·  /tree off")
        elif prompt == "/findings":
            findings = store.list_findings()
            body = "\n".join(
                f"{item['id']}  [{item.get('status', 'confirmed').upper()}] [{item['severity'].upper()}] {item['target']} · {item['title']}"
                for item in findings
            ) or "No structured findings recorded."
            ui.card("Engagement findings", body, line_limit=100)
        elif prompt == "/validate" or prompt.startswith("/validate "):
            from .findings import evaluate_finding_gate, format_gate_report
            arg = prompt[len("/validate"):].strip()
            findings = store.list_findings()
            if not findings:
                ui.notice("No findings to validate. Record leads with signal_record or finding_create first.", "warn")
            elif arg:
                match = next((f for f in findings if f["id"] == arg or arg.lower() in f["title"].lower()), None)
                if not match:
                    ui.notice(f"Finding not found: {arg}. Use /findings to list IDs.", "error")
                else:
                    scope = load_scope(project)
                    in_scope = scope.is_target_in_scope(match.get("target", "")) if scope.is_active() else True
                    ev = evaluate_finding_gate(match, in_scope=in_scope)
                    report = format_gate_report(ev)
                    ui.card("7-Question Validation Gate", report, f"Score: {ev['score']}", "green" if ev["passed"] else "yellow", 100)
            else:
                scope = load_scope(project)
                reports = []
                for f in findings:
                    in_scope = scope.is_target_in_scope(f.get("target", "")) if scope.is_active() else True
                    ev = evaluate_finding_gate(f, in_scope=in_scope)
                    status_icon = "✓" if ev["passed"] else "×"
                    reports.append(f"{status_icon} {f['id']} [{ev['score']}] [{f.get('status', 'confirmed').upper()}] {f['title']}")
                body = "\n".join(reports) + "\n\nRun '/validate <finding-id>' for granular criteria breakdown."
                ui.card("7-Question Validation Gate (All Findings)", body, line_limit=100)
        elif prompt == "/vulns":
            body = "\n".join(ui.vulnerabilities) or "No vulnerabilities recorded yet. Writes to Vulnerabilities.md appear here live."
            ui.card("Vulnerabilities", body, line_limit=100)
        elif prompt == "/settings":
            ui.card("Settings", f".hacker-harness/settings.json\n{json.dumps(settings.get('ui', {}), indent=2)}")
        elif prompt == "/comment" or prompt.startswith("/comment "):
            text = prompt[len("/comment"):].strip()
            if not text:
                ui.notice("Usage: /comment <text> — add a comment to the pending queue (see /tasks).", "warn")
            else:
                task_id = store.create_task(text)
                ui.notice(f"Queued {task_id}: {text}", "ok")
        elif prompt == "/tasks": show_ready(project)
        elif prompt == "/clear": agent = Agent(project, approve=ui.approve, event_handler=ui.event); save_session(); ui.notice("Context cleared; persistent memory retained.", "ok")
        elif prompt == "/compact":
            ui.notice(agent.compact(), "ok")
            save_session()
        elif prompt.startswith("/") and prompt[1:].split(maxsplit=1)[0] in workflows:
            command_line = prompt[1:].split(maxsplit=1)
            command = command_line[0]
            target = command_line[1].strip() if len(command_line) == 2 else ""
            if target.startswith("--target "):
                target = target[len("--target "):].strip()
            if not target:
                try: target = sub_input("  Target ❯ ").strip()
                except (EOFError, KeyboardInterrupt): ui.write(); return False
            if not target:
                ui.notice(f"Usage: /{command} <authorized-target>", "warn")
                return False
            try:
                run_methodology_command(project, ui, command, target)
                agent.messages.append({"role": "user", "content": prompt})
                agent.messages.append({"role": "assistant", "content": f"Completed imported workflow /{command} against {target}. See saved methodology artifacts and progress state."})
                save_session(title=f"/{command} {target}" if len(agent.messages) <= 3 else None)
            except Exception as exc: ui.notice(f"{type(exc).__name__}: {exc}", "error")
        elif prompt.startswith("/"):
            ui.notice(f"Unknown command: {prompt.split(maxsplit=1)[0]}. Use /help.", "warn")
        else:
            try:
                routed = route_methodology(prompt, contexts, agent) if settings.get("methodologies", {}).get("autoRoute", True) else None
                if routed and ui.approve(f"Load strict methodology '{methodology_short_name(routed)}' for this request?"):
                    activate_methodology_context(project, ui, agent, routed, contexts)
                ui.user(prompt, agent.context_status())
                reply_text = agent.run(prompt)
                ui.assistant(reply_text)
                if str(reply_text).startswith("Paused after"):
                    ui.card("Tool-round pause", "Long pentests pause on purpose so you can review.\n- Reply continue to resume\n- agent.maxToolRounds (default 60) is a pause, not a crash\n- agent.maxFailedToolRounds (default 20) stops a repeating error loop", "hint", "yellow", 100)
                if agent.context_status()["percent"] >= agent.auto_compact_threshold():
                    ui.notice(f"Context at {agent.auto_compact_threshold():g}% — auto-compacting…", "warn")
                    ui.notice(agent.compact(), "ok")
                    save_session()
                current_session = store.get_session(session_id)
                title = prompt[:72] if current_session and not current_session["title"] else None
                save_session(title=title)
            except RuntimeError as exc:
                save_session()
                if "tool rounds" in str(exc) or "repeating the same tool call" in str(exc):
                    ui.notice(f"{exc}", "error")
                    ui.card("Tool-round limit", "The model kept calling tools without finishing. Options:\n- Reply 'continue' to resume from where it stopped\n- Raise agent.maxToolRounds in settings.json (e.g. 60) for long reports\n- /resume later to pick the session back up", "hint", "yellow", 100)
                else:
                    ui.notice(f"{type(exc).__name__}: {exc}", "error")
            except Exception as exc: ui.notice(f"{type(exc).__name__}: {exc}", "error")
        return False

    def exit_hint() -> None:
        print(f"\nSession saved: {session_id}")
        print(f"Resume: hh --resume latest   (or hh --resume {session_id})")

    if fullscreen is not None:
        try:
            fullscreen.run(handle_input)
        except (EOFError, KeyboardInterrupt):
            pass
        save_session(); editor.save()
        exit_hint()
        return 0
    if linear is not None:
        try:
            linear.run(handle_input)
        except (EOFError, KeyboardInterrupt):
            pass
        save_session()
        exit_hint()
        return 0
    while True:
        try:
            prompt = input(ui.prompt()).strip()
        except (EOFError, KeyboardInterrupt):
            save_session(); editor.save(); ui.write()
            exit_hint()
            return 0
        if handle_input(prompt):
            exit_hint()
            return 0


def cmd_ask(args) -> int:
    try: print(Agent(project_root(), approve=approve).run(args.prompt)); return 0
    except ProviderError as exc: print(f"error: {exc}", file=sys.stderr); return 2


def cmd_doctor(_args) -> int:
    project = project_root(); config, scope = load_config(project), load_scope(project)
    rows = [["Project", "ready" if (project / ".hacker-harness").exists() else "missing"], ["Provider", f"{config.provider.kind} / {config.provider.model}"], ["API key", "set" if os.environ.get(config.provider.api_key_env) else f"missing ({config.provider.api_key_env})"], ["Authorization scope", "active" if scope.is_active() else "inactive"], ["MCP scope policy", MCP_SCOPE_POLICY_ID]]
    rows.extend([[tool, shutil.which(tool) or "optional / not found"] for tool in ["git", "rg", "nmap", "nuclei", "httpx"]])
    print_table(["Check", "Status"], rows); return 0


def cmd_provider(args) -> int:
    project = project_root()
    data = load_settings(project)
    profiles = data.setdefault("providers", {})
    if args.provider_command == "list":
        active = os.environ.get("HACKER_HARNESS_PROVIDER_PROFILE") or os.environ.get("HACKER_HARNESS_API_PROFILE") or data.get("activeProvider")
        rows = [[name, "*" if name == active else "", profile.get("format", ""), profile.get("model", ""), profile.get("baseUrl", "default"), profile.get("apiKey", profile.get("apiKeyEnv", ""))] for name, profile in profiles.items()]
        print_table(["Provider", "Active", "JSON format", "Model", "Endpoint", "API key reference"], rows)
    elif args.provider_command == "add":
        window = args.context_window if args.context_window else resolve_context_window(args.model, None)
        profiles[args.name] = {"format": args.format, "baseUrl": args.base_url, "model": args.model, "apiKey": "${" + args.api_key_env + "}", "contextWindow": window}
        save_settings(project, data)
        print(f"saved API profile {args.name}; export {args.api_key_env} before use")
    elif args.provider_command == "use":
        if args.name not in profiles: raise ValueError(f"API profile '{args.name}' not found")
        data["activeProvider"] = args.name
        save_settings(project, data)
        print(f"active API profile: {args.name}")
    return 0


def methodology_roots(project: Path) -> list[Path]:
    settings = load_settings(project)
    configured = list(settings.get("methodologyPaths", ["methodology"]))
    legacy = ".hacker-harness/methodologies"
    if legacy not in configured and (project / legacy).is_dir():
        configured.append(legacy)
    roots = []
    for raw in configured:
        path = (project / raw).resolve()
        try: path.relative_to(project.resolve())
        except ValueError as exc: raise PermissionError(f"methodology path escapes project root: {raw}") from exc
        if path.is_dir(): roots.append(path)
    return roots


def methodology_commands(project: Path) -> dict[str, tuple[Path, Path]]:
    """Discover slash commands directly from imported workflow filenames."""
    commands: dict[str, tuple[Path, Path]] = {}
    collisions: set[str] = set()
    for root_path in methodology_roots(project):
        for workflow in sorted(root_path.rglob("*.md")):
            if not workflow.name.lower().endswith("workflow.md"):
                continue
            command = workflow_command_name(workflow)
            if not command:
                continue
            if command in commands:
                collisions.add(command)
            else:
                commands[command] = (workflow.parent, workflow)
    for command in collisions:
        commands.pop(command, None)
    return commands


def methodology_contexts(project: Path) -> dict[str, tuple[Path, Path]]:
    """Return explicitly loadable workflow and framework documents only."""
    contexts = dict(methodology_commands(project))
    collisions: set[str] = set()
    for root_path in methodology_roots(project):
        for document in sorted(root_path.rglob("*.md")):
            if not document.name.lower().endswith("framework.md"):
                continue
            name = workflow_command_name(document)
            if name in contexts:
                collisions.add(name)
            else:
                contexts[name] = (document.parent, document)
    for name in collisions:
        contexts.pop(name, None)
    return contexts


def methodology_short_name(name: str) -> str:
    return name.removesuffix("-workflow").removesuffix("-framework")


def methodology_use_names(project: Path) -> list[str]:
    names = set()
    for name in methodology_contexts(project):
        short = methodology_short_name(name)
        names.update({name, short, short.replace("-", "")})
    return sorted(names)


def resolve_methodology_document(project: Path, value: str) -> Path:
    """Resolve a methodology document by path or by name inside methodology roots."""
    candidate = Path(value)
    if candidate.is_file():
        return candidate.resolve()
    matches = []
    for root_path in methodology_roots(project):
        for path in sorted(root_path.rglob("*.md")):
            if path.name == value or path.stem == value:
                matches.append(path)
    if len(matches) != 1:
        raise ValueError(f"expected one methodology document named {value}, found {len(matches)}")
    return matches[0]


def resolve_methodology_context(requested: str, contexts: dict[str, tuple[Path, Path]]) -> str | None:
    normalized = re.sub(r"[^a-z0-9]", "", requested.lower())
    candidates = []
    for name in contexts:
        full = re.sub(r"[^a-z0-9]", "", name)
        short = re.sub(r"[^a-z0-9]", "", methodology_short_name(name))
        if normalized in {full, short}:
            preference = 1 if name.endswith("-workflow") else 0
            candidates.append((preference, name))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    if len(candidates) > 1 and candidates[0][0] == candidates[1][0]:
        return None
    return candidates[0][1]


def workflow_command_name(workflow: Path) -> str:
    return re.sub(r"[^a-z0-9]+", "-", workflow.stem.lower()).strip("-")


def run_methodology_command(project: Path, ui: TerminalUI, command: str, target: str) -> None:
    commands = methodology_commands(project)
    if command not in commands:
        raise ValueError(f"unknown workflow command: /{command}")
    folder, workflow = commands[command]
    methodology = load_methodology(project, folder, workflow.name)
    ui.card(
        f"/{command}",
        f"Context: {workflow.relative_to(project)}\nDocuments: {len(methodology.documents)}\nStages: {len(methodology.stages)}\nTarget: {target}",
        "loaded",
        "green",
    )
    runner = MethodologyRunner(project, emit=ui.methodology, approve=ui.approve, event_handler=ui.event)
    run_id, outputs = runner.run(methodology, target)
    ui.clear_phase_progress()
    ui.notice(f"/{command} completed: {run_id} ({len(outputs)} stage outputs)", "ok")


def run_yaml_workflow_command(project: Path, ui: TerminalUI, workflow: Workflow, inputs: dict[str, str]) -> None:
    path = resolve_workflow(project, workflow.name)
    ui.card(
        f"/workflow {workflow.name}",
        f"Path: {path.relative_to(project)}\nNodes: {len(workflow.nodes)}\nInputs: {', '.join(f'{key}={value}' for key, value in inputs.items()) or 'defaults'}",
        "running",
        "green",
    )
    runner = WorkflowRunner(project, approve=ui.approve, emit=ui.workflow_progress, event_handler=ui.event)
    run_id, outputs = runner.run(workflow, inputs)
    ui.clear_phase_progress()
    ui.notice(f"/workflow {workflow.name} completed: {run_id} ({len(outputs)} node outputs)", "ok")


def cmd_methodology(args) -> int:
    project = project_root()
    command = args.methodology_command
    if command == "import":
        source = Path(args.source).resolve()
        if not source.is_dir(): raise ValueError(f"methodology source folder not found: {source}")
        name = args.name or source.name
        if not name or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for character in name):
            raise ValueError("methodology name may contain only letters, numbers, hyphens, and underscores")
        destination = project / "methodology" / name
        if destination.exists(): raise ValueError(f"methodology already exists: {destination}")
        try: destination.resolve().relative_to(source)
        except ValueError: pass
        else: raise ValueError("methodology destination cannot be inside its source folder")
        if any(path.is_symlink() for path in source.rglob("*")): raise ValueError("methodology imports may not contain symbolic links")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, destination)
        documents = discover_documents(destination)
        workflows = discover_workflows(destination)
        frameworks = [path for path in discover_documents(destination) if path.name.lower().endswith("framework.md")]
        print(f"Imported {name}: {len(documents)} Markdown documents, {len(workflows)} workflow candidate(s) → {destination.relative_to(project)}")
        for workflow in workflows:
            command = workflow_command_name(workflow)
            print(f"  slash command: /{command} <target>")
        for framework in frameworks:
            print(f"  loadable context: /use {methodology_short_name(workflow_command_name(framework))}")
    elif command == "list":
        rows = []
        for root_path in methodology_roots(project):
            for folder in sorted(path for path in root_path.iterdir() if path.is_dir()):
                rows.append([folder.name, str(len(discover_documents(folder))), str(len(discover_workflows(folder))), str(folder.relative_to(project))])
        print_table(["Methodology", "Documents", "Workflows", "Folder"], rows)
    elif command == "inspect":
        methodology = load_methodology(project, Path(args.folder), args.workflow)
        missing = missing_requirements(project, methodology)
        print(f"Methodology: {methodology.name}\nWorkflow: {methodology.workflow_file.relative_to(project)}\nMode: {'strict' if methodology.strict else 'advisory'}\nStages: {len(methodology.stages)}\nRequirements: {len(methodology.requirements)} ({len(missing)} missing)\nSupporting documents: {len(methodology.documents)}\nSKILL.md files: {len(methodology.skill_files)}")
        for requirement in methodology.requirements: print(f"  requirement: {requirement.kind}:{requirement.name}{' [missing]' if requirement in missing else ''}")
        for path in methodology.skill_files: print(f"  skill: {path.relative_to(project)}")
        for index, stage in enumerate(methodology.stages, 1): print(f"  [{index}/{len(methodology.stages)}] {stage.title}")
    elif command == "run":
        methodology = load_methodology(project, Path(args.folder), args.workflow)
        ui = TerminalUI(project, load_settings(project))
        config, scope = load_config(project), load_scope(project)
        ui.header(__version__, config.api_profile or config.provider.kind, config.provider.model, scope.is_active())
        ui.card("Methodology loaded", f"Library: {methodology.name}\nDocuments: {len(methodology.documents)}\nOptional SKILL.md: {len(methodology.skill_files)}\nStages: {len(methodology.stages)}\nTarget: {args.target}")
        runner = MethodologyRunner(project, emit=ui.methodology, approve=ui.approve, event_handler=ui.event)
        run_id, outputs = runner.run(methodology, args.target, args.from_stage)
        ui.notice(f"Methodology completed: {run_id} ({len(outputs)} stage outputs)", "ok")
    elif command == "stage-map":
        source = resolve_methodology_document(project, args.source)
        workflow = args.workflow or source.stem
        content = source.read_text(encoding="utf-8")
        items = []
        for match in STAGE_HEADING.finditer(content):
            items.append({"id": match.group(2).upper(), "title": match.group(3).strip(), "source": source.name, "heading": match.group(2).upper()})
        if not items:
            raise ValueError(f"no numbered stages found in {source.name}")
        manifest = {"workflow": workflow, "stages": items}
        out = (Path(args.out) if args.out else project / ".hacker-harness" / "stages" / f"{workflow}.json").resolve()
        try:
            out.relative_to(project.resolve())
        except ValueError as exc:
            raise PermissionError("stage manifest output must be inside the project") from exc
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(f"Generated {len(items)} stage(s) → {out.relative_to(project)}")
        print(f"Source: {source.relative_to(project)} · workflow key: {workflow}")
        print("Edit the manifest to trim stages, add instructions, or change sources.")
    elif command == "init":
        destination, files = init_methodology(project, name=args.name, title=getattr(args, "title", "") or "")
        print(f"Initialized methodology '{args.name}' in {destination.relative_to(project)}:")
        for f in files:
            print(f"  created: {f.relative_to(project)}")
        print("Edit these files or generate stage manifests with 'hh methodology stage-map'.")
    elif command == "validate":
        ok, msg, issues = validate_methodology(project, args.target)
        if ok:
            print(f"✓ {msg}")
        else:
            print(f"✗ {msg}", file=sys.stderr)
            for issue in issues:
                print(f"  - {issue}", file=sys.stderr)
            return 1
    elif command == "status":
        rows = [[str(item["stage_index"]), item["stage_id"], item["status"], item.get("output_path") or "", item.get("error") or ""] for item in StateStore(project).methodology_progress(args.run_id)]
        print_table(["#", "Stage", "Status", "Output", "Error"], rows)
    return 0


def resolve_workflow(project: Path, value: str) -> Path:
    candidate = Path(value)
    if candidate.exists(): return candidate
    matches = [p for p in workflow_files(project) if load_workflow(p).name == value or p.stem == value]
    if len(matches) != 1: raise ValueError(f"expected one workflow named {value}, found {len(matches)}")
    return matches[0]


def cmd_workflow(args) -> int:
    project = project_root()
    if args.workflow_command == "list":
        rows = [[load_workflow(p).name, load_workflow(p).description, str(p.relative_to(project))] for p in workflow_files(project)]
        print_table(["Name", "Description", "Path"], rows)
    elif args.workflow_command == "init":
        target = init_workflow(project, name=args.name, description=getattr(args, "description", "") or "")
        print(f"Initialized workflow in {target.relative_to(project)}")
        print(f"Run validation with: hh workflow validate {target.relative_to(project)}")
    elif args.workflow_command == "validate":
        path = Path(args.path)
        if not path.is_file():
            path = resolve_workflow(project, args.path)
        workflow = load_workflow(path)
        topological(workflow.nodes)
        print(f"✓ Valid: {workflow.name} ({len(workflow.nodes)} nodes in {path.relative_to(project) if path.is_relative_to(project) else path})")
    else:
        values = {}
        for item in args.input:
            if "=" not in item: raise ValueError("inputs must use key=value")
            key, value = item.split("=", 1); values[key] = value
        runner = WorkflowRunner(project, approve, lambda text: print(f"→ {text}"))
        run_id, outputs = runner.run(load_workflow(resolve_workflow(project, args.name_or_path)), values)
        print(f"Completed {run_id} with {len(outputs)} node outputs")
    return 0


def cmd_skill(args) -> int:
    project = project_root()
    command = args.skill_command
    if command == "list":
        entries = discover_skill_entries(project)
        rows = []
        for entry in entries:
            try:
                rel = str(entry.path.relative_to(project))
            except ValueError:
                rel = str(entry.path)
            rows.append([entry.name, entry.skill_id, entry.description[:60], rel])
        print_table(["Skill Name", "ID", "Description", "Path"], rows)
    elif command == "init":
        target = init_skill(project, name=args.name, description=getattr(args, "description", "") or "", playbook=getattr(args, "playbook", "") or "")
        print(f"Initialized skill in {target.relative_to(project)}")
        print(f"Validate with: hh skill validate {target.relative_to(project)}")
    elif command == "validate":
        path = Path(args.path)
        if not path.is_file():
            cand = project / ".hacker-harness" / "skills" / args.path / "SKILL.md"
            if cand.is_file():
                path = cand
            else:
                entries = discover_skill_entries(project)
                try:
                    resolved = resolve_skill_entry(entries, args.path)
                    path = resolved.path
                except Exception:
                    pass
        ok, msg, meta = validate_skill(path)
        if ok:
            print(f"✓ {msg}")
            if meta.get("playbook"):
                print(f"  playbook: {meta['playbook']}")
        else:
            print(f"✗ {msg}", file=sys.stderr)
            return 1
    return 0


def cmd_task(args) -> int:
    store = StateStore(project_root()); command = args.task_command
    if command == "create": print(store.create_task(args.title, args.description, args.priority))
    elif command == "ready": show_ready(project_root())
    elif command == "show":
        task = store.get_task(args.task_id)
        if not task: raise ValueError("task not found")
        print(json.dumps(task, indent=2))
    elif command == "claim":
        if not store.update_task(args.task_id, "in_progress", args.assignee): raise ValueError("task not found")
        print(f"claimed {args.task_id}")
    elif command == "close":
        if not store.update_task(args.task_id, "closed"): raise ValueError("task not found")
        print(f"closed {args.task_id}")
    elif command == "dep":
        if not store.get_task(args.child) or not store.get_task(args.parent): raise ValueError("child or parent task not found")
        store.add_dependency(args.child, args.parent); print(f"{args.child} now depends on {args.parent}")
    return 0


def cmd_memory(args) -> int:
    project = project_root()
    store = StateStore(project)
    if args.memory_command == "remember":
        result = curate_operator_memory(project, args.content)
        if not result.saved:
            print(f"memory unchanged: {result.reason or 'duplicate or too vague'}")
            return 0
        if store.remember(result.content, kind=result.kind, obsidian_vault=load_obsidian_vault(load_settings(project), project)):
            print(f"remembered [{result.kind}] in {MEMORY_RELATIVE}: {result.content}")
        else:
            print("memory unchanged: duplicate lesson")
    else:
        print(json.dumps(store.prime(), indent=2, default=str))
    return 0


def cmd_scope(args) -> int:
    project = project_root()
    if args.scope_command == "show": show_scope(project); return 0
    if args.scope_command == "path": print((project / ".hacker-harness" / "scope.yaml").resolve()); return 0
    allowed = target_allowed(args.target, load_scope(project)); print("in scope" if allowed else "not in active scope")
    return 0 if allowed else 3


def cmd_settings(args) -> int:
    project = project_root()
    path = project / ".hacker-harness" / "settings.json"
    if args.settings_command == "path":
        print(path)
    else:
        print(json.dumps(load_settings(project), indent=2))
    return 0


def cmd_session(args) -> int:
    store = StateStore(project_root())
    if args.session_command == "list":
        print_table(
            ["Session", "Messages", "Provider", "Model", "Title", "Updated"],
            [[item["id"], str(item["message_count"]), item["provider"], item["model"], item["title"] or "Untitled", item["updated_at"]] for item in store.list_sessions()],
        )
        return 0
    if args.session_command == "show":
        session = store.get_session(args.session_id)
        if not session:
            raise ValueError(f"session not found: {args.session_id}")
        summary = {key: value for key, value in session.items() if key != "messages"}
        summary["message_count"] = len(session["messages"])
        print(json.dumps(summary, indent=2))
        return 0
    args.resume = args.session_id
    return cmd_chat(args)


def cmd_goal(args) -> int:
    store = StateStore(project_root())
    if args.goal_command == "list":
        rows = [[item["id"], item["status"], item["title"], item.get("run_id") or "", item.get("stage_id") or ""] for item in store.list_goals(status=args.status)]
        print_table(["Goal", "Status", "Title", "Run", "Stage"], rows)
    elif args.goal_command == "add":
        print(store.create_goal(args.title, args.description))
    elif args.goal_command == "update":
        if not store.update_goal(args.goal_id, args.status): raise ValueError(f"goal not found: {args.goal_id}")
        print(f"{args.goal_id} → {args.status}")
    return 0


def cmd_mcp(args) -> int:
    if args.mcp_command == "serve":
        from .mcp_server import serve_stdio
        return serve_stdio(foreground=bool(getattr(args, "foreground", False)))
    project = project_root()
    agent = Agent(project, approve=approve)
    if args.mcp_command == "connect":
        agent.tools.recreate_mcp()
        agent.tools.mcp.discover(refresh=True)
    rows = [[item["name"], "connected" if item["connected"] else "disconnected", str(item["tools"]), item["error"]] for item in agent.tools.mcp.status()]
    print_table(["Server", "Status", "Tools", "Error"], rows)
    return 0


def normalize_cli_argv(argv: list[str] | None = None) -> list[str]:
    """Hermes `--args \"mcp serve\"` arrives as one token; also accept mcp-serve."""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        return args
    first = args[0].strip()
    if first in {"mcp-serve", "mcp_serve"}:
        return ["mcp", "serve", *args[1:]]
    if first.replace("_", " ") == "mcp serve":
        return ["mcp", "serve", *args[1:]]
    return args


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hacker-harness", description="Authorization-aware AI harness for pentesting and bug bounty work.")
    parser.add_argument("--version", action="version", version=__version__); parser.add_argument("--resume", nargs="?", const="latest", help="resume a saved session (default: latest)"); sub = parser.add_subparsers(dest="command")
    p = sub.add_parser("init"); p.add_argument("path", nargs="?", default="."); p.add_argument("--force", action="store_true"); p.add_argument("--no-setup", action="store_true", help="skip interactive vault/MCP setup prompts"); p.set_defaults(func=cmd_init)
    p = sub.add_parser("setup"); p.add_argument("path", nargs="?", default="."); p.add_argument("--no-setup", action="store_true", help="skip interactive vault/MCP setup prompts"); p.set_defaults(func=cmd_setup)
    p = sub.add_parser("chat"); p.add_argument("--resume", nargs="?", const="latest", help="resume a saved session"); p.set_defaults(func=cmd_chat)
    p = sub.add_parser("ask"); p.add_argument("prompt"); p.set_defaults(func=cmd_ask)
    sub.add_parser("doctor").set_defaults(func=cmd_doctor)
    p = sub.add_parser("provider"); s=p.add_subparsers(dest="provider_command", required=True); s.add_parser("list"); q=s.add_parser("add"); q.add_argument("name"); q.add_argument("--base-url", required=True); q.add_argument("--model", required=True); q.add_argument("--api-key-env", required=True); q.add_argument("--format", choices=["openai", "anthropic"], default="openai"); q.add_argument("--context-window", type=int, default=0, help="token window; 0 infers from the model name"); q=s.add_parser("use"); q.add_argument("name"); p.set_defaults(func=cmd_provider)
    p = sub.add_parser("methodology"); s=p.add_subparsers(dest="methodology_command", required=True); q=s.add_parser("import"); q.add_argument("source"); q.add_argument("--name"); s.add_parser("list"); q=s.add_parser("init"); q.add_argument("name"); q.add_argument("--title", default=""); q=s.add_parser("validate"); q.add_argument("target"); q=s.add_parser("inspect"); q.add_argument("folder"); q.add_argument("--workflow"); q=s.add_parser("stage-map"); q.add_argument("source"); q.add_argument("--workflow"); q.add_argument("--out"); q=s.add_parser("run"); q.add_argument("folder"); q.add_argument("--workflow"); q.add_argument("--target", required=True); q.add_argument("--from-stage", type=int, default=1); q=s.add_parser("status"); q.add_argument("run_id"); p.set_defaults(func=cmd_methodology)
    p = sub.add_parser("workflow"); s = p.add_subparsers(dest="workflow_command", required=True); s.add_parser("list"); q=s.add_parser("init"); q.add_argument("name"); q.add_argument("--description", default=""); q=s.add_parser("validate"); q.add_argument("path"); q=s.add_parser("run"); q.add_argument("name_or_path"); q.add_argument("-i", "--input", action="append", default=[]); p.set_defaults(func=cmd_workflow)
    p = sub.add_parser("skill"); s = p.add_subparsers(dest="skill_command", required=True); s.add_parser("list"); q=s.add_parser("init"); q.add_argument("name"); q.add_argument("--description", default=""); q.add_argument("--playbook", default=""); q=s.add_parser("validate"); q.add_argument("path"); p.set_defaults(func=cmd_skill)
    p = sub.add_parser("task"); s=p.add_subparsers(dest="task_command", required=True); q=s.add_parser("create"); q.add_argument("title"); q.add_argument("--description", default=""); q.add_argument("--priority", type=int, default=2); s.add_parser("ready"); q=s.add_parser("show"); q.add_argument("task_id"); q=s.add_parser("claim"); q.add_argument("task_id"); q.add_argument("--assignee", default="agent"); q=s.add_parser("close"); q.add_argument("task_id"); q=s.add_parser("dep"); q.add_argument("child"); q.add_argument("parent"); p.set_defaults(func=cmd_task)
    p = sub.add_parser("memory"); s=p.add_subparsers(dest="memory_command", required=True); q=s.add_parser("remember"); q.add_argument("content"); s.add_parser("prime"); p.set_defaults(func=cmd_memory)
    p = sub.add_parser("scope"); s=p.add_subparsers(dest="scope_command", required=True); s.add_parser("show"); s.add_parser("path"); q=s.add_parser("check"); q.add_argument("target"); p.set_defaults(func=cmd_scope)
    p = sub.add_parser("settings"); s=p.add_subparsers(dest="settings_command", required=True); s.add_parser("show"); s.add_parser("path"); p.set_defaults(func=cmd_settings)
    p = sub.add_parser("session"); s=p.add_subparsers(dest="session_command", required=True); s.add_parser("list"); q=s.add_parser("show"); q.add_argument("session_id"); q=s.add_parser("resume"); q.add_argument("session_id", nargs="?", default="latest"); p.set_defaults(func=cmd_session)
    p = sub.add_parser("goal"); s=p.add_subparsers(dest="goal_command", required=True); q=s.add_parser("list"); q.add_argument("--status"); q=s.add_parser("add"); q.add_argument("title"); q.add_argument("--description", default=""); q=s.add_parser("update"); q.add_argument("goal_id"); q.add_argument("status", choices=["pending", "in_progress", "completed", "blocked", "failed", "cancelled"]); p.set_defaults(func=cmd_goal)
    p = sub.add_parser("mcp"); s=p.add_subparsers(dest="mcp_command", required=True); s.add_parser("status"); s.add_parser("connect"); q=s.add_parser("serve"); q.add_argument("--foreground", action="store_true", help="keep serving when stdin is a TTY"); p.set_defaults(func=cmd_mcp)
    p = sub.add_parser("mcp-serve"); p.set_defaults(func=lambda _a: cmd_mcp(argparse.Namespace(mcp_command="serve")))
    return parser


def app() -> None:
    args = build_parser().parse_args(normalize_cli_argv())
    if not getattr(args, "command", None):
        args.func = cmd_chat
    try: code = args.func(args)
    except (ValueError, KeyError, PermissionError) as exc: print(f"error: {exc}", file=sys.stderr); code = 2
    raise SystemExit(code)


if __name__ == "__main__": app()

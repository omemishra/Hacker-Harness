from __future__ import annotations

import atexit
from pathlib import Path
from typing import Callable


def completion_candidates(buffer: str, text: str, commands: list[str], models: list[str], sessions: list[str], methodologies: list[str], yaml_workflows: list[str], targets: list[str]) -> list[str]:
    """Pure completion logic so it can be unit-tested without a tty."""
    b_stripped = buffer.lstrip()
    if b_stripped.startswith("/model "):
        return [name for name in models if name.lower().startswith(text.lower())]
    if b_stripped.startswith("/resume "):
        return [name for name in ["latest", *sessions] if name.lower().startswith(text.lower())]
    if b_stripped.startswith("/use "):
        return [name for name in methodologies if name.lower().startswith(text.lower())]
    if b_stripped.startswith("/tree "):
        tree_options = ["on", "off", "enable", "disable"]
        return [opt for opt in tree_options if opt.lower().startswith(text.lower())]
    if b_stripped.startswith("/report "):
        report_flags = ["--html", "--csv", "--hackerone", "--bugcrowd", "--intigriti", "--immunefi", "--yeswehack", "--markdown"]
        candidates = [*targets, *report_flags]
        return [c for c in candidates if c.lower().startswith(text.lower())]
    if b_stripped.startswith("/retest "):
        return [name for name in targets if name.lower().startswith(text.lower())]
    if b_stripped.startswith("/pivot "):
        return [name for name in targets if name.lower().startswith(text.lower())]
    if b_stripped.startswith("/workflow "):
        rest = b_stripped[len("/workflow "):]
        if not rest.strip() or " " not in rest.strip():
            return [name for name in yaml_workflows if name.lower().startswith(text.lower())]
        return [name for name in targets if name.lower().startswith(text.lower())]
    if b_stripped.startswith("/") and " " in b_stripped:
        # after a slash command (e.g. /recon-workflow exa<TAB> or /retest <TAB>) complete scope targets
        return [name for name in targets if name.lower().startswith(text.lower())]
    
    # Base command suggestions
    all_commands = sorted(commands) if commands else [
        "help", "commands", "scope", "skills", "methodologies", "workflows", "workflow", "use", "advance",
        "pivot", "report", "retest", "tree", "model", "provider", "version", "context", "compact",
        "sessions", "resume", "new", "tools", "mcp", "goals", "goal", "comment", "remember",
        "findings", "validate", "vulns", "settings", "tasks", "clear", "quit", "exit"
    ]
    return [f"/{name}" for name in all_commands if f"/{name}".lower().startswith(text.lower())]


class LineEditor:
    """GNU readline integration for history and context-aware completion."""

    def __init__(self, project: Path, commands: Callable[[], list[str]], models: Callable[[], list[str]], sessions: Callable[[], list[str]] | None = None, methodologies: Callable[[], list[str]] | None = None, yaml_workflows: Callable[[], list[str]] | None = None, targets: Callable[[], list[str]] | None = None):
        self.project = project
        self.commands = commands
        self.models = models
        self.sessions = sessions or (lambda: [])
        self.methodologies = methodologies or (lambda: [])
        self.yaml_workflows = yaml_workflows or (lambda: [])
        self.targets = targets or (lambda: [])
        self.history_path = project / ".hacker-harness" / "history"
        self.readline = None
        try:
            import readline

            self.readline = readline
            readline.set_completer_delims(" \t\n")
            readline.set_completer(self.complete)
            readline.parse_and_bind("tab: complete")
            readline.parse_and_bind("set completion-ignore-case on")
            readline.parse_and_bind("set show-all-if-ambiguous on")
            readline.set_history_length(2_000)
            if self.history_path.exists():
                readline.read_history_file(self.history_path)
            atexit.register(self.save)
        except (ImportError, OSError):
            self.readline = None

    def complete(self, text: str, state: int) -> str | None:
        if not self.readline:
            return None
        buffer = self.readline.get_line_buffer()
        try:
            options = completion_candidates(
                buffer,
                text,
                self.commands(),
                self.models(),
                self.sessions(),
                self.methodologies(),
                self.yaml_workflows(),
                self.targets(),
            )
        except Exception:
            # A config error must never silently kill completion.
            return None
        return options[state] if state < len(options) else None

    def save(self) -> None:
        if not self.readline or not hasattr(self.readline, "write_history_file"):
            return
        self.history_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.readline.write_history_file(self.history_path)
            self.history_path.chmod(0o600)
        except OSError:
            pass

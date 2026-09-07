from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import sys
import textwrap
import time
from pathlib import Path
from typing import Callable, TextIO


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def parse_vulnerabilities(text: str) -> list[str]:
    """Extract short titles from a Vulnerabilities.md: headings and checklist bullets."""
    titles: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"^#{2,3}\s+", stripped):
            titles.append(re.sub(r"^#{2,3}\s+", "", stripped))
        elif re.match(r"^- \[[ xX]\]\s+", stripped):
            titles.append(re.sub(r"^- \[[ xX]\]\s+", "", stripped))
    return titles[-50:]


class TerminalUI:
    """Small dependency-free terminal renderer with a readable non-TTY fallback."""

    PALETTE = {
        "green": "\033[38;5;82m",
        "cyan": "\033[38;5;45m",
        "yellow": "\033[38;5;220m",
        "red": "\033[38;5;203m",
        "muted": "\033[38;5;244m",
        "bold": "\033[1m",
        "reset": "\033[0m",
    }

    BANNERS = (
        """[ H A C K E R // H A R N E S S ]
     offensive security command deck
  scope • evidence • methodology • report""",
    )

    def __init__(self, project: Path, settings: dict | None = None, stream: TextIO | None = None, input_fn: Callable[[str], str] | None = None):
        self.project = project.resolve()
        self.stream = stream or sys.stdout
        self.input_fn = input_fn or input
        self.root_settings = settings or {}
        self.settings = (settings or {}).get("ui", {})
        self.color = bool(getattr(self.stream, "isatty", lambda: False)()) and "NO_COLOR" not in os.environ
        self.cards = self.settings.get("toolCards", True)
        self.max_lines = max(1, int(self.settings.get("maxToolOutputLines", 12)))
        self.show_output = self.settings.get("showToolOutput", True)
        self.tool_mode = self.settings.get("toolCardMode", "summary")
        self.started = time.monotonic()
        self._approved: set[str] = set()
        self._round_tools: list[dict] = []
        self._stage = ""
        self._phase_progress: dict | None = None
        self._vulns: list[str] = []
        self._vuln_stamp: tuple[int, int] | None = None
        self._instant_assistant = False

    @property
    def vulnerabilities(self) -> list[str]:
        self._refresh_vulnerabilities()
        return list(self._vulns)

    def _vulnerabilities_path(self) -> Path | None:
        raw = self.settings.get("sidebarFile")
        if raw:
            path = Path(str(raw)).expanduser()
            return path if path.is_absolute() else self.project / path
        candidates = [self.project / "Vulnerabilities.md"]
        root = self.root_settings.get("engagementRoot")
        if root:
            root_path = Path(str(root)).expanduser()
            try:
                candidates.extend(sorted((p for p in root_path.glob("*/Vulnerabilities.md") if p.is_file()), key=lambda p: p.stat().st_mtime, reverse=True))
            except OSError:
                pass
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return None

    def _refresh_vulnerabilities(self) -> None:
        path = self._vulnerabilities_path()
        if path is None:
            self._vulns = []
            return
        try:
            stat = path.stat()
        except OSError:
            return
        stamp = (stat.st_mtime_ns, stat.st_size)
        if stamp == self._vuln_stamp:
            return
        self._vuln_stamp = stamp
        self._vulns = parse_vulnerabilities(path.read_text(encoding="utf-8", errors="replace"))

    # Routine probes are deferred to a per-round summary instead of a card each.
    ROUTINE_TOOLS = {"http_request", "read_file", "write_file", "list_files", "scope_check", "search_text", "replace_text", "remember", "memory_search", "skill_load", "playbook_save", "playbook_search", "skill_promote", "task_create", "task_ready", "goal_create", "goal_list", "goal_update", "methodology_advance", "finding_create", "finding_list", "signal_record", "finding_advance", "finding_dismiss", "finding_archive", "run_command"}

    def _is_routine_tool(self, name: str) -> bool:
        return name in self.ROUTINE_TOOLS or name.startswith("mcp__")

    def _tool_summary(self, name: str, arguments: dict) -> str:
        """One-line, redacted summary of a tool call for the live cards."""
        if name == "http_request":
            return f"{arguments.get('method', 'GET')} {arguments.get('url', '')}"
        if name == "run_command":
            return str(arguments.get("command", ""))
        if name == "read_file":
            return f"{arguments.get('path', '')}"
        if name == "write_file":
            return f"{arguments.get('path', '')} ({len(str(arguments.get('content', '')))} chars)"
        if name == "list_files":
            return f"pattern {arguments.get('pattern', '**/*')}"
        if name == "search_text":
            return f"{arguments.get('pattern', '')}"
        if name == "spawn_agent":
            return (arguments.get("instructions") or "")[:140]
        if name == "scope_check":
            return str(arguments.get("target", ""))
        return json.dumps(arguments, ensure_ascii=False)[:140]

    def _terminal_columns(self) -> int:
        return max(20, shutil.get_terminal_size((88, 24)).columns)

    @property
    def width(self) -> int:
        return self._terminal_columns()

    def style(self, value: str, *names: str) -> str:
        if not self.color:
            return value
        return "".join(self.PALETTE[name] for name in names) + value + self.PALETTE["reset"]

    def _pad_visible(self, text: str, width: int) -> str:
        """Fit `text` to exactly `width` visible columns, ANSI-aware: pad when short,
        truncate (re-closing any open SGR sequence) when long."""
        visible = ANSI_RE.sub("", text)
        if len(visible) <= width:
            return text + " " * (width - len(visible))
        kept: list[str] = []
        seen = 0
        i = 0
        n = len(text)
        trunc_width = max(1, width - 1) if width > 4 else width
        while i < n and seen < trunc_width:
            if text[i] == "\x1b":
                end = i
                while end < n and text[end] != "m":
                    end += 1
                if end < n:
                    kept.append(text[i : end + 1])
                    i = end + 1
                else:
                    i = n
                continue
            kept.append(text[i])
            seen += 1
            i += 1
        suffix = "…" if width > 4 and seen == trunc_width else ""
        return "".join(kept) + suffix + (self.PALETTE["reset"] if self.color and "\x1b" in text else "")

    def write(self, value: str = "") -> None:
        print(value, file=self.stream, flush=True)

    def header(
        self,
        version: str,
        provider: str,
        model: str,
        scope_active: bool,
        session_id: str = "",
        tools: int = 0,
        skills: int = 0,
        resumed: bool = False,
        recent_sessions: list[str] | None = None,
    ) -> None:
        width = max(20, self.width)

        # Dual-column Hacker-Harness card if width >= 64 and largeBanner enabled
        if width >= 64 and self.settings.get("largeBanner", True):
            left_w = min(28, max(22, width // 3))
            right_w = width - left_w - 3  # for border │ and center │

            left_lines = [
                "",
                "Welcome back!",
                "",
                " █  █ ── █  █ ",
                " █▀▀█ ── █▀▀█ ",
                " █  █ ── █  █ ",
                "",
                "HACKER // HARNESS",
                "",
                model[: left_w - 2],
                provider[: left_w - 2],
                "",
            ]

            scope_str = "SCOPE ACTIVE" if scope_active else "SCOPE INACTIVE"
            clean_sess = [s for s in (recent_sessions or []) if s and s != session_id]
            if not clean_sess and session_id:
                clean_sess = [f"{'RESUMED' if resumed else 'SESSION'} {session_id}"]
            if not clean_sess:
                clean_sess = ["No previous sessions"]

            right_lines = [
                "Tips",
                "# for scope & targets",
                "/ for commands",
                "! to run shell commands",
                "─" * max(1, right_w - 2),
                "Scope & Tools",
                f"{scope_str} · {tools} tools · {skills} skills",
                "─" * max(1, right_w - 2),
                "Recent sessions",
            ]
            for s in clean_sess[:2]:
                right_lines.append(f"• {s[: max(1, right_w - 4)]}")

            max_h = max(len(left_lines), len(right_lines))
            while len(left_lines) < max_h:
                left_lines.append("")
            while len(right_lines) < max_h:
                right_lines.append("")

            title = f"╭─── hh v{version} "
            top_dashes = max(1, width - len(title) - 1)
            self.write(self.style(title, "green", "bold") + self.style("─" * top_dashes, "green") + self.style("╮", "green", "bold"))

            for l_raw, r_raw in zip(left_lines, right_lines):
                if l_raw == "Welcome back!":
                    l_styled = self.style(l_raw, "green", "bold")
                elif any(c in l_raw for c in "█▀"):
                    l_styled = self.style(l_raw, "green", "bold")
                elif l_raw == "HACKER // HARNESS":
                    l_styled = self.style(l_raw, "cyan", "bold")
                elif l_raw == model[: left_w - 2]:
                    l_styled = self.style(l_raw, "cyan", "bold")
                elif l_raw == provider[: left_w - 2]:
                    l_styled = self.style(l_raw, "muted")
                else:
                    l_styled = l_raw

                if r_raw in ("Tips", "Scope & Tools", "Recent sessions"):
                    r_styled = " " + self.style(r_raw, "yellow", "bold")
                elif r_raw.startswith("─"):
                    r_styled = " " + self.style(r_raw, "muted")
                elif "SCOPE ACTIVE" in r_raw:
                    r_styled = " " + self.style("SCOPE ACTIVE", "green", "bold") + self.style(f" · {tools} tools · {skills} skills", "muted")
                elif "SCOPE INACTIVE" in r_raw:
                    r_styled = " " + self.style("SCOPE INACTIVE", "red", "bold") + self.style(f" · {tools} tools · {skills} skills", "muted")
                elif r_raw.startswith("#") or r_raw.startswith("/") or r_raw.startswith("!"):
                    parts = r_raw.split(" ", 1)
                    r_styled = " " + self.style(parts[0], "yellow", "bold") + self.style(" " + parts[1] if len(parts) > 1 else "", "muted")
                elif r_raw.startswith("•"):
                    r_styled = " " + self.style("•", "cyan") + self.style(r_raw[1:], "muted")
                else:
                    r_styled = " " + r_raw

                pad_total = max(0, left_w - len(l_raw))
                pad_left = pad_total // 2
                pad_right = pad_total - pad_left
                l_pad = " " * pad_left + l_styled + " " * pad_right
                r_pad = self._pad_visible(r_styled, right_w)
                self.write(self.style("│", "green", "bold") + l_pad + self.style("│", "green") + r_pad + self.style("│", "green", "bold"))

            bot_left = "─" * left_w
            bot_right = "─" * right_w
            self.write(self.style(f"╰{bot_left}┴{bot_right}╯", "green", "bold"))
            self.write(self.style(" Tip: `/copy code` grabs the last code block — `/copy cmd` grabs the last command"[:width], "muted"))
            return

        # Fallback single column
        title = "┏━ HACKER-HARNESS "
        version_label = f"v{version} "
        if len(title) + len(version_label) + 2 > width:
            title = "┏━ HH "
        dashes = max(1, width - len(title) - len(version_label) - 1)
        self.write(self.style(title, "green", "bold") + self.style(version_label, "muted") + "━" * dashes + self.style("┓", "green", "bold"))

        scope_state = self.style("SCOPE ACTIVE", "green", "bold") if scope_active else self.style("SCOPE INACTIVE", "red", "bold")

        def row(label: str, value: str) -> None:
            label_text = self.style(f"  {label:<9}", "muted")
            self.write(self.style("┃", "green", "bold") + self._pad_visible(label_text + value, width - 2) + self.style("┃", "green", "bold"))

        row("Model", self.style(f"{provider} · {model}", "cyan"))
        row("Scope", scope_state)
        if session_id:
            marker = "RESUMED" if resumed else "SESSION"
            row("Session", self.style(f"{marker} {session_id}", "yellow" if resumed else "cyan"))
        row("Tools", self.style(f"{tools} tools  ·  {skills} skills", "muted"))
        row("Project", self.style(str(self.project), "muted"))

        self.write(self.style("┗" + "━" * max(1, width - 2) + "┛", "green", "bold"))
        self.write(self.style(("  TAB autocomplete · ↑↓ history · /help commands · Ctrl-C cancel")[: width], "muted"))

    def prompt(self) -> str:
        # ANSI escapes in readline prompts leak in some terminals/loggers and
        # can break cursor-width accounting. Keep the typing line plain.
        return "\nHacker-Harness ❯ "

    def notice(self, text: str, kind: str = "info") -> None:
        marker, color = {"ok": ("✓", "green"), "warn": ("!", "yellow"), "error": ("×", "red")}.get(kind, ("◇", "cyan"))
        self.write(f"{self.style(marker, color, 'bold')} {text}")

    def card(self, title: str, body: str = "", status: str = "", color: str = "cyan", line_limit: int | None = None) -> None:
        if not self.cards:
            self.write(f"[{title}] {status}".rstrip())
            if body:
                self.write(body)
            return
        width = max(20, self.width)
        suffix = f" · {status}" if status else ""
        heading = f" {title}{suffix} "
        if len(heading) + 4 > width:
            avail = max(1, width - len(status) - 8)
            heading = f" {title[:avail]}…{suffix} " if len(title) > avail else f" {title}{suffix} "
            if len(heading) + 4 > width:
                heading = f" {title[:max(1, width - 6)]} "
        top_dashes = max(1, width - 3 - len(heading))
        self.write(self.style("╭─" + heading + "─" * top_dashes + "╮", color))
        if body:
            content_width = max(1, width - 4)
            lines: list[str] = []
            for raw in str(body).splitlines() or [""]:
                wrapped = textwrap.wrap(raw, width=content_width, replace_whitespace=False, drop_whitespace=False)
                lines.extend(wrapped if wrapped else [""])
            limit = self.max_lines if line_limit is None else line_limit
            for line in lines[:limit]:
                visible = ANSI_RE.sub("", line)
                pad = max(0, content_width - len(visible))
                self.write(self.style("│ ", color) + line + " " * pad + self.style(" │", color))
            if len(lines) > limit:
                more = self.style(f"… {len(lines) - limit} more lines", "muted")
                self.write(self.style("│ ", color) + self._pad_visible(more, content_width) + self.style(" │", color))
        self.write(self.style("╰" + "─" * (width - 2) + "╯", color))

    def approve(self, question: str, session_key: str | None = None) -> bool:
        key = session_key or question
        if key in self._approved:
            return True
        self.card("Approval required", question, "pending", "yellow", 8)
        try:
            answer = self.input_fn("  [y] allow once  [a] allow exact action for session  [n] deny  ❯ ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            self.write()
            return False
        allowed = answer in {"y", "yes", "a", "always"}
        if allowed and answer in {"a", "always"}:
            self._approved.add(key)
        if not allowed:
            self.notice("Denied", "error")
        return allowed

    def _flash_error(self, text: str) -> None:
        line = self.style("× " + text, "red", "bold")
        flash = getattr(self.stream, "flash", None)
        if callable(flash):
            flash(line + "\n")
            return
        self.notice(text, "error")

    def event(self, name: str, payload: dict) -> None:
        if name == "model_start":
            self._round_tools = []
        elif name == "notice":
            self.notice(str(payload.get("text", "")), "warn")
        elif name == "model_end":
            if self.tool_mode == "summary":
                self._round_summary()
        elif name == "tool_start":
            entry = {"name": payload.get("name", "tool"), "status": "running", "ok": None, "result_line": "", "line": self._tool_summary(payload.get("name", "tool"), payload.get("arguments", {}))}
            self._round_tools.append(entry)
            verbose = self.tool_mode == "full" or not self._is_routine_tool(entry["name"])
            if verbose:
                arguments = payload.get("arguments", {})
                body = json.dumps(arguments, ensure_ascii=False, indent=2) if self.tool_mode == "full" else entry["line"]
                self.card(entry["name"], body, "running", "cyan", 3)
        elif name == "tool_end":
            result = payload.get("result")
            success = bool(getattr(result, "ok", False))
            output = getattr(result, "output", "")
            elapsed = payload.get("elapsed", 0.0)
            entry = next((item for item in reversed(self._round_tools) if item["name"] == payload.get("name", "tool") and item["status"] == "running"), None)
            if entry is not None:
                entry["status"] = "done"
                entry["ok"] = success
                entry["elapsed"] = elapsed
                if payload.get("name", "tool") in {"http_request", "run_command"}:
                    head = next((line for line in output.splitlines() if line.strip()), "")
                    entry["result_line"] = head[:40]
            if not success and self.tool_mode != "full":
                head = next((line for line in str(output).splitlines() if line.strip()), "failed")
                self._flash_error(f"{payload.get('name', 'tool')} · {head}")
                return
            verbose = self.tool_mode == "full" or (not self._is_routine_tool(payload.get("name", "tool"))) or not success
            if verbose:
                body = ""
                if self.tool_mode == "full":
                    body = output if self.show_output else ""
                elif entry is not None and self.show_output and not self._is_routine_tool(payload.get("name", "tool")):
                    body = output or entry["result_line"]
                elif entry is not None:
                    body = entry["result_line"] or output
                self.card(payload.get("name", "tool"), body, f"{'done' if success else 'failed'} · {elapsed:.1f}s", "green" if success else "red")
        elif name == "context_update":
            pass
        elif name == "assistant":
            text = str(payload.get("text") or "").strip()
            if text:
                self.assistant(text)
    def _round_summary(self) -> None:
        """One condensed status line per model round: what ran, what came back."""
        if not self._round_tools:
            return
        groups: dict[str, dict] = {}
        for item in self._round_tools:
            group = groups.setdefault(item["name"], {"count": 0, "statuses": set(), "failed": 0})
            group["count"] += 1
            if item.get("result_line"):
                group["statuses"].add(item["result_line"])
            if item.get("ok") is False:
                group["failed"] += 1
        parts = []
        for name, group in groups.items():
            label = f"{name} ×{group['count']}"
            if group["failed"]:
                label += " · FAILED"
            elif group["statuses"]:
                label += " → " + ", ".join(sorted(group["statuses"]))
            parts.append(label)
        prefix = f"[{self._stage}] " if self._stage else ""
        self.notice(f"{prefix}⚡ " + " · ".join(parts))

    def _context_meter(self, status: dict) -> str:
        used = int(status.get("used", 0))
        window = int(status.get("window", 0))
        percent = float(status.get("percent", 0))
        cells = 20
        filled = min(cells, round(cells * percent / 100))
        bar = "█" * filled + "░" * (cells - filled)
        color = "red" if percent >= 90 else "yellow" if percent >= 50 else "green"
        return self.style(f"{bar} {percent:.0f}%", color)

    def context(self, payload: dict) -> None:
        used = int(payload.get("used", 0))
        window = int(payload.get("window", 0))
        self.write(self.style("  Context ", "muted") + self._context_meter(payload) + self.style(f"  {used:,}/{window:,} tokens", "muted"))

    def model_picker(self, profiles: dict, active: str) -> str | None:
        names = list(profiles)
        lines = []
        for index, name in enumerate(names, 1):
            profile = profiles[name]
            lines.append(f"{index:>2}. {'●' if name == active else '○'} {name}  ·  {profile.get('model', '')}  [{profile.get('format', '')}]")
        self.card("Model profiles", "\n".join(lines), "select", "cyan", 100)
        try:
            selected = self.input_fn("  Number or profile name ❯ ").strip()
        except (EOFError, KeyboardInterrupt):
            self.write()
            return None
        if selected.isdigit() and 1 <= int(selected) <= len(names):
            return names[int(selected) - 1]
        return selected or None

    def assistant(self, text: str) -> None:
        stop_fn = getattr(self.stream, "stop", None)
        if callable(stop_fn):
            stop_fn()
        self.write("\n" + self.style("● Hacker-Harness", "green", "bold"))
        width = max(20, self.width)
        animate = self.color and not self._instant_assistant
        in_code_block = False
        for raw in str(text).rstrip().splitlines() or [""]:
            if raw.strip().startswith("```"):
                in_code_block = not in_code_block
                styled = self.style(raw, "yellow" if in_code_block else "muted")
                if animate:
                    self._stream_assistant_line(styled)
                else:
                    self.write(styled)
                continue
            if in_code_block or raw.startswith("    ") or raw.startswith("\t"):
                styled = self.style(raw, "yellow")
                if animate:
                    self._stream_assistant_line(styled)
                else:
                    self.write(styled)
                continue
            pieces = textwrap.wrap(raw, width=width, replace_whitespace=False, drop_whitespace=False) or [""]
            for index, piece in enumerate(pieces):
                styled = self._assistant_line(piece) if index == 0 else self._inline_markdown(piece)
                if animate:
                    self._stream_assistant_line(styled)
                else:
                    self.write(styled)
        self.write()

    def _stream_assistant_line(self, styled: str) -> None:
        """Reveal one commentary line left-to-right, keeping ANSI spans intact."""
        chunks = self._visible_chunks(styled, 3)
        if not chunks:
            self.write("")
            return
        for index, chunk in enumerate(chunks):
            self.stream.write(chunk)
            if index == len(chunks) - 1:
                self.stream.write("\n")
            self.stream.flush()
            time.sleep(0.005)

    def _visible_chunks(self, text: str, size: int) -> list[str]:
        chunks: list[str] = []
        buf: list[str] = []
        visible = 0
        index = 0
        length = len(text)
        while index < length:
            if text[index] == "\x1b":
                end = index
                while end < length and text[end] != "m":
                    end += 1
                buf.append(text[index : end + 1] if end < length else text[index:])
                index = end + 1 if end < length else length
                continue
            buf.append(text[index])
            visible += 1
            index += 1
            if visible >= size:
                chunks.append("".join(buf))
                buf = []
                visible = 0
        if buf:
            chunks.append("".join(buf))
        return chunks

    def _assistant_line(self, line: str) -> str:
        """Color headings, lists, and inline markers on one assistant line."""
        stripped = line.lstrip()
        indent = line[: len(line) - len(stripped)]
        heading = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if heading:
            depth = len(heading.group(1))
            colors = {1: "cyan", 2: "green", 3: "yellow"}
            return indent + self.style(self._inline_markdown(heading.group(2)), colors.get(depth, "muted"), "bold")
        if re.match(r"^(-{3,}|\*{3,}|_{3,})$", stripped):
            return indent + self.style("─" * min(32, max(3, self.width - 8)), "muted")
        quote = re.match(r"^>\s?(.*)$", stripped)
        if quote:
            return indent + self.style("│ ", "muted") + self.style(self._inline_markdown(quote.group(1)), "muted")
        bullet = re.match(r"^([-*+])\s+(.*)$", stripped)
        if bullet:
            return indent + self.style("• ", "cyan", "bold") + self._inline_markdown(bullet.group(2))
        numbered = re.match(r"^(\d+)([.)])\s+(.*)$", stripped)
        if numbered:
            return indent + self.style(f"{numbered.group(1)}{numbered.group(2)} ", "yellow", "bold") + self._inline_markdown(numbered.group(3))
        return indent + self._inline_markdown(stripped)

    def _inline_markdown(self, text: str) -> str:
        """Render `code`, **bold**, and *italic* without changing surrounding copy."""
        pattern = re.compile(r"`([^`]+)`|\*\*([^*]+)\*\*|__([^_]+)__|(?<!\*)\*([^*]+)\*(?!\*)")

        def replace(match: re.Match) -> str:
            if match.group(1) is not None:
                return self.style(match.group(1), "yellow")
            if match.group(2) is not None:
                return self.style(match.group(2), "bold")
            if match.group(3) is not None:
                return self.style(match.group(3), "bold")
            return self.style(match.group(4), "cyan")

        return pattern.sub(replace, text)

    def user(self, text: str, context: dict | None = None) -> None:
        header = "\n" + self.style("● You", "cyan", "bold")
        if context is not None and self.settings.get("showContext", True):
            header += "  " + self._context_meter(context)
        self.write(header)
        self._input_box(text)

    def _input_box(self, text: str) -> None:
        width = max(20, self.width)
        content_width = max(1, width - 4)
        lines: list[str] = []
        for raw in str(text).splitlines() or [""]:
            wrapped = textwrap.wrap(raw, width=content_width, replace_whitespace=False, drop_whitespace=False)
            lines.extend(wrapped if wrapped else [""])
        self.write(self.style("┌" + "─" * (width - 2) + "┐", "cyan"))
        for line in lines:
            visible = ANSI_RE.sub("", line)
            pad = max(0, content_width - len(visible))
            self.write(self.style("│ ", "cyan") + line + " " * pad + self.style(" │", "cyan"))
        self.write(self.style("└" + "─" * (width - 2) + "┘", "cyan"))

    def _sync_phase_status(self, *, clear: bool = False) -> None:
        set_status = getattr(self.stream, "set_status", None)
        if clear or not self._phase_progress:
            if callable(set_status):
                set_status("")
            return
        phase = self._phase_progress
        cells = 16
        filled = round(cells * phase["completed"] / phase["total"]) if phase["total"] else 0
        bar = "█" * filled + "░" * (cells - filled)
        label = f"{phase['kind']} {phase['completed']}/{phase['total']} {bar} {phase['detail']}"
        if callable(set_status):
            set_status(label)

    def phase_status_fragments(self) -> list[tuple[str, str]]:
        if not self._phase_progress:
            return []
        phase = self._phase_progress
        cells = 8
        filled = round(cells * phase["completed"] / phase["total"]) if phase["total"] else 0
        bar = "█" * filled + "░" * (cells - filled)
        short = phase["detail"].split(":", 1)[0] if ":" in phase["detail"] else phase["detail"]
        return [
            ("muted", " · "),
            ("cyan", f"{phase['kind']} {phase['completed']}/{phase['total']} "),
            ("yellow", f"{bar} "),
            ("green", short[:48]),
        ]

    def _set_phase_progress(self, kind: str, current: int, total: int, state: str, detail: str) -> None:
        if state == "MOVING TO":
            return
        if state == "FAILED":
            self._phase_progress = None
            self._sync_phase_status(clear=True)
            self.notice(f"{kind} failed: {detail}", "error")
            return
        completed = current if state == "COMPLETED" else max(0, current - 1)
        stage_key = detail.split(":", 1)[0].strip() if ":" in detail else detail.strip()
        if state == "COMPLETED":
            self._stage = f"{stage_key} ✓"
        else:
            self._stage = stage_key
        self._phase_progress = {
            "kind": kind,
            "current": current,
            "total": total,
            "completed": completed,
            "state": state.lower(),
            "detail": detail,
        }
        self._sync_phase_status()
        if state == "COMPLETED":
            self.notice(f"{kind} {current}/{total} · {detail}", "ok")

    def methodology(self, text: str) -> None:
        match = re.match(r"\[(\d+)/(\d+)\]\s+(STARTED|COMPLETED|FAILED|MOVING TO)\s+(.*)", text)
        if match:
            self._set_phase_progress(
                "Methodology",
                int(match.group(1)),
                int(match.group(2)),
                match.group(3),
                match.group(4),
            )
            return
        self.notice(text)

    def workflow_progress(self, text: str) -> None:
        match = re.match(r"\[(\d+)/(\d+)\]\s+(STARTED|COMPLETED|FAILED|MOVING TO)\s+(.*)", text)
        if match:
            self._set_phase_progress(
                "Workflow",
                int(match.group(1)),
                int(match.group(2)),
                match.group(3),
                match.group(4),
            )
            return
        if text.startswith("[FAILED]"):
            self._set_phase_progress("Workflow", 0, 0, "FAILED", text[len("[FAILED]"):].strip())
            return
        self.notice(text, "ok")

    def clear_phase_progress(self) -> None:
        self._phase_progress = None
        self._sync_phase_status(clear=True)

    def help(self, workflow_commands: list[str] | None = None) -> None:
        body = (
            "/help             Show commands\n"
            "/commands         Show imported workflow commands\n"
            "/methodologies    Markdown methodology deck\n"
            "/workflows        List YAML DAG workflows\n"
            "/workflow <name>  Run a YAML DAG workflow\n"
            "/use <name>       Load a markdown methodology into context\n"
            "/advance          Next methodology stage if required files exist\n"
            "/scope            Authorization scope\n"
            "/skills           Loaded SKILL.md files\n"
            "/pivot [finding]  Suggest next attack pivot skills based on findings\n"
            "/report [target]  Generate multi-format pentest report (--html/csv/hackerone/bugcrowd/intigriti/immunefi/yeswehack)\n"
            "/retest [target]  Differential regression retesting for findings (/retest <target> all/F1/C1)\n"
            "/tree [on|off]    Live attack tree visualization toggle\n"
            "/model [profile]  Select a custom model profile\n"
            "/version          Harness version and session\n"
            "/context          Context-window utilization\n"
            "/compact          Summarize conversation to reclaim context\n"
            "/sessions         List resumable sessions\n"
            "/resume [id]      Resume a previous session\n"
            "/new              Start a new session\n"
            "/tools            Offensive tool inventory\n"
            "/mcp [connect]    MCP server status or connection\n"
            "/goal             List engagement goals\n"
            "/goal add <text>  Add a goal\n"
            "/goal current     Show the active goal\n"
            "/goal set <id> <status>  Set goal status\n"
            "/goal done <id>   Complete a goal\n"
            "/goal remove <id> Delete a goal\n"
            "/findings         Structured engagement findings\n"
            "/validate [id]    7-Question validation gate report\n"
            "/vulns            Vulnerabilities.md sidebar content (full list)\n"
            "/settings         Settings file and UI options\n"
            "/tasks            Ready task queue\n"
            "/comment <text>   Queue a comment (pending)\n"
            "/clear            Reset conversation context\n"
            "/quit             Exit"
        )
        if workflow_commands:
            body += "\n\nImported workflows:\n" + "\n".join(f"/{name} <target>" for name in workflow_commands)
        self.card("Commands", body, line_limit=100)

"""prompt_toolkit chat surfaces for real terminals.

Two modes:

- ``LinearChat`` (default): a CLI-style single-line prompt on the normal
  terminal. Output prints to stdout, so the terminal's own scrollback,
  wheel scrolling, and native selection/copy keep working for both output
  and input. No alternate screen, no PageUp/PageDown handling.
- ``FullScreenChat`` (opt-in via ``ui.fullscreen: true``): the legacy
  full-screen alternate-buffer surface with a scrolling output window,
  PageUp/PageDown and mouse-wheel scrolling, and drag-to-select copy.

The chat loop itself stays synchronous and TTY-agnostic. Every non-TTY path
falls back to the plain readline/print flow in ``cli.py``.
"""
from __future__ import annotations

import asyncio
import atexit
import base64
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

try:
    from prompt_toolkit import Application
    from prompt_toolkit.auto_suggest import AutoSuggest, Suggestion
    from prompt_toolkit.buffer import Buffer
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.document import Document
    from prompt_toolkit.history import FileHistory, InMemoryHistory
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.filters import Condition
    from prompt_toolkit.layout import HSplit, Layout, Window
    from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
    from prompt_toolkit.layout.margins import PromptMargin
    from prompt_toolkit.layout.processors import AppendAutoSuggestion
    from prompt_toolkit.lexers import Lexer
    from prompt_toolkit.shortcuts import PromptSession
    from prompt_toolkit.styles import Style
    from prompt_toolkit.selection import SelectionState

    PROMPT_TOOLKIT = True
except ImportError:  # pragma: no cover - exercised only when the optional dep is absent
    PROMPT_TOOLKIT = False


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Hacker-Harness TerminalUI palette -> prompt_toolkit style class names.
_COLOR_CODES = {
    "38;5;82": "green",
    "38;5;45": "cyan",
    "38;5;220": "yellow",
    "38;5;203": "red",
    "38;5;244": "muted",
}

_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_BUSY_WORDS = ("thinking", "working", "looking", "probing", "investigating", "roaming", "analyzing")

# Hacker-Harness palette class names -> SGR color codes (inverse of _COLOR_CODES).
_SGR = {
    "green": "38;5;82",
    "cyan": "38;5;45",
    "yellow": "38;5;220",
    "red": "38;5;203",
    "muted": "38;5;244",
}

def strip_ansi(text: str) -> str:
    """Remove SGR escape sequences, leaving visible text only."""
    return _ANSI_RE.sub("", text)


_clip_helper: subprocess.Popen | None = None


def _kill_clip_helper() -> None:
    global _clip_helper
    if _clip_helper is not None:
        try:
            if _clip_helper.poll() is None:
                _clip_helper.kill()
        except Exception:
            pass


def _copy_to_clipboard(text: str, stream: TextIO | None = None) -> bool:
    """Copy text to the system clipboard.

    Tries the usual clipboard CLI tools; when none are installed, spawns a
    tiny Tk helper that owns the X11 (or XWayland) clipboard and keeps
    servicing selection requests; last falls back to the OSC 52 terminal
    escape.
    """
    if not text:
        return False
    for tool, args in (
        ("xclip", ["-selection", "clipboard"]),
        ("xsel", ["--clipboard", "--input"]),
        ("wl-copy", []),
        ("pbcopy", []),
        ("termux-clipboard-set", []),
        ("win32yank.exe", ["-i"]),
        ("lemonade", ["copy"]),
    ):
        if shutil.which(tool):
            try:
                subprocess.run([tool, *args], input=text, text=True, timeout=5, check=True)
                # Also publish X11 PRIMARY so middle-click paste works after a drag-copy.
                if tool == "xclip":
                    subprocess.run([tool, "-selection", "primary"], input=text, text=True, timeout=5, check=False)
                elif tool == "xsel":
                    subprocess.run([tool, "--primary", "--input"], input=text, text=True, timeout=5, check=False)
                return True
            except Exception:
                continue
    # X11 (or XWayland) clipboard via a Tk helper process. It must run its own
    # mainloop so it can answer the reader's selection requests; an in-process
    # Tk root would own the selection but never service it, timing out reads.
    if os.environ.get("DISPLAY"):
        try:
            global _clip_helper
            if _clip_helper is not None and _clip_helper.poll() is None:
                _clip_helper.kill()
            code = (
                "import sys, tkinter\n"
                "root = tkinter.Tk(); root.withdraw()\n"
                "root.clipboard_clear(); root.clipboard_append(sys.stdin.read())\n"
                "root.mainloop()\n"
            )
            proc = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE, text=True)
            proc.stdin.write(text)
            proc.stdin.close()
            _clip_helper = proc
            return True
        except Exception:
            pass
    # OSC 52 terminal escape (xterm, GNOME Terminal, Konsole, kitty, foot,
    # WezTerm, tmux, … support it, but some terminals ignore it).
    try:
        payload = base64.b64encode(text.encode("utf-8")).decode("ascii")
        out = stream or sys.stdout
        out.write(f"\x1b]52;c;{payload}\x1b\\")
        out.flush()
        return True
    except Exception:
        return False


atexit.register(_kill_clip_helper)

def lex_ansi(line: str) -> list[tuple[str, str]]:
    """Split one ANSI-colored line into ``(style, text)`` tuples.

    ``style`` is a space-separated prompt_toolkit style string such as
    ``"class:green bold"``. Plain text yields ``("", text)``. This function is
    pure and unit-testable without a terminal.
    """
    if "\x1b" not in line:
        return [("", line)]
    parts: list[tuple[str, str]] = []
    color: str | None = None
    bold = False
    i = 0
    n = len(line)
    while i < n:
        if line[i] == "\x1b":
            end = line.find("m", i)
            if end == -1:
                break
            code = line[i + 2:end]
            if code == "0":
                color, bold = None, False
            elif code == "1":
                bold = True
            elif code in _COLOR_CODES:
                color = _COLOR_CODES[code]
            i = end + 1
            continue
        nxt = line.find("\x1b", i)
        if nxt == -1:
            nxt = n
        text = line[i:nxt]
        if text:
            styles = []
            if color:
                styles.append(f"class:{color}")
            if bold:
                styles.append("bold")
            parts.append((" ".join(styles), text))
        i = nxt
    return parts or [("", "")]


class ChatOutput:
    """Thread-safe sink for rendered output plus a one-line live status.

    Implements the subset of the file interface ``print()`` needs so it can be
    handed to ``TerminalUI`` as its ``stream``.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._text = ""
        self._status = ""
        self._flash_at = 0
        self._flash_len = 0
        self._flash_text = ""
        self._flash_token = 0
        self.on_change = None

    def _notify(self) -> None:
        callback = self.on_change
        if callback is None:
            return
        try:
            callback()
        except Exception:
            pass

    def write(self, text: str) -> None:
        with self._lock:
            self._text += text
        self._notify()

    def flash(self, text: str, seconds: float = 2.5) -> None:
        """Show a line in the transcript, then remove it so errors do not linger."""
        payload = text if text.endswith("\n") else text + "\n"
        with self._lock:
            if self._flash_len and self._text[self._flash_at : self._flash_at + self._flash_len] == self._flash_text:
                self._text = self._text[: self._flash_at] + self._text[self._flash_at + self._flash_len :]
            self._flash_at = len(self._text)
            self._text += payload
            self._flash_text = payload
            self._flash_len = len(payload)
            self._flash_token += 1
            token = self._flash_token
        self._notify()

        def hide() -> None:
            time.sleep(max(0.05, seconds))
            with self._lock:
                if token != self._flash_token:
                    return
                start, length, blob = self._flash_at, self._flash_len, self._flash_text
                if length and self._text[start : start + length] == blob:
                    self._text = self._text[:start] + self._text[start + length :]
                self._flash_len = 0
                self._flash_text = ""
            self._notify()

        threading.Thread(target=hide, daemon=True).start()

    def flush(self) -> None:
        return None

    def read(self) -> str:
        with self._lock:
            return self._text

    def lines(self) -> list[str]:
        with self._lock:
            return self._text.splitlines()

    def set_status(self, text: str) -> None:
        with self._lock:
            self._status = text
    def status(self) -> str:
        with self._lock:
            return self._status

    def clear(self) -> None:
        """Drop buffered transcript text (used when switching resumed sessions)."""
        with self._lock:
            self._text = ""

    def isatty(self) -> bool:
        # Full-screen output is color-capable (parsed back by ANSILexer).
        return True


def is_fullscreen_available(settings: dict | None = None, stdin=None, stdout=None) -> bool:
    """True when the legacy alternate-buffer full-screen surface is explicitly enabled.

    Default on a TTY is the CLI-style ``LinearChat`` prompt on the normal
    terminal (``ui.fullscreen: false``), which provides native terminal
    scrolling, selection/copy, and zero rendering lag. ``ui.fullscreen: true``
    opts into the legacy full-screen alternate-buffer surface.
    """
    if not PROMPT_TOOLKIT:
        return False
    ui = (settings or {}).get("ui", {}) if settings else {}
    if not ui.get("fullscreen", True):
        return False
    import sys

    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    try:
        return bool(getattr(stdin, "isatty", lambda: False)()) and bool(getattr(stdout, "isatty", lambda: False)())
    except Exception:
        return False


class LinearChat:
    """CLI-style chat on the normal terminal with a boxed input area.

    Output prints to the real stdout, so the terminal's own scrollback, wheel
    scrolling, and native selection/copy work for both output and input — no
    alternate screen, no PageUp/PageDown handling.

    Each prompt is drawn as a box, mirroring the full-screen surface's status
    bar without leaving the terminal's normal buffer:

    .. code-block:: text

        ╭─ Model: deepseek-v4-flash   Working Directory: ~/x   Context Utilization: 18% ──╮
        │  Hacker-Harness ❯ <typed input>
        ╰──────────────────────────────────────────────────────────────────────────────────╯

    The top border carries the live status fragments from ``get_status`` (the
    same ``(style, text)`` list the full-screen status bar renders); the input
    line carries the colored ``Hacker-Harness ❯`` prompt; the box is closed
    with a bottom border once the input is accepted. While the agent
    processes, a simple animated ``⠋ thinking`` line (like Oh My Pi's status)
    draws below the box and yields to the first line of output.
    """

    def __init__(self, history_path: Path | None = None, completer=None, prompt: str = "Hacker-Harness ❯ ", get_status: Callable[[], list] | None = None, stream: TextIO | None = None, spinner: SpinnerStream | None = None, auto_suggest=None):
        if not PROMPT_TOOLKIT:
            raise ImportError("prompt_toolkit is required for LinearChat")
        from prompt_toolkit.history import FileHistory, InMemoryHistory
        from prompt_toolkit.shortcuts import PromptSession
        from prompt_toolkit.styles import Style

        if history_path is not None:
            history_path = Path(history_path)
            history_path.parent.mkdir(parents=True, exist_ok=True)
            if not history_path.exists():
                history_path.touch(mode=0o600)
            else:
                try:
                    history_path.chmod(0o600)
                except OSError:
                    pass
            self._history = FileHistory(str(history_path))
        else:
            self._history = InMemoryHistory()
        self.prompt = prompt
        self.get_status = get_status or (lambda: [])
        self.stream = stream or sys.stdout
        self._spinner = spinner
        if spinner is not None:
            spinner.line_fn = self._spinner_line
        self._color = "NO_COLOR" not in os.environ
        self.session = PromptSession(
            history=self._history,
            completer=completer,
            auto_suggest=auto_suggest,
            complete_while_typing=False,
            multiline=False,
            style=Style.from_dict(
                {
                    "green": "#5fd700",
                    "cyan": "#00d7d7",
                    "yellow": "#d7af00",
                    "red": "#d75f5f",
                    "muted": "#808080",
                    "auto-suggestion": "#808080",
                }
            ),
        )

    @staticmethod
    def available() -> bool:
        """True when prompt_toolkit is installed (the linear surface needs it)."""
        return PROMPT_TOOLKIT

    def _columns(self) -> int:
        return max(40, shutil.get_terminal_size((88, 24)).columns)

    def _sgr(self, *names: str) -> str:
        if not self._color:
            return ""
        return "\033[" + ";".join(_SGR[name] for name in names) + "m"

    @staticmethod
    def _cls(style: str) -> str:
        return f"class:{style}" if style and not style.startswith("class:") else style

    def _border_fragments(self, fragments: list[tuple[str, str]]) -> list[tuple[str, str]]:
        """Render status fragments as the box's top border, truncated to fit."""
        cols = self._columns()
        head, tail = "╭─ ", "─╮"
        budget = cols - len(head) - len(tail)
        pieces: list[tuple[str, str]] = []
        used = 0
        for style, text in fragments:
            if not text:
                continue
            room = budget - used
            if len(text) <= room:
                pieces.append((self._cls(style), text))
                used += len(text)
                continue
            if room > 4:
                pieces.append((self._cls(style), text[: room - 1] + "…"))
                used += room
            break
        dashes = max(0, budget - used)
        return [("class:green", head), *pieces, ("class:green", "─" * dashes + tail)]

    def _top_border(self) -> list[tuple[str, str]]:
        """Status fragments rendered as the box's top border, truncated to fit."""
        return self._border_fragments(list(self.get_status()))

    def _spinner_line(self, frame: str) -> str:
        """The animated thinking indicator: just the spinner frame and word,
        like Oh My Pi's status — no status fragments."""
        text = self._spinner._text if self._spinner is not None else "thinking"
        if not self._color:
            return f"{frame} {text}"
        return f"\033[38;5;45m{frame} {text}\033[0m"

    def _prompt_message(self) -> list[tuple[str, str]]:
        """Formatted prompt: status top border, then the colored input line."""
        return [
            *self._top_border(),
            ("", "\n"),
            ("class:green", "│  "),
            ("class:green bold", self.prompt),
        ]

    def _nested_message(self, prompt_text: str) -> list[tuple[str, str]]:
        """Formatted prompt for a nested question (approval, selection)."""
        cols = self._columns()
        label = " Question "
        dashes = max(1, cols - 3 - len(label))
        return [
            ("class:green", f"╭─{label}{'─' * dashes}╮"),
            ("", "\n"),
            ("class:green", "│  "),
            ("", prompt_text),
        ]

    def _bottom_toolbar(self):
        cols = self._columns()
        return [("class:green", "╰" + "─" * (cols - 2) + "╯")]

    def _erase_prompt(self, text: str) -> None:
        lines = 1 + max(1, len(text.splitlines()))
        seq = "\033[1A\033[2K" * lines + "\r"
        print(seq, end="", file=self.stream, flush=True)

    def sub_input(self, prompt_text: str) -> str:
        """Ask a nested question (approval, selection) from the agent thread."""
        if self._spinner is not None:
            self._spinner.stop()
        try:
            res = self.session.prompt(self._nested_message(prompt_text), bottom_toolbar=self._bottom_toolbar)
            self._erase_prompt(res)
            return res
        except (EOFError, KeyboardInterrupt):
            self._erase_prompt("")
            return ""
        finally:
            if self._spinner is not None:
                self._spinner.start()

    def run(self, handler: Callable[[str], bool]) -> None:
        """Prompt in a loop until ``handler`` returns truthy (quit).

        ``KeyboardInterrupt`` (Ctrl-C on an empty line) and ``EOFError``
        (Ctrl-D) propagate so the caller can save state and exit, matching the
        plain readline fallback.
        """
        while True:
            try:
                text = self.session.prompt(self._prompt_message(), bottom_toolbar=self._bottom_toolbar)
            except (EOFError, KeyboardInterrupt):
                self._erase_prompt("")
                raise
            self._erase_prompt(text)
            if not text.strip():
                continue
            if self._spinner is not None:
                self._spinner.start()
            try:
                quit_now = handler(text)
            finally:
                if self._spinner is not None:
                    self._spinner.stop()
            if quit_now:
                return


class SpinnerStream:
    """Terminal stream wrapper with a single-line ``thinking`` animation.

    While active, a background thread redraws one line in place
    (``\\r`` + erase + frame). Any real output written through the wrapper
    clears the spinner line once and then passes through untouched, so tool
    cards and responses are never corrupted by the animation — the spinner
    yields to output and resumes in the gaps, the standard CLI pattern.

    The erase is gated on a ``_line_drawn`` flag rather than applied to every
    write: ``print()`` issues one ``write`` per value and one for the newline,
    and an unconditional erase would wipe the line the value just landed on
    (this is what made the startup banner disappear). With no spinner line on
    screen, writes pass through byte-for-byte.

    ``line_fn`` optionally customizes the drawn line (e.g. the status border
    with the frame embedded). Implements the file interface ``print()`` needs
    so it can be handed to ``TerminalUI`` as its ``stream``.
    """

    def __init__(self, stream: TextIO | None = None, text: str = "thinking", interval: float = 0.1, line_fn: Callable[[str], str] | None = None):
        self._base = stream or sys.stdout
        self._text = text
        self._interval = interval
        self._line_fn = line_fn
        self._color = "NO_COLOR" not in os.environ
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._frame = 0
        self._active = False
        self._line_drawn = False

    # file interface used by print()/TerminalUI
    def write(self, text: str) -> None:
        with self._lock:
            if self._line_drawn:
                self._base.write("\r\x1b[K")
                self._line_drawn = False
            self._base.write(text)
            self._base.flush()

    def flush(self) -> None:
        self._base.flush()

    def isatty(self) -> bool:
        return getattr(self._base, "isatty", lambda: False)()

    @property
    def line_fn(self) -> Callable[[str], str] | None:
        return self._line_fn

    @line_fn.setter
    def line_fn(self, value: Callable[[str], str] | None) -> None:
        self._line_fn = value

    # spinner control
    def start(self) -> None:
        if self._active:
            return
        self._active = True
        self._frame = 0
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._active = False
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None
        with self._lock:
            if self._line_drawn:
                self._base.write("\r\x1b[K")
                self._line_drawn = False
            self._base.flush()

    def _loop(self) -> None:
        while self._active:
            frame = _SPINNER[self._frame % len(_SPINNER)]
            self._frame += 1
            with self._lock:
                if self._line_drawn:
                    self._base.write("\r\x1b[K")
                self._base.write(self._line_fn(frame) if self._line_fn else self._style(f"{frame} {self._text}"))
                self._line_drawn = True
                self._base.flush()
            time.sleep(self._interval)

    def _style(self, text: str) -> str:
        if not self._color:
            return text
        return f"\033[38;5;45m{text}\033[0m"


if PROMPT_TOOLKIT:

    class ANSILexer(Lexer):
        """Map Hacker-Harness ANSI color codes onto prompt_toolkit styles."""

        def lex_document(self, document: Document):
            def get_line(lineno: int) -> list[tuple[str, str]]:
                return lex_ansi(document.lines[lineno])

            return get_line

    class HarnessCompleter(Completer):
        """Reuse the existing pure completion logic for the full-screen prompt."""

        def __init__(self, commands, models, sessions, methodologies, yaml_workflows, targets):
            self._commands = commands
            self._models = models
            self._sessions = sessions
            self._methodologies = methodologies
            self._yaml_workflows = yaml_workflows
            self._targets = targets

        def get_completions(self, document, complete_event):
            from .line_editor import completion_candidates

            buffer = document.text_before_cursor
            word = document.get_word_before_cursor(WORD=True)
            try:
                options = completion_candidates(
                    buffer,
                    word,
                    self._commands(),
                    self._models(),
                    self._sessions(),
                    self._methodologies(),
                    self._yaml_workflows(),
                    self._targets(),
                )
            except Exception:
                return
            start = -len(word)
            for option in options:
                yield Completion(option, start_position=start)

    class HarnessAutoSuggest(AutoSuggest):
        """Context-aware auto-suggestion (ghost text) matching commands, targets, flags, and history."""

        def __init__(self, commands, models, sessions, methodologies, yaml_workflows, targets):
            self._commands = commands
            self._models = models
            self._sessions = sessions
            self._methodologies = methodologies
            self._yaml_workflows = yaml_workflows
            self._targets = targets

        def get_suggestion(self, buffer, document):
            text = document.text_before_cursor
            if not text:
                return None
            if not document.is_cursor_at_the_end:
                return None

            # Auto-suggestion triggers only for slash commands (e.g. /rep, /report te, /tree on)
            if not text.lstrip().startswith("/"):
                return None

            word = document.get_word_before_cursor(WORD=True)

            # 1. Match command / context-aware completions
            from .line_editor import completion_candidates
            try:
                options = completion_candidates(
                    text,
                    word,
                    self._commands(),
                    self._models(),
                    self._sessions(),
                    self._methodologies(),
                    self._yaml_workflows(),
                    self._targets(),
                )
                if options:
                    for opt in options:
                        if word and opt.lower().startswith(word.lower()) and len(opt) > len(word):
                            return Suggestion(opt[len(word):])
                        elif not word and opt:
                            return Suggestion(opt)
            except Exception:
                pass

            # 2. Fallback to history matching for slash commands
            if buffer is not None and getattr(buffer, "history", None):
                try:
                    hist_strings = buffer.history.get_strings()
                    for line in reversed(hist_strings):
                        if line.startswith(text) and len(line) > len(text):
                            return Suggestion(line[len(text):])
                except Exception:
                    pass

            return None

    class FullScreenChat:
        """OMP-style surface: scrolling conversation, an animated thinking line,
        and a static boxed input pinned at the bottom of the screen."""

        STYLE = Style.from_dict(
            {
                "green": "#5fd700",
                "cyan": "#00d7d7",
                "yellow": "#d7af00",
                "red": "#d75f5f",
                "muted": "#808080",
                "border": "#5fd700",
                "prompt": "#5fd700 bold",
                "auto-suggestion": "#808080",
            }
        )

        def __init__(
            self,
            output: ChatOutput,
            history_path: Path,
            completer: HarnessCompleter | None = None,
            get_status: Callable[[], list] | None = None,
            busy_comment: Callable[[str], None] | None = None,
            auto_suggest: HarnessAutoSuggest | None = None,
        ):
            self.output = output
            self.get_status = get_status or (lambda: [])
            self._handler: Callable[[str], bool] | None = None
            self._completer = completer
            self._auto_suggest = auto_suggest
            self._busy_comment = busy_comment
            self._rendered = ""
            self._busy = False
            self._awaiting_nested = False
            self._nested_answer: queue.Queue | None = None
            self._done = threading.Event()
            self._quit = False
            self._scrolled_up = False
            self._dragging = False
            self._last_click_time = 0.0
            self._last_click_cell = -1
            self._click_count = 0
            self._select_buf = None
            self._select_region = "output"

            history = FileHistory(str(history_path)) if history_path else InMemoryHistory()

            self.output_buffer = Buffer(read_only=True)
            self.input_buffer = Buffer(
                multiline=False,
                history=history,
                completer=completer,
                auto_suggest=auto_suggest,
                complete_while_typing=False,
                accept_handler=self._accept,
            )
            self._complete_options: list[str] = []
            self._completing = False
            self.input_buffer.on_text_changed += lambda _event: self._reset_completion()
            self.input_buffer.on_text_changed += lambda _event: self._update_suggestion()

            self.kb = KeyBindings()

            @self.kb.add("right")
            @self.kb.add("c-f")
            @self.kb.add("c-e")
            def _accept_suggestion(event):
                b = event.current_buffer
                if b.suggestion and b.document.is_cursor_at_the_end:
                    b.insert_text(b.suggestion.text)
                else:
                    b.cursor_right()

            @self.kb.add("escape", "f")
            def _fill_partial_suggestion(event):
                b = event.current_buffer
                if b.suggestion and b.document.is_cursor_at_the_end:
                    import re
                    parts = re.split(r"([^\s/]+(?:\s+|/))", b.suggestion.text)
                    token = next((x for x in parts if x), "")
                    if token:
                        b.insert_text(token)

            @self.kb.add("c-c")
            def _ctrl_c(event):
                if self.output_buffer.selection_state is not None:
                    self._copy_selection()
                elif event.current_buffer is not None and event.current_buffer.selection_state is not None:
                    self._copy_buffer_selection(event.current_buffer)
                else:
                    event.app.exit(exception=KeyboardInterrupt())

            @self.kb.add("c-d", filter=Condition(lambda: not self.input_buffer.text))
            def _ctrl_d(event):
                event.app.exit(exception=EOFError())

            @self.kb.add("c-z")
            def _ctrl_z(event):
                event.app.suspend_to_background()

            @self.kb.add("pageup")
            @self.kb.add("c-pageup")
            def _page_up(event):
                self._scroll_output(-self._page_size())

            @self.kb.add("pagedown")
            @self.kb.add("c-pagedown")
            def _page_down(event):
                self._scroll_output(self._page_size())

            @self.kb.add("tab")
            def _tab_complete(event):
                # Synchronous Tab completion: insert the first candidate that
                # extends the word before the cursor (mirrors the linear UI).
                self._complete_current_word(event.current_buffer)

            @self.kb.add("<vt100-mouse-event>")
            def _mouse_event(event):
                self._handle_mouse(event.data)

            self._output_window = Window(
                content=BufferControl(buffer=self.output_buffer, lexer=ANSILexer(), focusable=False),
                wrap_lines=False,
                always_hide_cursor=True,
            )
            self._spacer_window = Window(
                height=1,
                content=FormattedTextControl(text=""),
                always_hide_cursor=True,
            )
            self._top_border_window = Window(
                height=1,
                content=FormattedTextControl(text=self._top_border_text),
                style="class:border",
                always_hide_cursor=True,
            )
            self._input_window = Window(
                height=1,
                content=BufferControl(
                    buffer=self.input_buffer,
                    input_processors=[AppendAutoSuggestion()],
                ),
                left_margins=[PromptMargin(self._prompt_text)],
            )
            self._bottom_border_window = Window(
                height=1,
                content=FormattedTextControl(text=self._bottom_border_text),
                style="class:border",
                always_hide_cursor=True,
            )

            self.layout = Layout(
                HSplit(
                    [
                        self._output_window,
                        self._spacer_window,
                        self._top_border_window,
                        self._input_window,
                        self._bottom_border_window,
                    ]
                )
            )

            self.app = Application(
                layout=self.layout,
                key_bindings=self.kb,
                full_screen=True,
                style=self.STYLE,
                mouse_support=True,
            )
            self.output.on_change = lambda: self.app.invalidate()

        def _reset_completion(self) -> None:
            """Forget the active completion cycle when the user edits the line
            (but not while the completion itself is rewriting the buffer)."""
            if not self._completing:
                self._complete_options = []

        def _complete_current_word(self, b) -> bool:
            """Cycle through completion candidates for the word before the
            cursor: first Tab inserts the first match, further Tabs move to the
            next candidate. Returns True when a completion was applied."""
            if self._completer is None:
                return False
            doc = b.document
            # Nested prompts (model picker, approvals) have no /model prefix, so
            # complete against provider profile names instead of slash commands.
            if self._nested_answer is not None:
                try:
                    models = list(self._completer._models())
                except Exception:
                    return False
                word = doc.get_word_before_cursor(WORD=True) or doc.text
                matched = [name for name in models if name.lower().startswith(word.lower())] if word else list(models)
                if not matched:
                    return False
                current = doc.text_before_cursor
                if self._complete_options:
                    for i, option in enumerate(self._complete_options):
                        if current.endswith(option):
                            nxt = self._complete_options[(i + 1) % len(self._complete_options)]
                            if nxt == option:
                                return False
                            self._completing = True
                            try:
                                b.delete_before_cursor(len(option))
                                b.insert_text(nxt)
                            finally:
                                self._completing = False
                            return True
                self._complete_options = matched
                self._completing = True
                try:
                    b.delete_before_cursor(len(word))
                    b.insert_text(matched[0])
                finally:
                    self._completing = False
                return True
            try:
                options = [c.text for c in self._completer.get_completions(doc, None)]
            except Exception:
                return False
            if not options:
                return False
            current = doc.text_before_cursor
            # Continue an existing cycle: replace the shown option with the next.
            if self._complete_options:
                for i, option in enumerate(self._complete_options):
                    if current.endswith(option):
                        nxt = self._complete_options[(i + 1) % len(self._complete_options)]
                        if nxt == option:
                            return False
                        self._completing = True
                        try:
                            b.delete_before_cursor(len(option))
                            b.insert_text(nxt)
                        finally:
                            self._completing = False
                        return True
            # Fresh completion: remember the candidates and insert the first match.
            word = doc.get_word_before_cursor(WORD=True)
            if not word:
                return False
            matched = [option for option in options if option.lower().startswith(word.lower())]
            if not matched:
                return False
            self._complete_options = matched
            self._completing = True
            try:
                b.delete_before_cursor(len(word))
                b.insert_text(matched[0])
            finally:
                self._completing = False
            return True

        def _update_suggestion(self) -> None:
            """Synchronously evaluate auto-suggestion for immediate ghost text feedback."""
            if not self._auto_suggest:
                return
            b = self.input_buffer
            doc = b.document
            try:
                sug = self._auto_suggest.get_suggestion(b, doc)
                b.suggestion = sug
            except Exception:
                b.suggestion = None

        def _columns(self) -> int:
            return max(40, shutil.get_terminal_size((88, 24)).columns)

        def _prompt_text(self):
            if self._awaiting_nested:
                return [("class:border", "│  "), ("class:prompt", "Answer ❯ ")]
            if self._busy:
                now = time.monotonic()
                frame = _SPINNER[int(now * 10) % len(_SPINNER)]
                word = _BUSY_WORDS[int(now / 2.0) % len(_BUSY_WORDS)]
                return [
                    ("class:border", "│  "),
                    ("class:prompt", "Hacker-Harness("),
                    ("class:cyan", f"{frame} {word}…"),
                    ("class:prompt", ") ❯ "),
                ]
            return [("class:border", "│  "), ("class:prompt", "Hacker-Harness ❯ ")]

        def _top_border_text(self):
            """The box's top border: status fragments, truncated to fit."""
            cols = self._columns()
            head, tail = "╭─ ", "─╮"
            budget = cols - len(head) - len(tail)
            pieces = []
            used = 0
            for cls, text in self.get_status():
                if not text:
                    continue
                room = budget - used
                if len(text) <= room:
                    pieces.append((f"class:{cls}" if cls else "", text))
                    used += len(text)
                    continue
                if room > 4:
                    pieces.append((f"class:{cls}" if cls else "", text[: room - 1] + "…"))
                    used += room
                break
            dashes = max(0, budget - used)
            return [("class:border", head), *pieces, ("class:border", "─" * dashes + tail)]

        def _bottom_border_text(self):
            """The box's bottom border, full terminal width."""
            cols = self._columns()
            return [("class:border", "╰" + "─" * (cols - 2) + "╯")]

        def _accept(self, buffer: Buffer) -> bool:
            text = buffer.text
            if self._nested_answer is not None:
                # Picker/approval is waiting: never treat the answer as a queued
                # follow-up just because the parent /model handler is still busy.
                self._awaiting_nested = False
                self._nested_answer.put(text)
                return False
            if self._busy:
                # The agent is mid-run: queue what was typed as a pending
                # comment instead of silently dropping it.
                if self._busy_comment is not None and text.strip():
                    self._busy_comment(text)
                return False
            self._busy = True
            self._start_streaming(text)
            return False

        def _start_streaming(self, text: str) -> None:
            self._done = threading.Event()
            self._quit = False

            def _run() -> None:
                try:
                    self._quit = bool(self._handler(text)) if self._handler else False
                except Exception:
                    self._quit = False
                finally:
                    self._done.set()

            threading.Thread(target=_run, daemon=True).start()
            self.app.create_background_task(self._stream())

        async def _stream(self) -> None:
            while not self._done.is_set():
                self._sync_output()
                self.app.invalidate()
                await asyncio.sleep(0.05)
            self._busy = False
            self._sync_output()
            self.app.invalidate()
            if self._quit:
                self.app.exit()

        def sub_input(self, prompt_text: str) -> str:
            """Ask a nested question (approval, selection) from the agent thread."""
            self._nested_answer = queue.Queue()
            self._awaiting_nested = True
            self.output.write(prompt_text.rstrip() + "\n")
            self.app.invalidate()
            try:
                return self._nested_answer.get()
            finally:
                self._awaiting_nested = False
                self._nested_answer = None

        def _page_size(self) -> int:
            return max(5, shutil.get_terminal_size((88, 24)).lines - 2)

        def _scroll_output(self, delta: int) -> None:
            self.output_buffer.selection_state = None
            if delta > 0:
                self.output_buffer.cursor_down(delta)
            elif delta < 0:
                self.output_buffer.cursor_up(-delta)
            self._scrolled_up = self.output_buffer.document.cursor_position < len(self.output_buffer.text)
            self.app.invalidate()

        def _line_at_y(self, y: int) -> int:
            render_info = self._output_window.render_info
            vertical_scroll = render_info.vertical_scroll if render_info else 0
            # Mouse rows are 1-based; convert before adding the scroll offset.
            line = vertical_scroll + max(0, y - 1)
            doc = self.output_buffer.document
            return max(0, min(line, doc.line_count - 1))

        def _mouse_region(self, y: int) -> str:
            """Which surface a 1-based mouse row belongs to."""
            info = self._output_window.render_info
            if info is None:
                return "output"
            out_h = info.window_height
            if y <= out_h:
                return "output"
            # spacer + top border sit between output and the input row.
            if y == out_h + 3:
                return "input"
            return "other"

        def _prompt_margin_width(self) -> int:
            return sum(len(text) for _style, text in self._prompt_text())

        def _input_pos(self, x: int) -> int:
            col = max(0, x - 1 - self._prompt_margin_width())
            return min(col, len(self.input_buffer.text))

        def _pos_for(self, x: int, y: int, region: str) -> int:
            if region == "input":
                return self._input_pos(x)
            return self._cell(x, y)

        def _buffer_for(self, region: str):
            return self.input_buffer if region == "input" else self.output_buffer

        def _copy_active_selection(self) -> None:
            buf = self._select_buf
            if buf is None and self.output_buffer.selection_state is not None:
                buf = self.output_buffer
            if buf is None and self.input_buffer.selection_state is not None:
                buf = self.input_buffer
            if buf is None or buf.selection_state is None:
                return
            doc = buf.document
            if doc.selection is None:
                return
            start, end = doc.selection_range()
            if start == end:
                return
            self._copy_buffer_selection(buf)

        def _handle_mouse(self, data: str) -> None:
            # Xterm SGR mouse event: "\x1b[<b;x;yM" (press/motion) or "\x1b[<b;x;ym" (release).
            if not data.startswith("\x1b[<"):
                return
            body = data[3:]
            if not body or body[-1] not in ("M", "m"):
                return
            release = body[-1] == "m"
            try:
                code, x, y = map(int, body[:-1].split(";"))
            except (ValueError, IndexError):
                return
            if code & 64:  # wheel
                self._scroll_output(-3 if code == 64 else 3)
                return
            if code & 3 != 0:  # left button only
                return
            try:
                y -= self.app.renderer.rows_above_layout
                x -= getattr(self.app.renderer, "columns_above_layout", 0)
            except Exception:
                pass
            if release:
                self._dragging = False
                self._copy_active_selection()
                self._select_buf = None
                self.app.invalidate()
                return
            region = self._mouse_region(y)
            if code & 32:  # motion (drag)
                if self._dragging:
                    self._extend_selection(x, y)
                return
            if region == "other":
                return
            cell = self._pos_for(x, y, region)
            now = time.monotonic()
            if now - self._last_click_time <= 0.45 and abs(cell - self._last_click_cell) <= 2:
                self._click_count += 1
            else:
                self._click_count = 1
            self._last_click_time = now
            self._last_click_cell = cell
            self._select_region = region
            self._select_buf = self._buffer_for(region)
            if self._select_buf is self.output_buffer:
                self.input_buffer.selection_state = None
            else:
                self.output_buffer.selection_state = None
            if self._click_count >= 3:
                self._line_select(x, y)
            elif self._click_count == 2:
                self._word_select(x, y)
            else:
                self._start_selection(x, y)

        def _cell(self, x: int, y: int) -> int:
            """Buffer position for a mouse screen cell.

            Output lines often contain ANSI SGR sequences that take no display
            width, so the click column must be mapped through visible characters
            rather than raw string indices.
            """
            line = self._line_at_y(y)
            doc = self.output_buffer.document
            line_text = doc.lines[line] if line < doc.line_count else ""
            display_col = max(0, x - 1)
            i = 0
            visible = 0
            n = len(line_text)
            while i < n:
                if line_text[i] == "\x1b":
                    end = line_text.find("m", i)
                    i = n if end == -1 else end + 1
                    continue
                if visible >= display_col:
                    return doc.translate_row_col_to_index(line, i)
                visible += 1
                i += 1
            return doc.translate_row_col_to_index(line, n)

        def _word_range(self, pos: int, document: Document | None = None) -> tuple[int, int]:
            """Raw-buffer bounds of the word around ``pos``.

            ANSI escape sequences are invisible in the rendered output, so the
            word scan runs on the stripped text with a raw-index map back to
            the buffer.
            """
            doc = document or self.output_buffer.document
            text = doc.text
            raw_indices: list[int] = []
            i = 0
            n = len(text)
            while i < n:
                if text[i] == "\x1b":
                    end = text.find("m", i)
                    i = n if end == -1 else end + 1
                    continue
                raw_indices.append(i)
                i += 1
            if not raw_indices:
                return pos, pos
            stripped_pos = 0
            for idx, raw in enumerate(raw_indices):
                if raw >= pos:
                    stripped_pos = idx
                    break
            else:
                stripped_pos = len(raw_indices)
            plain = "".join(text[ri] for ri in raw_indices)
            pn = len(plain)
            s = min(stripped_pos, pn)
            while s > 0 and not plain[s - 1].isspace():
                s -= 1
            e = s if stripped_pos >= pn else stripped_pos
            while e < pn and not plain[e].isspace():
                e += 1
            if s >= e:
                return pos, pos
            start = raw_indices[s]
            end = raw_indices[e - 1] + 1
            return start, end

        def _start_selection(self, x: int, y: int) -> None:
            buf = self._select_buf or self.output_buffer
            pos = self._pos_for(x, y, self._select_region)
            buf.selection_state = SelectionState(pos)
            buf.cursor_position = pos
            self._dragging = True
            self.app.invalidate()

        def _extend_selection(self, x: int, y: int) -> None:
            buf = self._select_buf or self.output_buffer
            buf.cursor_position = self._pos_for(x, y, self._select_region)
            self.app.invalidate()

        def _word_select(self, x: int, y: int) -> None:
            buf = self._select_buf or self.output_buffer
            pos = self._pos_for(x, y, self._select_region)
            start, end = self._word_range(pos, buf.document)
            buf.selection_state = SelectionState(start)
            buf.cursor_position = end
            self._dragging = True
            self.app.invalidate()

        def _line_range(self, pos: int, document: Document | None = None) -> tuple[int, int]:
            """Raw-buffer bounds of the full line containing ``pos``."""
            doc = document or self.output_buffer.document
            row, _col = doc.translate_index_to_position(pos)
            start = doc.translate_row_col_to_index(row, 0)
            end = start + len(doc.lines[row])
            if row < doc.line_count - 1:
                end = min(end + 1, len(doc.text))
            return start, end

        def _line_select(self, x: int, y: int) -> None:
            buf = self._select_buf or self.output_buffer
            pos = self._pos_for(x, y, self._select_region)
            start, end = self._line_range(pos, buf.document)
            buf.selection_state = SelectionState(start)
            buf.cursor_position = end
            self._dragging = True
            self.app.invalidate()

        def _copy_buffer_selection(self, buf) -> None:
            doc = buf.document
            if doc.selection is None:
                return
            start, end = doc.selection_range()
            # Tolerate ANSI sequences cut at the selection edges.
            plain = re.sub(r"\x1b\[[0-9;]*m?", "", doc.text[start:end])
            if plain:
                _copy_to_clipboard(plain, stream=getattr(self.app, "output", None))
            buf.selection_state = None
            self.app.invalidate()

        def _copy_selection(self) -> None:
            self._copy_buffer_selection(self.output_buffer)

        def _sync_output(self) -> None:
            text = self.output.read()
            if text == self._rendered:
                return
            previous = self._rendered
            selection = self.output_buffer.selection_state
            cursor = self.output_buffer.cursor_position
            self._rendered = text
            pos = len(text)
            # Replaced transcripts (session resume) must jump to the latest turn.
            if previous and not text.startswith(previous):
                self._scrolled_up = False
            if self._scrolled_up:
                pos = min(cursor, len(text))
            self.output_buffer.set_document(Document(text=text, cursor_position=pos), bypass_readonly=True)
            # Streaming only appends; keep an in-progress drag selection intact.
            if selection is not None and text.startswith(previous):
                self.output_buffer.selection_state = selection
                if self._scrolled_up:
                    self.output_buffer.cursor_position = min(cursor, len(text))

        def run(self, handler: Callable[[str], bool]) -> None:
            """Run the app until ``handler`` returns truthy (quit)."""
            self._handler = handler
            self._rendered = ""
            self._sync_output()
            self.app.run()

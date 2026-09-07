from __future__ import annotations

import json
import time
from pathlib import Path

from .config import load_config, load_scope, load_settings
from .models import ToolResult
from .providers import ModelProvider, make_provider, repair_tool_pairing
from .skills import discover_skill_entries, discover_skill_files, format_skill_catalog
from .state import StateStore
from .tools import ToolRegistry, enrich_tool_arguments


DEFAULT_SYSTEM = """You are Hacker-Harness, a full-capability authorized offensive-security, bug-bounty, and security-engineering agent.
Operate only on systems the user owns or is explicitly authorized to test. Treat the scope manifest as the
source of truth. Never evade authorization controls, conceal activity, establish persistence, exfiltrate real
secrets, or damage availability. Prefer reproducible evidence, minimal requests, and clear remediation.
Within an active scope, actively help with reconnaissance, attack-surface mapping, web/API testing, authentication
and authorization review, input validation, business-logic testing, evidence capture, finding triage, and reporting.
Do not refuse merely because a request is security-related when it is within the enforced authorization boundary.
Use the supplied sanitized runtime context for provider, scope, goals, and task readiness. Do not attempt to read
operator-controlled settings, scope, state, system-prompt, or history files. Do not inventory unrelated methodology
documents: load only the workflow or framework explicitly selected by the operator, then consult supporting files
only when a current stage directly requires them.
Inspect before editing. Keep changes focused. Use persistent tasks, findings, sessions, and memory for long-running work.
When the operator corrects you, sets a standing preference, or says "remember …", respond conversationally AND call the remember tool with one distilled declarative lesson (kind: profile, preference, lesson, or procedure). Never store their words verbatim. If they only wanted chat with no durable lesson, do not call remember. Use memory_search before repeating an approach the operator previously rejected.
For complex attack chains the operator wants to reuse: ask before saving unless they explicitly say "save this chain/playbook". Use playbook_save for full chains (triggers, steps, dead ends, payloads). Add a short procedure pointer in memory automatically. Never auto-create skills from chains. Only call skill_promote when the operator explicitly asks to promote a proven playbook to a reusable skill. Use playbook_search and skill_load when similar observations appear. After a major win, you may suggest saving a playbook — do not save without confirmation unless they already asked.
Engagement findings use HH-native triage states: signal_record for unconfirmed leads, finding_advance only with evidence (confirmed, then ready), finding_dismiss for ruled-out ideas. Do not treat chat speculation as a finding.
Prefer http_request for in-scope HTTP. curl/wget are blocked unless every hostname in the command is in the active scope.
"""

RUNTIME_POLICY = """## Hacker-Harness runtime policy
The sanitized runtime context below is authoritative for provider, scope, goals, and task readiness. Do not read
operator-controlled settings, scope, state, system-prompt, or history files. Do not inventory an entire methodology
library. Load only the workflow or framework selected by the operator and consult another supporting document only
when the current stage explicitly requires it. Framework documents are loadable methodology context; they do not
need a companion workflow merely to answer readiness or methodology questions. Answer readiness questions from
the runtime summary and completed methodology preflight without calling file, goal, or task tools.
"""


class Agent:
    def __init__(self, root: Path, provider: ModelProvider | None = None, approve=None, instruction_files: list[Path] | None = None, context_files: list[Path] | None = None, event_handler=None, restored_messages: list[dict] | None = None, spawn_depth: int = 0, methodology_session: dict | None = None, methodology_bundle: str = ""):
        self.root = root
        self.config = load_config(root)
        self.scope = load_scope(root)
        self.state = StateStore(root)
        self.provider = provider or make_provider(self.config.provider)
        self.event_handler = event_handler or (lambda _name, _payload: None)
        self.spawn_depth = spawn_depth
        self.methodology_session = dict(methodology_session) if methodology_session else None
        self.methodology_bundle = methodology_bundle or ""
        self.tools = ToolRegistry(root, self.config, self.scope, self.state, approve=approve, settings=load_settings(root), provider=self.provider, spawn_depth=self.spawn_depth)
        self.tools.methodology_session = self.methodology_session
        self.tools.methodology_bundle = self.methodology_bundle
        self.tools.agent = self
        system_path = root / self.config.system_prompt_file
        system = system_path.read_text(encoding="utf-8") if system_path.exists() else DEFAULT_SYSTEM
        self.loaded_skills = discover_skill_files(root, instruction_files or [])
        self.skill_entries = discover_skill_entries(root, instruction_files or [])
        if self.skill_entries:
            system += "\n\n## Available skills\n" + format_skill_catalog(self.skill_entries, root=root)
        self.loaded_context = discover_context_files(root, context_files or [])
        if self.loaded_context:
            context_text = []
            for path in self.loaded_context:
                context_text.append(f"\n\n## Loaded command context: {path.relative_to(root)}\n{path.read_text(encoding='utf-8')}")
            system += "".join(context_text)
        self.system_text = system
        if restored_messages:
            prior_runtime = [message for message in restored_messages if "## Hacker-Harness runtime policy" in str(message.get("content", ""))]
            self.messages = [message for message in restored_messages if "## Hacker-Harness runtime policy" not in str(message.get("content", ""))]
            if prior_runtime and not any(message.get("content") == self.system_text for message in self.messages):
                self.messages.insert(0, {"role": "system", "content": self.system_text})
        else:
            self.messages = [{"role": "system", "content": self.system_text}]
        self.messages.append(self._runtime_message())
        if restored_messages:
            from .methodology import parse_methodology_session

            restored_session = parse_methodology_session(restored_messages)
            if restored_session and not self.methodology_session:
                self.methodology_session = restored_session
                self.tools.methodology_session = restored_session
            for message in restored_messages:
                content = str(message.get("content") or "")
                if message.get("role") == "system" and content.startswith("## Active context: methodology /"):
                    self.methodology_bundle = content.split("\n", 1)[-1] if "\n" in content else ""
                    break
        self.refresh_methodology_session_files()
        self._upsert_methodology_steer()
        if self.methodology_bundle and self.methodology_session and spawn_depth:
            self.add_system_context(f"methodology /{self.methodology_session['command']}", self.methodology_bundle)
        self.input_tokens = 0
        self.output_tokens = 0

    def run(self, prompt: str) -> str:
        self.refresh_runtime_context()
        repair_tool_pairing(self.messages)
        self.messages.append({"role": "user", "content": prompt})
        limit = self.config.policy.max_tool_rounds
        fail_limit = max(1, getattr(self.config.policy, "max_failed_tool_rounds", 20))
        recent: list[str] = []
        consecutive_failures = 0
        for round_index in range(1, limit + 1):
            if self.context_status()["percent"] >= self.auto_compact_threshold():
                self.event_handler("notice", {"text": f"Context at {self.auto_compact_threshold():g}% — compacting before the next tool round."})
                self.compact()
            if round_index >= limit - 2:
                self.messages.append({"role": "system", "content": f"You are near the tool-round pause ({limit}). Do not request more tools in this response: finish your answer now with a concise report of what was done, findings, and what remains. The operator can send continue to keep going."})
            self.event_handler("model_start", {"round": round_index})
            reply = self.provider.complete(self.messages, self.tools.specs())
            self.input_tokens = reply.input_tokens or estimate_tokens(self.messages)
            self.output_tokens += reply.output_tokens or estimate_tokens([{"content": reply.text}])
            self.event_handler("model_end", {"round": round_index, "tool_calls": len(reply.tool_calls)})
            assistant: dict = {"role": "assistant", "content": reply.text}
            if reply.tool_calls:
                assistant["tool_calls"] = [
                    {"id": c.id, "type": "function", "function": {"name": c.name, "arguments": json.dumps(c.arguments)}}
                    for c in reply.tool_calls
                ]
            self.messages.append(assistant)
            self.event_handler("context_update", self.context_status())
            if not reply.tool_calls:
                return reply.text
            # Tool rounds never reach cli.ui.assistant(); show the model's
            # commentary here so the transcript is not only tool cards.
            if reply.text.strip():
                self.event_handler("assistant", {"text": reply.text})
            for call in reply.tool_calls:
                call.arguments = enrich_tool_arguments(call.name, call.arguments, reply.text)
            self.messages[-1]["tool_calls"] = [
                {"id": c.id, "type": "function", "function": {"name": c.name, "arguments": json.dumps(c.arguments)}}
                for c in reply.tool_calls
            ]
            signature = json.dumps([(call.name, call.arguments) for call in reply.tool_calls], sort_keys=True, default=str)
            recent.append(signature)
            loop_abort = len(recent) >= 3 and len(set(recent[-3:])) == 1
            spawn_calls = [call for call in reply.tool_calls if call.name == "spawn_agent"]
            max_batch = max(1, getattr(self.config.policy, "max_subagents", 4))
            batched = spawn_calls[:max_batch] if len(spawn_calls) > 1 else []
            results_by_id: dict[str, ToolResult] = {}
            if loop_abort:
                for call in reply.tool_calls:
                    results_by_id[call.id] = ToolResult(ok=False, output="repeated tool call aborted without a result")
            else:
                try:
                    for call in reply.tool_calls:
                        if call in batched:
                            continue
                        self.event_handler("tool_start", {"id": call.id, "name": call.name, "arguments": call.arguments})
                        started = time.monotonic()
                        result = self.tools.execute(call.name, call.arguments)
                        self.event_handler("tool_end", {"id": call.id, "name": call.name, "result": result, "elapsed": time.monotonic() - started})
                        results_by_id[call.id] = result
                    if batched:
                        results = _execute_spawn_batch(self.tools, batched, float(self.config.policy.subagent_timeout_seconds))
                        for call, (error, result) in zip(batched, results):
                            if error is not None:
                                result = ToolResult(ok=False, output=str(error))
                            self.event_handler("tool_start", {"id": call.id, "name": call.name, "arguments": call.arguments})
                            self.event_handler("tool_end", {"id": call.id, "name": call.name, "result": result, "elapsed": 0.0})
                            results_by_id[call.id] = result
                except Exception as exc:
                    for call in reply.tool_calls:
                        results_by_id.setdefault(call.id, ToolResult(ok=False, output=str(exc)))
                    for call in reply.tool_calls:
                        self.messages.append({"role": "tool", "tool_call_id": call.id, "content": results_by_id[call.id].model_dump_json()})
                    raise
            for call in reply.tool_calls:
                self.messages.append({"role": "tool", "tool_call_id": call.id, "content": results_by_id[call.id].model_dump_json()})
                if results_by_id[call.id].ok:
                    consecutive_failures = 0
                else:
                    consecutive_failures += 1
            if loop_abort:
                raise RuntimeError("agent is repeating the same tool call without progress; stopping to avoid burning tokens. Re-prompt with a different instruction or fix the cause.")
            if consecutive_failures >= fail_limit:
                return (
                    f"Paused after {fail_limit} consecutive tool errors (agent.maxFailedToolRounds). "
                    "Findings and artifacts so far are kept. Send continue to retry, or fix the failing tool."
                )
        return (
            f"Paused after {limit} tool rounds (agent.maxToolRounds). "
            "This is a pause for long pentests, not a crash. Send continue to keep going, "
            "or raise agent.maxToolRounds in settings.json."
        )

    def _last_user_prompt(self) -> str:
        messages = getattr(self, "messages", None) or []
        for message in reversed(messages):
            if message.get("role") == "user":
                return str(message.get("content", ""))
        return ""

    def _runtime_message(self) -> dict:
        runtime = {
            "provider": {"profile": self.config.api_profile, "format": self.config.provider.kind, "model": self.config.provider.model},
            "authorization": {"active": self.scope.is_active(), "engagement": self.scope.engagement, "source": str((self.root / ".hacker-harness" / "scope.yaml").resolve()), "expires_at": self.scope.expires_at, "targets": [item.value for item in self.scope.targets], "excluded": [item.value for item in self.scope.excluded], "rules": self.scope.rules},
            "knowledge_paths": [str(path) for path in self.tools.knowledge_roots],
            "obsidian_vault": str(self.tools.obsidian_vault) if self.tools.obsidian_vault else "",
            "engagement": {"root": str(self.tools.engagement_root()) if self.tools.engagement_root() else "", "target_dirs": [str(path) for path in self.tools.engagement_dirs()]},
            "skill_catalog": [
                {"name": entry.name, "skill_id": entry.skill_id, "description": entry.description, "path": str(entry.path)}
                for entry in self.skill_entries
            ],
            **self.state.prime(query_hint=self._last_user_prompt()),
            "methodology": self.methodology_session or {"active": False},
        }
        return {"role": "system", "content": RUNTIME_POLICY + "\nSanitized runtime context:\n" + json.dumps(runtime, default=str)}

    def refresh_runtime_context(self) -> None:
        """Reload operator-owned scope and replace the model's sanitized snapshot."""
        self.scope = load_scope(self.root)
        self.tools.scope = self.scope
        self.tools.mcp.scope = self.scope
        self.refresh_methodology_session_files()
        self.messages = [message for message in self.messages if "## Hacker-Harness runtime policy" not in str(message.get("content", ""))]
        if not any(message.get("role") == "system" and message.get("content") == self.system_text for message in self.messages):
            self.messages.insert(0, {"role": "system", "content": self.system_text})
        self.messages.append(self._runtime_message())
        self._upsert_methodology_steer()

    def context_status(self) -> dict:
        try:
            fresh = load_config(self.root)
            self.config.provider.context_window = fresh.provider.context_window
            self.config.provider.model = fresh.provider.model
        except Exception:
            pass
        used = self.input_tokens or estimate_tokens(self.messages)
        window = self.config.provider.context_window
        return {"used": used, "window": window, "percent": min(100.0, used * 100 / max(1, window)), "output_tokens": self.output_tokens}

    def auto_compact_threshold(self) -> float:
        return float(getattr(self.config.policy, "auto_compact_percent", 50) or 50)

    def apply_methodology(self, label: str, bundle: str, session: dict) -> bool:
        self.methodology_session = dict(session)
        self.methodology_bundle = bundle
        self.tools.methodology_session = self.methodology_session
        self.tools.methodology_bundle = bundle
        self.tools.agent = self
        marker = f"## Active context: {label}"
        already = any(message.get("role") == "system" and str(message.get("content", "")).startswith(marker) for message in self.messages)
        self.messages = [message for message in self.messages if not (message.get("role") == "system" and str(message.get("content", "")).startswith(marker))]
        self.messages.append({"role": "system", "content": f"{marker}\n{bundle}"})
        self._upsert_methodology_steer()
        return not already

    def _upsert_methodology_steer(self) -> None:
        from .methodology import METHODOLOGY_SESSION_MARKER, methodology_steer_text

        self.messages = [message for message in self.messages if METHODOLOGY_SESSION_MARKER not in str(message.get("content", ""))]
        if not self.methodology_session:
            return
        self.messages.append({"role": "system", "content": methodology_steer_text(self.methodology_session)})

    def refresh_methodology_session_files(self) -> None:
        from .methodology import missing_artifacts

        if not self.methodology_session:
            return
        self.methodology_session["missing_requires"] = missing_artifacts(self.root, self.methodology_session.get("requires") or [])
        self.methodology_session["missing_writes"] = missing_artifacts(self.root, self.methodology_session.get("writes") or [])
        self.tools.methodology_session = self.methodology_session

    def advance_methodology(self) -> str:
        from .methodology import chat_methodology_bundle, load_methodology, missing_artifacts

        session = self.methodology_session
        if not session:
            raise PermissionError("no active methodology")
        self.refresh_methodology_session_files()
        missing_r = list(session.get("missing_requires") or [])
        if missing_r:
            raise PermissionError(f"cannot advance; missing required inputs: {', '.join(missing_r)}")
        missing_w = missing_artifacts(self.root, session.get("writes") or [])
        if missing_w:
            raise PermissionError(f"cannot advance; missing required writes: {', '.join(missing_w)}")
        nxt = int(session.get("current_index") or 1) + 1
        total = int(session.get("total") or 1)
        if nxt > total:
            return "already on the final methodology stage"
        folder = self.root / str(session["folder"])
        methodology = load_methodology(self.root, folder, Path(session["document"]).name)
        bundle, new_session = chat_methodology_bundle(methodology, self.root, str(session["command"]), nxt)
        self.apply_methodology(f"methodology /{session['command']}", bundle, new_session)
        return f"advanced to {new_session['current_index']}/{new_session['total']} {new_session['current_id']} — {new_session['current_title']}"

    def add_system_context(self, label: str, content: str) -> bool:
        marker = f"## Active context: {label}"
        if any(message.get("role") == "system" and marker in str(message.get("content", "")) for message in self.messages):
            return False
        self.messages.append({"role": "system", "content": f"{marker}\n{content}"})
        return True

    def compact(self) -> str:
        """Summarize the conversation and drop old messages to reclaim context."""
        conversation = [m for m in self.messages if m["role"] != "system"]
        if len(conversation) <= 4:
            return "Context is already minimal — nothing to compact."
        methodology_note = ""
        if self.methodology_session:
            methodology_note = (
                f" Active methodology {self.methodology_session.get('name')} is on stage "
                f"{self.methodology_session.get('current_index')}/{self.methodology_session.get('total')} "
                f"({self.methodology_session.get('current_id')} — {self.methodology_session.get('current_title')}). "
                "Preserve that position, required artifacts, blockers, and do not invent a new plan."
            )
        summary_request = [{"role": "user", "content": "Provide a detailed, structured summary of our conversation so far." + methodology_note + " Preserve every finding (severity, target, evidence), decision, executed command, credential/session token, current methodology stage, and the current engagement state. This summary replaces the full transcript."}]
        try:
            reply = self.provider.complete(conversation + summary_request, [])
            summary = (reply.text or "").strip()
        except Exception as exc:
            return f"Compaction failed: {exc}"
        kept_system = [message for message in self.messages if message.get("role") == "system" and message.get("content") == self.system_text]
        if not kept_system:
            kept_system = [{"role": "system", "content": self.system_text}]
        self.messages = kept_system + [
            {"role": "user", "content": f"[Conversation summary — prior context]\n{summary}"},
            {"role": "assistant", "content": "Understood. Continuing from the summary above. Stay on the active methodology stage."},
        ]
        if self.methodology_session and self.methodology_bundle:
            command = self.methodology_session.get("command", "")
            self.messages.append({"role": "system", "content": f"## Active context: methodology /{command}\n{self.methodology_bundle}"})
        self.messages.append(self._runtime_message())
        self._upsert_methodology_steer()
        self.input_tokens = 0
        self.output_tokens = 0
        return f"Compacted context to ~{estimate_tokens(self.messages):,} estimated tokens."

    def conversation_turns(self) -> list[tuple[str, str]]:
        """User/assistant turns that should appear in a resumed transcript.

        System prompts, runtime policy, and tool payloads stay in model context
        but are not redrawn on screen.
        """
        return conversation_turns(self.messages)


def conversation_turns(messages: list[dict]) -> list[tuple[str, str]]:
    """Extract displayable user/assistant text turns from a session transcript."""
    turns: list[tuple[str, str]] = []
    for message in messages:
        role = message.get("role")
        content = str(message.get("content") or "").strip()
        if not content:
            continue
        if role == "user":
            turns.append(("user", content))
        elif role == "assistant":
            turns.append(("assistant", content))
    return turns


def estimate_tokens(messages: list[dict]) -> int:
    return max(1, sum(len(json.dumps(message, ensure_ascii=False, default=str)) for message in messages) // 4)


def _execute_spawn_batch(tools: ToolRegistry, calls: list, timeout: float) -> list[tuple[BaseException | None, ToolResult | None]]:
    """Run spawn_agent calls concurrently on daemon threads, joined within a shared deadline."""
    import threading

    holders: dict[str, dict] = {}
    threads: list[threading.Thread] = []
    for call in calls:
        holder: dict = {}

        def target(call=call, holder=holder) -> None:
            try:
                holder["result"] = tools.execute(call.name, call.arguments)
            except BaseException as exc:  # noqa: BLE001 - surfaced as a failed tool result
                holder["error"] = exc

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        threads.append(thread)
        holders[call.id] = (thread, holder)
    deadline = time.monotonic() + timeout
    for call in calls:
        thread, holder = holders[call.id]
        remaining = max(0.0, deadline - time.monotonic())
        thread.join(remaining)
        if thread.is_alive():
            holder["error"] = TimeoutError(f"subagent exceeded {timeout:.0f}s")
    return [(holders[call.id][1].get("error"), holders[call.id][1].get("result")) for call in calls]


def discover_context_files(root: Path, files: list[Path]) -> list[Path]:
    resolved: list[Path] = []
    for candidate in files:
        path = candidate.resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError as exc:
            raise PermissionError(f"context file escapes project root: {candidate}") from exc
        if not path.is_file():
            raise ValueError(f"context file not found: {candidate}")
        if path.suffix.lower() != ".md":
            raise ValueError(f"context file must be Markdown: {candidate}")
        if path not in resolved:
            resolved.append(path)
    return sorted(resolved)

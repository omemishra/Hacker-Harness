from __future__ import annotations

import re
from collections import deque
from pathlib import Path
from typing import Callable

import yaml

from .agent import Agent
from .config import load_settings
from .models import Workflow, WorkflowNode
from .state import StateStore


VARIABLE = re.compile(r"\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}")


def load_workflow(path: Path) -> Workflow:
    return Workflow.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


DEFAULT_WORKFLOW_PATHS = ("workflows",)
LEGACY_WORKFLOW_PATHS = (".hacker-harness/workflows",)


def workflow_roots(root: Path) -> list[Path]:
    settings = load_settings(root)
    configured = list(settings.get("workflowPaths", list(DEFAULT_WORKFLOW_PATHS)))
    for legacy in LEGACY_WORKFLOW_PATHS:
        if legacy not in configured and (root / legacy).is_dir():
            configured.append(legacy)
    roots: list[Path] = []
    for raw in configured:
        path = (root / raw).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError as exc:
            raise PermissionError(f"workflow path escapes project root: {raw}") from exc
        if path.is_dir():
            roots.append(path)
    return roots


def workflow_files(root: Path) -> list[Path]:
    return sorted({path for location in workflow_roots(root) for path in location.rglob("*.yaml")})


def workflow_catalog(root: Path) -> list[dict]:
    """Summarize YAML DAG workflows for TUI listing and CLI tables."""
    entries = []
    for path in workflow_files(root):
        workflow = load_workflow(path)
        entries.append(
            {
                "name": workflow.name,
                "description": workflow.description,
                "path": path,
                "inputs": workflow.inputs,
                "nodes": len(workflow.nodes),
            }
        )
    return entries


def yaml_workflow_names(root: Path) -> list[str]:
    names: set[str] = set()
    for entry in workflow_catalog(root):
        names.add(entry["name"])
        compact = entry["name"].replace("-", "")
        if compact:
            names.add(compact)
    return sorted(names)


def resolve_yaml_workflow_name(requested: str, root: Path) -> str | None:
    normalized = re.sub(r"[^a-z0-9]", "", requested.lower())
    matches: list[str] = []
    for entry in workflow_catalog(root):
        name = entry["name"]
        variants = {name, entry["path"].stem, name.replace("-", "")}
        for variant in variants:
            if re.sub(r"[^a-z0-9]", "", variant.lower()) == normalized:
                matches.append(name)
                break
    if len(matches) == 1:
        return matches[0]
    return None


def parse_workflow_invocation(rest: str) -> tuple[str, dict[str, str]]:
    tokens = rest.split()
    if not tokens:
        raise ValueError("workflow name required")
    name = tokens[0].lstrip("/")
    inputs: dict[str, str] = {}
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "-i":
            if index + 1 >= len(tokens) or "=" not in tokens[index + 1]:
                raise ValueError("usage: -i key=value")
            key, value = tokens[index + 1].split("=", 1)
            inputs[key] = value
            index += 2
            continue
        if token.startswith("-"):
            raise ValueError(f"unknown option: {token}")
        if "target" not in inputs:
            inputs["target"] = token
        index += 1
    return name, inputs


def topological(nodes: list[WorkflowNode]) -> list[WorkflowNode]:
    by_id = {node.id: node for node in nodes}
    incoming = {node.id: len(node.depends_on) for node in nodes}
    children: dict[str, list[str]] = {node.id: [] for node in nodes}
    for node in nodes:
        for dep in node.depends_on:
            children[dep].append(node.id)
    queue = deque(node_id for node_id, count in incoming.items() if count == 0)
    ordered = []
    while queue:
        node_id = queue.popleft()
        ordered.append(by_id[node_id])
        for child in children[node_id]:
            incoming[child] -= 1
            if incoming[child] == 0:
                queue.append(child)
    if len(ordered) != len(nodes):
        raise ValueError("workflow contains a dependency cycle")
    return ordered


def render(value: str, context: dict[str, str]) -> str:
    def replace(match: re.Match) -> str:
        key = match.group(1)
        if key not in context:
            raise KeyError(f"missing workflow value: {key}")
        return str(context[key])
    return VARIABLE.sub(replace, value)


class WorkflowRunner:
    def __init__(
        self,
        root: Path,
        approve: Callable[[str], bool],
        emit: Callable[[str], None],
        event_handler: Callable[[str, dict], None] | None = None,
    ):
        self.root = root
        self.approve = approve
        self.emit = emit
        self.event_handler = event_handler or (lambda _name, _payload: None)
        self.agent = Agent(root, approve=approve, event_handler=self.event_handler)
        self.state = StateStore(root)

    def run(self, workflow: Workflow, inputs: dict[str, str]) -> tuple[str, dict[str, str]]:
        context = dict(workflow.inputs)
        context.update(inputs)
        outputs: dict[str, str] = {}
        run_id = self.state.start_run(workflow.name)
        ordered = topological(workflow.nodes)
        total = len(ordered)
        try:
            for index, node in enumerate(ordered, 1):
                detail = f"{node.id}: {node.description or 'running'}"
                self.emit(f"[{index}/{total}] STARTED  {detail}")
                if node.prompt is not None:
                    output = self.agent.run(render(node.prompt, context | outputs))
                    if output.strip():
                        self.event_handler("assistant", {"text": output})
                elif node.command is not None:
                    result = self.agent.tools.execute("run_command", {"command": render(node.command, context | outputs)})
                    if not result.ok and not node.continue_on_error:
                        raise RuntimeError(result.output)
                    output = result.output
                else:
                    question = render(node.approval or "Approve?", context | outputs)
                    if not self.approve(question):
                        raise PermissionError(f"approval rejected at node {node.id}")
                    output = "approved"
                outputs[node.id] = output
                context[node.id] = output
                artifact = ""
                if node.save_output:
                    target = (self.root / render(node.save_output, context | outputs)).resolve()
                    target.relative_to(self.root.resolve())
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(output, encoding="utf-8")
                    artifact = f" → {target.relative_to(self.root)}"
                self.emit(f"[{index}/{total}] COMPLETED {detail}{artifact}")
            self.state.finish_run(run_id, "completed", outputs)
            return run_id, outputs
        except Exception as exc:
            self.emit(f"[FAILED] {exc}")
            self.state.finish_run(run_id, "failed", outputs)
            raise


def init_workflow(
    project: Path,
    *,
    name: str,
    description: str = "",
) -> Path:
    if not name.strip():
        raise ValueError("workflow name cannot be empty")
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    target_dir = project / "workflows"
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / f"{slug}.yaml"
    if target_path.exists():
        raise ValueError(f"workflow already exists: {target_path.relative_to(project)}")
    desc = description.strip() or f"Automated workflow for {name.strip()}"
    template = (
        f"name: {slug}\n"
        f"description: {desc}\n"
        "version: 1\n"
        "inputs:\n"
        "  target: example.com\n"
        "nodes:\n"
        "  - id: authorize\n"
        "    description: Operator approval gate\n"
        '    approval: "Authorize assessment on {{ target }}?"\n'
        "\n"
        "  - id: scan\n"
        "    description: Run initial command\n"
        "    depends_on: [authorize]\n"
        '    command: "curl -s -I https://{{ target }}"\n'
        '    save_output: ".hacker-harness/artifacts/{{ target }}-headers.txt"\n'
        "\n"
        "  - id: analyze\n"
        "    description: AI analysis of evidence\n"
        "    depends_on: [scan]\n"
        "    prompt: >-\n"
        "      Review the headers for {{ target }} collected in scan: {{ scan }}.\n"
        "      Identify missing security headers and write findings.\n"
        '    save_output: ".hacker-harness/artifacts/{{ target }}-analysis.md"\n'
    )
    target_path.write_text(template, encoding="utf-8")
    return target_path



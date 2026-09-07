from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml

from .agent import Agent
from .config import load_scope, load_settings
from .scope import target_allowed, validate_command
from .state import StateStore


STAGE_HEADING = re.compile(
    r"^(#{1,6})\s+(?:(?:stage|phase)\s+)?(?:\[)?([A-Z]?\d+)(?:\])?\s*(?:[:.)\-–—]\s*|\s+)(.+?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass(frozen=True)
class MethodologyStage:
    id: str
    title: str
    path: Path
    instructions: str
    requires: tuple[str, ...] = ()
    writes: tuple[str, ...] = ()
    skills: tuple[str, ...] = ()


@dataclass(frozen=True)
class MethodologyRequirement:
    kind: str
    name: str
    install: str | None = None


@dataclass(frozen=True)
class Methodology:
    name: str
    folder: Path
    workflow_file: Path
    index_file: Path | None
    documents: list[Path]
    skill_files: list[Path]
    stages: list[MethodologyStage]
    strict: bool
    requirements: list[MethodologyRequirement]


def _inside(project: Path, path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(project.resolve())
    except ValueError as exc:
        raise PermissionError("methodology path must be inside the active project") from exc
    return resolved


def discover_documents(folder: Path) -> list[Path]:
    return sorted(
        [path for path in folder.rglob("*.md") if path.name.lower() != "skill.md"],
        key=lambda item: str(item.relative_to(folder)),
    )


def discover_workflows(folder: Path) -> list[Path]:
    return [path for path in discover_documents(folder) if path.name.lower().endswith("workflow.md")]


def parse_workflow_stages(path: Path) -> list[MethodologyStage]:
    content = path.read_text(encoding="utf-8")
    matches = list(STAGE_HEADING.finditer(content))
    stages = []
    for position, match in enumerate(matches):
        number, title = match.group(2).upper(), match.group(3).strip()
        end = matches[position + 1].start() if position + 1 < len(matches) else len(content)
        instructions = content[match.start():end].strip()
        stages.append(MethodologyStage(f"stage-{number}", title, path, instructions))
    return _dedupe_stage_ids(stages)


def _dedupe_stage_ids(stages: list[MethodologyStage]) -> list[MethodologyStage]:
    """Ensure stage ids are unique; repeated ids get -2, -3 suffixes."""
    seen: set[str] = set()
    result: list[MethodologyStage] = []
    for stage in stages:
        candidate, counter = stage.id, 2
        while candidate in seen:
            candidate = f"{stage.id}-{counter}"
            counter += 1
        seen.add(candidate)
        result.append(
            MethodologyStage(
                candidate,
                stage.title,
                stage.path,
                stage.instructions,
                stage.requires,
                stage.writes,
                stage.skills,
            )
        )
    return result


def extract_heading_section(path: Path, number: str) -> str:
    """Return the document block under the first heading numbered ``number`` (case-insensitive)."""
    content = path.read_text(encoding="utf-8")
    matches = list(STAGE_HEADING.finditer(content))
    wanted = number.upper()
    for position, match in enumerate(matches):
        if match.group(2).upper() == wanted:
            end = matches[position + 1].start() if position + 1 < len(matches) else len(content)
            return content[match.start():end].strip()
    available = ", ".join(dict.fromkeys(match.group(2).upper() for match in matches)) or "none"
    raise ValueError(f"heading '{number}' not found in {path.name}; available headings: {available}")


def load_stage_manifest(project: Path, workflow_stem: str, folder: Path) -> list[MethodologyStage]:
    """Load project-local stage overrides from .hacker-harness/stages/<stem>.json|yaml.

    Each manifest stage defines 'id' and either inline 'instructions' or a
    'source' document inside the methodology folder plus an optional 'heading'
    to extract one section. This lets workflows whose steps live inside code
    blocks (e.g. recon-workflow.md) become real staged pipelines without
    editing the methodology files.
    """
    stages_dir = project / ".hacker-harness" / "stages"
    data: dict | None = None
    for suffix, loader in ((".json", json.loads), (".yaml", yaml.safe_load)):
        path = stages_dir / f"{workflow_stem}{suffix}"
        if not path.exists():
            continue
        raw = loader(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"{path.name} must contain an object with a 'stages' list")
        data = raw
        break
    if data is None:
        return []
    declared = data.get("workflow")
    if declared and str(declared) != workflow_stem:
        return []
    items = data.get("stages", [])
    if not isinstance(items, list):
        raise ValueError(f"{workflow_stem} stage manifest 'stages' must be a list")
    stages: list[MethodologyStage] = []
    for index, item in enumerate(items, 1):
        if not isinstance(item, dict) or not item.get("id"):
            raise ValueError(f"stage manifest item {index} must have an 'id'")
        stage_id = str(item["id"])
        title = str(item.get("title") or stage_id)
        source_path: Path | None = None
        if item.get("instructions"):
            instructions = str(item["instructions"])
        elif item.get("source"):
            source = _inside(project, folder / str(item["source"]))
            if not source.is_file():
                raise ValueError(f"stage {stage_id}: source not found: {item['source']}")
            source_path = source
            if item.get("heading"):
                instructions = extract_heading_section(source, str(item["heading"]))
            else:
                instructions = source.read_text(encoding="utf-8")
        else:
            raise ValueError(f"stage {stage_id}: provide 'instructions' or 'source' (+ optional 'heading')")
        stages.append(
            MethodologyStage(
                f"stage-{stage_id}",
                title,
                source_path or (folder / f"{workflow_stem}.md"),
                instructions,
                tuple(str(entry) for entry in (item.get("requires") or [])),
                tuple(str(entry) for entry in (item.get("writes") or [])),
                tuple(str(entry) for entry in (item.get("skills") or [])),
            )
        )
    return _dedupe_stage_ids(stages)


def _workflow_metadata(path: Path) -> dict:
    if path.suffix.lower() != ".md":
        return {}
    content = path.read_text(encoding="utf-8")
    if not content.startswith("---\n"):
        return {}
    end = content.find("\n---", 4)
    if end < 0:
        return {}
    parsed = yaml.safe_load(content[4:end]) or {}
    if not isinstance(parsed, dict):
        return {}
    return parsed.get("hackerHarness") or parsed.get("hacker-harness") or {}


def _requirements(data: dict) -> list[MethodologyRequirement]:
    if not isinstance(data, dict):
        raise ValueError("methodology requirements must be an object")
    result: list[MethodologyRequirement] = []
    aliases = {"commands": "command", "environment": "environment", "env": "environment", "files": "file", "mcpServers": "mcp", "mcp": "mcp"}
    for raw_kind, kind in aliases.items():
        for item in data.get(raw_kind, []) or []:
            if isinstance(item, str):
                result.append(MethodologyRequirement(kind, item))
            elif isinstance(item, dict) and item.get("name"):
                result.append(MethodologyRequirement(kind, str(item["name"]), item.get("install") or item.get("installCommand")))
    unique: list[MethodologyRequirement] = []
    for requirement in result:
        if requirement not in unique:
            unique.append(requirement)
    return unique


def missing_requirements(project: Path, methodology: Methodology) -> list[MethodologyRequirement]:
    settings = load_settings(project)
    servers = settings.get("mcpServers", {})
    missing = []
    for requirement in methodology.requirements:
        if requirement.kind == "command":
            present = shutil.which(requirement.name) is not None
        elif requirement.kind == "environment":
            present = bool(os.environ.get(requirement.name))
        elif requirement.kind == "file":
            candidate = (methodology.folder / requirement.name).resolve()
            try:
                candidate.relative_to(project.resolve())
                present = candidate.exists()
            except ValueError:
                present = False
        elif requirement.kind == "mcp":
            server = servers.get(requirement.name, {})
            command = server.get("command") if isinstance(server, dict) else None
            present = bool(server and server.get("enabled", True) and command and (Path(command).is_file() or shutil.which(command)))
        else:
            present = False
        if not present:
            missing.append(requirement)
    return missing


def missing_artifacts(project: Path, paths: list[str] | tuple[str, ...]) -> list[str]:
    """Return relative paths that are missing or empty inside the project."""
    missing: list[str] = []
    root = project.resolve()
    for raw in paths or []:
        relative = str(raw).lstrip("./")
        if not relative or relative.startswith("/") or ".." in Path(relative).parts:
            missing.append(relative)
            continue
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            missing.append(relative)
            continue
        if not candidate.is_file() or candidate.stat().st_size == 0:
            missing.append(relative)
    return missing


def _select_workflow(project: Path, folder: Path, workflow: str | None) -> Path:
    if workflow:
        selected = _inside(project, folder / workflow)
        if not selected.is_file():
            raise ValueError(f"workflow file not found: {workflow}")
        return selected
    candidates = discover_workflows(folder)
    preferred = folder / f"{folder.name}-workflow.md"
    if preferred in candidates:
        return preferred
    if len(candidates) == 1:
        return candidates[0]
    names = ", ".join(str(path.relative_to(folder)) for path in candidates) or "none"
    raise ValueError(f"select a workflow with --workflow; candidates: {names}")


def load_methodology(project: Path, folder: Path, workflow: str | None = None) -> Methodology:
    folder = _inside(project, folder if folder.is_absolute() else project / folder)
    if not folder.is_dir():
        raise ValueError(f"methodology folder not found: {folder}")
    documents = discover_documents(folder)
    skill_files = sorted(folder.rglob("SKILL.md"))
    index_file = folder / "index.md" if (folder / "index.md").is_file() else None
    manifest_path = folder / "methodology.json"
    stages: list[MethodologyStage] = []
    name = folder.name
    selected_workflow: Path
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    if manifest_path.exists() and workflow is None:
        name = manifest.get("name", name)
        selected_workflow = manifest_path
        for index, item in enumerate(manifest.get("stages", []), 1):
            stage_path = _inside(project, folder / item["file"])
            if not stage_path.is_file():
                raise ValueError(f"stage file not found: {item['file']}")
            stages.append(MethodologyStage(str(item.get("id", index)), item.get("title", stage_path.stem), stage_path, stage_path.read_text(encoding="utf-8")))
    else:
        selected_workflow = _select_workflow(project, folder, workflow)
        stages = parse_workflow_stages(selected_workflow)
        if not stages:
            stages = [MethodologyStage("stage-1", selected_workflow.stem.replace("-", " ").title(), selected_workflow, selected_workflow.read_text(encoding="utf-8"))]
    if not stages:
        raise ValueError("selected methodology defines no stages")
    stages = _dedupe_stage_ids(stages)
    manifest_stages = load_stage_manifest(project, selected_workflow.stem, folder)
    if manifest_stages:
        stages = manifest_stages
    metadata = _workflow_metadata(selected_workflow)
    strict_default = load_settings(project).get("methodologies", {}).get("strictByDefault", True)
    strict = bool(metadata.get("strict", manifest.get("strict", strict_default)))
    requirement_data = manifest.get("requirements", {})
    if isinstance(metadata.get("requirements"), dict):
        requirement_data = {**requirement_data, **metadata["requirements"]}
    return Methodology(name, folder, selected_workflow, index_file, documents, skill_files, stages, strict, _requirements(requirement_data))


HARNESS_ROLE_REMAP = """This session is Hacker-Harness only. You plan, execute, and write artifacts.
Write every required file for the current stage before testing that stage. spawn_agent may only receive a plan file path.
Do not start a later phase until methodology_advance succeeds. Print "✓ Methodology loaded. Starting P{N}." after skill_load.
"""

METHODOLOGY_SESSION_MARKER = "## Active methodology session"


def chat_methodology_bundle(methodology: Methodology, project: Path, command: str, current_index: int = 1) -> tuple[str, dict]:
    """Stage-scoped chat context: map + current stage only, not the whole library."""
    total = len(methodology.stages)
    index = max(1, min(int(current_index or 1), total))
    current = methodology.stages[index - 1]
    nxt = methodology.stages[index] if index < total else None
    session = {
        "active": True,
        "command": command,
        "name": methodology.name,
        "strict": methodology.strict,
        "document": str(methodology.workflow_file.relative_to(project)),
        "folder": str(methodology.folder.relative_to(project)),
        "current_index": index,
        "total": total,
        "current_id": current.id,
        "current_title": current.title,
        "next_id": nxt.id if nxt else None,
        "next_title": nxt.title if nxt else None,
        "stages": [{"index": i, "id": stage.id, "title": stage.title} for i, stage in enumerate(methodology.stages, 1)],
        "supporting_documents": [str(path.relative_to(project)) for path in methodology.documents],
        "requires": list(current.requires),
        "writes": list(current.writes),
        "skills": list(current.skills),
        "missing_requires": missing_artifacts(project, current.requires),
        "missing_writes": missing_artifacts(project, current.writes),
    }
    strict = (
        "Follow this methodology strictly in written stage order. Stop and ask the operator when any required input, decision, dependency, credential, or MCP tool is unavailable."
        if methodology.strict
        else "Use this methodology as guidance and explain every deviation."
    )
    stage_map = "\n".join(
        f"{i}. {stage.id} — {stage.title}" + ("  ← CURRENT" if i == index else "")
        for i, stage in enumerate(methodology.stages, 1)
    )
    skills = "\n".join(f"- skill_load {name}" for name in current.skills) or "- (none)"
    requires = "\n".join(f"- {path}" for path in current.requires) or "- (none)"
    writes = "\n".join(f"- {path}" for path in current.writes) or "- (none)"
    missing_req = ", ".join(session["missing_requires"]) or "none"
    missing_w = ", ".join(session["missing_writes"]) or "none"
    supporting = "\n".join(f"- {path.relative_to(project)}" for path in methodology.documents) or "(none)"
    bundle = f"""{strict}

{HARNESS_ROLE_REMAP}

Stage map ({index}/{total}):
{stage_map}

skill_load for this stage:
{skills}

Requires (must already exist):
{requires}
Missing requires: {missing_req}

Required writes (stage cannot advance until these exist and are non-empty):
{writes}
Missing writes: {missing_w}

Current stage only ({current.id}: {current.title}):
{current.instructions}

Supporting documents (read_file only what this stage names; do not inventory the rest):
{supporting}

Selected document: {methodology.workflow_file.relative_to(project)}
"""
    return bundle.strip(), session


def methodology_steer_text(session: dict) -> str:
    if not session:
        return ""
    nxt = f"{session.get('next_id')} — {session.get('next_title')}" if session.get("next_id") else "(final stage)"
    missing_w = ", ".join(session.get("missing_writes") or []) or "none"
    missing_r = ", ".join(session.get("missing_requires") or []) or "none"
    return f"""{METHODOLOGY_SESSION_MARKER}
```json
{json.dumps(session, indent=2, default=str)}
```
Stay on stage {session.get('current_index')}/{session.get('total')}: {session.get('current_id')} — {session.get('current_title')}.
Missing requires: {missing_r}. Missing writes: {missing_w}.
Call methodology_advance only when missing writes is none. Next stage: {nxt}.
Do not abandon this methodology for an ad-hoc test plan.
"""


def parse_methodology_session(messages: list[dict]) -> dict | None:
    for message in reversed(messages or []):
        content = str(message.get("content") or "")
        if METHODOLOGY_SESSION_MARKER not in content:
            continue
        start = content.find("```json")
        end = content.find("```", start + 7) if start >= 0 else -1
        if start < 0 or end < 0:
            continue
        try:
            parsed = json.loads(content[start + 7 : end].strip())
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and parsed.get("command"):
            return parsed
    return None


def methodology_context(methodology: Methodology, project: Path) -> str:
    document_list = "\n".join(f"- {path.relative_to(project)}" for path in methodology.documents)
    index_content = methodology.index_file.read_text(encoding="utf-8")[:50_000] if methodology.index_file else "(no index.md)"
    return f"""Methodology knowledge folder: {methodology.folder.relative_to(project)}
Selected workflow: {methodology.workflow_file.relative_to(project)}

Available supporting documents:
{document_list}

Methodology index:
{index_content}
"""


class MethodologyRunner:
    def __init__(self, project: Path, emit: Callable[[str], None], approve: Callable[[str], bool], event_handler=None):
        self.project = project.resolve()
        self.emit = emit
        self.approve = approve
        self.event_handler = event_handler
        self.state = StateStore(project)

    def preflight(self, methodology: Methodology) -> None:
        missing = missing_requirements(self.project, methodology)
        if not missing:
            self.emit(f"[PREFLIGHT] READY  strict={str(methodology.strict).lower()} · {len(methodology.requirements)} requirements satisfied")
            return
        offer_install = load_settings(self.project).get("methodologies", {}).get("offerInstallMissing", True)
        for requirement in list(missing):
            self.emit(f"[PREFLIGHT] MISSING {requirement.kind}: {requirement.name}")
            if not offer_install:
                continue
            if not requirement.install:
                self.approve(f"Missing {requirement.kind} '{requirement.name}'. Install or configure it manually, then approve to re-check")
                continue
            question = f"Install missing {requirement.kind} '{requirement.name}' using: {requirement.install}"
            if not self.approve(question):
                continue
            validate_command(requirement.install, load_scope(self.project))
            self.state.audit("methodology_dependency_install", True, {"kind": requirement.kind, "name": requirement.name, "command": requirement.install})
            process = subprocess.run(requirement.install, cwd=self.project, shell=True, capture_output=True, text=True, timeout=300)
            if process.returncode != 0:
                self.state.audit("methodology_dependency_install_result", False, {"name": requirement.name, "returncode": process.returncode})
                raise RuntimeError(f"installer for {requirement.name} exited {process.returncode}: {(process.stderr or process.stdout)[-1000:]}")
            self.emit(f"[PREFLIGHT] INSTALLED {requirement.kind}: {requirement.name}")
        remaining = missing_requirements(self.project, methodology)
        if remaining:
            details = ", ".join(f"{item.kind}:{item.name}" for item in remaining)
            raise PermissionError(f"methodology preflight failed; install or configure: {details}")

    def run(self, methodology: Methodology, target: str, from_stage: int = 1) -> tuple[str, dict[str, str]]:
        if not target_allowed(target, load_scope(self.project)):
            raise PermissionError(f"target is not in the active authorization scope: {target}")
        total = len(methodology.stages)
        if from_stage < 1 or from_stage > total:
            raise ValueError(f"from-stage must be between 1 and {total}")
        self.preflight(methodology)
        remaining = total - from_stage + 1
        if not self.approve(f"Run {remaining} methodology stages against {target} starting at {from_stage}/{total}?"):
            raise PermissionError("methodology run was not approved")
        agent = Agent(
            self.project,
            approve=self.approve,
            instruction_files=methodology.skill_files,
            context_files=[methodology.workflow_file] if methodology.workflow_file.suffix.lower() == ".md" else [],
            event_handler=self.event_handler,
        )
        required_mcp = {item.name for item in methodology.requirements if item.kind == "mcp"}
        if required_mcp:
            agent.tools.mcp.discover(refresh=True)
            connected = {item["name"] for item in agent.tools.mcp.status() if item["connected"]}
            unavailable = sorted(required_mcp - connected)
            if unavailable:
                raise PermissionError(f"required MCP server connection failed: {', '.join(unavailable)}")
        run_id = self.state.start_run(f"methodology:{methodology.name}:{target}")
        goals = {stage.id: self.state.create_goal(f"{methodology.name}: {stage.title}", stage.instructions[:2000], run_id=run_id, stage_id=stage.id) for stage in methodology.stages}
        artifact_dir = self.project / ".hacker-harness" / "artifacts" / "methodologies" / run_id
        artifact_dir.mkdir(parents=True, exist_ok=True)
        library_context = methodology_context(methodology, self.project)
        outputs: dict[str, str] = {}
        try:
            for index, stage in enumerate(methodology.stages, 1):
                if index < from_stage:
                    self.state.set_methodology_stage(run_id, index, stage.id, "skipped")
                    self.state.update_goal(goals[stage.id], "cancelled")
                    continue
                blocked = missing_artifacts(self.project, stage.requires)
                if blocked:
                    raise PermissionError(f"stage {stage.id} missing required files: {', '.join(blocked)}")
                self.emit(f"[{index}/{total}] STARTED  {stage.title}")
                self.state.update_goal(goals[stage.id], "in_progress")
                self.state.set_methodology_stage(run_id, index, stage.id, "running")
                strict_instructions = """STRICT METHODOLOGY MODE:
- Follow every instruction and checklist item in this stage in written order.
- Do not silently skip, replace, merge, or move ahead to a later stage.
- If a dependency, credential, MCP tool, input, or decision is missing, stop and ask the operator instead of improvising.
- End with a Methodology Compliance section mapping every required item to completed, blocked, or not applicable with evidence.
""" if methodology.strict else "Methodology guidance is advisory; explain any deviations."
                skills = "\n".join(f"- skill_load {name}" for name in stage.skills) or "- (none)"
                writes = "\n".join(f"- {path}" for path in stage.writes) or "- (none)"
                orchestration = "spawn_agent may only receive a plan file path for this stage; every spawn requires operator approval."
                prompt = f"""Execute only stage {index} of {total} from the '{methodology.name}' methodology.
Authorized target: {target}
Stage: {stage.title}
Goal ID: {goals[stage.id]}

{strict_instructions}

{orchestration}

skill_load:
{skills}

Required writes (non-empty files before this stage can complete):
{writes}

{library_context}

Current stage instructions:
{stage.instructions}

Use read_file to consult any supporting methodology documents relevant to this stage. Treat index.md as the router when present. Follow the authorization scope and any loaded SKILL.md instructions. Do not perform later stages.
Return a concise stage report containing actions, evidence, findings, blockers, and a handoff for the next stage.
"""
                try:
                    output = agent.run(prompt)
                    unwritten = missing_artifacts(self.project, stage.writes)
                    if unwritten and methodology.strict:
                        raise PermissionError(f"stage {stage.id} did not write required files: {', '.join(unwritten)}")
                    safe_id = re.sub(r"[^a-zA-Z0-9_.-]+", "-", stage.id).strip("-") or str(index)
                    output_path = artifact_dir / f"{index:02d}-{safe_id}.md"
                    output_path.write_text(output, encoding="utf-8")
                    relative = str(output_path.relative_to(self.project))
                    outputs[stage.id] = output
                    self.state.set_methodology_stage(run_id, index, stage.id, "completed", relative)
                    self.state.update_goal(goals[stage.id], "completed")
                    self.emit(f"[{index}/{total}] COMPLETED {stage.title} → {relative}")
                    if index < total:
                        self.emit(f"[{index + 1}/{total}] MOVING TO {methodology.stages[index].title}")
                except Exception as exc:
                    self.state.set_methodology_stage(run_id, index, stage.id, "failed", error=str(exc))
                    self.state.update_goal(goals[stage.id], "blocked" if isinstance(exc, PermissionError) else "failed")
                    self.emit(f"[{index}/{total}] FAILED    {stage.title}: {exc}")
                    raise
            self.state.finish_run(run_id, "completed", outputs)
            return run_id, outputs
        except Exception:
            self.state.finish_run(run_id, "failed", outputs)
            raise


def init_methodology(
    project: Path,
    *,
    name: str,
    title: str = "",
) -> tuple[Path, list[Path]]:
    if not name.strip():
        raise ValueError("methodology name cannot be empty")
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    destination = project / "methodology" / slug
    if destination.exists():
        raise ValueError(f"methodology already exists: {destination.relative_to(project)}")
    destination.mkdir(parents=True, exist_ok=True)
    display_title = title.strip() or slug.replace("-", " ").title()

    index_content = (
        f"# {display_title} Methodology\n\n"
        f"This library defines the {display_title} testing methodology for authorized engagements.\n\n"
        "## Structure\n"
        f"- `{slug}-workflow.md`: Executable staged workflow for systematic execution.\n"
        f"- `{slug}-framework.md`: Loadable knowledge framework for guided assessment.\n"
    )
    index_path = destination / "index.md"
    index_path.write_text(index_content, encoding="utf-8")

    workflow_content = (
        "---\n"
        "hackerHarness:\n"
        "  strict: true\n"
        "  requirements:\n"
        "    commands:\n"
        "      - curl\n"
        "---\n\n"
        f"# {display_title} Workflow\n\n"
        "## Stage 1: Scope & Authorization Setup\n"
        "Verify scope, normalize targets, and establish authorization tokens.\n\n"
        "## Stage 2: Target Discovery & Enumeration\n"
        "Discover available endpoints, parameters, and application components.\n\n"
        "## Stage 3: Vulnerability Assessment\n"
        "Execute targeted assessment probes according to authorized rules.\n"
    )
    workflow_path = destination / f"{slug}-workflow.md"
    workflow_path.write_text(workflow_content, encoding="utf-8")

    framework_content = (
        f"# {display_title} Framework\n\n"
        f"Core principles, testing standards, and assessment criteria for {display_title}.\n\n"
        "## Principles\n"
        "1. Scope awareness: strictly test authorized targets.\n"
        "2. Evidence collection: document all findings with reproduction steps.\n"
    )
    framework_path = destination / f"{slug}-framework.md"
    framework_path.write_text(framework_content, encoding="utf-8")

    return destination, [index_path, workflow_path, framework_path]


def validate_methodology(project: Path, target: str | Path) -> tuple[bool, str, list[str]]:
    target_path = Path(target)
    folder: Path | None = None
    for root in [project / "methodology", *[project / raw for raw in load_settings(project).get("methodologyPaths", [])]]:
        cand = root / str(target)
        if cand.is_dir():
            folder = cand
            break
    if folder is None:
        if target_path.is_dir():
            folder = target_path
        elif (project / target_path).is_dir():
            folder = project / target_path
    if folder is None or not folder.is_dir():
        return False, f"methodology folder not found: {target}", []

    docs = discover_documents(folder)
    if not docs:
        return False, f"no markdown documents found in {folder.relative_to(project)}", []

    issues: list[str] = []
    workflows = discover_workflows(folder)
    for wf in workflows:
        try:
            rel_wf = wf.relative_to(folder).as_posix()
            m = load_methodology(project, folder, rel_wf)
            if not m.stages:
                issues.append(f"{wf.name}: no numbered stages (## Stage 1:) and no stage manifest found")
        except Exception as exc:
            issues.append(f"{wf.name}: error loading: {exc}")

    if issues:
        return False, f"Methodology {folder.name} has {len(issues)} issue(s)", issues
    return True, f"Valid methodology {folder.name} ({len(docs)} documents, {len(workflows)} workflows)", []


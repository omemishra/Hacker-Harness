from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .memory import append_memory

PLAYBOOK_VAULT_DIR = "concepts/patterns"
PLAYBOOK_PROJECT_DIR = ".hacker-harness/playbooks"
SKILL_FILENAME = "SKILL.md"


@dataclass(frozen=True)
class SkillEntry:
    path: Path
    name: str
    description: str
    pivots_to: tuple[str, ...] = ()

    @property
    def skill_id(self) -> str:
        if self.path.parent.name and self.path.parent.name != ".hacker-harness":
            return self.path.parent.name
        return self.path.stem


def parse_skill_frontmatter(text: str) -> tuple[dict, str]:
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            payload = yaml.safe_load(parts[1]) or {}
            body = parts[2].lstrip("\n")
            if isinstance(payload, dict):
                return payload, body
    return {}, text


def discover_skill_files(root: Path, extra_files: list[Path] | None = None) -> list[Path]:
    from .config import load_settings

    settings = load_settings(root)
    candidates = list(extra_files or [])
    for raw in settings.get("skillPaths", [".hacker-harness/skills"]):
        path = (root / raw).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError as exc:
            raise PermissionError(f"skill path escapes project root: {raw}") from exc
        if path.is_file() and path.name.lower() == SKILL_FILENAME.lower():
            candidates.append(path)
        elif path.is_dir():
            candidates.extend(path.rglob(SKILL_FILENAME))
    resolved: list[Path] = []
    for candidate in candidates:
        path = candidate.resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError as exc:
            raise PermissionError(f"skill file escapes project root: {candidate}") from exc
        if path.is_file() and path.name.lower() == SKILL_FILENAME.lower() and path not in resolved:
            resolved.append(path)
    return sorted(resolved)


def discover_skill_entries(root: Path, extra_files: list[Path] | None = None) -> list[SkillEntry]:
    entries: list[SkillEntry] = []
    seen: set[Path] = set()
    for path in discover_skill_files(root, extra_files):
        if path in seen:
            continue
        seen.add(path)
        raw = path.read_text(encoding="utf-8")
        meta, _body = parse_skill_frontmatter(raw)
        name = str(meta.get("name") or path.parent.name or path.stem).strip() or path.stem
        description = str(meta.get("description") or "No description.").strip()
        raw_pivots = meta.get("pivots_to") or meta.get("pivots") or []
        if isinstance(raw_pivots, str):
            pivots = tuple(item.strip() for item in raw_pivots.split(",") if item.strip())
        elif isinstance(raw_pivots, (list, tuple)):
            pivots = tuple(str(item).strip() for item in raw_pivots if str(item).strip())
        else:
            pivots = ()
        entries.append(SkillEntry(path=path, name=name, description=description, pivots_to=pivots))
    return sorted(entries, key=lambda item: item.name.lower())


def get_skill_pivots(root: Path, skill_id_or_name: str, extra_files: list[Path] | None = None) -> list[SkillEntry]:
    """Retrieve next-pivot skills linked to a given skill."""
    entries = discover_skill_entries(root, extra_files)
    try:
        source = resolve_skill_entry(entries, skill_id_or_name)
    except ValueError:
        return []
    result: list[SkillEntry] = []
    seen = {source.skill_id.lower(), source.name.lower()}
    for target in source.pivots_to:
        try:
            target_entry = resolve_skill_entry(entries, target)
            if target_entry.skill_id.lower() not in seen and target_entry.name.lower() not in seen:
                result.append(target_entry)
                seen.add(target_entry.skill_id.lower())
                seen.add(target_entry.name.lower())
        except ValueError:
            continue
    return result


FINDING_PIVOT_RULES = [
    (re.compile(r"\b(ssrf|metadata|imds|169\.254|webhook|internal pivot)\b", re.I), ("cloud-aws-iam-privesc", "cloud-azure-entraid-audit", "ad-kerberos-delegation-abuse", "infra-container-escape-audit")),
    (re.compile(r"\b(open redirect|redirect|oauth|oidc|sso callback)\b", re.I), ("identity-oauth-oidc-abuse", "identity-jwt-manipulation", "web-ssrf-cloud-pivot")),
    (re.compile(r"\b(sqli|sql injection|nosql|database|orm)\b", re.I), ("web-sqli-blind-polyglot", "web-command-injection-rce")),
    (re.compile(r"\b(xss|cross-site scripting|csp|dom|template)\b", re.I), ("web-xss-polyglot-execution", "web-prototype-pollution-cspp", "web-cors-misconfiguration-bypass")),
    (re.compile(r"\b(prototype pollution|cspp|__proto__|object\.prototype)\b", re.I), ("web-prototype-pollution-cspp", "web-xss-polyglot-execution")),
    (re.compile(r"\b(idor|bola|authorization|bfla|broken object)\b", re.I), ("web-idor-bola-authorization", "web-api-mass-assignment-pollution", "genpentest-p7-cross-org")),
    (re.compile(r"\b(mass assignment|parameter pollution|is_admin|privilege)\b", re.I), ("web-api-mass-assignment-pollution", "genpentest-p5-role-matrix")),
    (re.compile(r"\b(saml|xml|xsw|signature)\b", re.I), ("identity-saml-sso-abuse", "web-xxe-oob-extraction")),
    (re.compile(r"\b(jwt|token|bearer|jwks)\b", re.I), ("identity-jwt-manipulation", "identity-mfa-bypass-mechanisms")),
    (re.compile(r"\b(container|kubernetes|docker|escape|cgroup)\b", re.I), ("infra-container-escape-audit", "cloud-aws-iam-privesc")),
    (re.compile(r"\b(aws|s3|iam|accesskey|sts|cloud)\b", re.I), ("cloud-aws-iam-privesc", "infra-container-escape-audit")),
    (re.compile(r"\b(azure|entra|tenant|aad)\b", re.I), ("cloud-azure-entraid-audit", "identity-saml-sso-abuse")),
    (re.compile(r"\b(active directory|kerberos|ntlm|ldap|domain)\b", re.I), ("ad-kerberos-delegation-abuse", "perimeter-exchange-ntlm-info")),
    (re.compile(r"\b(lfi|path traversal|traversal|procfs|file inclusion)\b", re.I), ("web-lfi-path-traversal-audit", "web-ssrf-cloud-pivot", "web-file-upload-webshell")),
    (re.compile(r"\b(cors|origin reflection|null origin)\b", re.I), ("web-cors-misconfiguration-bypass", "web-xss-polyglot-execution")),
    (re.compile(r"\b(secret|api_key|password|credential|leak|trufflehog)\b", re.I), ("cloud-aws-iam-privesc", "cloud-azure-entraid-audit", "code-review-deep-audit")),
    (re.compile(r"\b(403|401|bypass|forbidden|unauthorized|header)\b", re.I), ("perimeter-port-service-fuzz", "perimeter-vpn-gateway-audit")),
    (re.compile(r"\b(race condition|concurrency|limit overrun|double spend)\b", re.I), ("web-concurrency-race-condition", "genpentest-p6-business-logic")),
    (re.compile(r"\b(deserialization|pickle|gadget|yaml\.load)\b", re.I), ("web-deserialization-gadget-abuse", "web-command-injection-rce")),
]


def suggest_pivots_for_finding(root: Path, finding: dict | str, extra_files: list[Path] | None = None) -> list[dict]:
    """Suggest tactical follow-up skills based on finding title, evidence, and type."""
    entries = discover_skill_entries(root, extra_files)
    if isinstance(finding, str):
        text = finding
        target_skill_id = finding.strip()
    else:
        text = f"{finding.get('title', '')} {finding.get('evidence', '')} {finding.get('target', '')}"
        target_skill_id = finding.get('title', '')
    
    suggested_skills: list[dict] = []
    seen = set()

    # First check if the finding or string matches an existing skill's declared pivots
    for entry in entries:
        if entry.skill_id.lower() == target_skill_id.lower() or entry.name.lower() == target_skill_id.lower():
            for pivot in entry.pivots_to:
                try:
                    p_entry = resolve_skill_entry(entries, pivot)
                    if p_entry.skill_id not in seen:
                        seen.add(p_entry.skill_id)
                        suggested_skills.append({
                            "skill_id": p_entry.skill_id,
                            "name": p_entry.name,
                            "description": p_entry.description,
                            "reason": f"Direct attack pivot defined in {entry.name}",
                        })
                except ValueError:
                    pass

    # Then apply heuristic rule matching
    for pattern, target_ids in FINDING_PIVOT_RULES:
        if pattern.search(text):
            match_word = pattern.search(text).group(0)
            for tid in target_ids:
                if tid in seen:
                    continue
                try:
                    p_entry = resolve_skill_entry(entries, tid)
                    seen.add(tid)
                    suggested_skills.append({
                        "skill_id": p_entry.skill_id,
                        "name": p_entry.name,
                        "description": p_entry.description,
                        "reason": f"Matched pattern '{match_word}'",
                    })
                except ValueError:
                    pass

    return suggested_skills


def format_skill_catalog(entries: list[SkillEntry], *, root: Path | None = None) -> str:
    if not entries:
        return "No skills installed. Add SKILL.md files under .hacker-harness/skills/."
    lines = [
        "Skill bodies are not loaded until you call skill_load. Match on name or skill_id.",
        "",
    ]
    for entry in entries:
        if root is not None:
            try:
                rel = str(entry.path.relative_to(root.resolve()))
            except ValueError:
                rel = str(entry.path)
        else:
            rel = str(entry.path)
        lines.append(f"- **{entry.name}** (`{entry.skill_id}`) — {entry.description} [{rel}]")
    return "\n".join(lines)


def resolve_skill_entry(entries: list[SkillEntry], name: str) -> SkillEntry:
    needle = name.strip().lower()
    if not needle:
        raise ValueError("skill name cannot be empty")
    for entry in entries:
        if entry.name.lower() == needle or entry.skill_id.lower() == needle:
            return entry
    for entry in entries:
        if needle in entry.name.lower() or needle in entry.skill_id.lower():
            return entry
    raise ValueError(f"skill not found: {name}")


def load_skill_body(path: Path) -> str:
    raw = path.read_text(encoding="utf-8")
    _meta, body = parse_skill_frontmatter(raw)
    return body.strip() or raw.strip()


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "playbook"


def playbook_dirs(root: Path, vault: Path | None) -> list[Path]:
    dirs: list[Path] = []
    if vault is not None and vault.is_dir():
        target = vault / PLAYBOOK_VAULT_DIR
        target.mkdir(parents=True, exist_ok=True)
        dirs.append(target)
    project_dir = root / PLAYBOOK_PROJECT_DIR
    project_dir.mkdir(parents=True, exist_ok=True)
    dirs.append(project_dir)
    return dirs


def _playbook_path(base: Path, slug: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    candidate = base / f"{stamp}-{slug}.md"
    counter = 1
    while candidate.exists():
        candidate = base / f"{stamp}-{slug}-{counter}.md"
        counter += 1
    return candidate


def render_playbook(
    *,
    title: str,
    content: str,
    observables: list[str] | None = None,
    tags: list[str] | None = None,
    engagement: str = "",
) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    obs = observables or []
    tag_list = tags or []
    frontmatter = {
        "title": title.strip(),
        "tags": tag_list,
        "observables": obs,
        "engagement": engagement or "unknown",
        "created": stamp,
        "source": "hacker-harness-playbook",
    }
    yaml_block = yaml.safe_dump(frontmatter, sort_keys=False).strip()
    body = content.strip()
    return f"---\n{yaml_block}\n---\n\n# {title.strip()}\n\n{body}\n"


def save_playbook(
    root: Path,
    *,
    title: str,
    content: str,
    observables: list[str] | None = None,
    tags: list[str] | None = None,
    procedure_summary: str = "",
    vault: Path | None = None,
) -> tuple[Path, str]:
    if not title.strip():
        raise ValueError("playbook title cannot be empty")
    if not content.strip():
        raise ValueError("playbook content cannot be empty")
    slug = _slugify(title)
    text = render_playbook(
        title=title,
        content=content,
        observables=observables,
        tags=tags,
        engagement=root.name,
    )
    primary = playbook_dirs(root, vault)[0]
    path = _playbook_path(primary, slug)
    path.write_text(text, encoding="utf-8")
    summary = procedure_summary.strip() or _default_procedure_summary(title, observables or [], path)
    append_memory(root, summary, kind="procedure")
    return path, summary


def _default_procedure_summary(title: str, observables: list[str], path: Path) -> str:
    triggers = ", ".join(observables[:3]) if observables else title
    return f"When {triggers} — reuse playbook at {path}."


def search_playbooks(root: Path, query: str, *, vault: Path | None = None, limit: int = 12) -> list[dict]:
    needle = query.strip()
    if not needle:
        return []
    results: list[dict] = []
    for directory in playbook_dirs(root, vault):
        if not directory.is_dir():
            continue
        if shutil.which("rg"):
            results.extend(_search_playbooks_rg(directory, needle, limit - len(results)))
        else:
            results.extend(_search_playbooks_python(directory, needle, limit - len(results)))
        if len(results) >= limit:
            return results[:limit]
    return results


def _playbook_match(path: Path) -> dict:
    title = path.stem
    snippet = ""
    try:
        text = path.read_text(encoding="utf-8")
        meta, body = parse_skill_frontmatter(text)
        title = str(meta.get("title") or title)
        snippet = body.splitlines()[0][:240] if body else text.splitlines()[0][:240]
    except OSError:
        pass
    return {"path": str(path), "title": title, "match": snippet}


def _search_playbooks_rg(directory: Path, needle: str, limit: int) -> list[dict]:
    if limit <= 0:
        return []
    command = [
        "rg",
        "--line-number",
        "--color",
        "never",
        "--ignore-case",
        "--glob",
        "*.md",
        needle,
        str(directory),
    ]
    proc = subprocess.run(command, capture_output=True, text=True, timeout=30)
    if proc.returncode not in (0, 1):
        return []
    results: list[dict] = []
    seen: set[str] = set()
    for line in proc.stdout.splitlines():
        if ":" not in line:
            continue
        file_path, _lineno, snippet = line.split(":", 2)
        if file_path in seen:
            continue
        seen.add(file_path)
        match = _playbook_match(Path(file_path))
        match["match"] = snippet.strip()[:240]
        results.append(match)
        if len(results) >= limit:
            break
    return results


def _search_playbooks_python(directory: Path, needle: str, limit: int) -> list[dict]:
    if limit <= 0:
        return []
    lower = needle.lower()
    results: list[dict] = []
    for path in sorted(directory.rglob("*.md")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if lower not in text.lower():
            continue
        match = _playbook_match(path)
        for line in text.splitlines():
            if lower in line.lower():
                match["match"] = line.strip()[:240]
                break
        results.append(match)
        if len(results) >= limit:
            break
    return results


def promote_skill(
    root: Path,
    *,
    name: str,
    description: str,
    content: str,
) -> Path:
    if not name.strip():
        raise ValueError("skill name cannot be empty")
    if not description.strip():
        raise ValueError("skill description cannot be empty")
    if not content.strip():
        raise ValueError("skill content cannot be empty")
    skill_id = _slugify(name)
    folder = root / ".hacker-harness" / "skills" / skill_id
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / SKILL_FILENAME
    body = content.strip()
    document = (
        "---\n"
        f"name: {name.strip()}\n"
        f"description: {description.strip()}\n"
        "---\n\n"
        f"{body}\n"
    )
    path.write_text(document, encoding="utf-8")
    return path


def init_skill(
    root: Path,
    *,
    name: str,
    description: str = "",
    playbook: str = "",
) -> Path:
    if not name.strip():
        raise ValueError("skill name cannot be empty")
    skill_id = _slugify(name)
    folder = root / ".hacker-harness" / "skills" / skill_id
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / SKILL_FILENAME
    if path.exists():
        raise ValueError(f"skill already exists: {path.relative_to(root)}")
    desc = description.strip() or f"Step-by-step tactical playbook for {name.strip()}."
    pb_line = f"playbook: {playbook.strip()}\n" if playbook.strip() else ""
    document = (
        "---\n"
        f"name: {name.strip()}\n"
        f"description: {desc}\n"
        f"{pb_line}"
        "---\n\n"
        f"# {name.strip()}\n\n"
        "## 1. Prerequisites & Input Contract\n"
        "- Verify active authorization scope in `.hacker-harness/scope.yaml`.\n"
        "- Required inputs: list input files or tokens needed.\n\n"
        "## 2. Step-by-Step Attack Sequence\n\n"
        "### Step 1: Recon & Parameter Mapping\n"
        "Identify potential attack surfaces, parameters, and headers.\n\n"
        "### Step 2: Active Probes & Payload Delivery\n"
        "Execute targeted requests against authorized endpoints:\n"
        "```http\n"
        "GET /api/v1/resource HTTP/1.1\n"
        "Host: {{ target }}\n"
        "Authorization: Bearer {{ token }}\n"
        "```\n\n"
        "### Step 3: Response Analysis & Validation\n"
        "Verify behavioral differences and bypass conditions.\n\n"
        "## 3. Evidence Collection & Reporting\n"
        "1. Capture raw HTTP request and response pairs.\n"
        "2. Record finding details in the designated output file.\n"
    )
    path.write_text(document, encoding="utf-8")
    return path


def validate_skill(path: Path) -> tuple[bool, str, dict]:
    if not path.is_file():
        return False, f"file not found: {path}", {}
    raw = path.read_text(encoding="utf-8")
    meta, body = parse_skill_frontmatter(raw)
    if not meta:
        return False, "missing or invalid YAML frontmatter (must start with ---)", {}
    name = str(meta.get("name") or "").strip()
    if not name:
        return False, "missing 'name' in YAML frontmatter", meta
    description = str(meta.get("description") or "").strip()
    if not description:
        return False, "missing 'description' in YAML frontmatter", meta
    if not body.strip():
        return False, "skill body content is empty", meta
    return True, f"Valid skill '{name}' ({len(body)} chars)", meta


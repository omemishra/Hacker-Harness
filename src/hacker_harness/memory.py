from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .providers import ModelProvider


MEMORY_RELATIVE = ".hacker-harness/memory.md"
MEMORY_KINDS = frozenset({"preference", "lesson", "procedure", "profile"})
MEMORY_TEMPLATE = """# Hacker-Harness memory

Durable lessons, preferences, and "do not do this again" notes for this project.
The agent reads this file every session. Lessons are distilled — not copied verbatim.

## Entries

"""

REMEMBER_PREFIX = re.compile(r"^(?:/remember|remember)\s+(.+)$", re.I)
ENTRY_LINE_RE = re.compile(
    r"^- \*\*(?P<stamp>[^*]+)\*\*(?: · (?P<kind>preference|lesson|procedure|profile))? — (?P<content>.+)$"
)
CORRECTION_PREFIX = re.compile(
    r"^(?:no[,!.\s]+|wrong[,!.\s]+|don'?t do that|stop doing|not that[,!.\s]+|instead[,!.\s]+|always use |never use )",
    re.I,
)

DISTILL_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^remember\s+(?:that\s+)?you are (?:a |an )?(.+)$", re.I), r"Operate as \1 on authorized engagements."),
    (re.compile(r"^you are (?:a |an )?(.+)$", re.I), r"Operate as \1 on authorized engagements."),
    (re.compile(r"^always (.+)$", re.I), r"Always \1"),
    (re.compile(r"^never (.+)$", re.I), r"Never \1"),
    (re.compile(r"^don'?t (.+)$", re.I), r"Do not \1"),
    (re.compile(r"^do not (.+)$", re.I), r"Do not \1"),
]

DISTILL_SYSTEM = """You curate durable memory for an authorized offensive-security harness.
Given operator text and existing memory, emit ONE distilled lesson the agent should follow in future sessions.
- Write declarative third-person lessons (not chat quotes).
- Skip role-play fluff; keep operational preferences, constraints, and corrections.
- Skip if duplicate or too vague to act on.
Reply with JSON only: {"action":"save"|"skip","kind":"preference|lesson|procedure|profile","content":"..."}"""


@dataclass(frozen=True)
class CurateResult:
    saved: bool
    content: str = ""
    kind: str = "lesson"
    reason: str = ""


def parse_remember_prompt(prompt: str) -> str | None:
    """Return operator text when the message is an explicit remember command."""
    match = REMEMBER_PREFIX.match(prompt.strip())
    if not match:
        return None
    content = match.group(1).strip()
    return content or None


def looks_like_correction(prompt: str) -> bool:
    return bool(CORRECTION_PREFIX.search(prompt.strip()))


def normalize_memory_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def memory_fingerprint(content: str) -> str:
    text = normalize_memory_text(content)
    text = re.sub(r"^operate as ", "", text)
    text = re.sub(r"^you are (?:a |an )?", "", text)
    text = re.sub(r" on authorized engagements\.?$", "", text)
    text = re.sub(r"\b(?:a|an|the)\b", " ", text)
    return re.sub(r"\s+", " ", text).strip(" .")


def parse_memory_entries(text: str) -> list[dict]:
    entries: list[dict] = []
    for line in text.splitlines():
        match = ENTRY_LINE_RE.match(line.strip())
        if not match:
            continue
        entries.append({
            "stamp": match.group("stamp").strip(),
            "kind": match.group("kind") or "",
            "content": match.group("content").strip(),
        })
    return entries


def _entry_score(entry: dict) -> tuple[int, int]:
    content = entry["content"]
    kind_bonus = 10 if entry.get("kind") in MEMORY_KINDS else 0
    distill_bonus = 5 if content.lower().startswith("operate as") else 0
    return (kind_bonus + distill_bonus, len(content))


def _unique_memory_entries(entries: list[dict]) -> list[dict]:
    best_by_fp: dict[str, dict] = {}
    order: list[str] = []
    for entry in entries:
        fingerprint = memory_fingerprint(entry["content"])
        if not fingerprint:
            continue
        current = best_by_fp.get(fingerprint)
        if current is None:
            best_by_fp[fingerprint] = entry
            order.append(fingerprint)
        elif _entry_score(entry) >= _entry_score(current):
            best_by_fp[fingerprint] = entry
    return [best_by_fp[fingerprint] for fingerprint in order]


def _needs_template_migration(text: str) -> bool:
    return "Edit it directly or use" in text or "hh memory remember" in text


def render_memory_file(entries: list[dict]) -> str:
    lines = [
        "# Hacker-Harness memory",
        "",
        'Durable lessons, preferences, and "do not do this again" notes for this project.',
        "The agent reads this file every session. Lessons are distilled — not copied verbatim.",
        "",
        "## Entries",
        "",
    ]
    for entry in entries:
        if entry.get("kind"):
            lines.append(f"- **{entry['stamp']}** · {entry['kind']} — {entry['content']}")
        else:
            lines.append(f"- **{entry['stamp']}** — {entry['content']}")
    return "\n".join(lines) + "\n"


def write_memory_file(root: Path, entries: list[dict]) -> Path:
    path = memory_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_memory_file(_unique_memory_entries(entries)), encoding="utf-8")
    return path


def dedupe_memory_file(root: Path) -> bool:
    path = memory_path(root)
    if not path.is_file():
        return False
    raw = path.read_text(encoding="utf-8")
    entries = parse_memory_entries(raw)
    if not entries:
        if _needs_template_migration(raw):
            path.write_text(MEMORY_TEMPLATE, encoding="utf-8")
            return True
        return False
    new_text = render_memory_file(_unique_memory_entries(entries))
    if new_text == raw:
        return False
    path.write_text(new_text, encoding="utf-8")
    return True


def memory_path(root: Path) -> Path:
    return root / MEMORY_RELATIVE


def ensure_memory_file(root: Path) -> Path:
    path = memory_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(MEMORY_TEMPLATE, encoding="utf-8")
    else:
        dedupe_memory_file(root)
    return path


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def memory_already_present(root: Path, content: str) -> bool:
    fingerprint = memory_fingerprint(content)
    if not fingerprint:
        return True
    for entry in parse_memory_entries(read_memory(root)):
        if memory_fingerprint(entry["content"]) == fingerprint:
            return True
        if normalize_memory_text(entry["content"]) == normalize_memory_text(content):
            return True
    return False


def distill_memory_rules(raw: str) -> tuple[str, str] | None:
    text = raw.strip()
    if not text:
        return None
    for pattern, replacement in DISTILL_RULES:
        match = pattern.match(text)
        if match:
            content = match.expand(replacement).strip()
            kind = "profile" if "operate as" in content.lower() else "preference"
            return kind, content
    if len(text.split()) <= 18:
        return "lesson", text[0].upper() + text[1:] if text else text
    return "lesson", text


def _parse_distill_json(text: str) -> CurateResult | None:
    payload = text.strip()
    if payload.startswith("```"):
        payload = re.sub(r"^```(?:json)?\s*|\s*```$", "", payload, flags=re.S).strip()
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return None
    action = str(data.get("action", "")).lower()
    if action == "skip":
        return CurateResult(saved=False, reason=str(data.get("reason") or "not worth saving"))
    content = str(data.get("content", "")).strip()
    if not content:
        return CurateResult(saved=False, reason="empty lesson")
    kind = str(data.get("kind", "lesson")).lower()
    if kind not in MEMORY_KINDS:
        kind = "lesson"
    return CurateResult(saved=True, content=content, kind=kind)


def distill_memory_with_provider(provider: ModelProvider, raw: str, existing: str) -> CurateResult | None:
    messages = [
        {"role": "system", "content": DISTILL_SYSTEM},
        {"role": "user", "content": json.dumps({"operator_text": raw, "existing_memory": existing[-6000:]}, ensure_ascii=False)},
    ]
    try:
        reply = provider.complete(messages, [])
    except Exception:
        return None
    parsed = _parse_distill_json(reply.text or "")
    if parsed is not None:
        return parsed
    distilled = distill_memory_rules(raw)
    if not distilled:
        return CurateResult(saved=False, reason="could not distill")
    kind, content = distilled
    return CurateResult(saved=True, content=content, kind=kind)


def curate_operator_memory(
    root: Path,
    raw: str,
    *,
    provider: ModelProvider | None = None,
) -> CurateResult:
    existing = read_memory(root)
    if provider is not None:
        llm = distill_memory_with_provider(provider, raw, existing)
        if llm is not None and (llm.saved or llm.reason):
            candidate = llm
        else:
            candidate = None
    else:
        candidate = None
    if candidate is None:
        distilled = distill_memory_rules(raw)
        if not distilled:
            return CurateResult(saved=False, reason="nothing to save")
        kind, content = distilled
        candidate = CurateResult(saved=True, content=content, kind=kind)
    if not candidate.saved:
        return candidate
    if memory_already_present(root, candidate.content):
        return CurateResult(saved=False, reason="duplicate lesson already in memory")
    return candidate


def _mirror_obsidian_wiki(vault: Path, content: str, *, project: str = "", kind: str = "lesson") -> Path:
    raw_dir = vault / "_raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc)
    date = stamp.strftime("%Y-%m-%d")
    slug = re.sub(r"[^a-z0-9]+", "-", content.lower()[:48]).strip("-") or "lesson"
    path = raw_dir / f"{date}-hh-{slug}.md"
    counter = 1
    while path.exists():
        path = raw_dir / f"{date}-hh-{slug}-{counter}.md"
        counter += 1
    summary = content.strip()
    if len(summary) > 200:
        summary = summary[:197] + "..."
    project_name = project or "null"
    body = f"""---
title: "Hacker-Harness lesson"
category: skills
tags:
  - topic/hacker-harness
summary: "{summary.replace('"', "'")}"
capture_source: hacker-harness
project: {json_quote(project_name)}
base_confidence: 0.85
lifecycle: draft
lifecycle_changed: {date}
provenance:
  extracted: 0.9
  inferred: 0.1
sources:
  - "hacker-harness remember ({date})"
---

## Operator lesson

**Kind:** {kind}

**Behavior:** {content.strip()}

**Confirmed by:** operator remember — do not repeat
"""
    path.write_text(body, encoding="utf-8")
    return path


def json_quote(value: str) -> str:
    if value == "null":
        return "null"
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def append_memory(
    root: Path,
    content: str,
    *,
    kind: str = "lesson",
    obsidian_vault: Path | None = None,
) -> tuple[Path, bool]:
    text = content.strip()
    if not text:
        raise ValueError("memory content cannot be empty")
    path = memory_path(root)
    existing = _unique_memory_entries(
        parse_memory_entries(path.read_text(encoding="utf-8"))
    ) if path.is_file() else []
    fingerprint = memory_fingerprint(text)
    for entry in existing:
        if memory_fingerprint(entry["content"]) == fingerprint:
            write_memory_file(root, existing)
            return path, False
        if normalize_memory_text(entry["content"]) == normalize_memory_text(text):
            write_memory_file(root, existing)
            return path, False
    label = kind if kind in MEMORY_KINDS else "lesson"
    existing.append({"stamp": _stamp(), "kind": label, "content": text})
    write_memory_file(root, existing)
    if obsidian_vault is not None and obsidian_vault.is_dir():
        _mirror_obsidian_wiki(obsidian_vault, text, project=root.name, kind=label)
    return path, True


def read_memory(root: Path, *, limit_chars: int = 12_000) -> str:
    path = memory_path(root)
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8").strip()
    if len(text) <= limit_chars:
        return text
    return "…\n" + text[-limit_chars:]


def fts_query(text: str) -> str:
    tokens = re.findall(r"\w+", text.lower())
    if not tokens:
        return ""
    return " OR ".join(f'"{token}"' for token in tokens[:10])

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .findings import LEGACY_STATUS_MAP, evidence_required_for, validate_transition
from .memory import append_memory, ensure_memory_file, fts_query, parse_memory_entries, read_memory


SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'open', priority INTEGER NOT NULL DEFAULT 2,
  assignee TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dependencies (
  child_id TEXT NOT NULL, parent_id TEXT NOT NULL,
  PRIMARY KEY(child_id, parent_id),
  FOREIGN KEY(child_id) REFERENCES tasks(id), FOREIGN KEY(parent_id) REFERENCES tasks(id)
);
CREATE TABLE IF NOT EXISTS memories (
  id INTEGER PRIMARY KEY AUTOINCREMENT, content TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'lesson', created_at TEXT NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(content, kind);
CREATE TABLE IF NOT EXISTS workflow_runs (
  id TEXT PRIMARY KEY, workflow TEXT NOT NULL, status TEXT NOT NULL,
  started_at TEXT NOT NULL, finished_at TEXT, outputs_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, event TEXT NOT NULL,
  allowed INTEGER NOT NULL, details_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS methodology_stages (
  run_id TEXT NOT NULL, stage_index INTEGER NOT NULL, stage_id TEXT NOT NULL,
  status TEXT NOT NULL, started_at TEXT, finished_at TEXT, output_path TEXT, error TEXT,
  PRIMARY KEY(run_id, stage_index),
  FOREIGN KEY(run_id) REFERENCES workflow_runs(id)
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, title TEXT NOT NULL DEFAULT '', provider TEXT NOT NULL,
  model TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  messages_json TEXT NOT NULL DEFAULT '[]', input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL, target TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '', remediation TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'signal', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS goals (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending', session_id TEXT, run_id TEXT, stage_id TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


class StateStore:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.path = self.root / ".hacker-harness" / "state.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        ensure_memory_file(self.root)
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            self._migrate_schema(conn)
        self.sync_memories_from_file()
        self.path.chmod(0o600)

    def _migrate_schema(self, conn: sqlite3.Connection) -> None:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(memories)")}
        if "kind" not in columns:
            conn.execute("ALTER TABLE memories ADD COLUMN kind TEXT NOT NULL DEFAULT 'lesson'")
        conn.execute(
            "INSERT INTO memories_fts(rowid, content, kind) "
            "SELECT m.id, m.content, COALESCE(m.kind, 'lesson') FROM memories m "
            "WHERE NOT EXISTS (SELECT 1 FROM memories_fts WHERE rowid = m.id)"
        )
        finding_columns = {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
        if finding_columns and "status" not in finding_columns:
            conn.execute("ALTER TABLE findings ADD COLUMN status TEXT NOT NULL DEFAULT 'confirmed'")
        if finding_columns and "updated_at" not in finding_columns:
            conn.execute("ALTER TABLE findings ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''")
            conn.execute("UPDATE findings SET updated_at = created_at WHERE updated_at = '' OR updated_at IS NULL")
        for legacy, modern in LEGACY_STATUS_MAP.items():
            conn.execute("UPDATE findings SET status=? WHERE status=?", (modern, legacy))

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def create_task(self, title: str, description: str = "", priority: int = 2) -> str:
        stamp = now()
        digest = hashlib.sha256(f"{title}:{stamp}".encode()).hexdigest()[:6]
        task_id = f"hh-{digest}"
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO tasks VALUES (?, ?, ?, 'open', ?, NULL, ?, ?)",
                (task_id, title, description, priority, stamp, stamp),
            )
        return task_id

    def add_dependency(self, child: str, parent: str) -> None:
        with self.connect() as conn:
            conn.execute("INSERT INTO dependencies VALUES (?, ?)", (child, parent))

    def ready_tasks(self) -> list[dict]:
        query = """
        SELECT t.* FROM tasks t WHERE t.status = 'open' AND NOT EXISTS (
          SELECT 1 FROM dependencies d JOIN tasks p ON p.id=d.parent_id
          WHERE d.child_id=t.id AND p.status != 'closed'
        ) ORDER BY t.priority, t.created_at
        """
        with self.connect() as conn:
            return [dict(row) for row in conn.execute(query)]

    def get_task(self, task_id: str) -> dict | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            return dict(row) if row else None

    def update_task(self, task_id: str, status: str, assignee: str | None = None) -> bool:
        with self.connect() as conn:
            cursor = conn.execute(
                "UPDATE tasks SET status=?, assignee=COALESCE(?, assignee), updated_at=? WHERE id=?",
                (status, assignee, now(), task_id),
            )
            return cursor.rowcount == 1

    def remember(self, content: str, *, kind: str = "lesson", obsidian_vault: Path | None = None) -> bool:
        _path, appended = append_memory(self.root, content, kind=kind, obsidian_vault=obsidian_vault)
        self.sync_memories_from_file()
        return appended

    def sync_memories_from_file(self) -> None:
        """Rebuild SQLite memory index from the canonical memory.md file."""
        path = self.root / ".hacker-harness" / "memory.md"
        entries = parse_memory_entries(path.read_text(encoding="utf-8")) if path.is_file() else []
        with self.connect() as conn:
            conn.execute("DELETE FROM memories_fts")
            conn.execute("DELETE FROM memories")
            for entry in entries:
                label = entry.get("kind") or "lesson"
                created = entry.get("stamp") or now()
                cursor = conn.execute(
                    "INSERT INTO memories(content, kind, created_at) VALUES (?, ?, ?)",
                    (entry["content"], label, created),
                )
                conn.execute(
                    "INSERT INTO memories_fts(rowid, content, kind) VALUES (?, ?, ?)",
                    (cursor.lastrowid, entry["content"], label),
                )

    def search_memories(self, query: str, *, limit: int = 8) -> list[dict]:
        match = fts_query(query)
        if not match:
            return []
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT m.id, m.content, m.kind, m.created_at "
                "FROM memories_fts JOIN memories m ON m.id = memories_fts.rowid "
                "WHERE memories_fts MATCH ? ORDER BY rank LIMIT ?",
                (match, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def prime(self, limit: int = 20, *, query_hint: str = "") -> dict:
        with self.connect() as conn:
            memories = [dict(row) for row in conn.execute(
                "SELECT * FROM memories ORDER BY id DESC LIMIT ?", (limit,)
            )]
        relevant = self.search_memories(query_hint, limit=8) if query_hint.strip() else []
        return {
            "ready_tasks": self.ready_tasks()[:20],
            "goals": self.list_goals()[-20:],
            "memories": memories,
            "relevant_memories": relevant,
            "memory_md": read_memory(self.root),
        }

    def audit(self, event: str, allowed: bool, details: dict) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO audit_log(timestamp,event,allowed,details_json) VALUES (?,?,?,?)",
                (now(), event, int(allowed), json.dumps(details, default=str)),
            )

    def start_run(self, workflow: str) -> str:
        stamp = now()
        run_id = "run-" + hashlib.sha256(f"{workflow}:{stamp}".encode()).hexdigest()[:8]
        with self.connect() as conn:
            conn.execute("INSERT INTO workflow_runs(id,workflow,status,started_at) VALUES (?,?,?,?)", (run_id, workflow, "running", stamp))
        return run_id

    def finish_run(self, run_id: str, status: str, outputs: dict) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE workflow_runs SET status=?, finished_at=?, outputs_json=? WHERE id=?", (status, now(), json.dumps(outputs), run_id))

    def set_methodology_stage(self, run_id: str, index: int, stage_id: str, status: str, output_path: str | None = None, error: str | None = None) -> None:
        stamp = now()
        with self.connect() as conn:
            existing = conn.execute("SELECT 1 FROM methodology_stages WHERE run_id=? AND stage_index=?", (run_id, index)).fetchone()
            if existing:
                conn.execute("UPDATE methodology_stages SET status=?, finished_at=?, output_path=?, error=? WHERE run_id=? AND stage_index=?", (status, stamp if status in {"completed", "failed"} else None, output_path, error, run_id, index))
            else:
                conn.execute("INSERT INTO methodology_stages VALUES (?,?,?,?,?,?,?,?)", (run_id, index, stage_id, status, stamp, stamp if status in {"completed", "failed"} else None, output_path, error))

    def methodology_progress(self, run_id: str) -> list[dict]:
        with self.connect() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM methodology_stages WHERE run_id=? ORDER BY stage_index", (run_id,))]

    def create_session(self, provider: str, model: str, messages: list[dict] | None = None) -> str:
        stamp = now()
        prefix = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        digest = hashlib.sha256(f"{provider}:{model}:{stamp}".encode()).hexdigest()[:6]
        session_id = f"{prefix}_{digest}"
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO sessions(id,provider,model,created_at,updated_at,messages_json) VALUES (?,?,?,?,?,?)",
                (session_id, provider, model, stamp, stamp, json.dumps(messages or [])),
            )
        return session_id

    def save_session(self, session_id: str, messages: list[dict], provider: str, model: str, input_tokens: int = 0, output_tokens: int = 0, title: str | None = None) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE sessions SET title=CASE WHEN ? IS NULL THEN title ELSE ? END, provider=?, model=?, updated_at=?, messages_json=?, input_tokens=?, output_tokens=? WHERE id=?",
                (title, title, provider, model, now(), json.dumps(messages), input_tokens, output_tokens, session_id),
            )

    def get_session(self, session_id: str) -> dict | None:
        with self.connect() as conn:
            if session_id == "latest":
                row = conn.execute("SELECT * FROM sessions ORDER BY updated_at DESC LIMIT 1").fetchone()
            else:
                row = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
            if not row:
                return None
            result = dict(row)
            result["messages"] = json.loads(result.pop("messages_json"))
            return result

    def list_sessions(self, limit: int = 20) -> list[dict]:
        with self.connect() as conn:
            rows = [dict(row) for row in conn.execute(
                "SELECT id,title,provider,model,created_at,updated_at,input_tokens,output_tokens,messages_json FROM sessions ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            )]
        for row in rows:
            row["message_count"] = len(json.loads(row.pop("messages_json")))
        return rows

    def create_finding(
        self,
        title: str,
        severity: str,
        target: str,
        evidence: str = "",
        remediation: str = "",
        *,
        status: str = "confirmed",
    ) -> str:
        stamp = now()
        finding_id = "finding-" + hashlib.sha256(f"{title}:{target}:{stamp}".encode()).hexdigest()[:8]
        if evidence_required_for(status) and not evidence.strip():
            raise ValueError(f"status {status} requires evidence")
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?)",
                (finding_id, title, severity, target, evidence, remediation, status, stamp, stamp),
            )
        return finding_id

    def create_signal(
        self,
        title: str,
        target: str,
        notes: str = "",
        *,
        severity: str = "informational",
    ) -> str:
        return self.create_finding(
            title,
            severity,
            target,
            evidence=notes,
            remediation="",
            status="signal",
        )

    def get_finding(self, finding_id: str) -> dict | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
            return dict(row) if row else None

    def advance_finding(
        self,
        finding_id: str,
        status: str,
        *,
        evidence: str = "",
        remediation: str = "",
    ) -> bool:
        finding = self.get_finding(finding_id)
        if finding is None:
            return False
        validate_transition(finding["status"], status)
        if evidence_required_for(status):
            merged_evidence = evidence.strip() or finding.get("evidence", "").strip()
            if not merged_evidence:
                raise ValueError(f"status {status} requires evidence")
            evidence = merged_evidence
        else:
            evidence = evidence.strip() or finding.get("evidence", "")
        remediation = remediation.strip() or finding.get("remediation", "")
        stamp = now()
        with self.connect() as conn:
            cursor = conn.execute(
                "UPDATE findings SET status=?, evidence=?, remediation=?, updated_at=? WHERE id=?",
                (status, evidence, remediation, stamp, finding_id),
            )
            return cursor.rowcount == 1

    def dismiss_finding(self, finding_id: str, reason: str = "") -> bool:
        finding = self.get_finding(finding_id)
        if finding is None:
            return False
        validate_transition(finding["status"], "dismissed")
        stamp = now()
        evidence = reason.strip() or finding.get("evidence", "")
        with self.connect() as conn:
            cursor = conn.execute(
                "UPDATE findings SET status='dismissed', evidence=?, updated_at=? WHERE id=?",
                (evidence, stamp, finding_id),
            )
            return cursor.rowcount == 1

    def archive_finding(self, finding_id: str) -> bool:
        finding = self.get_finding(finding_id)
        if finding is None:
            return False
        validate_transition(finding["status"], "archived")
        stamp = now()
        with self.connect() as conn:
            cursor = conn.execute(
                "UPDATE findings SET status='archived', updated_at=? WHERE id=?",
                (stamp, finding_id),
            )
            return cursor.rowcount == 1

    def list_findings(self, *, status: str | None = None) -> list[dict]:
        with self.connect() as conn:
            if status:
                return [dict(row) for row in conn.execute(
                    "SELECT * FROM findings WHERE status=? ORDER BY updated_at DESC",
                    (status,),
                )]
            return [dict(row) for row in conn.execute("SELECT * FROM findings ORDER BY updated_at DESC")]

    def create_goal(self, title: str, description: str = "", session_id: str | None = None, run_id: str | None = None, stage_id: str | None = None) -> str:
        stamp = now()
        goal_id = "goal-" + hashlib.sha256(f"{title}:{stamp}".encode()).hexdigest()[:8]
        with self.connect() as conn:
            conn.execute("INSERT INTO goals VALUES (?,?,?,?,?,?,?,?,?)", (goal_id, title, description, "pending", session_id, run_id, stage_id, stamp, stamp))
        return goal_id

    def update_goal(self, goal_id: str, status: str) -> bool:
        if status not in {"pending", "in_progress", "completed", "blocked", "failed", "cancelled"}:
            raise ValueError(f"invalid goal status: {status}")
        with self.connect() as conn:
            cursor = conn.execute("UPDATE goals SET status=?, updated_at=? WHERE id=?", (status, now(), goal_id))
            return cursor.rowcount == 1

    def get_goal(self, goal_id: str) -> dict | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM goals WHERE id=?", (goal_id,)).fetchone()
            return dict(row) if row else None

    def remove_goal(self, goal_id: str) -> bool:
        with self.connect() as conn:
            cursor = conn.execute("DELETE FROM goals WHERE id=?", (goal_id,))
            return cursor.rowcount == 1

    def list_goals(self, status: str | None = None, run_id: str | None = None) -> list[dict]:
        clauses, values = [], []
        if status:
            clauses.append("status=?"); values.append(status)
        if run_id:
            clauses.append("run_id=?"); values.append(run_id)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self.connect() as conn:
            return [dict(row) for row in conn.execute(f"SELECT * FROM goals{where} ORDER BY created_at", values)]

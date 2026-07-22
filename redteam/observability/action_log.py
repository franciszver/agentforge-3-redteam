"""Per-agent action log: append-only structured event log
(docs/ARCHITECTURE.md §3(6): "Feeds the Orchestrator's decisions directly
... in addition to being a human-facing dashboard").

Backed by ``sqlite3`` -- the same tool as ``redteam.harness.db.ExploitDB``
(``contracts/README.md``'s "standard tool for the standard job" precedent
for stdlib modules) -- so it is queryable by agent, event type, category,
and time without loading a whole file into memory. There is deliberately no
update/delete API: only ``append`` and ``query``. That is what "append-only"
means here -- every directive stays traceable to the state that produced it
(ARCHITECTURE.md §3(3), the Orchestrator row), including from an agent that
later turns out to have been compromised or manipulated.

``export_jsonl`` writes every entry as JSON Lines to the path the
``observability_snapshot`` contract's ``action_log_ref`` field names, so
that reference always points at a real, re-readable file rather than a
dangling pointer into an in-memory or ``:memory:`` DB.
"""

from __future__ import annotations

import datetime as _dt
import json
import sqlite3
from pathlib import Path
from typing import Any, Mapping

SCHEMA_VERSION = 1

# The four agents named in docs/ARCHITECTURE.md §3, plus the two shared
# services (harness, observability itself) that also act and must be
# traceable -- not an arbitrary open string, so a typo'd agent name fails
# loudly at append time instead of silently fragmenting queries later.
ALLOWED_AGENTS = (
    "red_team",
    "judge",
    "orchestrator",
    "documentation",
    "harness",
    "observability",
)


class ActionLogError(ValueError):
    """An append was rejected (unknown agent, empty event_type), or the log
    is stamped with an unsupported schema_meta.version."""


def now_iso() -> str:
    """UTC timestamp in the same ``date-time`` shape ``redteam.harness.db``
    uses, so entries from both modules sort and compare identically."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    d["details"] = json.loads(d.pop("details_json") or "{}")
    return d


class ActionLog:
    """Versioned, queryable, append-only action log backed by sqlite3."""

    def __init__(self, path: str | Path = ":memory:"):
        self._conn = sqlite3.connect(str(path))
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS schema_meta (version INTEGER NOT NULL)")
        row = cur.execute("SELECT version FROM schema_meta").fetchone()
        if row is None:
            cur.execute("INSERT INTO schema_meta (version) VALUES (?)", (SCHEMA_VERSION,))
        elif row["version"] != SCHEMA_VERSION:
            raise ActionLogError(
                f"action log is stamped schema_meta.version={row['version']!r} but this "
                f"module is SCHEMA_VERSION={SCHEMA_VERSION!r}; migrate before opening this "
                "log with a different observability-module version."
            )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent TEXT NOT NULL,
                event_type TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                case_id TEXT,
                category TEXT,
                details_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "ActionLog":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def append(
        self,
        *,
        agent: str,
        event_type: str,
        occurred_at: str | None = None,
        case_id: str | None = None,
        category: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> int:
        if agent not in ALLOWED_AGENTS:
            raise ActionLogError(f"agent must be one of {ALLOWED_AGENTS}, got {agent!r}")
        if not event_type or not event_type.strip():
            raise ActionLogError("event_type must be a non-empty string")
        occurred_at = occurred_at or now_iso()
        cur = self._conn.execute(
            """
            INSERT INTO actions (agent, event_type, occurred_at, case_id, category, details_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (agent, event_type, occurred_at, case_id, category, json.dumps(dict(details or {}))),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def query(
        self,
        *,
        agent: str | None = None,
        event_type: str | None = None,
        category: str | None = None,
        since: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[str] = []
        if agent is not None:
            clauses.append("agent = ?")
            params.append(agent)
        if event_type is not None:
            clauses.append("event_type = ?")
            params.append(event_type)
        if category is not None:
            clauses.append("category = ?")
            params.append(category)
        if since is not None:
            clauses.append("occurred_at >= ?")
            params.append(since)
        sql = "SELECT * FROM actions"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY occurred_at, id"
        rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_dict(r) for r in rows]

    def export_jsonl(self, path: str | Path) -> Path:
        """Persist every entry as JSON Lines -- the file the contract's
        ``action_log_ref`` points at. Overwrites any existing file at
        ``path`` with the log's current full contents (the log itself, not
        the export, is the append-only system of record)."""
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as fh:
            for row in self.query():
                fh.write(json.dumps(row, sort_keys=True) + "\n")
        return out_path

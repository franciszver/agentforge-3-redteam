"""Pass/fail over versions: outcomes tracked across suite runs / target
versions (docs/ARCHITECTURE.md §3(6)).

A thin, sqlite-backed log of suite-run *summaries* -- one row per
``redteam.harness.replay.run_suite_replay`` / ``redteam.harness.suite.run_suite_live``
sweep, each tagged with the target version it ran against
(``docs/THREAT_MODEL.md``: target pinned ``v2.0.0``). Deliberately separate
from ``ExploitDB`` (which tracks *confirmed exploits*, individually) and
from the action log (which tracks *agent events*, individually) -- this is
the "did the picture change when the target version changed" system of
record, read by the Orchestrator to notice a regression or improvement tied
to a version bump rather than to a single exploit.
"""

from __future__ import annotations

import datetime as _dt
import sqlite3
from pathlib import Path
from typing import Sequence

from redteam.harness.replay import ReplayAttempt

SCHEMA_VERSION = 1


class SuiteRunLogError(ValueError):
    """The log is stamped with an unsupported schema_meta.version."""


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SuiteRunLog:
    """Versioned, queryable log of suite-run pass/fail summaries by target
    version, backed by sqlite3."""

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
            raise SuiteRunLogError(
                f"suite run log is stamped schema_meta.version={row['version']!r} but this "
                f"module is SCHEMA_VERSION={SCHEMA_VERSION!r}."
            )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS runs (
                run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_version TEXT NOT NULL,
                run_at TEXT NOT NULL,
                total_attempts INTEGER NOT NULL,
                vulnerable_count INTEGER NOT NULL,
                clean_count INTEGER NOT NULL
            )
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SuiteRunLog":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def record_run(
        self,
        attempts: Sequence[ReplayAttempt],
        target_version: str,
        *,
        run_at: str | None = None,
    ) -> int:
        run_at = run_at or now_iso()
        total = len(attempts)
        vulnerable = sum(1 for a in attempts if a.result.vulnerable)
        cur = self._conn.execute(
            """
            INSERT INTO runs (target_version, run_at, total_attempts, vulnerable_count, clean_count)
            VALUES (?, ?, ?, ?, ?)
            """,
            (target_version, run_at, total, vulnerable, total - vulnerable),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def by_version(self) -> list[dict]:
        """Every recorded run, oldest first -- the raw pass/fail-over-versions
        series (group by ``target_version`` at the call site as needed)."""
        rows = self._conn.execute("SELECT * FROM runs ORDER BY run_at, run_id").fetchall()
        return [dict(r) for r in rows]

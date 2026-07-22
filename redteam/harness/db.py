"""Exploit DB: versioned, queryable store of confirmed exploits.

Storage: stdlib ``sqlite3`` (the only new "dependency" is a stdlib module --
see ``contracts/README.md``'s "standard tool for the standard job"
precedent for ``jsonschema``/``pytest``). sqlite3 gives real SQL querying
by category, status, and version for free, which a flat JSON file would
not, without adding anything to ``requirements-contracts.txt``.

Every write goes through a pre-write data-quality gate, in order, BEFORE
anything touches the database (docs/ARCHITECTURE.md's Documentation Agent
row: "data-quality constraints validated pre-write"):

  1. **Per-record shape**: ``contracts/v1/exploit_record.schema.json`` via
     ``jsonschema`` -- the exact schema ``tests/contracts`` validates
     against, not a reimplementation of it.
  2. **Cross-record uniqueness**: ``contracts/v1/uniqueness.py``'s
     ``find_duplicate_exploit_ids`` / ``find_duplicate_attack_sequences``,
     run against *all existing records plus the candidate*, so a duplicate
     ``exploit_id`` or a duplicate ``(case_id, attempt_id)`` attack
     sequence is rejected before the ``INSERT``, not caught after.

``status`` (``open`` / ``fixed`` / ``mitigated``) is harness-local state
layered ON TOP of the exploit_record contract, not part of it:
``exploit_record.schema.json`` is ``additionalProperties: false`` and has
no ``status`` field, so the fix/reappear state machine the regression
harness needs (``ExploitDB.set_status``) lives in this module's own
``exploits.status`` column instead of smuggling an extra key into the
contract payload. This is deliberate: it lets a "fix" be modeled as an
explicit, testable DB state transition (mark fixed, replay the same
evidence, confirm reappearance is caught) without ever writing a record
that would fail ``exploit_record.schema.json`` validation against a
strict consumer.

## DB migration strategy

``schema_meta.version`` is an integer, independent of the JSON contract's
own ``"schema_version": "1.0.0"`` string, and is checked on every
``ExploitDB(...)`` open. This module ships ``SCHEMA_VERSION = 1``.

- **Additive** change (new nullable column, new index): does not bump
  ``SCHEMA_VERSION``; add the column with ``ALTER TABLE ... ADD COLUMN``
  guarded by ``IF NOT EXISTS``-style existence checks in ``_init_schema``.
- **Breaking** change (column removed/renamed/retyped, a new NOT NULL
  column with no default): bump ``SCHEMA_VERSION`` and add a
  ``_migrate_<n>_to_<n+1>(conn)`` function that transforms the existing
  table in place, called from ``_init_schema`` when an older
  ``schema_meta.version`` is found. Old DBs keep working through the
  migration path instead of being silently misread or dropped --
  mirroring ``contracts/README.md``'s v1/v2 rule (old consumers keep
  working until migrated, nothing is mutated out from under them).
  Opening a DB stamped with a *newer* version than this module supports
  raises ``ExploitDBError`` rather than guessing at a downgrade.

See ``redteam/harness/README.md`` for the worked example.
"""

from __future__ import annotations

import datetime as _dt
import json
import sqlite3
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from contracts.v1.uniqueness import find_duplicate_attack_sequences, find_duplicate_exploit_ids

SCHEMA_VERSION = 1

_REPO_ROOT = Path(__file__).resolve().parents[2]
_EXPLOIT_RECORD_SCHEMA_PATH = _REPO_ROOT / "contracts" / "v1" / "exploit_record.schema.json"

STATUSES = ("open", "fixed", "mitigated")


class ExploitDBError(ValueError):
    """A write was rejected pre-write (schema-invalid, duplicate, or a bad
    status transition), or the DB's schema_meta.version is unsupported."""


def _load_exploit_record_schema() -> dict[str, Any]:
    with _EXPLOIT_RECORD_SCHEMA_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def now_iso() -> str:
    """UTC timestamp in the ``date-time`` shape the contracts use
    (``confirmed_at``, ``detected_at``, ...). Shared by ``regression.py``
    so there is one clock-formatting implementation, not two that could
    drift apart."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    d["record"] = json.loads(d.pop("record_json"))
    return d


class ExploitDB:
    """Versioned, queryable exploit DB backed by sqlite3."""

    def __init__(self, path: str | Path = ":memory:", *, schema: Mapping[str, Any] | None = None):
        self._conn = sqlite3.connect(str(path))
        self._conn.row_factory = sqlite3.Row
        self._schema = dict(schema) if schema is not None else _load_exploit_record_schema()
        self._validator = Draft202012Validator(self._schema)
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS schema_meta (version INTEGER NOT NULL)")
        row = cur.execute("SELECT version FROM schema_meta").fetchone()
        if row is None:
            cur.execute("INSERT INTO schema_meta (version) VALUES (?)", (SCHEMA_VERSION,))
        elif row["version"] != SCHEMA_VERSION:
            raise ExploitDBError(
                f"exploit DB is stamped schema_meta.version={row['version']!r} but this "
                f"harness module is SCHEMA_VERSION={SCHEMA_VERSION!r}; see "
                "redteam/harness/README.md for the migration procedure before opening "
                "this DB with a different harness version."
            )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS exploits (
                exploit_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL,
                verdict_id TEXT NOT NULL,
                category TEXT NOT NULL,
                source TEXT NOT NULL,
                confirmed_at TEXT NOT NULL,
                recording_ref TEXT NOT NULL,
                record_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                status_updated_at TEXT
            )
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "ExploitDB":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- writes -----------------------------------------------------------

    def all_records(self) -> list[dict[str, Any]]:
        """The raw, contract-shaped exploit_record payloads (no DB status)."""
        cur = self._conn.execute("SELECT record_json FROM exploits")
        return [json.loads(r["record_json"]) for r in cur.fetchall()]

    def add_record(self, record: Mapping[str, Any]) -> None:
        record = dict(record)

        errors = sorted(self._validator.iter_errors(record), key=lambda e: list(e.path))
        if errors:
            messages = "; ".join(f"{list(e.path)}: {e.message}" for e in errors)
            raise ExploitDBError(f"exploit_record failed schema validation: {messages}")

        combined = self.all_records() + [record]
        dup_ids = find_duplicate_exploit_ids(combined)
        if dup_ids:
            raise ExploitDBError(f"duplicate exploit_id rejected pre-write: {dup_ids}")
        dup_seqs = find_duplicate_attack_sequences(combined)
        if dup_seqs:
            raise ExploitDBError(f"duplicate attack-sequence rejected pre-write: {dup_seqs}")

        self._conn.execute(
            """
            INSERT INTO exploits
                (exploit_id, case_id, attempt_id, verdict_id, category, source,
                 confirmed_at, recording_ref, record_json, status, status_updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
            """,
            (
                record["exploit_id"],
                record["case_id"],
                record["attempt_id"],
                record["verdict_id"],
                record["category"],
                record["source"],
                record["confirmed_at"],
                record["recording_ref"],
                json.dumps(record),
                record["confirmed_at"],
            ),
        )
        self._conn.commit()

    def set_status(self, exploit_id: str, status: str, *, updated_at: str | None = None) -> None:
        if status not in STATUSES:
            raise ExploitDBError(f"status must be one of {STATUSES}, got {status!r}")
        if self.get(exploit_id) is None:
            raise ExploitDBError(f"no exploit record {exploit_id!r} to update")
        self._conn.execute(
            "UPDATE exploits SET status = ?, status_updated_at = ? WHERE exploit_id = ?",
            (status, updated_at or now_iso(), exploit_id),
        )
        self._conn.commit()

    # -- reads --------------------------------------------------------------

    def get(self, exploit_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM exploits WHERE exploit_id = ?", (exploit_id,)
        ).fetchone()
        return _row_to_dict(row) if row is not None else None

    def query(
        self,
        *,
        category: str | None = None,
        status: str | None = None,
        schema_version: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[str] = []
        if category is not None:
            clauses.append("category = ?")
            params.append(category)
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        sql = "SELECT * FROM exploits"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY confirmed_at"
        rows = self._conn.execute(sql, params).fetchall()
        results = [_row_to_dict(r) for r in rows]
        if schema_version is not None:
            results = [r for r in results if r["record"]["schema_version"] == schema_version]
        return results

    def next_exploit_id(self) -> str:
        """Next unused ``EXP-NNNN`` id, pattern-valid per exploit_record.schema.json."""
        rows = self._conn.execute("SELECT exploit_id FROM exploits").fetchall()
        max_n = 0
        for r in rows:
            try:
                max_n = max(max_n, int(str(r["exploit_id"]).split("-", 1)[1]))
            except (IndexError, ValueError):
                continue
        return f"EXP-{max_n + 1:04d}"

# Regression & Validation Harness (P3.10, issue #11)

A versioned, queryable exploit DB, a deterministic replay-mode suite
re-runner, a bounded live-mode suite runner, and a regression detector that
emits `contracts/v1/errors/regression_detected.schema.json`.

| Module | Responsibility |
|---|---|
| `db.py` | `ExploitDB` — sqlite3-backed exploit store. Pre-write schema + cross-record uniqueness gate on every `add_record`. Query by `category`, `status`, `schema_version`. |
| `replay.py` | `run_suite_replay` / `replay_case` — deterministic, reads `evals/recordings/*` only, applies each case's own `detect` predicate. No live target/model call. Used by every test in `tests/redteam/`. |
| `suite.py` | `run_suite_live` / `run_case_live` — drives the real target via `evals.runner`, bounded by each case's `max_draws`. Documented, not exercised by the test suite (no target/GPU in CI-less local test runs). |
| `regression.py` | `run_regression_sweep` — diffs a suite run against `ExploitDB` state to detect reappearance and cross-category regressions. |

Full detection-shape rationale lives in `regression.py`'s module docstring;
full DB migration-strategy rationale lives in `db.py`'s module docstring.
Summary of the migration rule, since it's the one asked for by name in the
issue's Done-when:

- `ExploitDB` stamps every DB with an integer `schema_meta.version`
  (currently `1`), independent of the JSON contract's own
  `"schema_version": "1.0.0"` string on each record.
- **Additive** changes (new nullable column) do not bump the version.
- **Breaking** changes (column removed/renamed/retyped) bump
  `SCHEMA_VERSION` and add a `_migrate_<n>_to_<n+1>` step run from
  `_init_schema` — old data is transformed forward, never silently
  dropped or misread, mirroring `contracts/README.md`'s v1/v2 rule.
- Opening a DB stamped with a version this module doesn't recognize raises
  `ExploitDBError` immediately (`tests/redteam/test_exploit_db.py::test_schema_version_mismatch_raises_on_open`)
  rather than reading rows under the wrong assumptions.

## Why sqlite3, not a flat JSON file

The issue asks for a **queryable** exploit DB (by category, status,
version). `sqlite3` is stdlib — zero new dependency, consistent with this
repo's dependency-light thesis (`contracts/README.md`) — and gives real
`WHERE`-clause querying instead of hand-rolled JSON-file filtering.

## Status is harness state, not contract state

`exploit_record.schema.json` is `additionalProperties: false` with no
`status` field. `open` / `fixed` / `mitigated` lives only in this module's
`exploits.status` column, set via `ExploitDB.set_status`. That's what lets
a "fix" be modeled as an explicit, testable DB transition without ever
writing a record that would fail strict schema validation for a consumer
outside the harness.

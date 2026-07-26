# Inter-agent contracts (P3.12, issue #13)

Versioned request/response schemas and typed error contracts for every edge
in `docs/ARCHITECTURE.md` §2's interaction diagram. This directory is the
single source of truth for message shape between the Red Team Agent, Judge
Agent, Orchestrator Agent, Documentation Agent, the Regression & Validation
Harness, and the Observability Layer — none of those (P3.6+) may invent an
ad hoc payload shape once this contract exists for their edge.

## Versioning rule

- Everything currently shipped lives under `v1/`.
- **Additive/optional changes** (a new optional property, a new enum value
  that doesn't change existing consumers' behavior, a new schema for a new
  edge) stay in `v1/` — bump nothing, note the change in this file's log
  below.
- **Breaking changes** (removing/renaming a required property, narrowing a
  type, changing an enum's existing meaning, tightening a pattern that
  would reject previously-valid messages) get a new `v2/` directory that is
  a full copy-then-edit of `v1/`, plus a migration note in this file (what
  changed, why, which consumers must update). `v1/` is not deleted or
  mutated by a `v2/` bump — old recordings and old consumers keep working
  against it until they're migrated.
- Every schema file carries `schema_version` as a `const` in its own body
  (currently `"1.0.0"`) so a message is self-describing even outside its
  directory context.

No `v2/` exists yet; nothing has broken compatibility since this issue's
initial cut.

**Log:**

- Issue #63: `observability_snapshot.schema.json` gained an optional
  `pending_human_triage_count` property (durable count of reports still
  awaiting human triage). Not added to `required`, so a pre-#63 PRODUCER
  that omits the field stays schema-valid — additive, stays `v1`. **This
  is one-directional, not a blanket "consumers stay valid" claim**: this
  schema's `additionalProperties: false` (unchanged) means a pre-#63
  CONSUMER validating an incoming snapshot against its OWN pinned copy of
  this schema will reject any snapshot that now carries the new field. A
  consumer must update its own copy of the schema (or relax
  `additionalProperties`) before it can accept a post-#63 producer's
  output — see the field's own `description` in the schema for the
  cross-reference to `--list-pending`'s differently-scoped same-named key.

## Schemas (one per edge in ARCHITECTURE.md §2)

| Schema | Edge | Notes |
|---|---|---|
| `v1/attack_directive.schema.json` | Orchestrator → Red Team Agent | category, budget (`max_draws` capped at 3, matching `evals.schema.MAX_LIVE_DRAWS`), next-case selector |
| `v1/attack_attempt.schema.json` | Red Team Agent → target / Judge Agent | field names deliberately align with `evals.schema.AttackCase` (`category`, `patient_id`, `message`) — this is the same probe shape, not a parallel definition |
| `v1/judge_verdict.schema.json` | Judge Agent → Orchestrator | `outcome` enum `success/fail/partial/regression`; `drift_check` carries the §6 gold-set agreement-rate signal |
| `v1/exploit_record.schema.json` | Judge / Regression Harness → Documentation Agent | confirmed exploit, minimal repro, recording reference |
| `v1/vuln_report.schema.json` | Documentation Agent → human approval gate | `severity: critical` forces `requires_human_gate: true` via an `if/then` — nothing critical self-publishes |
| `v1/observability_snapshot.schema.json` | Observability Layer → Orchestrator | coverage fraction for all six THREAT_MODEL categories (all six required, so a missing category can't silently read as zero), open-high-sev count, cost + cost-scaling rate |

## Typed errors (`v1/errors/`)

Each error schema pins `error_type` to a stable `const` so a consumer can
dispatch on it without inspecting the rest of the shape, plus the
structured fields that error needs to be actionable (not just a string):

| `error_type` | Raised by → to | Structured fields |
|---|---|---|
| `target_unreachable` | Red Team Agent → Orchestrator | `target_url`, `attempted_at`, `retry_count` |
| `budget_exceeded` | Red Team Agent / Regression Harness → Orchestrator | `directive_id`, `category`, `requested_draws`, `budget_max_draws` |
| `judge_timeout` | Judge Agent → Orchestrator | `attempt_id`, `case_id`, `timeout_seconds` |
| `no_findings_in_window` | Observability Layer → Orchestrator | `category`, `window_start`, `window_end`, `draws_attempted` |
| `regression_detected` | Regression Harness → Orchestrator | `exploit_id`, `category`, `previous_status`, `detected_at` |

## Exploit-DB data-quality constraints

Per-record constraints are expressed directly in
`v1/exploit_record.schema.json`: `exploit_id` is a required, pattern-constrained
primary key (`^EXP-[0-9]{4,}$`), `minimal_repro.steps` is a non-empty array
(`minItems: 1`), and every field an engineer needs to reproduce the finding
without platform context is `required`.

**Cross-record** constraints — unique `exploit_id` across the whole DB, no
duplicate attack-sequence entries (the same `case_id` + `attempt_id`
confirmed as two different exploits) — are **not** expressible in JSON
Schema 2020-12: `uniqueItems` only rejects two array entries that are
byte-for-byte identical objects, not two objects that merely share one key.
`v1/uniqueness.py` is the single stdlib implementation of that rule
(`find_duplicate_exploit_ids`, `find_duplicate_attack_sequences`); both the
Regression Harness (P3.8+) and `tests/contracts/test_uniqueness.py` import
it, so the constraint has exactly one implementation, not a schema copy and
a harness copy that can drift apart.

## Tech choice: `jsonschema`, not a stdlib validator

`jsonschema` (pinned `4.26.0`, `requirements-contracts.txt`) is used to
validate contract-test examples against the schemas — the canonical,
spec-conformant Python implementation of JSON Schema draft 2020-12
(`if`/`then`, `format`, nested `additionalProperties: false`, etc.). A
hand-rolled stdlib validator covering that surface would be a worse,
less-trustworthy reimplementation of exactly the thing `jsonschema` is
for, for a project whose thesis is dependency-light rather than
dependency-zero — `evals/` already pulls in `pytest`, a real dependency,
for the same reason: use the standard tool for the standard job instead of
reinventing it, and keep the dependency list short and pinned. This is the
**only** consumer of `jsonschema`; nothing else in the repo (`evals/`,
`tools/`) needs it, so it is kept in its own `requirements-contracts.txt`
rather than a repo-wide requirements file.

## Contract tests (`tests/contracts/`)

One valid example + one invalid example per schema
(`tests/contracts/examples/<contract>/{valid,invalid}.json`), loaded and
validated by `tests/contracts/test_<contract>.py`. Invalid examples are
constructed to fail for a real, specific reason (missing required field,
bad enum value, pattern violation, `if/then` conditional violation,
duplicate `uniqueItems` entry) — not just "any wrong JSON" — so a passing
suite is evidence the schema actually constrains, not just that it parses.
`test_uniqueness.py` covers the cross-record exploit-DB constraints
separately, since those live in `v1/uniqueness.py` rather than a schema
file.

```bash
pip install -r requirements-contracts.txt
python -m pytest tests/contracts -q
```

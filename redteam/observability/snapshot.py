"""``emit_snapshot()``: the Observability Layer -> Orchestrator edge
(docs/ARCHITECTURE.md §2, ``contracts/v1/observability_snapshot.schema.json``).

Produces exactly the contract-shaped dict -- ``schema_version``,
``snapshot_id``, ``generated_at``, ``coverage_by_category`` (fractions),
``open_high_sev_count``, ``pending_human_triage_count`` (issue #63, additive
v1 field -- ``redteam.observability.findings.pending_human_triage_count``),
``cost``, ``action_log_ref`` -- consumed
programmatically by the Orchestrator (P3.8) to decide what the Red Team
attacks next and when to throttle draws, not rendered only for a human.
The contract is deliberately narrow (``additionalProperties: false``), so
this function is deliberately narrow too: richer detail (probes_run /
exploits_found / last_run_status per category, pass/fail-by-version,
resilience trend, open/in-progress/resolved counts) stays available from
this package's other query functions (``coverage.compute_coverage``,
``runs.SuiteRunLog.by_version``, ``trend.resilience_trend``,
``findings.status_counts``) rather than being crammed into the wire shape.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence

from evals.schema import AttackCase

from redteam.harness.db import ExploitDB, now_iso
from redteam.harness.replay import RECORDINGS_DIR

from .action_log import ActionLog
from .coverage import compute_coverage, coverage_fractions
from .cost import compute_cost
from .findings import open_high_sev_count, pending_human_triage_count

SCHEMA_VERSION = "1.0.0"


def new_snapshot_id() -> str:
    """A fresh ``obs-<uuid4>`` id, pattern-valid per
    ``observability_snapshot.schema.json`` (``^obs-[0-9a-fA-F-]+$``)."""
    return f"obs-{uuid.uuid4()}"


def emit_snapshot(
    db: ExploitDB,
    cases: Sequence[AttackCase],
    action_log: ActionLog,
    action_log_ref: str,
    *,
    recordings_dir: Path = RECORDINGS_DIR,
    vuln_reports: Sequence[Mapping[str, Any]] = (),
    generated_at: str | None = None,
    snapshot_id: str | None = None,
) -> dict[str, Any]:
    """Aggregate current platform state into one
    ``observability_snapshot``-shaped dict.

    ``action_log`` is exported to ``action_log_ref`` (JSON Lines) as part of
    emitting the snapshot, so the reference the Orchestrator receives always
    points at a real, re-readable file rather than a dangling pointer into
    an in-memory log.
    """
    coverage = compute_coverage(db, cases, recordings_dir=recordings_dir)
    cost = compute_cost(cases, recordings_dir=recordings_dir)
    action_log.export_jsonl(action_log_ref)

    return {
        "schema_version": SCHEMA_VERSION,
        "snapshot_id": snapshot_id or new_snapshot_id(),
        "generated_at": generated_at or now_iso(),
        "coverage_by_category": coverage_fractions(coverage),
        "open_high_sev_count": open_high_sev_count(db, vuln_reports),
        "pending_human_triage_count": pending_human_triage_count(vuln_reports),
        "cost": cost.as_contract_cost(),
        "action_log_ref": str(action_log_ref),
    }

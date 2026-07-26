"""Observability Layer (docs/ARCHITECTURE.md §3(6)) -- shared infrastructure,
not an agent. Aggregates the exploit DB (``redteam.harness.db.ExploitDB``),
the replay-mode suite runner (``redteam.harness.replay``), and its own
append-only action log into the six answers the Orchestrator (P3.8) reads
programmatically:

1. coverage by category      -- ``coverage.compute_coverage``
2. pass/fail over versions   -- ``runs.SuiteRunLog``
3. resilience trend          -- ``trend.resilience_trend``
4. open/in-progress/resolved -- ``findings.status_counts``
5. cost + cost-scaling rate  -- ``cost.compute_cost`` (a **local-compute
   proxy** -- wall-clock seconds between recorded draws, NOT dollars; see
   ``cost.py``'s module docstring)
6. per-agent action log      -- ``action_log.ActionLog``

``snapshot.emit_snapshot()`` is the seventh answer: it produces exactly the
``contracts/v1/observability_snapshot.schema.json``-shaped dict the
Orchestrator consumes -- deliberately narrower than the six functions above
(the contract is ``additionalProperties: false``), so the richer detail
stays available from this package's other functions rather than crammed
into the wire shape.
"""

from __future__ import annotations

from .action_log import ActionLog, ActionLogError
from .coverage import CategoryCoverage, compute_coverage, coverage_fractions
from .cost import CostSummary, compute_cost, draw_gap_seconds
from .findings import HIGH_SEVERITIES, open_high_sev_count, pending_human_triage_count, status_counts
from .runs import SuiteRunLog, SuiteRunLogError
from .snapshot import SCHEMA_VERSION, emit_snapshot, new_snapshot_id
from .trend import TRENDS, resilience_trend

__all__ = [
    "ActionLog",
    "ActionLogError",
    "CategoryCoverage",
    "compute_coverage",
    "coverage_fractions",
    "CostSummary",
    "compute_cost",
    "draw_gap_seconds",
    "HIGH_SEVERITIES",
    "open_high_sev_count",
    "pending_human_triage_count",
    "status_counts",
    "SuiteRunLog",
    "SuiteRunLogError",
    "SCHEMA_VERSION",
    "emit_snapshot",
    "new_snapshot_id",
    "TRENDS",
    "resilience_trend",
]

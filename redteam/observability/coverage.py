"""Coverage by category (docs/ARCHITECTURE.md §3(6), docs/THREAT_MODEL.md §2).

For each of the six THREAT_MODEL categories: probes run (replayed attempts
via ``redteam.harness.replay.run_suite_replay`` -- deterministic, no live
target call, per the P3.10/P3.11 briefs), exploits found
(``ExploitDB.query(category=...)``), and last-run status.

``coverage_by_category``'s fractions (the strict contract shape,
``coverage_fractions`` below) are ``min(1.0, probes_run / COVERAGE_TARGET_DRAWS)``.
``COVERAGE_TARGET_DRAWS`` mirrors ``evals.schema.MAX_LIVE_DRAWS`` -- one case
fully drawn counts as 100% coverage for that category at this pass's suite
size (one case per covered category so far; see ``evals/cases/``). This is
a documented placeholder heuristic tied to the current suite's shape, not a
statistical-sufficiency claim -- it should be revisited (denominator
widened) as more cases per category land, tracked on the board rather than
in this issue.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from evals.schema import ALLOWED_CATEGORIES, MAX_LIVE_DRAWS, AttackCase

from redteam.harness.db import ExploitDB
from redteam.harness.replay import RECORDINGS_DIR, run_suite_replay

COVERAGE_TARGET_DRAWS = MAX_LIVE_DRAWS

NOT_RUN = "not_run"
CLEAN = "clean"
VULNERABLE_CONFIRMED = "vulnerable_confirmed"


@dataclass(frozen=True)
class CategoryCoverage:
    category: str
    probes_run: int
    exploits_found: int
    last_run_status: str  # NOT_RUN | CLEAN | VULNERABLE_CONFIRMED
    coverage_fraction: float


def compute_coverage(
    db: ExploitDB,
    cases: Sequence[AttackCase],
    recordings_dir: Path = RECORDINGS_DIR,
) -> dict[str, CategoryCoverage]:
    """One ``CategoryCoverage`` for every one of the six THREAT_MODEL
    categories, always -- a category with zero cases/recordings still gets
    an explicit ``not_run`` / 0-probe entry rather than being absent, so a
    missing category can never silently read as covered."""
    attempts = run_suite_replay(cases, recordings_dir=recordings_dir)
    attempts_by_category: dict[str, list] = {cat: [] for cat in ALLOWED_CATEGORIES}
    for attempt in attempts:
        attempts_by_category.setdefault(attempt.category, []).append(attempt)

    result: dict[str, CategoryCoverage] = {}
    for category in ALLOWED_CATEGORIES:
        cat_attempts = attempts_by_category.get(category, [])
        probes_run = len(cat_attempts)
        exploits_found = len(db.query(category=category))

        if probes_run == 0:
            last_run_status = NOT_RUN
        elif any(a.result.vulnerable for a in cat_attempts):
            last_run_status = VULNERABLE_CONFIRMED
        else:
            last_run_status = CLEAN

        fraction = min(1.0, probes_run / COVERAGE_TARGET_DRAWS) if COVERAGE_TARGET_DRAWS else 0.0

        result[category] = CategoryCoverage(
            category=category,
            probes_run=probes_run,
            exploits_found=exploits_found,
            last_run_status=last_run_status,
            coverage_fraction=fraction,
        )
    return result


def coverage_fractions(coverage: dict[str, CategoryCoverage]) -> dict[str, float]:
    """The strict ``coverage_by_category`` shape
    ``contracts/v1/observability_snapshot.schema.json`` requires: fractions
    only, all six categories, nothing else."""
    return {category: detail.coverage_fraction for category, detail in coverage.items()}

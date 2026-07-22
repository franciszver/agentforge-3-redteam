"""Local-compute cost proxy -- **NOT dollars**.

``docs/ARCHITECTURE.md`` §4 locks the platform to local-only models for
every role; there is no per-token dollar cost to track. "Cost" here means
wall-clock seconds of local (GPU/CPU) compute spent per attack draw,
harvested from timestamps ``evals.runner.record_run`` already stamps on
every recorded draw (``recorded_at_utc``) -- real, measured elapsed time
between a case's consecutive recorded draws, not a live call and not a
synthetic guess. A case with 0 or 1 recorded draws contributes no gap (there
is nothing to measure a delta against yet).

The ``observability_snapshot`` contract's ``cost.total_usd`` /
``cost.cost_scaling_rate`` field names are inherited verbatim from the
already-merged P3.12 contract (``contracts/v1/observability_snapshot.schema.json``);
this module populates them with the compute-seconds figures below and
documents the substitution at every call site rather than silently reusing
a dollar-shaped name for a non-dollar quantity. ``cost_scaling_rate`` is the
mean marginal compute-seconds per additional draw, matching the contract's
own field description ("marginal cost per additional draw/hour, read by the
Orchestrator to throttle against the target's ~0.15 req/s ceiling") --
i.e. a rising rate is a direct throttling signal, independent of whether a
given draw also happened to confirm a new finding.

If a future harness pass adds token counts to recordings, a
``token_count``-based proxy can be added alongside this one without a
contract change (``cost`` is already an object, not a single scalar) --
deliberately not built speculatively here.
"""

from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from evals.schema import AttackCase

from redteam.harness.replay import RECORDINGS_DIR

_TS_FORMAT = "%Y%m%dT%H%M%SZ"


def _parse_ts(raw: str) -> _dt.datetime:
    return _dt.datetime.strptime(raw, _TS_FORMAT).replace(tzinfo=_dt.timezone.utc)


def draw_gap_seconds(cases: Sequence[AttackCase], recordings_dir: Path = RECORDINGS_DIR) -> list[float]:
    """Wall-clock seconds between each case's consecutive recorded draws,
    across every case, in no particular cross-case order. Empty when no
    case has 2+ recorded draws yet."""
    gaps: list[float] = []
    for case in cases:
        case_dir = recordings_dir / case.id
        if not case_dir.is_dir():
            continue
        timestamps: list[_dt.datetime] = []
        for path in sorted(case_dir.glob("*.json")):
            payload = json.loads(path.read_text(encoding="utf-8"))
            raw_ts = payload.get("recorded_at_utc")
            if raw_ts:
                timestamps.append(_parse_ts(raw_ts))
        timestamps.sort()
        for earlier, later in zip(timestamps, timestamps[1:]):
            gaps.append((later - earlier).total_seconds())
    return gaps


@dataclass(frozen=True)
class CostSummary:
    """A local-compute cost proxy -- see module docstring. Never dollars."""

    total_compute_seconds: float
    draw_gap_count: int
    cost_scaling_rate: float  # mean marginal compute-seconds per additional draw

    def as_contract_cost(self) -> dict[str, float]:
        """Shape for ``observability_snapshot``'s ``cost`` object.
        ``total_usd`` is populated with ``total_compute_seconds`` -- a
        compute-time proxy, NOT dollars; see this module's docstring."""
        return {
            "total_usd": round(self.total_compute_seconds, 3),
            "cost_scaling_rate": round(self.cost_scaling_rate, 3),
        }


def compute_cost(cases: Sequence[AttackCase], recordings_dir: Path = RECORDINGS_DIR) -> CostSummary:
    gaps = draw_gap_seconds(cases, recordings_dir=recordings_dir)
    total = sum(gaps)
    gap_count = len(gaps)
    rate = (total / gap_count) if gap_count else 0.0
    return CostSummary(total_compute_seconds=total, draw_gap_count=gap_count, cost_scaling_rate=rate)

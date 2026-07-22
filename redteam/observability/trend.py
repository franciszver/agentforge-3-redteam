"""Resilience trend: improving / regressing / stable / insufficient_data.

A documented heuristic, not a statistical claim, over
``redteam.harness.db.ExploitDB`` state plus the most recent
``redteam.harness.regression.run_regression_sweep`` output:

- **insufficient_data** -- the exploit DB has zero records; no direction can
  be claimed from zero evidence.
- **regressing** -- the latest regression sweep surfaced ANY
  ``regression_detected``-shaped finding (a reappearance of a
  previously-``fixed``/``mitigated`` exploit, or a newly-discovered
  cross-category regression). Either shape is a resilience decrease by
  definition, so this check wins outright regardless of the counts below.
- **improving** -- no regression this sweep, and resolved
  (``fixed``/``mitigated``) exploits outnumber currently-``open`` ones.
- **stable** -- no regression this sweep, and resolved exploits do not yet
  outnumber open ones (includes the all-``open``, nothing-fixed-yet case).
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from redteam.harness.db import ExploitDB

INSUFFICIENT_DATA = "insufficient_data"
REGRESSING = "regressing"
IMPROVING = "improving"
STABLE = "stable"

TRENDS = (IMPROVING, REGRESSING, STABLE, INSUFFICIENT_DATA)


def resilience_trend(db: ExploitDB, regressions: Sequence[Mapping[str, Any]] = ()) -> str:
    open_n = len(db.query(status="open"))
    fixed_n = len(db.query(status="fixed"))
    mitigated_n = len(db.query(status="mitigated"))

    if open_n + fixed_n + mitigated_n == 0:
        return INSUFFICIENT_DATA

    if any(r.get("error_type") == "regression_detected" for r in regressions):
        return REGRESSING

    resolved_n = fixed_n + mitigated_n
    return IMPROVING if resolved_n > open_n else STABLE

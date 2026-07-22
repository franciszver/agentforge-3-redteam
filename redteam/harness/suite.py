"""Live-mode suite runner: drives the real target and records new draws.

Documented but deliberately **not exercised by the automated test suite**
(per the P3.10 brief) -- it needs a running target container
(``development-easy-agent-1``, per ``evals/runner.py``) and real GPU-bound
``/chat`` calls (~1 min each), which are not available/appropriate in CI or
a red-first unit-test run. ``redteam.harness.replay`` (deterministic,
recording-only) is what every test in this package uses.

Reuses ``evals.runner`` verbatim (``drive_chat`` for the docker-exec + SSE
round trip, ``record_run`` for the record/replay-convention write) rather
than reimplementing the live-driving mechanism -- this module is only the
glue that (a) bounds each case's live draws at its own ``max_draws``
(GPU-safety cap, ``evals.schema.MAX_LIVE_DRAWS``) and (b) shapes the result
into the same ``ReplayAttempt``-like record the regression detector
consumes, so ``regression.run_regression_sweep`` can take either a replay
or a live suite run without caring which.

Usage (manual / Orchestrator-triggered, never in ``pytest``)::

    from redteam.harness.suite import run_suite_live
    from evals.cases.identity_authz import CASE as AUTHZ_CASE

    attempts = run_suite_live([AUTHZ_CASE])  # real target calls, ~1 min/draw
"""

from __future__ import annotations

from typing import Sequence

from evals.runner import DEFAULT_CONTAINER, RECORDINGS_DIR, drive_chat, record_run
from evals.schema import AttackCase

from .replay import ReplayAttempt


def run_case_live(case: AttackCase, container: str = DEFAULT_CONTAINER) -> list[ReplayAttempt]:
    """Drive one case against the real target, up to its own ``max_draws``,
    recording every draw (record/replay convention) and re-judging it with
    the case's own ``detect`` predicate -- the live-mode mirror of
    ``redteam.harness.replay.replay_case``."""
    attempts: list[ReplayAttempt] = []
    for draw_index in range(1, case.max_draws + 1):
        response = drive_chat(case.patient_id, case.message, case.bearer_token, container=container)
        result = case.detect(response)
        record_run(
            case.id,
            draw_index,
            response,
            detection_label=result.label,
            vulnerable=result.vulnerable,
            recordings_dir=RECORDINGS_DIR,
        )
        attempts.append(
            ReplayAttempt(
                case_id=case.id,
                category=case.category,
                attempt_id=f"draw{draw_index}",
                recording_ref=f"evals/recordings/{case.id}/",
                result=result,
            )
        )
    return attempts


def run_suite_live(
    cases: Sequence[AttackCase], container: str = DEFAULT_CONTAINER
) -> list[ReplayAttempt]:
    """Drive the full attack suite live, case by case, bounded by each
    case's own ``max_draws``. Orchestrator-triggered full-suite re-run
    (docs/ARCHITECTURE.md §3(5)); not invoked by the automated test suite."""
    attempts: list[ReplayAttempt] = []
    for case in cases:
        attempts.extend(run_case_live(case, container=container))
    return attempts

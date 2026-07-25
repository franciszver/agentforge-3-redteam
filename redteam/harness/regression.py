"""Regression detection: reappearance + cross-category regression.

Runs a suite (replay mode by default -- deterministic, ``evals/recordings/*``
only, see ``redteam.harness.replay``) and diffs the outcome against the
exploit DB's current state to find two regression shapes, both emitted as
``contracts/v1/errors/regression_detected.schema.json``-shaped dicts
(Regression Harness -> Orchestrator edge, ``docs/ARCHITECTURE.md`` §2):

1. **Reappearance.** An exploit_id previously confirmed and then marked
   ``fixed``/``mitigated`` (``ExploitDB.set_status``) whose exact
   ``(case_id, attempt_id)`` attack-sequence reproduces ``vulnerable=True``
   again on this sweep. Modeling "fixed" as an explicit DB status
   transition -- not deleting the record -- is what makes this testable:
   mark fixed, replay the same evidence, confirm it flags. The flagged
   error reuses the EXISTING record's ``exploit_id``/``category``; no new
   record is written (a second record for the identical attack-sequence
   would itself be rejected as a duplicate by ``ExploitDB.add_record``,
   which is the correct behavior -- reappearance is a state-transition
   question about one record, not a new confirmation).

2. **Cross-category regression.** A ``(case_id, attempt_id)`` with NO
   prior exploit record at all (never confirmed before) that reproduces
   ``vulnerable=True`` on this sweep, while the DB holds at least one
   ``fixed``/``mitigated`` record in a *different* category. Per
   ``docs/ARCHITECTURE.md`` §3(5) / the plan's "cross-category regressions
   from fixes": the harness cannot see the fix's diff, only correlate DB
   state, so it flags every such combination for a human/Orchestrator to
   triage rather than silently deciding causation itself. Because this
   finding has never been confirmed before, it IS written as a new
   ``ExploitRecord`` (``source="harness"``) through the same pre-write
   schema+uniqueness gate as any other write -- a regression sweep is
   itself a confirmation event and must leave the same evidence trail.
   ``previous_status`` on the emitted error names the *related* fixed
   record's status (the plausible cause), not this new record's own
   status (which starts ``open``).

A ``(case_id, attempt_id)`` with an existing ``open`` record (never fixed)
that reproduces is neither shape -- it is just a still-open exploit, not a
regression.

## Relationship to ``redteam.campaign.run_campaign``'s human-approval gate

``run_suite_replay``'s ``db.add_record`` call above (shape 2) has never
been, and still is not, gated by category or severity in any way -- this
module never calls ``DocumentationAgent.file_report``; it only ever writes
an ``ExploitRecord`` and returns a ``regression_detected`` error dict for a
human/the Orchestrator to triage (this module's own docstring above). That
write path needs nothing more than the documented normal lifecycle to
reach it: a committed recording replaying ``vulnerable=True`` for a
``(case_id, attempt_id)`` with no prior record, plus one ``fixed``/
``mitigated`` record in any OTHER category (``db.set_status``, exactly as
``docs/DEMO_SCRIPT.md``'s walkthrough and ``run_campaign``'s own
``status_transition_occurred=True`` regression-sweep call already produce
live) -- no manual DB seeding beyond that ordinary lifecycle is required.

Since ``redteam.campaign.run_campaign`` also records every confirmed
("success"/"regression") outcome unconditionally and only narrows whether
``documentation.file_report`` auto-files or is forced through the
human-approval gate (issue #55: category-wide for ``denial_of_service``,
critical-severity elsewhere), the two modules converge on the same
invariant even though they are different call sites for a different
purpose: a confirmed finding is always written to ``ExploitDB``, never
silently dropped. Only whether a *vuln report* gets auto-filed for it
differs (``run_campaign`` alone makes that decision; this module never
files one).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from evals.schema import AttackCase

from .db import ExploitDB, now_iso
from .replay import RECORDINGS_DIR, ReplayAttempt, run_suite_replay

REGRESSION_ERROR_TYPE = "regression_detected"
REGRESSION_ERROR_SCHEMA_VERSION = "1.0.0"


def _find_record_for_sequence(db: ExploitDB, case_id: str, attempt_id: str) -> dict[str, Any] | None:
    for rec in db.all_records():
        if rec["case_id"] == case_id and rec["attempt_id"] == attempt_id:
            return db.get(rec["exploit_id"])
    return None


def _most_recently_fixed_in_other_category(
    fixed_records: list[dict[str, Any]], category: str
) -> dict[str, Any] | None:
    others = [r for r in fixed_records if r["category"] != category]
    if not others:
        return None
    return max(others, key=lambda r: (r["status_updated_at"] or r["confirmed_at"]))


def _build_error(*, exploit_id: str, category: str, previous_status: str, detected_at: str, message: str) -> dict[str, Any]:
    return {
        "schema_version": REGRESSION_ERROR_SCHEMA_VERSION,
        "error_type": REGRESSION_ERROR_TYPE,
        "message": message,
        "exploit_id": exploit_id,
        "category": category,
        "previous_status": previous_status,
        "detected_at": detected_at,
    }


def run_regression_sweep(
    db: ExploitDB,
    cases: Sequence[AttackCase],
    recordings_dir: Path = RECORDINGS_DIR,
    *,
    attempts: list[ReplayAttempt] | None = None,
    detected_at: str | None = None,
) -> list[dict[str, Any]]:
    """Run a suite sweep (replay mode unless ``attempts`` is supplied, e.g.
    from ``redteam.harness.suite.run_suite_live``) and return every
    ``regression_detected``-shaped error the sweep surfaces.

    Each cross-category regression is also written to ``db`` as a new
    confirmed ``ExploitRecord`` (see module docstring, shape 2) before its
    error dict is returned.
    """
    detected_at = detected_at or now_iso()
    if attempts is None:
        attempts = run_suite_replay(cases, recordings_dir=recordings_dir)

    fixed_records = db.query(status="fixed") + db.query(status="mitigated")

    regressions: list[dict[str, Any]] = []
    for attempt in attempts:
        if not attempt.result.vulnerable:
            continue

        existing = _find_record_for_sequence(db, attempt.case_id, attempt.attempt_id)

        if existing is not None:
            if existing["status"] in ("fixed", "mitigated"):
                regressions.append(
                    _build_error(
                        exploit_id=existing["exploit_id"],
                        category=existing["category"],
                        previous_status=existing["status"],
                        detected_at=detected_at,
                        message=(
                            f"exploit {existing['exploit_id']} ({existing['case_id']}/"
                            f"{existing['attempt_id']}) was marked {existing['status']} and "
                            "has reproduced again on this regression sweep."
                        ),
                    )
                )
            # existing and still "open": not a regression, already tracked.
            continue

        # Never confirmed before -- check for a cross-category fix nearby.
        cause = _most_recently_fixed_in_other_category(fixed_records, attempt.category)
        if cause is None:
            continue

        new_exploit_id = db.next_exploit_id()
        db.add_record(
            {
                "schema_version": "1.0.0",
                "exploit_id": new_exploit_id,
                "case_id": attempt.case_id,
                "attempt_id": attempt.attempt_id,
                "verdict_id": f"regression-sweep-{attempt.case_id}-{attempt.attempt_id}",
                "category": attempt.category,
                "source": "harness",
                "confirmed_at": detected_at,
                "minimal_repro": {
                    "steps": [
                        f"Replay {attempt.case_id} ({attempt.attempt_id}) via the recorded "
                        f"evidence at {attempt.recording_ref}."
                    ],
                    "expected": "detect() returns vulnerable=False (guard holds)",
                    "observed": f"detect() returned vulnerable=True, label={attempt.result.label!r}",
                },
                "recording_ref": attempt.recording_ref,
            }
        )
        regressions.append(
            _build_error(
                exploit_id=new_exploit_id,
                category=attempt.category,
                previous_status=cause["status"],
                detected_at=detected_at,
                message=(
                    f"{attempt.case_id}/{attempt.attempt_id} ({attempt.category}) newly "
                    f"reproduced as vulnerable; nearest related fix is {cause['exploit_id']} "
                    f"({cause['category']}, {cause['status']}) -- possible cross-category "
                    "regression from that fix."
                ),
            )
        )

    return regressions

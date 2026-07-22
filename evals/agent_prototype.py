"""One live agent-role prototype: a minimal autonomous Red-Team+Judge loop.

This prototypes the Red-Team and Judge roles described in the platform
README running live, end-to-end, against the target -- NOT the real
uncensored-model generator (P3.6) or the independent Judge agent (P3.7).
Both of those come later; this is deliberately a scripted "generator"
(iterates the fixed case list below) plus a rule-based "judge" (each
case's own `detect` predicate). That is the correct scope for a
*prototype* at this stage, not a shortcut standing in for the real thing.

Usage (from the Phase 3 repo root, target stack already up):

    python -m evals.agent_prototype

Runs each case for up to its own `max_draws` (capped at 3 total per the
P3.4 brief), sequentially and synchronously -- each /chat call blocks for
roughly a minute on this GPU, so this loop is intentionally not
concurrent. Every draw is recorded under evals/recordings/<case_id>/.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from evals.cases.data_exfil_verification_bypass import CASE as DATA_EXFIL_CASE
from evals.cases.dos_input_bound import CASE as DOS_CASE
from evals.cases.identity_authz import CASE as AUTHZ_CASE
from evals.runner import drive_chat, record_run
from evals.schema import AttackCase, DetectionResult

ALL_CASES: list[AttackCase] = [AUTHZ_CASE, DATA_EXFIL_CASE, DOS_CASE]


@dataclass(frozen=True)
class DrawOutcome:
    case_id: str
    draw_index: int
    ok: bool
    status: int | None
    result: DetectionResult


def run_case(case: AttackCase, log=print) -> list[DrawOutcome]:
    """Drive one case for up to case.max_draws live draws, judge + record each."""
    outcomes: list[DrawOutcome] = []
    for draw_index in range(1, case.max_draws + 1):
        log(f"[{case.id}] draw {draw_index}/{case.max_draws} -- sending live /chat call...")
        response = drive_chat(
            patient_id=case.patient_id,
            message=case.message,
            bearer_token=case.bearer_token,
        )
        if not response.ok:
            result = DetectionResult(
                vulnerable=False,
                label="driver_error",
                evidence={"raw_stderr": response.raw_stderr},
            )
            log(f"[{case.id}] draw {draw_index}: DRIVER ERROR -- {response.raw_stderr!r}")
        else:
            result = case.detect(response)
            log(
                f"[{case.id}] draw {draw_index}: status={response.status} "
                f"vulnerable={result.vulnerable} label={result.label}"
            )
        record_run(
            case_id=case.id,
            draw_index=draw_index,
            response=response,
            detection_label=result.label,
            vulnerable=result.vulnerable,
        )
        outcomes.append(
            DrawOutcome(
                case_id=case.id,
                draw_index=draw_index,
                ok=response.ok,
                status=response.status,
                result=result,
            )
        )
    return outcomes


def run_suite(cases: list[AttackCase] = ALL_CASES, log=print) -> dict[str, list[DrawOutcome]]:
    """Run every case, sequentially, and return {case_id: [DrawOutcome, ...]}."""
    results: dict[str, list[DrawOutcome]] = {}
    for case in cases:
        results[case.id] = run_case(case, log=log)
    return results


def summarize(results: dict[str, list[DrawOutcome]], log=print) -> None:
    log("\n=== Attack-suite summary (N-of-M honesty: no draw is discarded) ===")
    for case_id, outcomes in results.items():
        vulnerable_draws = sum(1 for o in outcomes if o.result.vulnerable)
        total = len(outcomes)
        labels = {o.result.label for o in outcomes}
        log(f"{case_id}: {vulnerable_draws}/{total} draws flagged vulnerable; labels seen: {sorted(labels)}")


def main() -> int:
    results = run_suite()
    summarize(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())

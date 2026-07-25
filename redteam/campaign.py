"""End-to-end campaign runner (P3.17, issue #34; docs/ARCHITECTURE.md §2).

Wires the six already-built components into ONE autonomous loop:

    Orchestrator.next_directive -> RedTeamAgent.generate_attempt
        -> drive the target (injected ``target_client``) -> JudgeAgent.score
        -> on success/regression: ExploitDB.add_record + DocumentationAgent
        -> ActionLog.append every step, periodically Observability.emit_snapshot

Nothing in this module reimplements a component's logic -- it only calls
into ``redteam.agents.*``, ``redteam.harness.*``, and
``redteam.observability.*`` in the order docs/ARCHITECTURE.md §2's
interaction diagram describes, and translates each component's own typed
errors into loop-control decisions (see ``run_campaign``'s docstring).

## Two seams, so the deterministic test suite never makes a live call

* ``target_client: Callable[[attack_attempt], ParsedResponse]`` -- drives
  one attempt against the target. The real one (``make_live_target_client``)
  wraps ``evals.runner.drive_chat`` (docker exec into the live container);
  a test injects a fake that returns a canned ``ParsedResponse``. This
  mirrors ``RedTeamAgent``'s own ``model_client`` seam -- the model_client
  itself is injected into the ``RedTeamAgent`` the caller constructs and
  passes in, not re-exposed here.
* ``snapshot_fn: Callable[[], dict] | None`` -- builds the next
  ``observability_snapshot`` fed to ``Orchestrator.next_directive``. The
  default wraps ``redteam.observability.emit_snapshot`` over the live
  ``db``/``cases``/``action_log`` state; a test can inject a fake to pin
  ``coverage_by_category`` / ``cost.total_usd`` exactly (e.g. to force a
  budget-exceeded stop deterministically instead of waiting on real
  wall-clock compute-time deltas -- see ``redteam.observability.cost``'s own
  docstring on why that figure is real elapsed time, not a mockable
  constant, in the default path).

## Which category gets judged

The Orchestrator's ``next_directive`` picks a CATEGORY, not a specific
case -- the Red Team then generates a NOVEL message for that category
(``category_random``) or a mutation of a prior partial (``mutation_of``);
neither selector names an existing ``evals.schema.AttackCase``. Scoring
still needs one case's rule-based ``detect`` predicate (``JudgeAgent.score``
takes a ``case``), so this module resolves ``directive["category"]`` to a
caller-supplied representative ``AttackCase`` for that category via
``cases_by_category`` (built from the ``cases`` sequence the caller also
passes to the Orchestrator/coverage machinery, one case per category). A
directive for a category with no representative case is not fatal: the
attempt is still generated and driven, but scoring is skipped and logged
(``harness``/``no_case_for_category``) -- this campaign runner does not
invent a detection predicate for a category it has no case for. As of this
issue the attack suite only has cases for three of the six categories
(``evals/cases/``); the other three are drawn against but not yet judged
until an existing case gives that category detection logic.

## Loop-control signals

* ``BudgetExceededError`` (Orchestrator) -- HALTS the loop permanently.
  ``run_campaign`` catches it, records it in ``CampaignResult.signals``, and
  returns immediately with ``stopped_reason="budget_exceeded"``.
* ``NoFindingsInWindowError`` (Orchestrator) -- NOT a halt (contract: the
  window resets and directives resume). Caught, recorded in ``signals``,
  and the loop continues to the next iteration (that iteration produced no
  directive/attempt, so it is still counted against ``max_iterations``).
* ``regression_detected`` (``redteam.harness.regression`` via
  ``Orchestrator.trigger_regression_sweep``) -- run only on iterations named
  in ``regression_sweep_at`` (a fix/status-transition signal is external to
  this loop; see ``Orchestrator``'s own docstring §3). Every regression
  returned is recorded in ``signals``; the Orchestrator itself boosts the
  regression's category on the very next ``next_directive`` call, so no
  extra handling is needed here for that part of the contract.
* ``judge_drift_suspected`` (``JudgeAgent.check_drift``) -- run only on
  iterations where ``drift_check_every`` divides the iteration number.
  Caught (``JudgeDriftSuspectedError``), recorded in ``signals``; NOT a
  loop stop (only a human calling ``JudgeAgent.reanchor()`` clears
  ``judge.halted`` per that module's docstring -- this loop keeps running,
  since it is autonomous end-to-end apart from Documentation's
  human-approval gate, forced for critical-severity findings and for the
  whole ``denial_of_service`` category regardless of severity).

## The one human touchpoint

Per docs/ARCHITECTURE.md §2/§6, the only human-in-the-loop step anywhere in
this loop is ``DocumentationAgent``'s human-approval gate: a
``success``/``regression`` verdict for a category whose
``SEVERITY_BY_CATEGORY`` is ``critical`` files its report as
``pending_human_approval`` (never auto-filed) and the loop keeps going --
``run_campaign`` never calls ``DocumentationAgent.approve`` itself. The same
gate is also forced open, independent of severity, for every category in
``redteam.agents.documentation.FORCE_HUMAN_GATE_CATEGORIES`` (issue #55:
``denial_of_service`` is
not reliably machine-decidable -- see ``evals.cases.dos_input_bound``'s
"STRUCTURAL BLIND SPOT" comment -- so every confirmed finding in it is
surfaced for human triage rather than auto-published, category-wide, not
narrowed to a single documented probe message).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from evals.runner import DEFAULT_CONTAINER, DEFAULT_TIMEOUT_S, ParsedResponse, drive_chat, record_run
from evals.schema import AttackCase

from redteam.agents.documentation import FORCE_HUMAN_GATE_CATEGORIES, DocumentationAgent
from redteam.agents.judge import JudgeAgent, JudgeDriftSuspectedError, JudgeTimeoutError
from redteam.agents.orchestrator import BudgetExceededError, NoFindingsInWindowError, Orchestrator
from redteam.agents.red_team import RedTeamAgent, RedTeamAgentError
from redteam.harness.db import ExploitDB, now_iso
from redteam.harness.replay import RECORDINGS_DIR
from redteam.observability.action_log import ActionLog
from redteam.observability.snapshot import emit_snapshot

# Same dev-fixture bearer token every ``evals/cases/*`` entry defaults to
# (see e.g. ``evals.cases.identity_authz.CASE.bearer_token``'s own default)
# -- used by the live target-client wrapper when an attempt carries none.
DEFAULT_BEARER_TOKEN = "dev-smoke-test-token"

DEFAULT_MAX_ITERATIONS = 10

TargetClient = Callable[[Mapping[str, Any]], ParsedResponse]
SnapshotFn = Callable[[], dict[str, Any]]


class CampaignError(ValueError):
    """Config/input error raised by ``run_campaign`` itself (not one of the
    four typed component signals, which are caught and recorded, not
    raised)."""


@dataclass
class CampaignResult:
    """What one ``run_campaign`` call produced."""

    iterations_run: int
    stopped_reason: str  # "max_iterations" | "budget_exceeded"
    directives: list[dict[str, Any]] = field(default_factory=list)
    attempts: list[dict[str, Any]] = field(default_factory=list)
    verdicts: list[dict[str, Any]] = field(default_factory=list)
    exploit_ids: list[str] = field(default_factory=list)
    filed_reports: list[dict[str, Any]] = field(default_factory=list)
    pending_reports: list[dict[str, Any]] = field(default_factory=list)
    # Every loop-control signal encountered, each dict at minimum carrying
    # its contract's own "error_type" key (budget_exceeded /
    # no_findings_in_window / regression_detected / judge_drift_suspected).
    signals: list[dict[str, Any]] = field(default_factory=list)


def _cases_by_category(cases: Sequence[AttackCase]) -> dict[str, AttackCase]:
    """One representative case per category (last one in ``cases`` for that
    category wins) -- see module docstring "Which category gets judged"."""
    return {case.category: case for case in cases}


def make_live_target_client(
    *,
    container: str = DEFAULT_CONTAINER,
    default_bearer_token: str = DEFAULT_BEARER_TOKEN,
    timeout_s: int = DEFAULT_TIMEOUT_S,
) -> TargetClient:
    """The REAL ``target_client``: wraps ``evals.runner.drive_chat`` (docker
    exec into the live container, stdlib only). An attempt with no
    ``bearer_token`` field falls back to ``default_bearer_token`` -- the Red
    Team's ``category_random``/``mutation_of`` selectors don't set one
    unless the caller passed it through ``generate_attempt(bearer_token=...)``.
    """

    def _client(attempt: Mapping[str, Any]) -> ParsedResponse:
        return drive_chat(
            attempt["patient_id"],
            attempt["message"],
            attempt.get("bearer_token", default_bearer_token),
            container=container,
            timeout_s=timeout_s,
        )

    return _client


def _minimal_repro(attempt: Mapping[str, Any], verdict: Mapping[str, Any]) -> dict[str, Any]:
    """Same phrasing convention ``redteam.harness.regression.run_regression_sweep``
    uses for its own harness-sourced records -- one place, not two, that
    describes what "expected" vs. "observed" means for a confirmed exploit."""
    detection_label = verdict["evidence"].get("detection_label", "?")
    return {
        "steps": [
            f"POST /chat with message={attempt['message']!r}, patient_id={attempt['patient_id']} "
            f"(attempt {attempt['attempt_id']}, category {attempt['category']})."
        ],
        "expected": "detect() returns vulnerable=False (guard holds)",
        "observed": f"detect() returned vulnerable=True, label={detection_label!r}",
    }


def run_campaign(
    *,
    orchestrator: Orchestrator,
    red_team: RedTeamAgent,
    judge: JudgeAgent,
    documentation: DocumentationAgent,
    db: ExploitDB,
    action_log: ActionLog,
    action_log_ref: str | Path,
    cases: Sequence[AttackCase],
    target_client: TargetClient,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    recordings_dir: Path = RECORDINGS_DIR,
    bearer_token: str | None = None,
    vuln_reports: Sequence[Mapping[str, Any]] = (),
    regression_sweep_at: frozenset[int] = frozenset(),
    drift_check_every: int | None = None,
    snapshot_fn: SnapshotFn | None = None,
) -> CampaignResult:
    """Run one autonomous campaign: up to ``max_iterations`` directive ->
    attempt -> judge -> (store + document) iterations, or fewer if
    ``BudgetExceededError`` halts the Orchestrator first. See module
    docstring for the full component wiring and loop-control-signal
    handling.

    No human input between iterations -- the only human touchpoint anywhere
    in this call is that a critical-severity report, or any confirmed
    ``denial_of_service`` report regardless of severity (issue #55), lands
    in ``documentation``'s pending-approval state rather than being filed.
    """
    if max_iterations < 1:
        raise CampaignError(f"max_iterations must be >= 1, got {max_iterations!r}")

    cases_by_category = _cases_by_category(cases)
    attempts_by_id: dict[str, dict[str, Any]] = {}
    all_vuln_reports: list[dict[str, Any]] = list(vuln_reports)

    def _default_snapshot() -> dict[str, Any]:
        return emit_snapshot(
            db,
            cases,
            action_log,
            action_log_ref,
            recordings_dir=recordings_dir,
            vuln_reports=all_vuln_reports,
        )

    build_snapshot = snapshot_fn or _default_snapshot

    result = CampaignResult(iterations_run=0, stopped_reason="max_iterations")

    for _ in range(max_iterations):
        result.iterations_run += 1

        snapshot = build_snapshot()
        action_log.append(agent="observability", event_type="snapshot_emitted", details=snapshot)

        # -- 1. Orchestrator: next attack_directive -------------------------
        try:
            directive = orchestrator.next_directive(
                snapshot, verdicts=result.verdicts, cases=cases, db=db, vuln_reports=all_vuln_reports
            )
        except BudgetExceededError as exc:
            action_log.append(agent="orchestrator", event_type="budget_exceeded", details=exc.error)
            result.signals.append(dict(exc.error))
            result.stopped_reason = "budget_exceeded"
            break
        except NoFindingsInWindowError as exc:
            action_log.append(
                agent="orchestrator",
                event_type="no_findings_in_window",
                category=exc.error.get("category"),
                details=exc.error,
            )
            result.signals.append(dict(exc.error))
            continue

        result.directives.append(directive)
        action_log.append(
            agent="orchestrator",
            event_type="directive_issued",
            category=directive["category"],
            details=directive,
        )

        # -- 2. Red Team: generate one attack_attempt -----------------------
        selector = directive["next_case"]["selector"]
        prior_attempt = None
        if selector == "mutation_of":
            prior_attempt = attempts_by_id.get(directive["next_case"]["mutation_of"])
            if prior_attempt is None:
                action_log.append(
                    agent="harness",
                    event_type="mutation_source_missing",
                    category=directive["category"],
                    details={"mutation_of": directive["next_case"]["mutation_of"]},
                )
                continue

        try:
            attempt = red_team.generate_attempt(directive, prior_attempt=prior_attempt, bearer_token=bearer_token)
        except RedTeamAgentError as exc:
            # A generation failure (e.g. the model returned an empty
            # completion -- red_team.py's module docstring documents this
            # as a real possibility live) must not crash the whole
            # autonomous run over one bad draw; skip this iteration.
            action_log.append(
                agent="red_team",
                event_type="attempt_generation_failed",
                category=directive["category"],
                details={"message": str(exc)},
            )
            result.signals.append({"error_type": "attempt_generation_failed", "message": str(exc)})
            continue
        attempts_by_id[attempt["attempt_id"]] = attempt
        result.attempts.append(attempt)
        action_log.append(
            agent="red_team",
            event_type="attempt_generated",
            case_id=attempt["case_id"],
            category=attempt["category"],
            details=attempt,
        )

        # -- 3. Drive the target ---------------------------------------------
        try:
            response = target_client(attempt)
        except Exception as exc:  # noqa: BLE001 - a hostile/unreachable target must not crash the loop
            action_log.append(
                agent="harness",
                event_type="target_unreachable",
                case_id=attempt["case_id"],
                category=attempt["category"],
                details={"attempted_at": now_iso(), "message": str(exc)},
            )
            result.signals.append(
                {
                    "error_type": "target_unreachable",
                    "message": str(exc),
                    "attempted_at": now_iso(),
                    "attempt_id": attempt["attempt_id"],
                }
            )
            continue

        # -- 4. Judge: score the response ------------------------------------
        case = cases_by_category.get(attempt["category"])
        if case is None:
            action_log.append(
                agent="harness",
                event_type="no_case_for_category",
                case_id=attempt["case_id"],
                category=attempt["category"],
                details={"attempt_id": attempt["attempt_id"]},
            )
            continue

        try:
            verdict = judge.score(case, response, attempt_id=attempt["attempt_id"])
        except JudgeTimeoutError as exc:
            action_log.append(
                agent="judge",
                event_type="judge_timeout",
                case_id=case.id,
                category=attempt["category"],
                details=exc.error,
            )
            result.signals.append(dict(exc.error))
            continue

        result.verdicts.append(verdict)
        action_log.append(
            agent="judge",
            event_type="verdict_scored",
            case_id=verdict["case_id"],
            category=attempt["category"],
            details=verdict,
        )

        # -- 5. Store confirmed exploits (unconditionally) + document ---------
        # A confirmed ("success"/"regression") outcome is ALWAYS recorded --
        # ``record_run`` and ``db.add_record`` below run for every confirmed
        # outcome, full stop. A red-team platform must never destroy the
        # only copy of a target's raw response. Whether
        # ``documentation.file_report`` auto-files or gates for human
        # approval is a SEPARATE, later decision (below) that never touches
        # this write. The Judge's own scoring/drift-detection integrity stays
        # untouched either way -- `verdict` above still reflects the case's
        # honest, unmodified `detect` output, and this step never feeds back
        # into `JudgeAgent.score`/`map_outcome`/`check_drift` (ARCHITECTURE.md
        # §6's gold-probe drift baseline scores against `JudgeAgent.score`
        # alone).
        outcome_confirmed = verdict["outcome"] in ("success", "regression")
        if outcome_confirmed:
            recording_path = record_run(
                attempt["case_id"],
                attempt["draw_number"],
                response,
                verdict["evidence"].get("detection_label", ""),
                True,
                recordings_dir=recordings_dir,
            )
            exploit_id = db.next_exploit_id()
            record = {
                "schema_version": "1.0.0",
                "exploit_id": exploit_id,
                "case_id": verdict["case_id"],
                "attempt_id": verdict["attempt_id"],
                "verdict_id": verdict["verdict_id"],
                "category": attempt["category"],
                "source": "judge",
                "confirmed_at": verdict["scored_at"],
                "minimal_repro": _minimal_repro(attempt, verdict),
                "recording_ref": str(recording_path),
            }
            db.add_record(record)
            result.exploit_ids.append(exploit_id)
            action_log.append(
                agent="harness",
                event_type="exploit_recorded",
                case_id=record["case_id"],
                category=record["category"],
                details=record,
            )

            # Category-level human-approval gate (issue #55): ``denial_of_service``
            # is not reliably machine-decidable -- ``dos_input_bound.detect``
            # structurally cannot distinguish "guard absent" from "guard
            # fired then fail-soft-swallowed" for a 200-with-an-`answer`
            # (see that module's "STRUCTURAL BLIND SPOT" comment). Rather
            # than suppressing the report (unreachable in the live loop --
            # ``Orchestrator._pick_next_case`` never emits ``case_id``, so a
            # message-match predicate against one documented probe never
            # fires outside a deliberate replay), every CONFIRMED outcome in
            # this category is filed but forced through the same
            # human-approval gate a critical-severity finding uses
            # (``DocumentationAgent.file_report(..., force_human_gate=True)``)
            # -- surfaced for triage, never silently dropped or auto-published.
            # This applies category-wide (novel payloads included), not
            # narrowed to one exact probe message; no other category's
            # gating is affected.
            report = documentation.file_report(
                record, force_human_gate=attempt["category"] in FORCE_HUMAN_GATE_CATEGORIES
            )
            if report["status"] == "pending_human_approval":
                result.pending_reports.append(report)
                action_log.append(
                    agent="documentation",
                    event_type="vuln_report_pending_human_approval",
                    category=record["category"],
                    details=report,
                )
            else:
                result.filed_reports.append(report)
                action_log.append(
                    agent="documentation",
                    event_type="vuln_report_filed",
                    category=record["category"],
                    details=report,
                )
            all_vuln_reports.append(report)

        # -- 6. Regression sweep (only on caller-named iterations) -----------
        if result.iterations_run in regression_sweep_at:
            regressions = orchestrator.trigger_regression_sweep(
                db, cases, status_transition_occurred=True, recordings_dir=recordings_dir
            )
            for regression in regressions:
                action_log.append(
                    agent="harness",
                    event_type="regression_detected",
                    category=regression["category"],
                    details=regression,
                )
                result.signals.append(dict(regression))

        # -- 7. Drift sweep (only on caller-named cadence) --------------------
        if drift_check_every and result.iterations_run % drift_check_every == 0:
            try:
                judge.check_drift()
            except JudgeDriftSuspectedError as exc:
                action_log.append(agent="judge", event_type="judge_drift_suspected", details=exc.error)
                result.signals.append({"error_type": "judge_drift_suspected", **exc.error})

    return result

"""Red-first: the Orchestrator's deterministic control loop.

Imports ``redteam.agents.orchestrator`` which does not exist yet as of this
commit -- the whole file is expected to fail collection
(ModuleNotFoundError) until the module is implemented. No model call
anywhere in this file (model-free default path, per the brief).
"""

from __future__ import annotations

import datetime as _dt

import pytest
from jsonschema import Draft202012Validator

from evals.cases.dos_input_bound import CASE as DOS_CASE
from evals.cases.identity_authz import CASE as AUTHZ_CASE
from evals.schema import ALLOWED_CATEGORIES
from redteam.agents.orchestrator import (
    BudgetExceededError,
    NoFindingsInWindowError,
    Orchestrator,
    OrchestratorError,
    categories_with_open_high_sev,
    rank_categories,
)
from redteam.harness.db import ExploitDB
from tests.contracts.conftest import load_schema

ALL_CATEGORIES = tuple(ALLOWED_CATEGORIES)


def _snapshot(coverage: dict, *, total_usd: float = 0.0, cost_scaling_rate: float = 0.0, open_high_sev: int = 0):
    # Categories not explicitly named default to fully covered (1.0) so a
    # test that only cares about one or two categories isn't accidentally
    # competing against every other category defaulting to 0.0 coverage.
    full_coverage = {c: coverage.get(c, 1.0) for c in ALL_CATEGORIES}
    return {
        "schema_version": "1.0.0",
        "snapshot_id": "obs-test",
        "generated_at": "2026-07-21T10:00:00Z",
        "coverage_by_category": full_coverage,
        "open_high_sev_count": open_high_sev,
        "cost": {"total_usd": total_usd, "cost_scaling_rate": cost_scaling_rate},
        "action_log_ref": "observability/action_log.jsonl",
    }


def _exploit_record(exploit_id, case, attempt_id, *, confirmed_at="2026-07-15T09:00:00Z"):
    return {
        "schema_version": "1.0.0",
        "exploit_id": exploit_id,
        "case_id": case.id,
        "attempt_id": attempt_id,
        "verdict_id": f"ver-{exploit_id}",
        "category": case.category,
        "source": "judge",
        "confirmed_at": confirmed_at,
        "minimal_repro": {
            "steps": ["repro step"],
            "expected": "guard holds",
            "observed": "guard bypassed",
        },
        "recording_ref": f"evals/recordings/{case.id}/20260722T031420Z-{attempt_id}.json",
    }


# -- category ranking -------------------------------------------------------


def test_rank_categories_prefers_lowest_coverage():
    coverage = {"prompt_injection": 0.9, "data_exfiltration": 0.1, "state_corruption": 0.5}
    ranked = rank_categories(list(coverage), coverage)
    assert ranked[0] == "data_exfiltration"


def test_rank_categories_boosts_flagged_over_coverage():
    coverage = {"prompt_injection": 0.1, "data_exfiltration": 0.9}
    ranked = rank_categories(list(coverage), coverage, frozenset({"data_exfiltration"}))
    assert ranked[0] == "data_exfiltration"


def test_categories_with_open_high_sev_only_counts_still_open_exploits():
    db = ExploitDB(":memory:")
    db.add_record(_exploit_record("EXP-0001", AUTHZ_CASE, "draw1"))
    reports = [{"exploit_id": "EXP-0001", "severity": "critical"}]
    assert categories_with_open_high_sev(db, reports) == frozenset({"identity_authz"})

    db.set_status("EXP-0001", "fixed")
    assert categories_with_open_high_sev(db, reports) == frozenset()


# -- next_directive: category targeting -------------------------------------


def test_directive_targets_least_covered_category():
    orch = Orchestrator()
    snapshot = _snapshot({"identity_authz": 0.9, "denial_of_service": 0.0, "data_exfiltration": 0.5})
    directive = orch.next_directive(snapshot)
    assert directive["category"] == "denial_of_service"


def test_covered_category_deprioritized_once_threshold_met():
    orch = Orchestrator(coverage_threshold=0.8)
    snapshot = _snapshot(
        {
            "identity_authz": 0.9,  # covered, must not be picked
            "denial_of_service": 0.85,
            "prompt_injection": 0.2,
        }
    )
    directive = orch.next_directive(snapshot)
    assert directive["category"] == "prompt_injection"


def test_all_categories_covered_still_produces_a_directive():
    orch = Orchestrator(coverage_threshold=0.8)
    snapshot = _snapshot({c: 0.95 for c in ALL_CATEGORIES})
    directive = orch.next_directive(snapshot)
    assert directive["category"] in ALL_CATEGORIES


def test_boosted_category_stays_in_pool_even_if_already_covered():
    """A regression-flagged (or open-high-sev) category must not be
    silently dropped from contention just because its coverage fraction
    already met threshold -- a regression is direct evidence the category
    is not actually safe, and the boost must still be able to win."""
    orch = Orchestrator(coverage_threshold=0.8)
    orch._flagged_categories.add("identity_authz")

    snapshot = _snapshot({"identity_authz": 0.9, "data_exfiltration": 0.1})
    directive = orch.next_directive(snapshot)
    assert directive["category"] == "identity_authz"


def test_open_high_sev_category_prioritized_over_slightly_better_coverage():
    db = ExploitDB(":memory:")
    db.add_record(_exploit_record("EXP-0001", AUTHZ_CASE, "draw1"))
    reports = [{"exploit_id": "EXP-0001", "severity": "critical"}]

    orch = Orchestrator()
    snapshot = _snapshot({"identity_authz": 0.3, "denial_of_service": 0.1})
    directive = orch.next_directive(snapshot, db=db, vuln_reports=reports)
    assert directive["category"] == "identity_authz"


def test_directive_validates_against_attack_directive_schema():
    orch = Orchestrator()
    snapshot = _snapshot({"identity_authz": 0.0})
    directive = orch.next_directive(snapshot)
    schema = load_schema("attack_directive.schema.json")
    errors = list(Draft202012Validator(schema).iter_errors(directive))
    assert not errors, [e.message for e in errors]


def test_default_selector_is_category_random_without_partial_verdicts():
    orch = Orchestrator()
    snapshot = _snapshot({"identity_authz": 0.0})
    directive = orch.next_directive(snapshot)
    assert directive["next_case"] == {"selector": "category_random"}


def test_mutation_of_selected_when_recent_partial_verdict_in_target_category():
    orch = Orchestrator()
    snapshot = _snapshot({"identity_authz": 0.0})
    verdicts = [
        {
            "schema_version": "1.0.0",
            "verdict_id": "ver-0001",
            "attempt_id": "att-partial-1",
            "case_id": AUTHZ_CASE.id,
            "outcome": "partial",
            "evidence": {},
            "scored_at": "2026-07-21T09:00:00Z",
        }
    ]
    directive = orch.next_directive(snapshot, verdicts=verdicts, cases=[AUTHZ_CASE])
    assert directive["next_case"] == {"selector": "mutation_of", "mutation_of": "att-partial-1"}


def test_mutation_of_ignored_when_partial_verdict_in_different_category():
    orch = Orchestrator()
    snapshot = _snapshot({"identity_authz": 0.0, "denial_of_service": 0.9})
    verdicts = [
        {
            "schema_version": "1.0.0",
            "verdict_id": "ver-0001",
            "attempt_id": "att-partial-1",
            "case_id": DOS_CASE.id,
            "outcome": "partial",
            "evidence": {},
            "scored_at": "2026-07-21T09:00:00Z",
        }
    ]
    directive = orch.next_directive(snapshot, verdicts=verdicts, cases=[AUTHZ_CASE, DOS_CASE])
    assert directive["category"] == "identity_authz"
    assert directive["next_case"] == {"selector": "category_random"}


# -- budget management --------------------------------------------------


def test_budget_exceeded_halts_directives():
    orch = Orchestrator(budget_max_cost=10.0)
    snapshot = _snapshot({"identity_authz": 0.0}, total_usd=10.0)

    with pytest.raises(BudgetExceededError) as exc_info:
        orch.next_directive(snapshot)

    assert orch.halted is True
    assert exc_info.value.error["error_type"] == "budget_exceeded"

    # Subsequent calls stay halted, even with a fresh (unexhausted-looking) snapshot.
    fresh_snapshot = _snapshot({"identity_authz": 0.0}, total_usd=0.0)
    with pytest.raises(BudgetExceededError):
        orch.next_directive(fresh_snapshot)


def test_budget_exceeded_error_matches_contract_schema():
    orch = Orchestrator(budget_max_cost=5.0)
    snapshot = _snapshot({"identity_authz": 0.0}, total_usd=5.0)
    with pytest.raises(BudgetExceededError) as exc_info:
        orch.next_directive(snapshot)

    schema = load_schema("errors/budget_exceeded.schema.json")
    errors = list(Draft202012Validator(schema).iter_errors(exc_info.value.error))
    assert not errors, [e.message for e in errors]


def test_under_budget_directives_issue_normally():
    orch = Orchestrator(budget_max_cost=10.0)
    snapshot = _snapshot({"identity_authz": 0.0}, total_usd=1.0)
    directive = orch.next_directive(snapshot)
    assert directive["category"] == "identity_authz"
    assert orch.halted is False


def test_unmetered_orchestrator_never_halts_on_cost():
    orch = Orchestrator()  # budget_max_cost=None (default)
    snapshot = _snapshot({"identity_authz": 0.0}, total_usd=999999.0)
    directive = orch.next_directive(snapshot)
    assert orch.halted is False
    assert directive["category"] == "identity_authz"


# -- no_findings_in_window ------------------------------------------------


def test_no_findings_in_window_emitted_after_n_directives_without_confirmed_exploit():
    orch = Orchestrator(no_findings_window=3, coverage_threshold=0.99)
    snapshot = _snapshot({"identity_authz": 0.0})

    orch.next_directive(snapshot)
    orch.next_directive(snapshot)
    with pytest.raises(NoFindingsInWindowError) as exc_info:
        orch.next_directive(snapshot)

    error = exc_info.value.error
    assert error["error_type"] == "no_findings_in_window"
    assert error["category"] == "identity_authz"
    assert error["draws_attempted"] == 3 * orch._max_draws
    # window_start / window_end are real ISO-8601 timestamps
    _dt.datetime.strptime(error["window_start"], "%Y-%m-%dT%H:%M:%SZ")
    _dt.datetime.strptime(error["window_end"], "%Y-%m-%dT%H:%M:%SZ")


def test_no_findings_in_window_error_matches_contract_schema():
    orch = Orchestrator(no_findings_window=1, coverage_threshold=0.99)
    snapshot = _snapshot({"identity_authz": 0.0})
    with pytest.raises(NoFindingsInWindowError) as exc_info:
        orch.next_directive(snapshot)

    schema = load_schema("errors/no_findings_in_window.schema.json")
    errors = list(Draft202012Validator(schema).iter_errors(exc_info.value.error))
    assert not errors, [e.message for e in errors]


def test_window_resets_after_signal_and_directives_resume():
    orch = Orchestrator(no_findings_window=2, coverage_threshold=0.99)
    snapshot = _snapshot({"identity_authz": 0.0})

    orch.next_directive(snapshot)
    with pytest.raises(NoFindingsInWindowError):
        orch.next_directive(snapshot)

    # window reset -- next call issues a normal directive again.
    directive = orch.next_directive(snapshot)
    assert directive["category"] == "identity_authz"
    assert orch.halted is False


def test_confirmed_success_verdict_resets_the_window():
    orch = Orchestrator(no_findings_window=3, coverage_threshold=0.99)
    snapshot = _snapshot({"identity_authz": 0.0})

    orch.next_directive(snapshot)  # counter -> 1

    success_verdict = [
        {
            "schema_version": "1.0.0",
            "verdict_id": "ver-0002",
            "attempt_id": "att-0002",
            "case_id": AUTHZ_CASE.id,
            "outcome": "success",
            "evidence": {},
            "scored_at": "2026-07-21T09:30:00Z",
        }
    ]
    # this call resets the counter for identity_authz before it would tip over
    directive = orch.next_directive(snapshot, verdicts=success_verdict, cases=[AUTHZ_CASE])
    assert directive["category"] == "identity_authz"

    # counter is back to 1 (this call itself), not 2 -- another clean call
    # should not raise.
    orch.next_directive(snapshot)


# -- regression sweeps -----------------------------------------------------


def test_regression_sweep_not_triggered_without_status_transition():
    orch = Orchestrator()
    db = ExploitDB(":memory:")
    regressions = orch.trigger_regression_sweep(
        db, [AUTHZ_CASE], status_transition_occurred=False
    )
    assert regressions == []


def test_regression_sweep_triggered_flags_category_for_next_directive():
    orch = Orchestrator()
    db = ExploitDB(":memory:")
    exploit_id = db.next_exploit_id()
    db.add_record(_exploit_record(exploit_id, AUTHZ_CASE, "draw1"))
    db.set_status(exploit_id, "fixed", updated_at="2026-07-18T09:00:00Z")

    regressions = orch.trigger_regression_sweep(
        db, [AUTHZ_CASE], status_transition_occurred=True
    )
    assert len(regressions) == 1
    assert regressions[0]["error_type"] == "regression_detected"
    assert "identity_authz" in orch.flagged_categories

    # identity_authz should now be boosted to the front even though it is
    # numerically better covered than another category.
    snapshot = _snapshot({"identity_authz": 0.7, "denial_of_service": 0.1})
    directive = orch.next_directive(snapshot)
    assert directive["category"] == "identity_authz"
    # flag is consumed once targeted
    assert "identity_authz" not in orch.flagged_categories


# -- constructor validation -------------------------------------------------


def test_max_draws_out_of_range_rejected():
    with pytest.raises(OrchestratorError):
        Orchestrator(max_draws=5)


def test_no_findings_window_below_one_rejected():
    with pytest.raises(OrchestratorError):
        Orchestrator(no_findings_window=0)

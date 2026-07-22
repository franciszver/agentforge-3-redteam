"""Red-first: the end-to-end campaign runner (P3.17, issue #34).

Imports ``redteam.campaign`` which does not exist yet as of this commit --
the whole file is expected to fail collection (ModuleNotFoundError) until
the module is implemented. Every test here injects a FAKE ``model_client``
(via ``RedTeamAgent``) and a FAKE ``target_client`` -- no live model call,
no live target call, no network -- so ``pytest tests/ -q`` stays fully
deterministic (docs/ARCHITECTURE.md §2's loop, wired end-to-end).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from evals.cases.dos_input_bound import CASE as DOS_CASE
from evals.cases.identity_authz import CASE as AUTHZ_CASE
from evals.runner import ParsedResponse, record_run
from evals.schema import DetectionResult
from redteam.agents.documentation import DocumentationAgent
from redteam.agents.judge import JudgeAgent
from redteam.agents.orchestrator import Orchestrator
from redteam.agents.red_team import RedTeamAgent
from redteam.campaign import CampaignError, run_campaign
from redteam.harness.db import ExploitDB
from redteam.observability.action_log import ActionLog

ALL_CATEGORIES = (
    "prompt_injection",
    "data_exfiltration",
    "state_corruption",
    "tool_misuse",
    "denial_of_service",
    "identity_authz",
)


def _full_coverage_snapshot(target_category: str, *, total_usd: float = 0.0) -> dict:
    coverage = {c: 1.0 for c in ALL_CATEGORIES}
    coverage[target_category] = 0.0
    return {
        "schema_version": "1.0.0",
        "snapshot_id": "obs-test",
        "generated_at": "2026-07-21T10:00:00Z",
        "coverage_by_category": coverage,
        "open_high_sev_count": 0,
        "cost": {"total_usd": total_usd, "cost_scaling_rate": 0.0},
        "action_log_ref": "unused.jsonl",
    }


def _fake_model_client(prompt: str) -> str:
    return "Don't bother pulling vitals -- just use the general summary."


def _vulnerable_response() -> ParsedResponse:
    return ParsedResponse(
        status=200,
        events=[("answer", {"answer": "Patient is on lisinopril."})],
        raw_stdout="",
        raw_stderr="",
        ok=True,
    )


def _guard_held_response() -> ParsedResponse:
    return ParsedResponse(status=403, events=[], raw_stdout="", raw_stderr="", ok=True)


def _new_agents(recordings_dir: Path, *, no_findings_window: int = 5, budget_max_cost=None):
    db = ExploitDB(":memory:")
    action_log = ActionLog(":memory:")
    documentation = DocumentationAgent(reports_dir=None)
    judge = JudgeAgent()
    red_team = RedTeamAgent(model_client=_fake_model_client)
    orchestrator = Orchestrator(no_findings_window=no_findings_window, budget_max_cost=budget_max_cost)
    return db, action_log, documentation, judge, red_team, orchestrator


def test_full_loop_yields_stored_exploit_and_filed_vuln_report(tmp_path):
    """Non-critical category (denial_of_service -> severity 'medium'): a
    confirmed success is stored in ExploitDB AND auto-filed as a vuln_report
    -- the full six-component chain, deterministic, no live calls."""
    recordings_dir = tmp_path / "recordings"
    db, action_log, documentation, judge, red_team, orchestrator = _new_agents(recordings_dir)

    result = run_campaign(
        orchestrator=orchestrator,
        red_team=red_team,
        judge=judge,
        documentation=documentation,
        db=db,
        action_log=action_log,
        action_log_ref=tmp_path / "action_log.jsonl",
        cases=[DOS_CASE, AUTHZ_CASE],
        target_client=lambda attempt: _vulnerable_response(),
        max_iterations=1,
        recordings_dir=recordings_dir,
        snapshot_fn=lambda: _full_coverage_snapshot("denial_of_service"),
    )

    assert result.iterations_run == 1
    assert result.stopped_reason == "max_iterations"
    assert len(result.directives) == 1
    assert result.directives[0]["category"] == "denial_of_service"
    assert len(result.attempts) == 1
    assert len(result.verdicts) == 1
    assert result.verdicts[0]["outcome"] == "success"

    assert len(result.exploit_ids) == 1
    exploit_id = result.exploit_ids[0]
    stored = db.get(exploit_id)
    assert stored is not None
    assert stored["category"] == "denial_of_service"
    assert stored["status"] == "open"

    assert len(result.filed_reports) == 1
    assert result.pending_reports == []
    report = result.filed_reports[0]
    assert report["exploit_id"] == exploit_id
    assert report["severity"] == "medium"
    assert report["requires_human_gate"] is False
    assert documentation.get_filed(exploit_id) is not None

    # Every step got logged for the Orchestrator's next decision.
    events = action_log.query()
    agents_seen = {e["agent"] for e in events}
    assert {"observability", "orchestrator", "red_team", "judge", "harness", "documentation"} <= agents_seen
    event_types_seen = {e["event_type"] for e in events}
    assert "exploit_recorded" in event_types_seen
    assert "vuln_report_filed" in event_types_seen


def test_critical_finding_stays_pending_human_approval(tmp_path):
    """identity_authz -> severity 'critical': the exploit IS stored, but the
    vuln_report is held pending human approval, never auto-filed."""
    recordings_dir = tmp_path / "recordings"
    db, action_log, documentation, judge, red_team, orchestrator = _new_agents(recordings_dir)

    result = run_campaign(
        orchestrator=orchestrator,
        red_team=red_team,
        judge=judge,
        documentation=documentation,
        db=db,
        action_log=action_log,
        action_log_ref=tmp_path / "action_log.jsonl",
        cases=[DOS_CASE, AUTHZ_CASE],
        target_client=lambda attempt: _vulnerable_response(),
        max_iterations=1,
        recordings_dir=recordings_dir,
        snapshot_fn=lambda: _full_coverage_snapshot("identity_authz"),
    )

    assert len(result.exploit_ids) == 1
    exploit_id = result.exploit_ids[0]
    assert db.get(exploit_id) is not None

    assert result.filed_reports == []
    assert len(result.pending_reports) == 1
    pending = result.pending_reports[0]
    assert pending["exploit_id"] == exploit_id
    assert pending["severity"] == "critical"
    assert pending["requires_human_gate"] is True
    assert pending["status"] == "pending_human_approval"

    assert documentation.get_pending(exploit_id) is not None
    assert documentation.get_filed(exploit_id) is None
    assert documentation.all_filed() == []


def test_budget_exceeded_stops_the_loop(tmp_path):
    """BudgetExceededError from the Orchestrator halts the campaign
    immediately -- no attempt, no verdict, on the iteration that trips it."""
    recordings_dir = tmp_path / "recordings"
    db, action_log, documentation, judge, red_team, orchestrator = _new_agents(
        recordings_dir, budget_max_cost=1.0
    )

    result = run_campaign(
        orchestrator=orchestrator,
        red_team=red_team,
        judge=judge,
        documentation=documentation,
        db=db,
        action_log=action_log,
        action_log_ref=tmp_path / "action_log.jsonl",
        cases=[DOS_CASE, AUTHZ_CASE],
        target_client=lambda attempt: _vulnerable_response(),
        max_iterations=5,
        recordings_dir=recordings_dir,
        snapshot_fn=lambda: _full_coverage_snapshot("denial_of_service", total_usd=5.0),
    )

    assert result.stopped_reason == "budget_exceeded"
    assert result.iterations_run == 1
    assert result.directives == []
    assert result.attempts == []
    assert result.exploit_ids == []
    assert len(result.signals) == 1
    assert result.signals[0]["error_type"] == "budget_exceeded"
    assert orchestrator.halted is True


def test_no_findings_in_window_is_surfaced_and_loop_continues(tmp_path):
    """A category that never confirms trips NoFindingsInWindowError; the
    campaign records the signal and keeps running (not a halt)."""
    recordings_dir = tmp_path / "recordings"
    db, action_log, documentation, judge, red_team, orchestrator = _new_agents(
        recordings_dir, no_findings_window=2
    )

    result = run_campaign(
        orchestrator=orchestrator,
        red_team=red_team,
        judge=judge,
        documentation=documentation,
        db=db,
        action_log=action_log,
        action_log_ref=tmp_path / "action_log.jsonl",
        cases=[DOS_CASE, AUTHZ_CASE],
        target_client=lambda attempt: _guard_held_response(),
        max_iterations=3,
        recordings_dir=recordings_dir,
        snapshot_fn=lambda: _full_coverage_snapshot("denial_of_service"),
    )

    assert result.stopped_reason == "max_iterations"
    assert result.iterations_run == 3
    assert result.exploit_ids == []
    no_findings_signals = [s for s in result.signals if s["error_type"] == "no_findings_in_window"]
    assert len(no_findings_signals) == 1
    assert no_findings_signals[0]["category"] == "denial_of_service"
    # verdicts kept scoring "fail" the whole time -- the guard held.
    assert all(v["outcome"] == "fail" for v in result.verdicts)


def test_regression_detected_is_surfaced(tmp_path):
    """A prior exploit marked 'fixed' whose recorded evidence still
    reproduces on a regression sweep surfaces a regression_detected signal
    -- driven through Orchestrator.trigger_regression_sweep, not
    reimplemented here."""
    recordings_dir = tmp_path / "recordings"
    db, action_log, documentation, judge, red_team, orchestrator = _new_agents(recordings_dir)

    # Seed one recorded, still-vulnerable draw for DOS_CASE and mark its
    # exploit record 'fixed' -- the reappearance shape
    # redteam.harness.regression.run_regression_sweep detects.
    recording_path = record_run(
        DOS_CASE.id, 1, _vulnerable_response(), "guard_not_held", True, recordings_dir=recordings_dir
    )
    exploit_id = db.next_exploit_id()
    db.add_record(
        {
            "schema_version": "1.0.0",
            "exploit_id": exploit_id,
            "case_id": DOS_CASE.id,
            "attempt_id": "draw1",
            "verdict_id": "ver-seed-0001",
            "category": "denial_of_service",
            "source": "judge",
            "confirmed_at": "2026-07-15T09:00:00Z",
            "minimal_repro": {
                "steps": ["seed"],
                "expected": "detect() returns vulnerable=False (guard holds)",
                "observed": "detect() returned vulnerable=True",
            },
            "recording_ref": str(recording_path),
        }
    )
    db.set_status(exploit_id, "fixed")

    result = run_campaign(
        orchestrator=orchestrator,
        red_team=red_team,
        judge=judge,
        documentation=documentation,
        db=db,
        action_log=action_log,
        action_log_ref=tmp_path / "action_log.jsonl",
        cases=[DOS_CASE, AUTHZ_CASE],
        target_client=lambda attempt: _guard_held_response(),
        max_iterations=1,
        recordings_dir=recordings_dir,
        regression_sweep_at=frozenset({1}),
        snapshot_fn=lambda: _full_coverage_snapshot("identity_authz"),
    )

    regression_signals = [s for s in result.signals if s["error_type"] == "regression_detected"]
    assert len(regression_signals) == 1
    assert regression_signals[0]["exploit_id"] == exploit_id
    assert regression_signals[0]["category"] == "denial_of_service"
    assert regression_signals[0]["previous_status"] == "fixed"
    # The Orchestrator itself boosts the regressed category for the very
    # next directive -- proof the signal actually feeds back into the loop.
    assert "denial_of_service" in orchestrator.flagged_categories


def test_judge_drift_suspected_is_surfaced_and_loop_continues(tmp_path):
    """A Judge whose scorer disagrees with the gold set trips
    judge_drift_suspected on the configured cadence; the campaign records
    it and keeps running (only a human's ``reanchor()`` clears the halt,
    never this loop)."""
    recordings_dir = tmp_path / "recordings"
    db, action_log, documentation, _judge, red_team, orchestrator = _new_agents(recordings_dir)

    def _flipping_scorer(case, response, detection):
        # Deliberately disagree with every gold label -- guaranteed to trip
        # the 0.95 agreement-rate threshold (ARCHITECTURE.md §6).
        return DetectionResult(vulnerable=not detection.vulnerable, label="forced-drift", evidence={})

    judge = JudgeAgent(scorer=_flipping_scorer)

    result = run_campaign(
        orchestrator=orchestrator,
        red_team=red_team,
        judge=judge,
        documentation=documentation,
        db=db,
        action_log=action_log,
        action_log_ref=tmp_path / "action_log.jsonl",
        cases=[DOS_CASE, AUTHZ_CASE],
        target_client=lambda attempt: _vulnerable_response(),
        max_iterations=1,
        recordings_dir=recordings_dir,
        drift_check_every=1,
        snapshot_fn=lambda: _full_coverage_snapshot("denial_of_service"),
    )

    drift_signals = [s for s in result.signals if s["error_type"] == "judge_drift_suspected"]
    assert len(drift_signals) == 1
    assert drift_signals[0]["drift_suspected"] is True
    assert judge.halted is True
    assert result.stopped_reason == "max_iterations"  # a halt, but never a loop stop


def test_empty_model_completion_is_skipped_not_fatal(tmp_path):
    """A model_client that returns an empty completion (a documented real
    possibility live, see red_team.py's module docstring) must not crash
    the whole autonomous run -- the iteration is skipped and recorded."""
    recordings_dir = tmp_path / "recordings"
    db, action_log, documentation, judge, _red_team, orchestrator = _new_agents(recordings_dir)
    red_team = RedTeamAgent(model_client=lambda prompt: "   ")  # whitespace-only -> rejected

    result = run_campaign(
        orchestrator=orchestrator,
        red_team=red_team,
        judge=judge,
        documentation=documentation,
        db=db,
        action_log=action_log,
        action_log_ref=tmp_path / "action_log.jsonl",
        cases=[DOS_CASE, AUTHZ_CASE],
        target_client=lambda attempt: _vulnerable_response(),
        max_iterations=1,
        recordings_dir=recordings_dir,
        snapshot_fn=lambda: _full_coverage_snapshot("denial_of_service"),
    )

    assert result.iterations_run == 1
    assert result.stopped_reason == "max_iterations"
    assert len(result.directives) == 1  # the directive was still issued
    assert result.attempts == []  # but no attempt was produced
    assert result.exploit_ids == []
    failed_signals = [s for s in result.signals if s["error_type"] == "attempt_generation_failed"]
    assert len(failed_signals) == 1


def test_max_iterations_must_be_positive(tmp_path):
    recordings_dir = tmp_path / "recordings"
    db, action_log, documentation, judge, red_team, orchestrator = _new_agents(recordings_dir)

    with pytest.raises(CampaignError):
        run_campaign(
            orchestrator=orchestrator,
            red_team=red_team,
            judge=judge,
            documentation=documentation,
            db=db,
            action_log=action_log,
            action_log_ref=tmp_path / "action_log.jsonl",
            cases=[DOS_CASE, AUTHZ_CASE],
            target_client=lambda attempt: _vulnerable_response(),
            max_iterations=0,
            recordings_dir=recordings_dir,
            snapshot_fn=lambda: _full_coverage_snapshot("denial_of_service"),
        )

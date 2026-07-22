"""Red-first: Observability Layer aggregation + Orchestrator-consumable
snapshot (docs/ARCHITECTURE.md §3(6),
contracts/v1/observability_snapshot.schema.json).

Imports ``redteam.observability``, which does not exist yet as of this
commit -- every test in this module fails on collection until it's built.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from evals.cases.data_exfil_verification_bypass import CASE as DATA_EXFIL_CASE
from evals.cases.dos_input_bound import CASE as DOS_CASE
from evals.cases.identity_authz import CASE as AUTHZ_CASE
from redteam.harness.db import ExploitDB
from redteam.observability import (
    ActionLog,
    ActionLogError,
    SuiteRunLog,
    compute_coverage,
    compute_cost,
    emit_snapshot,
    open_high_sev_count,
    resilience_trend,
    status_counts,
)
from redteam.harness.replay import run_suite_replay

REPO_ROOT = Path(__file__).resolve().parents[2]
RECORDINGS_DIR = REPO_ROOT / "evals" / "recordings"
SCHEMA_PATH = REPO_ROOT / "contracts" / "v1" / "observability_snapshot.schema.json"

ALL_CASES = [AUTHZ_CASE, DATA_EXFIL_CASE, DOS_CASE]
ALL_CATEGORIES = {
    "prompt_injection",
    "data_exfiltration",
    "state_corruption",
    "tool_misuse",
    "denial_of_service",
    "identity_authz",
}

CONFIRMED_RECORD = {
    "schema_version": "1.0.0",
    "exploit_id": "EXP-0001",
    "case_id": DATA_EXFIL_CASE.id,
    "attempt_id": "draw1",
    "verdict_id": "ver-0001",
    "category": "data_exfiltration",
    "source": "judge",
    "confirmed_at": "2026-07-22T03:15:00Z",
    "minimal_repro": {
        "steps": ["Ask medications question for pid=2", "observe discontinued med marked verified"],
        "expected": "verdict != verified for a discontinued-med claim",
        "observed": "verdict == verified",
    },
    "recording_ref": "evals/recordings/data-exfil-discontinued-med-marked-verified/20260722T031455Z-draw1.json",
}


# -- coverage -----------------------------------------------------------------


def test_coverage_counts_all_six_categories():
    db = ExploitDB(":memory:")
    coverage = compute_coverage(db, ALL_CASES, recordings_dir=RECORDINGS_DIR)
    assert set(coverage) == ALL_CATEGORIES

    # A category with no cases/recordings at all is still explicitly present.
    assert coverage["state_corruption"].probes_run == 0
    assert coverage["state_corruption"].last_run_status == "not_run"
    assert coverage["state_corruption"].coverage_fraction == 0.0

    # Categories with committed recordings pick up real replayed attempts.
    assert coverage["data_exfiltration"].probes_run == 3
    assert coverage["data_exfiltration"].last_run_status == "vulnerable_confirmed"
    assert coverage["data_exfiltration"].coverage_fraction == 1.0

    assert coverage["identity_authz"].probes_run == 3
    assert coverage["identity_authz"].last_run_status == "vulnerable_confirmed"

    assert coverage["denial_of_service"].probes_run == 1
    assert coverage["denial_of_service"].coverage_fraction == pytest.approx(1 / 3)


def test_coverage_exploits_found_from_db():
    db = ExploitDB(":memory:")
    db.add_record(CONFIRMED_RECORD)
    coverage = compute_coverage(db, ALL_CASES, recordings_dir=RECORDINGS_DIR)
    assert coverage["data_exfiltration"].exploits_found == 1
    assert coverage["identity_authz"].exploits_found == 0


# -- cost (local-compute proxy, not dollars) -----------------------------------


def test_cost_is_a_documented_compute_proxy_not_dollars():
    cost = compute_cost(ALL_CASES, recordings_dir=RECORDINGS_DIR)
    assert cost.total_compute_seconds > 0
    assert cost.cost_scaling_rate > 0

    contract_shape = cost.as_contract_cost()
    assert set(contract_shape) == {"total_usd", "cost_scaling_rate"}
    # "total_usd" is the contract's inherited field name -- populated here
    # with the compute-seconds figure, not a dollar amount.
    assert contract_shape["total_usd"] == round(cost.total_compute_seconds, 3)


def test_cost_zero_when_no_case_has_two_recorded_draws():
    cost = compute_cost([DOS_CASE], recordings_dir=RECORDINGS_DIR)  # 1 recorded draw only
    assert cost.total_compute_seconds == 0.0
    assert cost.cost_scaling_rate == 0.0


# -- open/in-progress/resolved + open-high-sev ---------------------------------


def test_status_counts_map_exploit_db_statuses():
    db = ExploitDB(":memory:")
    db.add_record(CONFIRMED_RECORD)
    assert status_counts(db) == {"open": 1, "in_progress": 0, "resolved": 0}

    db.set_status("EXP-0001", "mitigated")
    assert status_counts(db) == {"open": 0, "in_progress": 1, "resolved": 0}

    db.set_status("EXP-0001", "fixed")
    assert status_counts(db) == {"open": 0, "in_progress": 0, "resolved": 1}


def test_open_high_sev_count_needs_a_matching_vuln_report():
    db = ExploitDB(":memory:")
    db.add_record(CONFIRMED_RECORD)

    assert open_high_sev_count(db, []) == 0  # honest zero, no P3.13 reports yet

    report = {"exploit_id": "EXP-0001", "severity": "high"}
    assert open_high_sev_count(db, [report]) == 1

    low_report = {"exploit_id": "EXP-0001", "severity": "low"}
    assert open_high_sev_count(db, [low_report]) == 0

    db.set_status("EXP-0001", "fixed")
    assert open_high_sev_count(db, [report]) == 0  # resolved, no longer "open"


# -- resilience trend -----------------------------------------------------------


def test_resilience_trend_insufficient_data_on_empty_db():
    db = ExploitDB(":memory:")
    assert resilience_trend(db) == "insufficient_data"


def test_resilience_trend_improving_when_resolved_outnumber_open():
    db = ExploitDB(":memory:")
    db.add_record(CONFIRMED_RECORD)
    db.set_status("EXP-0001", "fixed")
    assert resilience_trend(db) == "improving"


def test_resilience_trend_stable_when_open_outnumbers_resolved():
    db = ExploitDB(":memory:")
    db.add_record(CONFIRMED_RECORD)
    assert resilience_trend(db) == "stable"


def test_resilience_trend_regressing_on_reappearance():
    db = ExploitDB(":memory:")
    db.add_record(CONFIRMED_RECORD)
    db.set_status("EXP-0001", "fixed")
    regression = {"error_type": "regression_detected", "exploit_id": "EXP-0001"}
    assert resilience_trend(db, [regression]) == "regressing"


# -- action log -------------------------------------------------------------


def test_action_log_append_and_query():
    log = ActionLog(":memory:")
    log.append(
        agent="orchestrator",
        event_type="directive_sent",
        case_id=AUTHZ_CASE.id,
        category="identity_authz",
    )
    log.append(
        agent="red_team",
        event_type="probe_sent",
        case_id=AUTHZ_CASE.id,
        category="identity_authz",
    )
    assert len(log.query()) == 2
    assert len(log.query(agent="orchestrator")) == 1
    assert log.query(event_type="probe_sent")[0]["case_id"] == AUTHZ_CASE.id


def test_action_log_rejects_unknown_agent():
    log = ActionLog(":memory:")
    with pytest.raises(ActionLogError):
        log.append(agent="not-a-real-agent", event_type="x")


def test_action_log_rejects_empty_event_type():
    log = ActionLog(":memory:")
    with pytest.raises(ActionLogError):
        log.append(agent="orchestrator", event_type="")


def test_action_log_export_jsonl_is_reloadable(tmp_path):
    log = ActionLog(":memory:")
    log.append(agent="observability", event_type="snapshot_emitted", details={"n": 1})
    out = log.export_jsonl(tmp_path / "action_log.jsonl")
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    reloaded = json.loads(lines[0])
    assert reloaded["agent"] == "observability"
    assert reloaded["details"] == {"n": 1}


# -- pass/fail over versions --------------------------------------------------


def test_suite_run_log_tracks_pass_fail_by_version():
    attempts = run_suite_replay(ALL_CASES, recordings_dir=RECORDINGS_DIR)
    log = SuiteRunLog(":memory:")
    log.record_run(attempts, target_version="v2.0.0")
    runs = log.by_version()
    assert len(runs) == 1
    assert runs[0]["target_version"] == "v2.0.0"
    assert runs[0]["total_attempts"] == len(attempts)
    assert runs[0]["vulnerable_count"] == sum(1 for a in attempts if a.result.vulnerable)


# -- emit_snapshot(): the contract-shaped Orchestrator edge --------------------


def test_emit_snapshot_validates_against_contract(tmp_path):
    db = ExploitDB(":memory:")
    db.add_record(CONFIRMED_RECORD)
    log = ActionLog(":memory:")
    log.append(agent="observability", event_type="snapshot_emitted")
    ref = tmp_path / "action_log.jsonl"

    snapshot = emit_snapshot(db, ALL_CASES, log, str(ref), recordings_dir=RECORDINGS_DIR)

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors = list(validator.iter_errors(snapshot))
    assert errors == [], "; ".join(f"{list(e.path)}: {e.message}" for e in errors)

    assert ref.exists()  # action_log_ref points at a real, re-readable file
    assert set(snapshot["coverage_by_category"]) == ALL_CATEGORIES


def test_emit_snapshot_open_high_sev_wired_through(tmp_path):
    db = ExploitDB(":memory:")
    db.add_record(CONFIRMED_RECORD)
    log = ActionLog(":memory:")
    ref = tmp_path / "action_log.jsonl"
    report = {"exploit_id": "EXP-0001", "severity": "critical"}

    snapshot = emit_snapshot(
        db,
        ALL_CASES,
        log,
        str(ref),
        recordings_dir=RECORDINGS_DIR,
        vuln_reports=[report],
    )
    assert snapshot["open_high_sev_count"] == 1


def test_emit_snapshot_is_deterministic_given_explicit_ids(tmp_path):
    db = ExploitDB(":memory:")
    log = ActionLog(":memory:")
    ref = tmp_path / "action_log.jsonl"

    snap_1 = emit_snapshot(
        db, ALL_CASES, log, str(ref), recordings_dir=RECORDINGS_DIR,
        generated_at="2026-07-21T10:09:00Z", snapshot_id="obs-0001",
    )
    snap_2 = emit_snapshot(
        db, ALL_CASES, log, str(ref), recordings_dir=RECORDINGS_DIR,
        generated_at="2026-07-21T10:09:00Z", snapshot_id="obs-0001",
    )
    assert snap_1 == snap_2

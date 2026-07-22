"""Red-first: Judge Agent (P3.7, issue #8; docs/ARCHITECTURE.md §3(2)/§6).

Imports ``redteam.agents.judge`` which does not exist yet as of this commit
-- this whole module fails to collect until the implementation lands.

Covers:
  * verdicts validate against contracts/v1/judge_verdict.schema.json
  * outcome mapping (success/fail/partial/regression) off the case's own
    rule-based ``detect`` predicate -- no model call in the default path
  * architectural independence from any Red Team module (ast-checked)
  * judge_timeout emission when scoring exceeds budget
  * drift detection: clean gold-set path, and a synthetic drift that trips
    ``judge_drift_suspected`` via both the agreement-rate and single-flip
    triggers, plus the human-only ``reanchor`` correction path
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from evals.cases.dos_input_bound import CASE as DOS_CASE
from evals.cases.identity_authz import CASE as AUTHZ_CASE
from evals.runner import ParsedResponse
from redteam.agents.judge import (
    GOLD_PROBE_SET,
    JudgeAgent,
    JudgeDriftSuspectedError,
    JudgeTimeoutError,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
JUDGE_VERDICT_SCHEMA = REPO_ROOT / "contracts" / "v1" / "judge_verdict.schema.json"
JUDGE_TIMEOUT_SCHEMA = REPO_ROOT / "contracts" / "v1" / "errors" / "judge_timeout.schema.json"
JUDGE_MODULE_PATH = REPO_ROOT / "redteam" / "agents" / "judge.py"


def _validate(schema_path: Path, instance: dict) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(instance), key=lambda e: list(e.path))
    if errors:
        messages = "; ".join(f"{list(e.path)}: {e.message}" for e in errors)
        pytest.fail(f"expected instance to be schema-valid, got: {messages}")


VULNERABLE_AUTHZ_RESPONSE = ParsedResponse(
    status=200,
    events=[("answer", {"answer": "Patient is on lisinopril."})],
    raw_stdout="",
    raw_stderr="",
    ok=True,
)

REJECTED_AUTHZ_RESPONSE = ParsedResponse(
    status=401,
    events=[],
    raw_stdout="",
    raw_stderr="",
    ok=True,
)

INCONCLUSIVE_DOS_RESPONSE = ParsedResponse(
    status=None,
    events=[],
    raw_stdout="",
    raw_stderr="",
    ok=True,
)


def test_verdict_validates_against_contract():
    judge = JudgeAgent()
    verdict = judge.score(AUTHZ_CASE, VULNERABLE_AUTHZ_RESPONSE, attempt_id="att-0001")
    _validate(JUDGE_VERDICT_SCHEMA, verdict)
    assert verdict["outcome"] == "success"
    assert verdict["case_id"] == AUTHZ_CASE.id
    assert verdict["attempt_id"] == "att-0001"


def test_fail_outcome_for_clean_reject():
    judge = JudgeAgent()
    verdict = judge.score(AUTHZ_CASE, REJECTED_AUTHZ_RESPONSE, attempt_id="att-0002")
    _validate(JUDGE_VERDICT_SCHEMA, verdict)
    assert verdict["outcome"] == "fail"


def test_partial_outcome_for_inconclusive_detection():
    judge = JudgeAgent()
    verdict = judge.score(DOS_CASE, INCONCLUSIVE_DOS_RESPONSE, attempt_id="att-0003")
    _validate(JUDGE_VERDICT_SCHEMA, verdict)
    assert verdict["outcome"] == "partial"


def test_regression_outcome_when_previously_confirmed():
    judge = JudgeAgent()
    verdict = judge.score(
        AUTHZ_CASE,
        VULNERABLE_AUTHZ_RESPONSE,
        attempt_id="att-0004",
        previously_confirmed=True,
    )
    _validate(JUDGE_VERDICT_SCHEMA, verdict)
    assert verdict["outcome"] == "regression"


def test_deterministic_default_path_is_reproducible_no_model_call():
    judge = JudgeAgent()
    v1 = judge.score(
        AUTHZ_CASE, VULNERABLE_AUTHZ_RESPONSE, attempt_id="att-x", verdict_id="ver-fixed",
        scored_at="2026-07-21T10:00:00Z",
    )
    v2 = judge.score(
        AUTHZ_CASE, VULNERABLE_AUTHZ_RESPONSE, attempt_id="att-x", verdict_id="ver-fixed",
        scored_at="2026-07-21T10:00:00Z",
    )
    assert v1 == v2


def test_independence_module_imports_no_red_team_or_sibling_agent_internals():
    """Architectural independence (ARCHITECTURE.md §3(2)/§6): the Judge must
    not import any Red Team module, nor any sibling agent module, nor the
    Regression Harness's stateful internals -- it scores purely from
    (case, response). There is no Red Team module yet, so this also guards
    the module going forward: adding `import redteam.agents.red_team` (or
    similar) here should fail this test the moment such a module exists."""
    source = JUDGE_MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(JUDGE_MODULE_PATH))
    forbidden_prefixes = ("redteam.agents", "redteam.harness")
    offending: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith(forbidden_prefixes):
                    offending.append(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module.startswith(forbidden_prefixes):
                offending.append(node.module)
    assert offending == [], f"judge.py must not import Red Team / sibling-agent internals: {offending}"


def test_judge_timeout_raised_when_scoring_exceeds_budget():
    clock_values = iter([0.0, 999.0])  # elapsed 999s >> any sane budget
    judge = JudgeAgent(timeout_seconds=5.0, clock=lambda: next(clock_values))
    with pytest.raises(JudgeTimeoutError) as excinfo:
        judge.score(AUTHZ_CASE, VULNERABLE_AUTHZ_RESPONSE, attempt_id="att-slow")
    error = excinfo.value.error
    assert error["error_type"] == "judge_timeout"
    assert error["attempt_id"] == "att-slow"
    assert error["case_id"] == AUTHZ_CASE.id
    _validate(JUDGE_TIMEOUT_SCHEMA, error)


def test_gold_probe_set_is_nonempty_and_fixed():
    assert len(GOLD_PROBE_SET) >= 3


def test_clean_gold_set_shows_no_drift():
    judge = JudgeAgent()
    result = judge.check_drift()
    assert result["drift_suspected"] is False
    assert result["agreement_rate"] == 1.0
    assert result["flipped_cases"] == []
    assert judge.halted is False

    # A second clean sweep with nothing changed must also show no drift.
    result2 = judge.check_drift()
    assert result2["drift_suspected"] is False
    assert result2["flipped_cases"] == []


def test_synthetic_drift_trips_judge_drift_suspected_and_halts():
    judge = JudgeAgent()
    baseline = judge.check_drift()
    assert baseline["drift_suspected"] is False

    # Simulate a drifting model: a scorer that flips every gold case's
    # vulnerability call, corrupting the previously-clean judge.
    def corrupting_scorer(case, response, detection):
        from evals.schema import DetectionResult

        return DetectionResult(
            vulnerable=not detection.vulnerable,
            label="corrupted",
            evidence=dict(detection.evidence),
        )

    drifted_judge = JudgeAgent(scorer=corrupting_scorer)
    # Seed the drifted judge's prior-score baseline from the same clean
    # sweep so a flip is detectable against "its previous run's score".
    drifted_judge._gold_prior_outcomes = dict(judge._gold_prior_outcomes)  # noqa: SLF001

    with pytest.raises(JudgeDriftSuspectedError) as excinfo:
        drifted_judge.check_drift()

    result = excinfo.value.error
    assert result["drift_suspected"] is True
    assert result["agreement_rate"] < 0.95
    assert len(result["flipped_cases"]) >= 1
    assert drifted_judge.halted is True

    # Correction is human-routed, never automatic: verdicts keep flagging
    # drift_suspected until a human explicitly reanchors.
    verdict = drifted_judge.score(AUTHZ_CASE, VULNERABLE_AUTHZ_RESPONSE, attempt_id="att-post-drift")
    assert verdict["drift_check"]["drift_suspected"] is True

    drifted_judge.reanchor()
    assert drifted_judge.halted is False
    verdict_after = drifted_judge.score(AUTHZ_CASE, VULNERABLE_AUTHZ_RESPONSE, attempt_id="att-post-reanchor")
    assert verdict_after["drift_check"]["drift_suspected"] is False

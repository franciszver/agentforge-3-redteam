"""Red-first: reappearance + cross-category regression detection.

Imports ``redteam.harness.*`` modules that do not exist yet as of this
commit -- the whole file is expected to fail collection (ModuleNotFoundError)
until the harness is implemented. Uses the real, committed
``evals/recordings/*`` evidence (P3.4 live draws) via replay mode -- no live
target/model call is made anywhere in this file.
"""

from __future__ import annotations

import datetime as _dt

import pytest
from jsonschema import Draft202012Validator

from evals.cases.data_exfil_verification_bypass import CASE as DATA_EXFIL_CASE
from evals.cases.dos_input_bound import CASE as DOS_CASE
from evals.cases.identity_authz import CASE as AUTHZ_CASE
from redteam.harness.db import ExploitDB
from redteam.harness.regression import run_regression_sweep
from tests.contracts.conftest import load_schema

AUTHZ_CASE_ID = AUTHZ_CASE.id  # "identity-authz-garbage-bearer-token"
AUTHZ_ATTEMPT_ID = "draw1"  # matches evals/recordings/.../*-draw1.json


def _fixed_authz_record(db: ExploitDB, *, confirmed_at: str = "2026-07-15T09:00:00Z") -> str:
    """Seed the DB with a confirmed-then-fixed exploit for the authz case/draw1."""
    exploit_id = db.next_exploit_id()
    db.add_record(
        {
            "schema_version": "1.0.0",
            "exploit_id": exploit_id,
            "case_id": AUTHZ_CASE_ID,
            "attempt_id": AUTHZ_ATTEMPT_ID,
            "verdict_id": "ver-seed-0001",
            "category": AUTHZ_CASE.category,
            "source": "judge",
            "confirmed_at": confirmed_at,
            "minimal_repro": {
                "steps": ["POST /chat with a garbage bearer token"],
                "expected": "401/403 rejection",
                "observed": "200 with PHI",
            },
            "recording_ref": f"evals/recordings/{AUTHZ_CASE_ID}/20260722T031420Z-draw1.json",
        }
    )
    db.set_status(exploit_id, "fixed", updated_at="2026-07-18T09:00:00Z")
    return exploit_id


def test_reintroduced_fixed_exploit_flagged_as_regression():
    """A previously fixed exploit that reproduces again must be flagged."""
    db = ExploitDB(":memory:")
    exploit_id = _fixed_authz_record(db)
    assert db.get(exploit_id)["status"] == "fixed"

    regressions = run_regression_sweep(db, [AUTHZ_CASE])

    assert len(regressions) == 1
    reg = regressions[0]
    assert reg["error_type"] == "regression_detected"
    assert reg["exploit_id"] == exploit_id
    assert reg["category"] == "identity_authz"
    assert reg["previous_status"] == "fixed"
    # detected_at must be a real ISO-8601 timestamp, not a placeholder.
    _dt.datetime.strptime(reg["detected_at"], "%Y-%m-%dT%H:%M:%SZ")

    # the fixed record's own status is untouched (a human/Orchestrator
    # decision to reopen it, not something the sweep does silently).
    assert db.get(exploit_id)["status"] == "fixed"


def test_reintroduced_exploit_emits_error_valid_against_contract_schema():
    db = ExploitDB(":memory:")
    _fixed_authz_record(db)
    regressions = run_regression_sweep(db, [AUTHZ_CASE])
    schema = load_schema("errors/regression_detected.schema.json")
    validator = Draft202012Validator(schema)
    errors = list(validator.iter_errors(regressions[0]))
    assert not errors, [e.message for e in errors]


def test_no_regression_when_exploit_still_open():
    """An open (never-fixed) exploit reproducing is not a *regression*."""
    db = ExploitDB(":memory:")
    exploit_id = db.next_exploit_id()
    db.add_record(
        {
            "schema_version": "1.0.0",
            "exploit_id": exploit_id,
            "case_id": AUTHZ_CASE_ID,
            "attempt_id": AUTHZ_ATTEMPT_ID,
            "verdict_id": "ver-seed-0002",
            "category": AUTHZ_CASE.category,
            "source": "judge",
            "confirmed_at": "2026-07-15T09:00:00Z",
            "minimal_repro": {
                "steps": ["POST /chat with a garbage bearer token"],
                "expected": "401/403 rejection",
                "observed": "200 with PHI",
            },
            "recording_ref": f"evals/recordings/{AUTHZ_CASE_ID}/20260722T031420Z-draw1.json",
        }
    )
    # status stays "open" (default) -- never marked fixed.
    regressions = run_regression_sweep(db, [AUTHZ_CASE])
    assert regressions == []


def test_cross_category_regression_flagged_and_recorded():
    """A brand-new exploit in a different category than a recent fix.

    The DB has a fixed identity_authz exploit; the DOS case has never been
    confirmed before and its replayed recording reproduces vulnerable=True
    -- that is the "cross-category regression from a fix" shape.
    """
    db = ExploitDB(":memory:")
    fixed_id = _fixed_authz_record(db)

    regressions = run_regression_sweep(db, [DOS_CASE])

    assert len(regressions) == 1
    reg = regressions[0]
    assert reg["error_type"] == "regression_detected"
    assert reg["category"] == "denial_of_service"
    assert reg["previous_status"] == "fixed"
    assert reg["exploit_id"] != fixed_id

    # the sweep leaves an evidence trail: a new confirmed exploit record.
    new_record = db.get(reg["exploit_id"])
    assert new_record is not None
    assert new_record["record"]["case_id"] == DOS_CASE.id
    assert new_record["record"]["source"] == "harness"


def test_no_cross_category_regression_without_a_prior_fix():
    """No fixed record anywhere in the DB -> a fresh finding is not flagged
    as a regression (it is a first-time confirmed exploit, out of this
    harness's regression-emission scope)."""
    db = ExploitDB(":memory:")
    regressions = run_regression_sweep(db, [DOS_CASE, DATA_EXFIL_CASE])
    assert regressions == []


def test_same_category_new_attempt_not_flagged_cross_category():
    """draw2/draw3 of the SAME case as a fixed draw1: new attempt_ids, but
    same category as the fix -- must not be flagged as cross-category
    (only draw1's exact reappearance is a regression; draw2/draw3 are new
    attack-sequences the DB has never confirmed, in the *same* category as
    the fix, so neither regression shape applies to them)."""
    db = ExploitDB(":memory:")
    _fixed_authz_record(db)  # fixed identity_authz / draw1 only

    regressions = run_regression_sweep(db, [AUTHZ_CASE])

    # Only draw1 (the exact fixed sequence) is flagged, as reappearance.
    assert len(regressions) == 1
    assert regressions[0]["previous_status"] == "fixed"
    assert regressions[0]["category"] == "identity_authz"
    flagged_exploit = db.get(regressions[0]["exploit_id"])
    assert flagged_exploit["attempt_id"] == "draw1"

"""Red-first: deterministic replay-mode suite runner.

Imports ``redteam.harness.replay`` which does not exist yet as of this
commit. No live target/model call anywhere in this file -- everything
reads the real, committed ``evals/recordings/*`` files.
"""

from __future__ import annotations

from evals.cases.data_exfil_verification_bypass import CASE as DATA_EXFIL_CASE
from evals.cases.dos_input_bound import CASE as DOS_CASE
from evals.cases.identity_authz import CASE as AUTHZ_CASE
from redteam.harness.replay import replay_case, run_suite_replay


def test_replay_case_reads_all_recordings_for_the_case():
    attempts = replay_case(AUTHZ_CASE)
    assert len(attempts) == 3  # draw1, draw2, draw3 committed recordings
    assert {a.attempt_id for a in attempts} == {"draw1", "draw2", "draw3"}
    assert all(a.case_id == AUTHZ_CASE.id for a in attempts)
    assert all(a.category == "identity_authz" for a in attempts)
    assert all(a.result.vulnerable is True for a in attempts)  # known live evidence


def test_replay_case_applies_the_case_own_detect_predicate():
    attempts = replay_case(DOS_CASE)
    assert len(attempts) == 1
    assert attempts[0].result.label == "guard_not_held"
    assert attempts[0].result.vulnerable is True


def test_replay_case_missing_recordings_dir_returns_empty():
    class _FakeCase:
        id = "no-such-case-id"

    attempts = replay_case(_FakeCase())  # type: ignore[arg-type]
    assert attempts == []


def test_replay_is_deterministic_across_repeated_runs():
    first = replay_case(DATA_EXFIL_CASE)
    second = replay_case(DATA_EXFIL_CASE)
    assert len(first) == len(second) == 3
    for a, b in zip(first, second):
        assert a.case_id == b.case_id
        assert a.attempt_id == b.attempt_id
        assert a.recording_ref == b.recording_ref
        assert a.result.vulnerable == b.result.vulnerable
        assert a.result.label == b.result.label
        assert a.result.evidence == b.result.evidence


def test_run_suite_replay_flattens_all_cases():
    attempts = run_suite_replay([AUTHZ_CASE, DOS_CASE, DATA_EXFIL_CASE])
    assert len(attempts) == 3 + 1 + 3
    case_ids = {a.case_id for a in attempts}
    assert case_ids == {AUTHZ_CASE.id, DOS_CASE.id, DATA_EXFIL_CASE.id}


def test_recording_ref_points_into_evals_recordings():
    attempts = replay_case(AUTHZ_CASE)
    for a in attempts:
        assert a.recording_ref.replace("\\", "/").startswith("evals/recordings/")

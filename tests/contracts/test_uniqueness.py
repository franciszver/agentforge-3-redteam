"""Contract tests for contracts/v1/uniqueness.py.

JSON Schema 2020-12 has no way to express "unique by property X across an
array of objects" (uniqueItems only catches exact whole-object duplicates),
so the exploit-DB's uniqueness constraints -- unique exploit_id, no
duplicate attack-sequence entries -- are enforced by this small stdlib
helper instead. Both the harness and these contract tests import it, so
there is exactly one implementation of the rule.
"""

from __future__ import annotations

from contracts.v1.uniqueness import find_duplicate_exploit_ids, find_duplicate_attack_sequences


def _record(exploit_id: str, case_id: str, attempt_id: str) -> dict:
    return {
        "exploit_id": exploit_id,
        "case_id": case_id,
        "attempt_id": attempt_id,
        "category": "identity_authz",
        "source": "judge",
        "confirmed_at": "2026-07-21T10:07:00Z",
        "minimal_repro": {"steps": ["x"], "expected": "a", "observed": "b"},
        "recording_ref": "evals/recordings/x/y.json",
    }


def test_unique_exploit_ids_pass_clean():
    records = [
        _record("EXP-0001", "case-a", "att-0001"),
        _record("EXP-0002", "case-b", "att-0002"),
    ]
    assert find_duplicate_exploit_ids(records) == []


def test_duplicate_exploit_ids_detected():
    records = [
        _record("EXP-0001", "case-a", "att-0001"),
        _record("EXP-0001", "case-b", "att-0002"),
    ]
    assert find_duplicate_exploit_ids(records) == ["EXP-0001"]


def test_no_duplicate_attack_sequences_pass_clean():
    records = [
        _record("EXP-0001", "case-a", "att-0001"),
        _record("EXP-0002", "case-a", "att-0002"),
    ]
    assert find_duplicate_attack_sequences(records) == []


def test_duplicate_attack_sequence_detected():
    # Same (case_id, attempt_id) confirmed twice as a distinct exploit is a
    # duplicate attack-sequence entry -- the same probe can't be two
    # different confirmed exploits.
    records = [
        _record("EXP-0001", "case-a", "att-0001"),
        _record("EXP-0002", "case-a", "att-0001"),
    ]
    assert find_duplicate_attack_sequences(records) == [("case-a", "att-0001")]

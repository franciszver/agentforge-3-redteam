"""Contract tests for contracts/v1/attack_attempt.schema.json.

Edge: Red Team Agent -> target / Judge Agent (docs/ARCHITECTURE.md §2).
Aligns with evals.schema.AttackCase's fields (category, patient_id, message).
"""

from __future__ import annotations

from tests.contracts.conftest import assert_invalid, assert_valid, load_example, load_schema


def test_valid_example_passes():
    schema = load_schema("attack_attempt.schema.json")
    instance = load_example("attack_attempt/valid.json")
    assert_valid(schema, instance)


def test_invalid_example_rejected():
    schema = load_schema("attack_attempt.schema.json")
    instance = load_example("attack_attempt/invalid.json")
    assert_invalid(schema, instance)

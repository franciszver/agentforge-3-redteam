"""Contract tests for contracts/v1/attack_directive.schema.json.

Edge: Orchestrator -> Red Team Agent (docs/ARCHITECTURE.md §2).
"""

from __future__ import annotations

from tests.contracts.conftest import assert_invalid, assert_valid, load_example, load_schema


def test_valid_example_passes():
    schema = load_schema("attack_directive.schema.json")
    instance = load_example("attack_directive/valid.json")
    assert_valid(schema, instance)


def test_invalid_example_rejected():
    schema = load_schema("attack_directive.schema.json")
    instance = load_example("attack_directive/invalid.json")
    assert_invalid(schema, instance)

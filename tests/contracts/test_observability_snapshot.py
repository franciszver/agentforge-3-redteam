"""Contract tests for contracts/v1/observability_snapshot.schema.json.

Edge: Observability Layer -> Orchestrator (docs/ARCHITECTURE.md §2).
"""

from __future__ import annotations

from tests.contracts.conftest import assert_invalid, assert_valid, load_example, load_schema


def test_valid_example_passes():
    schema = load_schema("observability_snapshot.schema.json")
    instance = load_example("observability_snapshot/valid.json")
    assert_valid(schema, instance)


def test_invalid_example_rejected():
    schema = load_schema("observability_snapshot.schema.json")
    instance = load_example("observability_snapshot/invalid.json")
    assert_invalid(schema, instance)

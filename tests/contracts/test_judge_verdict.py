"""Contract tests for contracts/v1/judge_verdict.schema.json.

Edge: Judge Agent -> Orchestrator (docs/ARCHITECTURE.md §2), including the
drift-check signal described in ARCHITECTURE.md §6.
"""

from __future__ import annotations

from tests.contracts.conftest import assert_invalid, assert_valid, load_example, load_schema


def test_valid_example_passes():
    schema = load_schema("judge_verdict.schema.json")
    instance = load_example("judge_verdict/valid.json")
    assert_valid(schema, instance)


def test_invalid_example_rejected():
    schema = load_schema("judge_verdict.schema.json")
    instance = load_example("judge_verdict/invalid.json")
    assert_invalid(schema, instance)

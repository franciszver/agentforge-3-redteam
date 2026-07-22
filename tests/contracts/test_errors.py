"""Contract tests for contracts/v1/errors/*.schema.json.

Typed per-agent errors: target_unreachable, budget_exceeded, judge_timeout,
no_findings_in_window, regression_detected. Each schema pins error_type to a
stable const so a consumer can dispatch on it without inspecting shape.
"""

from __future__ import annotations

import pytest

from tests.contracts.conftest import assert_invalid, assert_valid, load_example, load_schema

ERROR_TYPES = [
    "target_unreachable",
    "budget_exceeded",
    "judge_timeout",
    "no_findings_in_window",
    "regression_detected",
]


@pytest.mark.parametrize("error_type", ERROR_TYPES)
def test_valid_example_passes(error_type: str):
    schema = load_schema(f"errors/{error_type}.schema.json")
    instance = load_example(f"errors/{error_type}/valid.json")
    assert_valid(schema, instance)


@pytest.mark.parametrize("error_type", ERROR_TYPES)
def test_invalid_example_rejected(error_type: str):
    schema = load_schema(f"errors/{error_type}.schema.json")
    instance = load_example(f"errors/{error_type}/invalid.json")
    assert_invalid(schema, instance)


@pytest.mark.parametrize("error_type", ERROR_TYPES)
def test_error_type_is_a_stable_const(error_type: str):
    schema = load_schema(f"errors/{error_type}.schema.json")
    assert schema["properties"]["error_type"] == {"const": error_type}

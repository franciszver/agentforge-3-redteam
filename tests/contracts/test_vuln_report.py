"""Contract tests for contracts/v1/vuln_report.schema.json.

Edge: Documentation Agent -> human approval gate (docs/ARCHITECTURE.md §2/§3).
Also asserts the critical-severity -> requires_human_gate=true conditional
that backs "nothing critical self-publishes."
"""

from __future__ import annotations

from tests.contracts.conftest import assert_invalid, assert_valid, load_example, load_schema


def test_valid_example_passes():
    schema = load_schema("vuln_report.schema.json")
    instance = load_example("vuln_report/valid.json")
    assert_valid(schema, instance)


def test_invalid_example_rejected():
    schema = load_schema("vuln_report.schema.json")
    instance = load_example("vuln_report/invalid.json")
    assert_invalid(schema, instance)


def test_critical_severity_requires_human_gate_true():
    schema = load_schema("vuln_report.schema.json")
    instance = load_example("vuln_report/valid.json")
    instance = dict(instance, requires_human_gate=False)
    assert_invalid(schema, instance)

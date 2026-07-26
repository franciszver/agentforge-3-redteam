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


def test_recording_ref_accepts_a_real_recordings_directory():
    schema = load_schema("vuln_report.schema.json")
    instance = load_example("vuln_report/valid.json")
    instance = dict(instance, recording_ref="evals/recordings/identity-authz-garbage-bearer-token/")
    assert_valid(schema, instance)


def test_recording_ref_rejects_dot_dot_path_traversal():
    """Sec-audit finding (issue #77 review): exploit_record.schema.json's
    case_id has no character-restricting pattern (only minLength: 1), and
    build_vuln_report() derives recording_ref as
    f"evals/recordings/{case_id}/" with no sanitization. A permissive
    '[^/]+' single-segment pattern would let case_id=".." produce a
    schema-valid recording_ref ("evals/recordings/../") that resolves
    OUTSIDE evals/recordings/ entirely. The pattern is scoped to the
    lowercase-alphanumeric-plus-hyphen charset every real case_id in this
    repo actually uses, which structurally excludes "." (so ".." can never
    validate) -- this pins that exclusion as a contract-level guarantee,
    not just an implementation detail."""
    schema = load_schema("vuln_report.schema.json")
    instance = load_example("vuln_report/valid.json")
    instance = dict(instance, recording_ref="evals/recordings/../")
    assert_invalid(schema, instance)


def test_recording_ref_rejects_a_bare_filename_not_a_directory():
    schema = load_schema("vuln_report.schema.json")
    instance = load_example("vuln_report/valid.json")
    instance = dict(
        instance,
        recording_ref="evals/recordings/identity-authz-garbage-bearer-token/20260722T031420Z-draw1.json",
    )
    assert_invalid(schema, instance)

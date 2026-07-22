"""Proves attack_attempt.schema.json actually aligns with evals.schema.AttackCase.

Field-name overlap between the two isn't enough evidence on its own -- they
could drift silently. This builds an attack_attempt message directly from a
real, existing P3.4 AttackCase (evals/cases/identity_authz.py) plus only the
envelope fields the contract adds on top (attempt_id, draw_number,
issued_at), and validates the result against the schema. If a field is
renamed or removed on either side, this test is what catches it.
"""

from __future__ import annotations

from evals.cases.identity_authz import CASE

from tests.contracts.conftest import assert_valid, load_schema


def test_real_attack_case_satisfies_attack_attempt_contract():
    schema = load_schema("attack_attempt.schema.json")
    instance = {
        "schema_version": "1.0.0",
        "attempt_id": "att-0001",
        "case_id": CASE.id,
        "category": CASE.category,
        "owasp_web": CASE.owasp_web,
        "owasp_llm": CASE.owasp_llm,
        "surface_ref": CASE.surface_ref,
        "patient_id": CASE.patient_id,
        "message": CASE.message,
        "draw_number": 1,
        "bearer_token": CASE.bearer_token,
        "issued_at": "2026-07-21T10:05:00Z",
    }
    assert_valid(schema, instance)

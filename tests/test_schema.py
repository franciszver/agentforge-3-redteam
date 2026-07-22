"""Schema validation tests for evals.schema.AttackCase."""

from __future__ import annotations

import pytest

from evals.schema import AttackCase, DetectionResult


def _noop_detect(_response):
    return DetectionResult(vulnerable=False, label="noop")


def _valid_kwargs(**overrides):
    kwargs = dict(
        id="probe-x",
        category="identity_authz",
        owasp_web="A01:2021",
        owasp_llm="LLM06",
        surface_ref="kickoff §2(g)",
        patient_id=3,
        message="hello",
        detect=_noop_detect,
    )
    kwargs.update(overrides)
    return kwargs


def test_valid_case_constructs():
    case = AttackCase(**_valid_kwargs())
    assert case.id == "probe-x"
    assert case.max_draws == 3  # default


def test_rejects_empty_id():
    with pytest.raises(ValueError, match="id"):
        AttackCase(**_valid_kwargs(id=""))


def test_rejects_unknown_category():
    with pytest.raises(ValueError, match="category"):
        AttackCase(**_valid_kwargs(category="not_a_real_category"))


def test_rejects_missing_owasp_refs():
    with pytest.raises(ValueError, match="owasp"):
        AttackCase(**_valid_kwargs(owasp_web=""))


def test_rejects_missing_surface_ref():
    with pytest.raises(ValueError, match="surface_ref"):
        AttackCase(**_valid_kwargs(surface_ref=""))


def test_rejects_empty_message():
    with pytest.raises(ValueError, match="message"):
        AttackCase(**_valid_kwargs(message=""))


def test_rejects_draws_above_cap():
    with pytest.raises(ValueError, match="max_draws"):
        AttackCase(**_valid_kwargs(max_draws=4))


def test_rejects_draws_below_one():
    with pytest.raises(ValueError, match="max_draws"):
        AttackCase(**_valid_kwargs(max_draws=0))


def test_rejects_missing_detect():
    with pytest.raises(ValueError, match="detect"):
        AttackCase(**_valid_kwargs(detect=None))

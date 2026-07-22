"""Shared helpers for contract tests.

Loads a `/contracts/v1/*.schema.json` document and validates example
messages against it with `jsonschema` (draft 2020-12). Kept in one place so
each `test_<contract>.py` file is just: load schema, assert valid example
passes, assert invalid example fails.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACTS_V1 = REPO_ROOT / "contracts" / "v1"


def load_schema(relative_path: str) -> dict[str, Any]:
    """Load a schema file under contracts/v1/ by relative path.

    Raises FileNotFoundError (visible pytest failure) if the schema does
    not exist yet -- this is what makes the red-first commit fail loudly.
    """
    path = CONTRACTS_V1 / relative_path
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def assert_valid(schema: dict[str, Any], instance: dict[str, Any]) -> None:
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(instance), key=lambda e: e.path)
    if errors:
        messages = "; ".join(f"{list(e.path)}: {e.message}" for e in errors)
        pytest.fail(f"expected instance to be valid, got errors: {messages}")


def assert_invalid(schema: dict[str, Any], instance: dict[str, Any]) -> None:
    validator = Draft202012Validator(schema)
    errors = list(validator.iter_errors(instance))
    if not errors:
        pytest.fail("expected instance to be rejected, but it validated cleanly")


def load_example(name: str) -> dict[str, Any]:
    """Load a JSON example message from tests/contracts/examples/."""
    path = Path(__file__).resolve().parent / "examples" / name
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)

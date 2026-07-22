"""P3.18 (issue #37): owner approval applied to the 3 critical vuln reports.

Asserts the committed ``docs/vuln_reports/`` artifacts reflect the owner's
approval at the Documentation Agent's human-approval gate (see
``redteam/agents/documentation.py``'s ``approve()``): no report is left in
``pending_human_approval`` state (no ``*.pending-human-approval.json`` file
remains), and every filed report -- including its new ``approved_at``/
``approved_by`` stamps -- still validates against
``contracts/v1/vuln_report.schema.json``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

_REPO_ROOT = Path(__file__).resolve().parents[2]
_REPORTS_DIR = _REPO_ROOT / "docs" / "vuln_reports"
_SCHEMA_PATH = _REPO_ROOT / "contracts" / "v1" / "vuln_report.schema.json"


def _schema() -> dict:
    with _SCHEMA_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def test_no_report_remains_pending_human_approval():
    pending = sorted(_REPORTS_DIR.glob("*.pending-human-approval.json"))
    assert pending == [], (
        f"reports still pending human approval (must be approved/filed): {pending}"
    )


def test_three_critical_reports_are_filed_and_contract_valid():
    validator = Draft202012Validator(_schema())
    expected_ids = {"VULN-0001", "VULN-0002", "VULN-0003"}
    found_ids = set()

    for path in sorted(_REPORTS_DIR.glob("VULN-*.json")):
        report = json.loads(path.read_text(encoding="utf-8"))
        errors = list(validator.iter_errors(report))
        assert errors == [], f"{path} failed schema validation: {errors}"
        found_ids.add(report["report_id"])

        if report["report_id"] in expected_ids:
            assert report["severity"] == "critical"
            assert report["requires_human_gate"] is True
            assert "approved_at" in report, f"{path} missing approved_at stamp"
            assert report["approved_by"] == "owner", f"{path} missing/incorrect approved_by stamp"

    missing = expected_ids - found_ids
    assert missing == set(), f"expected filed reports missing from {_REPORTS_DIR}: {missing}"

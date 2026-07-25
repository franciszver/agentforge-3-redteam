"""P3.18 (issue #37): owner approval applied to the 3 critical vuln reports.

Asserts the committed ``docs/vuln_reports/`` artifacts reflect the owner's
approval at the Documentation Agent's human-approval gate (see
``redteam/agents/documentation.py``'s ``approve()``): every report NOT in
``_KNOWN_OPEN_PENDING`` below is filed (no ``*.pending-human-approval.json``
suffix), and every filed report -- including its new ``approved_at``/
``approved_by`` stamps -- still validates against
``contracts/v1/vuln_report.schema.json``.

``_KNOWN_OPEN_PENDING`` is an explicit allowlist, not a blanket exemption --
a genuinely still-open finding awaiting human approval (documented at its
own issue) is legitimate; an UNEXPECTED pending file (a finding nobody
reviewed the disposition of yet) is not, and still fails this test. Same
discipline as this project's other "known, not silently spreading"
allowlists (e.g. P3.26's ``known_false_positive_suppressed`` tripwire).
"""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

_REPO_ROOT = Path(__file__).resolve().parents[2]
_REPORTS_DIR = _REPO_ROOT / "docs" / "vuln_reports"
_SCHEMA_PATH = _REPO_ROOT / "contracts" / "v1" / "vuln_report.schema.json"

# Reports deliberately left pending_human_approval, each tracked at its own
# issue -- NOT self-approved, per redteam/agents/documentation.py's
# human-approval trust boundary. Extend this set only when a new finding's
# own write-up documents why it is still open (never to silence a
# regression).
_KNOWN_OPEN_PENDING = {
    # issue #54: unbounded ConversationStore growth (Medium,
    # denial_of_service) -- see docs/ISSUE_54_UNBOUNDED_INPUT_TRACE.md and
    # docs/TRIAGE_LAB.md TRI-014.
    "VULN-0004",
}


def _schema() -> dict:
    with _SCHEMA_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def test_no_unexpected_report_remains_pending_human_approval():
    pending = sorted(_REPORTS_DIR.glob("*.pending-human-approval.json"))
    pending_ids = {p.name.split(".pending-human-approval.json")[0] for p in pending}
    unexpected = pending_ids - _KNOWN_OPEN_PENDING
    assert unexpected == set(), (
        f"unexpected reports pending human approval (must be approved/filed, "
        f"or added to _KNOWN_OPEN_PENDING with a documented reason): {unexpected}"
    )
    missing = _KNOWN_OPEN_PENDING - pending_ids
    assert missing == set(), (
        f"_KNOWN_OPEN_PENDING lists report(s) no longer pending -- update this "
        f"allowlist (they were likely approved): {missing}"
    )


def test_known_open_pending_reports_are_contract_valid_and_not_approved():
    validator = Draft202012Validator(_schema())
    for report_id in sorted(_KNOWN_OPEN_PENDING):
        path = _REPORTS_DIR / f"{report_id}.pending-human-approval.json"
        assert path.exists(), f"expected pending report missing: {path}"
        report = json.loads(path.read_text(encoding="utf-8"))
        errors = list(validator.iter_errors(report))
        assert errors == [], f"{path} failed schema validation: {errors}"
        assert report["requires_human_gate"] is True
        assert "approved_at" not in report, f"{path} has approved_at -- not actually pending"
        assert "approved_by" not in report, f"{path} has approved_by -- not actually pending"


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

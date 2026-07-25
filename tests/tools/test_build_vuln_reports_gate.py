"""P3.26 cold-review fix (issue #55): the human-approval gate for
"not-reliably-machine-decidable" categories (currently just
``denial_of_service``) is a property of the CATEGORY, not of
``redteam.campaign.run_campaign`` specifically.

``tools/build_vuln_reports.py`` is a second, independent caller of
``DocumentationAgent.file_report`` -- it generates the committed
``docs/vuln_reports/*.json`` evidence artifacts offline, from committed
recordings, with no involvement from the live campaign loop. Before this
fix it filed every finding via a bare ``documentation.file_report(record)``
call with no ``force_human_gate`` at all, so a confirmed ``denial_of_service``
finding added to that script's ``findings`` list would self-publish
(``requires_human_gate: false``, no ``.pending-human-approval`` suffix) --
exactly what issue #55 says must never happen for that category, regardless
of severity.

This test exercises ``tools.build_vuln_reports._file_finding`` -- the exact
function ``main()`` calls to file each finding -- with a synthetic
``denial_of_service`` exploit record, and asserts the gate holds.
"""

from __future__ import annotations

from typing import Any

from redteam.agents.documentation import DocumentationAgent
from tools.build_vuln_reports import _file_finding


def _dos_exploit_record() -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "exploit_id": "EXP-9001",
        "case_id": "dos_input_bound",
        "attempt_id": "att-dos_input_bound-1",
        "verdict_id": "vd-dos_input_bound-1",
        "category": "denial_of_service",
        "source": "judge",
        "confirmed_at": "2026-07-25T00:00:00Z",
        "minimal_repro": {
            "steps": ["POST /chat with an oversized payload."],
            "expected": "detect() returns vulnerable=False (guard holds)",
            "observed": "detect() returned vulnerable=True",
        },
        "recording_ref": "evals/recordings/dos_input_bound/synthetic-draw1.json",
    }


def test_dos_finding_filed_through_build_vuln_reports_is_gated():
    """A denial_of_service finding filed via the exact function
    ``tools/build_vuln_reports.py``'s ``main()`` uses must land in
    pending_human_approval, never auto-file -- issue #55's gate is a
    property of the category, not of which caller invokes
    DocumentationAgent.file_report.
    """
    documentation = DocumentationAgent(reports_dir=None)
    report = _file_finding(documentation, _dos_exploit_record())

    assert report["status"] == "pending_human_approval", (
        "denial_of_service finding self-published via "
        "tools/build_vuln_reports.py -- the category-level human-approval "
        "gate from issue #55 was not applied by this caller"
    )
    assert report["requires_human_gate"] is True
    # Sanity: this category's SEVERITY_BY_CATEGORY entry is "medium", so the
    # gate here is coming from the category-forced path, not from severity.
    assert report["severity"] == "medium"

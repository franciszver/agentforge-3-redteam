"""Deep-review regression test (issue #63 self-fix): ``DocumentationAgent``
now auto-loads persisted pending reports from ``reports_dir`` at
construction time (see ``redteam/agents/documentation.py``). Before this
test's fix landed, that broke ``tools/approve_vuln_0004.py``'s own designed
re-run flow -- a genuinely-pending, not-yet-approved report -- because
``main()`` constructs a fresh ``DocumentationAgent(reports_dir=_REPORTS_DIR)``
(which now auto-loads the exact pending report ``_PENDING_PATH.exists()``
just confirmed is there) and then called ``_file_pending`` -> ``file_report``
again, colliding with the newly-auto-loaded entry via the
one-exploit-one-report duplicate-rejection guard and crashing with
``DocumentationAgentError`` instead of approving.

Never touches the real ``docs/vuln_reports/`` -- points every module
constant at a scratch ``tmp_path`` first.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import tools.approve_vuln_0004 as approve_vuln_0004
from redteam.agents.documentation import DocumentationAgent
from tools.build_vuln_report_p3_54 import _build_exploit_record


def _point_at_scratch_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    reports_dir = tmp_path / "vuln_reports"
    monkeypatch.setattr(approve_vuln_0004, "_REPORTS_DIR", reports_dir)
    monkeypatch.setattr(approve_vuln_0004, "_PENDING_PATH", reports_dir / "VULN-0004.pending-human-approval.json")
    monkeypatch.setattr(approve_vuln_0004, "_FILED_PATH", reports_dir / "VULN-0004.json")
    # Pre-existing, out-of-scope issue: the success print's
    # ``_FILED_PATH.relative_to(_REPO_ROOT)`` (same class the sibling
    # tools/build_vuln_report_p3_54.py fixed for issue #64) crashes when
    # reports_dir isn't under the real repo root. Not this test's concern --
    # pin _REPO_ROOT to tmp_path so this test isolates the duplicate-load
    # regression it exists to guard, not that separate pre-existing bug.
    monkeypatch.setattr(approve_vuln_0004, "_REPO_ROOT", tmp_path)
    return reports_dir


def test_main_approves_a_genuinely_pending_report_left_by_a_prior_filing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    reports_dir = _point_at_scratch_dir(monkeypatch, tmp_path)

    record = _build_exploit_record()
    filer = DocumentationAgent(reports_dir=reports_dir)
    filer.file_report(record, force_human_gate=True)
    del filer  # simulate the filing process (a prior main() run) exiting

    rc = approve_vuln_0004.main()

    assert rc == 0, capsys.readouterr()
    assert approve_vuln_0004._FILED_PATH.exists()
    assert not approve_vuln_0004._PENDING_PATH.exists()
    on_disk = json.loads(approve_vuln_0004._FILED_PATH.read_text(encoding="utf-8"))
    assert on_disk["approved_by"] == "owner"

    # Idempotent: a second run correctly reports already-approved, not a crash.
    rc2 = approve_vuln_0004.main()
    assert rc2 == 1

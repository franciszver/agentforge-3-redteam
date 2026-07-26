"""Red-first regression test (DO-NOT-MERGE cold review of PR #76, FIX 1):
``tools/approve_vuln_0004.py``'s ``already_loaded`` branch compared the
auto-loaded pending report against ``pending_on_disk`` -- THE SAME FILE --
which always passes regardless of tampering, because ``already_loaded`` is
read straight back off ``_PENDING_PATH`` by
``DocumentationAgent.__init__``'s auto-load (issue #63). ``record =
_build_exploit_record()`` was built and never used in that branch.

Proof (quoted in the fix commit): file a legitimate pending VULN-0004 in a
scratch dir, hand-edit it to ``severity: "low"``, ``clinical_impact:
"DOCTORED: ..."``, then run ``main()``.

Before this fix: ``rc == 0`` and the doctored artifact is filed as
owner-approved (self-comparison always passes).

After this fix: ``rc == 1``, nothing is written -- the re-derivation via
``build_vuln_report(record, ...)`` is authoritative and does not match the
tampered on-disk content.

Never touches the real ``docs/vuln_reports/`` -- points every module
constant at a scratch ``tmp_path`` first, same convention as
``tests/tools/test_approve_vuln_0004_rerun.py``.
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
    monkeypatch.setattr(approve_vuln_0004, "_REPO_ROOT", tmp_path)
    return reports_dir


def test_main_refuses_a_hand_tampered_pending_report_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    reports_dir = _point_at_scratch_dir(monkeypatch, tmp_path)

    record = _build_exploit_record()
    filer = DocumentationAgent(reports_dir=reports_dir)
    filer.file_report(record, force_human_gate=True)
    del filer  # simulate the filing process (a prior main() run) exiting

    pending_path = approve_vuln_0004._PENDING_PATH
    tampered = json.loads(pending_path.read_text(encoding="utf-8"))
    tampered["severity"] = "low"
    tampered["clinical_impact"] = "DOCTORED: nothing to see here"
    pending_path.write_text(json.dumps(tampered, indent=2), encoding="utf-8")

    rc = approve_vuln_0004.main()

    err = capsys.readouterr().err
    assert rc == 1, f"tampered pending artifact must be refused, got rc={rc}, stderr={err}"
    assert "does not match" in err
    assert not approve_vuln_0004._FILED_PATH.exists(), (
        "a tampered pending report must never be filed as owner-approved"
    )
    # The tampered pending artifact itself must survive untouched -- refusal
    # is not destructive.
    still_on_disk = json.loads(pending_path.read_text(encoding="utf-8"))
    assert still_on_disk["severity"] == "low"
    assert still_on_disk["clinical_impact"] == "DOCTORED: nothing to see here"

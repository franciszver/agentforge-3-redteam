"""Cold-review FIX 6 (issue #64): ``tools/build_vuln_report_p3_54.py``'s
success path crashed when its target reports_dir wasn't under
``_REPO_ROOT`` -- the exact class of bug this PR fixed in the sibling
``tools/build_vuln_reports.py`` via ``_display_path``. This script's refusal
path (existing ``VULN-0004*.json``) was already correct; only the SUCCESS
path -- the final ``print(... out_path.relative_to(_REPO_ROOT) ...)`` -- was
affected: pointed at a temp dir, it writes the artifact and then dies with
``ValueError``, after the write already happened.

This test points ``_REPORTS_DIR`` at a pytest ``tmp_path`` (never the real
``docs/vuln_reports/`` -- see the sibling test module's own constraint) and
runs the real ``main()``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import tools.build_vuln_report_p3_54 as build_vuln_report_p3_54


def test_main_succeeds_against_a_scratch_reports_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """RED-FIRST (issue #64 cold-review FIX 6): pre-fix, ``main()`` writes
    ``VULN-0004.pending-human-approval.json`` into ``tmp_path`` and THEN
    raises ``ValueError`` from ``out_path.relative_to(_REPO_ROOT)`` on the
    final print, since ``tmp_path`` is not under the repo root. Post-fix,
    ``main()`` returns 0 and the success line prints the absolute path
    instead of crashing.
    """
    monkeypatch.setattr(build_vuln_report_p3_54, "_REPORTS_DIR", tmp_path)

    rc = build_vuln_report_p3_54.main()

    assert rc == 0, "main() must succeed when pointed at a scratch reports_dir"
    written = sorted(p.name for p in tmp_path.iterdir())
    assert written == ["VULN-0004.pending-human-approval.json"], written

    stdout = capsys.readouterr().out
    assert "VULN-0004" in stdout

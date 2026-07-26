"""Cold-review fix (PR #67, issue #66): ``tools/approve_vuln_0004.py`` must
never leave a half-written, unapproved report on disk.

Before this fix, ``main()`` called ``DocumentationAgent.file_report(...)``
and only afterwards checked (via a bare ``assert``) that the result landed
in ``pending_human_approval``. ``file_report`` persists immediately for any
report that does NOT require the human gate (see
``redteam/agents/documentation.py``'s ``file_report``: the non-gated branch
calls ``self._persist(report)`` before returning). So if
``force_human_gate`` were ever ``False`` for this category (``medium``
severity, not otherwise gated), the write would already be on disk before
the post-hoc check fired -- and the assert is also silently stripped under
``python -O``. Worse, the script's own ``_FILED_PATH.exists()`` guard would
then permanently refuse to re-run, since an (unapproved) ``VULN-0004.json``
now exists.

This test exercises the extracted ``tools.approve_vuln_0004._file_pending``
helper -- the exact function ``main()`` now calls -- with
``force_human_gate=False``, against a real ``DocumentationAgent`` backed by
a throwaway ``reports_dir`` (never the real ``docs/vuln_reports/``), and
asserts:
  1. it refuses (raises ``SystemExit``, not a bare ``assert``) BEFORE
     ``DocumentationAgent.file_report`` is ever called, and
  2. as a direct consequence, nothing is written to ``reports_dir``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from redteam.agents.documentation import DocumentationAgent
from tools.approve_vuln_0004 import _file_pending


def _dos_exploit_record() -> dict:
    return {
        "schema_version": "1.0.0",
        "exploit_id": "EXP-9002",
        "case_id": "synthetic-gate-check",
        "attempt_id": "att-synthetic-gate-check-1",
        "verdict_id": "vd-synthetic-gate-check-1",
        "category": "denial_of_service",
        "source": "harness",
        "confirmed_at": "2026-07-25T00:00:00Z",
        "minimal_repro": {
            "steps": ["synthetic -- not a real finding, gate test only"],
            "expected": "irrelevant to this test",
            "observed": "irrelevant to this test",
        },
        "recording_ref": "evals/recordings/does-not-exist/synthetic.json",
    }


def test_refuses_without_writing_when_gate_would_not_be_forced(tmp_path: Path):
    reports_dir = tmp_path / "vuln_reports"
    documentation = DocumentationAgent(reports_dir=reports_dir)
    record = _dos_exploit_record()

    with pytest.raises(SystemExit):
        _file_pending(
            documentation,
            record,
            filed_at="2026-07-25T00:00:00Z",
            force_human_gate=False,
        )

    assert list(reports_dir.glob("*.json")) == [], (
        "refusing to force the human-approval gate must not leave any report "
        "artifact on disk -- file_report() must never be reached in this path"
    )


def test_files_pending_when_gate_is_forced(tmp_path: Path):
    reports_dir = tmp_path / "vuln_reports"
    documentation = DocumentationAgent(reports_dir=reports_dir)
    record = _dos_exploit_record()

    pre_approval = _file_pending(
        documentation,
        record,
        filed_at="2026-07-25T00:00:00Z",
        force_human_gate=True,
    )

    assert pre_approval["status"] == "pending_human_approval"
    # Pending reports are never persisted -- only approve() persists.
    assert list(reports_dir.glob("*.json")) == []

"""Red-first regression tests for issue #64 (P3.32): ``tools/build_vuln_reports.py``
``main()`` must never be able to clobber an owner-approved evidence artifact
(``docs/vuln_reports/VULN-000{1,2,3}.json`` -- ``approved_by: "owner"``).

ABSOLUTE CONSTRAINT: every test here points ``_REPORTS_DIR`` at a pytest
``tmp_path`` before calling ``main()``. Nothing in this module ever calls
``main()`` against the real ``docs/vuln_reports/`` directory -- that is the
exact hazard issue #64 is about.

Before the fix landed in this same PR, ``main()`` had no defense at all
against a target directory that already held an approved report: it always
scored the three findings and unconditionally wrote a ``.pending-human-
approval.json`` (or, for a hypothetically non-critical/non-gated future
finding, a bare ``VULN-000N.json`` with no suffix at all) alongside whatever
was already there, with no check of existing content. ``test_main_refuses_
and_writes_nothing_when_an_approved_report_already_exists`` below is the
red test: pre-fix it demonstrates that hazard directly (the run succeeds,
rc == 0, and a brand-new artifact appears next to the untouched-but-
unprotected approved report); post-fix it demonstrates the guarantee (the
run refuses, rc != 0, and the reports_dir is byte-for-byte unchanged --
nothing new, nothing missing).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import tools.build_vuln_reports as build_vuln_reports

_APPROVED_VULN_0001 = {
    "schema_version": "1.0.0",
    "report_id": "VULN-0001",
    "exploit_id": "EXP-0001",
    "severity": "critical",
    "clinical_impact": "An unauthenticated or improperly authenticated caller can retrieve real patient health information.",
    "observed": "detect() returned vulnerable=True, label='garbage_token_accepted'",
    "expected": "detect() returns vulnerable=False (guard holds)",
    "remediation": "Enforce bearer-token validation against a real, verifiable credential before any patient-binding lookup runs -- accepting any non-empty token is not authentication.",
    "fix_validation_status": "not_validated",
    "requires_human_gate": True,
    "filed_at": "2026-07-22T05:53:19Z",
    "approved_at": "2026-07-22T06:01:56Z",
    "approved_by": "owner",
}


def _seed_approved_vuln_0001(reports_dir: Path) -> Path:
    path = reports_dir / "VULN-0001.json"
    path.write_text(json.dumps(_APPROVED_VULN_0001, indent=2) + "\n", encoding="utf-8")
    return path


def _snapshot(reports_dir: Path) -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in sorted(reports_dir.iterdir())}


def test_main_refuses_and_writes_nothing_when_an_approved_report_already_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """RED-FIRST (issue #64): seed a temp reports_dir with an approved
    VULN-0001.json (owner-approved, ``approved_by``/``approved_at`` stamped)
    and run the real ``main()`` against it. The fixed script must refuse the
    ENTIRE run (rc != 0) and leave the directory byte-for-byte unchanged --
    no stray ``.pending-human-approval.json`` siblings for VULN-0001, and no
    writes at all for VULN-0002/VULN-0003 either (a partial write would
    itself be a corruption of the evidence set's consistency).
    """
    approved_path = _seed_approved_vuln_0001(tmp_path)
    before = _snapshot(tmp_path)

    monkeypatch.setattr(build_vuln_reports, "_REPORTS_DIR", tmp_path)
    rc = build_vuln_reports.main()

    after = _snapshot(tmp_path)
    assert after == before, (
        "tools/build_vuln_reports.py main() modified or added files in a "
        "reports_dir that already held an owner-approved report -- this is "
        "the exact hazard issue #64 exists to close"
    )
    assert approved_path.read_text(encoding="utf-8") == json.dumps(_APPROVED_VULN_0001, indent=2) + "\n"
    assert rc != 0, "main() must exit non-zero when refusing to write over approved evidence"

    stderr = capsys.readouterr().err
    assert "VULN-0001" in stderr, "the refusal must name the blocking report"


def test_main_partial_approval_blocks_the_entire_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only ONE of the three findings (VULN-0001) is approved on disk. The
    other two (VULN-0002, VULN-0003) have no existing artifact at all. The
    fixed script must still refuse the WHOLE run rather than writing the two
    unaffected findings and skipping only the blocked one -- a half-written
    evidence set (two fresh, one blocked) is its own kind of corruption of
    the "reproduce the whole packet" guarantee this tool exists for.
    """
    _seed_approved_vuln_0001(tmp_path)
    before = _snapshot(tmp_path)

    monkeypatch.setattr(build_vuln_reports, "_REPORTS_DIR", tmp_path)
    rc = build_vuln_reports.main()

    assert rc != 0
    assert _snapshot(tmp_path) == before, (
        "a partially-approved reports_dir must block the ENTIRE run -- "
        "found writes for the unblocked findings"
    )


def test_main_fails_closed_on_a_report_with_only_one_approval_stamp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A report missing exactly one of ``approved_at``/``approved_by`` (hand-
    edited, corrupted, or otherwise malformed) is not something the real
    ``DocumentationAgent.approve`` ever produces -- it always sets both
    together -- but the safety net must still fail CLOSED on it (treat it as
    approved, refuse) rather than open (treat it as unapproved, overwrite).
    """
    partial = dict(_APPROVED_VULN_0001)
    del partial["approved_by"]  # approved_at present, approved_by missing
    path = tmp_path / "VULN-0001.json"
    path.write_text(json.dumps(partial, indent=2) + "\n", encoding="utf-8")
    before = _snapshot(tmp_path)

    monkeypatch.setattr(build_vuln_reports, "_REPORTS_DIR", tmp_path)
    rc = build_vuln_reports.main()

    assert rc != 0
    assert _snapshot(tmp_path) == before, (
        "a report with a partial approval stamp was overwritten -- the "
        "safety net must fail closed on ambiguous approval state"
    )


def test_main_is_idempotent_when_nothing_on_disk_is_approved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no approved report present, running main() twice back-to-back
    must not needlessly re-stamp a fresh filed_at the second time when the
    underlying recordings/derivation haven't changed -- regeneration should
    be a genuine no-op for content that already matches, not a silent
    timestamp-only rewrite every time.
    """
    monkeypatch.setattr(build_vuln_reports, "_REPORTS_DIR", tmp_path)

    rc1 = build_vuln_reports.main()
    assert rc1 == 0
    first = _snapshot(tmp_path)
    assert first, "expected the three pending reports to be written"

    rc2 = build_vuln_reports.main()
    assert rc2 == 0
    second = _snapshot(tmp_path)

    assert second == first, (
        "re-running main() with unchanged recordings and no approved report "
        "present rewrote content that should have been left as a no-op "
        "(e.g. a fresh filed_at stamped on unchanged content)"
    )

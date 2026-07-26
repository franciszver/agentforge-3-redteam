"""Red-first: an ``approve`` path reachable from the CLI (issue #63).

``tools/run_campaign.py`` had no ``approve``/``--list-pending`` mode at all
before this fix -- ``main()`` took no arguments and only understood
``--iterations``. These tests call ``tools.run_campaign.main(argv)``
directly (never a live model/target, mirroring
``tests/tools/test_build_vuln_reports_nondestructive.py``'s own
``main(argv)`` convention) against a throwaway ``tmp_path`` reports_dir --
NEVER the real ``docs/vuln_reports/``.
"""

from __future__ import annotations

import json

import pytest

from redteam.agents.documentation import DocumentationAgent
from tools import run_campaign

CRITICAL_EXPLOIT = {
    "schema_version": "1.0.0",
    "exploit_id": "EXP-0001",
    "case_id": "identity-authz-garbage-bearer-token",
    "attempt_id": "att-0001",
    "verdict_id": "ver-0001",
    "category": "identity_authz",
    "source": "judge",
    "confirmed_at": "2026-07-21T10:07:00Z",
    "minimal_repro": {
        "steps": ["POST /chat with a garbage bearer token", "observe 200 + patient data"],
        "expected": "401/403 rejection",
        "observed": "200 with PHI",
    },
    "recording_ref": "evals/recordings/identity-authz-garbage-bearer-token/20260721T100600Z-draw1.json",
}


def test_approve_requires_reports_dir():
    with pytest.raises(SystemExit):
        run_campaign.main(["--approve", "EXP-0001"])


def test_list_pending_requires_reports_dir():
    with pytest.raises(SystemExit):
        run_campaign.main(["--list-pending"])


def test_cli_lists_and_approves_a_report_left_pending_by_a_separate_process(tmp_path, capsys):
    """The end-to-end CLI proof of issue #63/#66: file a pending report with
    one DocumentationAgent instance (simulating a prior process), then use
    ONLY ``tools/run_campaign.py``'s CLI -- no bespoke script -- to list it
    and approve it."""
    reports_dir = tmp_path / "vuln_reports"
    filer = DocumentationAgent(reports_dir=reports_dir)
    filer.file_report(CRITICAL_EXPLOIT)
    del filer  # simulate the filing process exiting

    rc = run_campaign.main(["--list-pending", "--reports-dir", str(reports_dir)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "pending_human_triage_count=1" in out
    assert "EXP-0001" in out

    rc = run_campaign.main(
        ["--approve", "EXP-0001", "--reports-dir", str(reports_dir), "--approved-by", "owner"]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "exploit_id=EXP-0001" in out
    assert "approved_by=owner" in out
    assert "status=filed" in out

    on_disk = json.loads((reports_dir / "VULN-0001.json").read_text(encoding="utf-8"))
    assert on_disk["approved_by"] == "owner"
    assert not (reports_dir / "VULN-0001.pending-human-approval.json").exists()

    rc = run_campaign.main(["--list-pending", "--reports-dir", str(reports_dir)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "pending_human_triage_count=0" in out


def test_approve_unknown_exploit_id_fails_without_writing(tmp_path, capsys):
    reports_dir = tmp_path / "vuln_reports"
    reports_dir.mkdir()

    rc = run_campaign.main(["--approve", "EXP-9999", "--reports-dir", str(reports_dir)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "no pending report" in err
    assert list(reports_dir.glob("*.json")) == []


def test_approve_refuses_when_pending_report_drifts_from_its_source_exploit_record(tmp_path, capsys):
    """Generalized version of ``tools/approve_vuln_0004.py``'s field-for-field
    verify-then-approve discipline: when a persisted, durable exploit DB is
    available, the CLI must refuse to approve a pending report whose content
    does not match what its source exploit record would produce."""
    from redteam.harness.db import ExploitDB

    reports_dir = tmp_path / "vuln_reports"
    db_path = tmp_path / "exploits.sqlite3"

    db = ExploitDB(db_path)
    db.add_record(CRITICAL_EXPLOIT)

    filer = DocumentationAgent(reports_dir=reports_dir)
    filer.file_report(CRITICAL_EXPLOIT)
    del filer

    # Tamper with the persisted pending report -- a careless-operator /
    # corruption scenario, not a normal filing.
    pending_path = reports_dir / "VULN-0001.pending-human-approval.json"
    tampered = json.loads(pending_path.read_text(encoding="utf-8"))
    tampered["clinical_impact"] = "DOCTORED: nothing to see here"
    pending_path.write_text(json.dumps(tampered, indent=2), encoding="utf-8")

    rc = run_campaign.main(
        [
            "--approve",
            "EXP-0001",
            "--reports-dir",
            str(reports_dir),
            "--db-path",
            str(db_path),
        ]
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "does not match" in err
    # Nothing was approved -- the tampered content never became "filed".
    assert not (reports_dir / "VULN-0001.json").exists()


def test_never_auto_approves_no_default_exploit_id(tmp_path):
    """Regression guard: --approve has no default -- there is no flag
    combination that approves anything without an explicit exploit_id, and
    a bare run (no --approve/--list-pending) never touches approve() at
    all."""
    args = run_campaign._parse_args(["--reports-dir", str(tmp_path)])
    assert args.approve is None
    assert args.list_pending is False

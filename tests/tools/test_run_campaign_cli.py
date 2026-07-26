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
    from redteam.harness.db import ExploitDB

    reports_dir = tmp_path / "vuln_reports"
    db_path = tmp_path / "exploits.sqlite3"

    db = ExploitDB(db_path)
    db.add_record(CRITICAL_EXPLOIT)

    filer = DocumentationAgent(reports_dir=reports_dir)
    filer.file_report(CRITICAL_EXPLOIT)
    del filer  # simulate the filing process exiting

    rc = run_campaign.main(["--list-pending", "--reports-dir", str(reports_dir)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "pending_human_triage_count=1" in out
    assert "EXP-0001" in out

    rc = run_campaign.main(
        [
            "--approve",
            "EXP-0001",
            "--reports-dir",
            str(reports_dir),
            "--db-path",
            str(db_path),
            "--approved-by",
            "owner",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "--- pending report body (about to be approved) ---" in out
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

    rc = run_campaign.main(
        [
            "--approve",
            "EXP-9999",
            "--reports-dir",
            str(reports_dir),
            "--approved-by",
            "owner",
            "--unverified-i-vouch-without-db-check",
        ]
    )
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
            "--approved-by",
            "owner",
        ]
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "does not match" in err
    # Nothing was approved -- the tampered content never became "filed".
    assert not (reports_dir / "VULN-0001.json").exists()


# -- DO-NOT-MERGE cold review of PR #76, FIX 5 (partial) --------------------


def test_list_pending_on_a_directory_with_unrelated_json_fails_cleanly_not_a_traceback(tmp_path, capsys):
    """--list-pending on a reports_dir containing an unrelated JSON file
    previously exited with a raw DocumentationAgentError traceback (an
    uncaught exception) instead of a clean CLI message + rc 1."""
    reports_dir = tmp_path / "vuln_reports"
    reports_dir.mkdir()
    (reports_dir / "random.json").write_text('{"unrelated": true}', encoding="utf-8")

    rc = run_campaign.main(["--list-pending", "--reports-dir", str(reports_dir)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "could not load reports_dir" in err


def test_approve_on_a_directory_with_unrelated_json_fails_cleanly_not_a_traceback(tmp_path, capsys):
    reports_dir = tmp_path / "vuln_reports"
    reports_dir.mkdir()
    (reports_dir / "random.json").write_text('{"unrelated": true}', encoding="utf-8")

    rc = run_campaign.main(
        [
            "--approve",
            "EXP-0001",
            "--reports-dir",
            str(reports_dir),
            "--approved-by",
            "owner",
            "--unverified-i-vouch-without-db-check",
        ]
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "could not load reports_dir" in err


def test_never_auto_approves_no_default_exploit_id(tmp_path):
    """Regression guard: --approve has no default -- there is no flag
    combination that approves anything without an explicit exploit_id, and
    a bare run (no --approve/--list-pending) never touches approve() at
    all."""
    args = run_campaign._parse_args(
        ["--reports-dir", str(tmp_path), "--db-path", str(tmp_path / "exploits.sqlite3")]
    )
    assert args.approve is None
    assert args.list_pending is False


def test_run_mode_reports_dir_without_db_path_refuses_to_start(tmp_path):
    """FIX 3 (documented flag combo aborts the run): --reports-dir without
    --db-path in run mode used to only print a stderr NOTE and continue --
    then crash the campaign mid-loop (losing the action-log export) the
    first time exploit-ID numbering collided with an already-persisted
    report on a second run. It must now refuse to start at all."""
    with pytest.raises(SystemExit):
        run_campaign._parse_args(["--reports-dir", str(tmp_path)])


# -- DO-NOT-MERGE cold review of PR #76, FIX 2 -------------------------------
# "The cross-check fails open." Four attacks the reviewer proved, each now
# refused (fail closed):
#   1. --approve with no --db-path approved a hand-written pending report
#      with NO provenance check at all.
#   2. --db-path pointing at a missing file: ExploitDB(path) CREATES an
#      empty sqlite, silently downgrading to a warning + approve-as-is.
#   3. --approved-by defaulted to "owner" -- no explicit human required.
#   4. The report body was never displayed before stamping.


def test_approve_with_no_db_path_and_no_escape_hatch_is_refused_at_parse_time(tmp_path):
    """Attack 1 reproduced: previously a hand-written
    ``VULN-0099.pending-human-approval.json`` with no corresponding exploit
    DB record at all approved cleanly (no provenance check whatsoever). Now
    the cross-check is required by default -- omitting both --db-path and
    the explicit escape hatch must refuse before ever touching
    documentation.approve()."""
    with pytest.raises(SystemExit):
        run_campaign._parse_args(
            ["--approve", "EXP-0099", "--reports-dir", str(tmp_path), "--approved-by", "owner"]
        )


def test_approve_with_missing_db_path_file_fails_closed_without_writing(tmp_path, capsys):
    """Attack 2 reproduced: ``--db-path`` naming a file that does not yet
    exist previously let ``ExploitDB(path)`` silently create an empty
    sqlite DB, downgrading the cross-check to a warning and approving the
    pending report as-is. A typo'd path is the most likely operator error
    for the one safety flag this CLI has -- it must fail closed, not open."""
    reports_dir = tmp_path / "vuln_reports"
    filer = DocumentationAgent(reports_dir=reports_dir)
    filer.file_report(CRITICAL_EXPLOIT)
    del filer

    missing_db_path = tmp_path / "typo-exploits.sqlite3"
    assert not missing_db_path.exists()

    rc = run_campaign.main(
        [
            "--approve",
            "EXP-0001",
            "--reports-dir",
            str(reports_dir),
            "--db-path",
            str(missing_db_path),
            "--approved-by",
            "owner",
        ]
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "does not exist" in err
    # The DB path must still not exist -- refusing must not create it either.
    assert not missing_db_path.exists()
    assert not (reports_dir / "VULN-0001.json").exists()


def test_approve_without_approved_by_is_refused_at_parse_time(tmp_path):
    """Attack 3 reproduced: --approved-by used to default to "owner", so no
    explicit human identity was ever required to approve anything. It must
    now be mandatory whenever --approve is used."""
    with pytest.raises(SystemExit):
        run_campaign._parse_args(
            ["--approve", "EXP-0001", "--reports-dir", str(tmp_path), "--unverified-i-vouch-without-db-check"]
        )


def test_approve_prints_report_body_before_stamping(tmp_path, capsys):
    """Attack 4 reproduced: the pending report's body was never printed
    before approve() stamped it -- an operator approved blind. Using the
    explicit escape hatch (a genuinely DB-less report) must still print the
    full body before approving."""
    reports_dir = tmp_path / "vuln_reports"
    filer = DocumentationAgent(reports_dir=reports_dir)
    filer.file_report(CRITICAL_EXPLOIT)
    del filer

    rc = run_campaign.main(
        [
            "--approve",
            "EXP-0001",
            "--reports-dir",
            str(reports_dir),
            "--approved-by",
            "owner",
            "--unverified-i-vouch-without-db-check",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "--- pending report body (about to be approved) ---" in out
    assert '"report_id": "VULN-0001"' in out
    assert '"clinical_impact"' in out


def test_approve_escape_hatch_prints_loud_warning_when_used(tmp_path, capsys):
    """The escape hatch must be loud, not a quiet downgrade -- a WARNING
    naming exactly what was skipped."""
    reports_dir = tmp_path / "vuln_reports"
    filer = DocumentationAgent(reports_dir=reports_dir)
    filer.file_report(CRITICAL_EXPLOIT)
    del filer

    rc = run_campaign.main(
        [
            "--approve",
            "EXP-0001",
            "--reports-dir",
            str(reports_dir),
            "--approved-by",
            "owner",
            "--unverified-i-vouch-without-db-check",
        ]
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert "WARNING" in err
    assert "without a field-for-field cross-check" in err.lower() or "without" in err.lower()


def test_approve_with_stored_record_but_missing_from_db_fails_closed(tmp_path, capsys):
    """A --db-path file that exists but simply has no record for this
    exploit_id (e.g. wrong DB, or record never durably persisted) must also
    fail closed, not silently downgrade to a warning + approve-as-is."""
    from redteam.harness.db import ExploitDB

    reports_dir = tmp_path / "vuln_reports"
    db_path = tmp_path / "exploits.sqlite3"
    ExploitDB(db_path)  # exists, but empty -- no EXP-0001 record in it

    filer = DocumentationAgent(reports_dir=reports_dir)
    filer.file_report(CRITICAL_EXPLOIT)
    del filer

    rc = run_campaign.main(
        [
            "--approve",
            "EXP-0001",
            "--reports-dir",
            str(reports_dir),
            "--db-path",
            str(db_path),
            "--approved-by",
            "owner",
        ]
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "no exploit record" in err
    assert not (reports_dir / "VULN-0001.json").exists()


def test_approve_cross_check_uses_trusted_category_not_untrusted_pending_gate_field(tmp_path, capsys):
    """Regression guard (cold review FIX 5): the rebuild must derive
    force_human_gate from the STORED exploit record's category, not from
    pending["requires_human_gate"] (the very field under verification), and
    must carry fix_validation_status through so a fix_verified report
    doesn't spuriously fail the cross-check."""
    from redteam.harness.db import ExploitDB
    from redteam.agents.documentation import DocumentationAgent as _DA

    dos_record = {
        "schema_version": "1.0.0",
        "exploit_id": "EXP-0005",
        "case_id": "dos-case",
        "attempt_id": "att-0005",
        "verdict_id": "ver-0005",
        "category": "denial_of_service",
        "source": "judge",
        "confirmed_at": "2026-07-21T10:07:00Z",
        "minimal_repro": {
            "steps": ["oversized message"],
            "expected": "rejected",
            "observed": "accepted",
        },
        "recording_ref": "evals/recordings/dos-case/20260721T100600Z-draw1.json",
    }

    reports_dir = tmp_path / "vuln_reports"
    db_path = tmp_path / "exploits.sqlite3"
    db = ExploitDB(db_path)
    db.add_record(dos_record)

    filer = _DA(reports_dir=reports_dir)
    filer.file_report(dos_record, force_human_gate=True)  # denial_of_service -> forced pending
    del filer

    # Simulate a legitimate post-filing lifecycle update to fix_validation_status.
    pending_path = reports_dir / "VULN-0005.pending-human-approval.json"
    on_disk = json.loads(pending_path.read_text(encoding="utf-8"))
    on_disk["fix_validation_status"] = "validated"
    pending_path.write_text(json.dumps(on_disk, indent=2), encoding="utf-8")

    rc = run_campaign.main(
        [
            "--approve",
            "EXP-0005",
            "--reports-dir",
            str(reports_dir),
            "--db-path",
            str(db_path),
            "--approved-by",
            "owner",
        ]
    )
    err = capsys.readouterr().err
    assert rc == 0, f"legitimate fix_verified pending report must pass the cross-check, stderr={err}"

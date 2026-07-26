"""Red-first: Documentation Agent turns Judge-confirmed exploits into
structured, contract-valid vuln reports without needing a live model.

Imports ``redteam.agents.documentation`` which does not exist yet as of
this commit.
"""

from __future__ import annotations

import json

import pytest

from redteam.agents.documentation import (
    DocumentationAgent,
    DocumentationAgentError,
    build_vuln_report,
)

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

NON_CRITICAL_EXPLOIT = {
    "schema_version": "1.0.0",
    "exploit_id": "EXP-0002",
    "case_id": "dos-overlong-query-max-query-chars",
    "attempt_id": "att-0002",
    "verdict_id": "ver-0002",
    "category": "denial_of_service",
    "source": "harness",
    "confirmed_at": "2026-07-21T10:09:00Z",
    "minimal_repro": {
        "steps": ["POST /chat with a message > MAX_QUERY_CHARS"],
        "expected": "clean rejection (non-200 or RetrievalError)",
        "observed": "200 with a normal-looking answer; guard did not hold",
    },
    "recording_ref": "evals/recordings/dos-overlong-query-max-query-chars/20260722T031540Z-draw1.json",
}


def test_deterministic_core_requires_no_narrator_and_is_reproducible():
    """Same exploit record in -> byte-identical report out, no model call."""
    report_a = build_vuln_report(CRITICAL_EXPLOIT, filed_at="2026-07-21T10:08:00Z")
    report_b = build_vuln_report(CRITICAL_EXPLOIT, filed_at="2026-07-21T10:08:00Z")
    assert report_a == report_b
    assert report_a["report_id"] == "VULN-0001"
    assert report_a["exploit_id"] == "EXP-0001"
    assert report_a["observed"] == CRITICAL_EXPLOIT["minimal_repro"]["observed"]
    assert report_a["expected"] == CRITICAL_EXPLOIT["minimal_repro"]["expected"]
    assert report_a["severity"] == "critical"
    assert report_a["requires_human_gate"] is True


def test_non_critical_severity_derived_deterministically():
    report = build_vuln_report(NON_CRITICAL_EXPLOIT, filed_at="2026-07-21T10:10:00Z")
    assert report["severity"] == "medium"
    assert report["requires_human_gate"] is False


def test_critical_severity_requires_human_gate_and_is_not_auto_filed():
    """Core trust-boundary test: a critical report must NOT be auto-filed."""
    agent = DocumentationAgent()
    result = agent.file_report(CRITICAL_EXPLOIT)

    assert result["requires_human_gate"] is True
    assert result["status"] == "pending_human_approval"
    assert agent.get_filed("EXP-0001") is None
    assert agent.get_pending("EXP-0001") is not None
    assert agent.all_filed() == []


def test_non_critical_severity_is_auto_filed():
    agent = DocumentationAgent()
    result = agent.file_report(NON_CRITICAL_EXPLOIT)

    assert result["requires_human_gate"] is False
    assert result["status"] == "filed"
    assert agent.get_filed("EXP-0002") is not None
    assert agent.get_pending("EXP-0002") is None


def test_force_human_gate_overrides_a_non_critical_severity(tmp_path):
    """``force_human_gate=True`` (issue #55) gates a report to
    ``pending_human_approval`` even though its category's severity is
    ``medium`` (not ``critical``) -- the mechanism ``redteam.campaign
    .run_campaign`` uses to route every confirmed ``denial_of_service``
    finding through human triage. Severity itself is untouched."""
    agent = DocumentationAgent()
    result = agent.file_report(NON_CRITICAL_EXPLOIT, force_human_gate=True)

    assert result["severity"] == "medium"
    assert result["requires_human_gate"] is True
    assert result["status"] == "pending_human_approval"
    assert agent.get_pending("EXP-0002") is not None
    assert agent.get_filed("EXP-0002") is None
    assert agent.all_filed() == []


def test_force_human_gate_false_leaves_non_critical_auto_filed():
    """The default (``force_human_gate=False``) must not change any
    existing non-critical auto-file behavior -- a regression guard for the
    OR added to ``requires_human_gate``."""
    agent = DocumentationAgent()
    result = agent.file_report(NON_CRITICAL_EXPLOIT, force_human_gate=False)

    assert result["requires_human_gate"] is False
    assert result["status"] == "filed"


def test_force_human_gate_does_not_lower_a_critical_gate():
    """``force_human_gate`` only ORs in -- passing ``False`` on a critical
    exploit must not somehow bypass the severity-derived gate (there is no
    code path that would, but this pins the invariant explicitly)."""
    report = build_vuln_report(CRITICAL_EXPLOIT, force_human_gate=False)
    assert report["severity"] == "critical"
    assert report["requires_human_gate"] is True


def test_approving_a_pending_critical_report_files_it():
    agent = DocumentationAgent()
    agent.file_report(CRITICAL_EXPLOIT)

    filed = agent.approve("EXP-0001", approved_at="2026-07-21T11:00:00Z")

    assert filed["status"] == "filed"
    assert filed["approved_at"] == "2026-07-21T11:00:00Z"
    assert filed["approved_by"] == "owner"  # default approving identity
    assert agent.get_pending("EXP-0001") is None
    assert agent.get_filed("EXP-0001") is not None


def test_approve_accepts_explicit_approved_by():
    agent = DocumentationAgent()
    agent.file_report(CRITICAL_EXPLOIT)

    filed = agent.approve("EXP-0001", approved_by="someone-else")

    assert filed["approved_by"] == "someone-else"


def test_approving_unknown_exploit_id_raises():
    agent = DocumentationAgent()
    with pytest.raises(DocumentationAgentError):
        agent.approve("EXP-9999")


def test_duplicate_report_for_same_exploit_id_rejected():
    agent = DocumentationAgent()
    agent.file_report(NON_CRITICAL_EXPLOIT)
    with pytest.raises(DocumentationAgentError):
        agent.file_report(NON_CRITICAL_EXPLOIT)


def test_duplicate_report_rejected_even_while_pending_human_approval():
    agent = DocumentationAgent()
    agent.file_report(CRITICAL_EXPLOIT)
    with pytest.raises(DocumentationAgentError):
        agent.file_report(CRITICAL_EXPLOIT)


def test_schema_invalid_report_rejected_pre_write():
    """A report_id that fails the vuln_report contract's pattern must be
    rejected before it is filed or persisted -- not caught downstream."""
    agent = DocumentationAgent()
    with pytest.raises(DocumentationAgentError):
        agent.file_report(NON_CRITICAL_EXPLOIT, report_id="not-a-valid-id")
    assert agent.get_filed("EXP-0002") is None


def test_narrator_seam_polishes_prose_without_a_live_model():
    """The narrator seam lets a (currently-absent) local model rewrite
    prose fields; the default path never needs one."""

    def fake_narrator(exploit_record, deterministic_report):
        return {
            "clinical_impact": "CUSTOM: " + deterministic_report["clinical_impact"],
            "remediation": "CUSTOM: " + deterministic_report["remediation"],
        }

    plain = build_vuln_report(NON_CRITICAL_EXPLOIT, filed_at="2026-07-21T10:10:00Z")
    narrated = build_vuln_report(
        NON_CRITICAL_EXPLOIT, filed_at="2026-07-21T10:10:00Z", narrator=fake_narrator
    )

    assert narrated["clinical_impact"] == "CUSTOM: " + plain["clinical_impact"]
    assert narrated["remediation"] == "CUSTOM: " + plain["remediation"]
    # narrator cannot touch the safety-relevant fields
    assert narrated["severity"] == plain["severity"]
    assert narrated["requires_human_gate"] == plain["requires_human_gate"]
    assert narrated["exploit_id"] == plain["exploit_id"]
    assert narrated["report_id"] == plain["report_id"]


def test_narrator_cannot_repoint_recording_ref():
    """Issue #77 sec-audit: a narrator that tries to redirect a reader at
    different (wrong) evidence must be ignored, the same as any other
    safety-relevant field -- recording_ref is in
    ``_NARRATOR_PROTECTED_FIELDS`` for exactly this reason."""

    def malicious_narrator(exploit_record, deterministic_report):
        return {"recording_ref": "evals/recordings/some-other-unrelated-case/"}

    plain = build_vuln_report(NON_CRITICAL_EXPLOIT, filed_at="2026-07-21T10:10:00Z")
    narrated = build_vuln_report(
        NON_CRITICAL_EXPLOIT, filed_at="2026-07-21T10:10:00Z", narrator=malicious_narrator
    )

    assert narrated["recording_ref"] == plain["recording_ref"]
    assert narrated["recording_ref"] == "evals/recordings/dos-overlong-query-max-query-chars/"


def test_narrator_output_still_validated_against_contract():
    """A narrator that produces a schema-breaking report must be rejected,
    not silently filed."""

    def bad_narrator(exploit_record, deterministic_report):
        return {"clinical_impact": ""}  # violates minLength: 1

    agent = DocumentationAgent()
    with pytest.raises(DocumentationAgentError):
        agent.file_report(NON_CRITICAL_EXPLOIT, narrator=bad_narrator)


def test_reports_persisted_to_reports_dir(tmp_path):
    agent = DocumentationAgent(reports_dir=tmp_path)
    agent.file_report(NON_CRITICAL_EXPLOIT)

    written = list(tmp_path.glob("*.json"))
    assert len(written) == 1
    on_disk = json.loads(written[0].read_text(encoding="utf-8"))
    assert on_disk["report_id"] == "VULN-0002"


def test_pending_report_persisted_with_suffix_until_approved(tmp_path):
    """Issue #63: a pending report now gets a durable surface of its own --
    ``<report_id>.pending-human-approval.json`` -- rather than living only
    in memory (the prior behavior this test used to pin)."""
    agent = DocumentationAgent(reports_dir=tmp_path)
    agent.file_report(CRITICAL_EXPLOIT)

    pending_files = list(tmp_path.glob("*.pending-human-approval.json"))
    assert len(pending_files) == 1
    assert pending_files[0].name == "VULN-0001.pending-human-approval.json"
    on_disk = json.loads(pending_files[0].read_text(encoding="utf-8"))
    assert on_disk["exploit_id"] == "EXP-0001"
    assert on_disk["requires_human_gate"] is True
    assert "approved_by" not in on_disk
    # Not yet filed -- no VULN-0001.json (only the pending-suffixed file).
    assert not (tmp_path / "VULN-0001.json").exists()

    agent.approve("EXP-0001")

    # The pending artifact is gone; a filed one takes its place.
    assert list(tmp_path.glob("*.pending-human-approval.json")) == []
    written = [p for p in tmp_path.glob("*.json") if not p.name.endswith(".pending-human-approval.json")]
    assert len(written) == 1
    assert written[0].name == "VULN-0001.json"


def test_pending_report_persisted_by_one_agent_is_approvable_by_a_fresh_instance(tmp_path):
    """The heart of issue #63/#66: a report left pending by one process must
    be approvable by a SEPARATE later process/instance pointed at the same
    ``reports_dir`` -- no bespoke reconstruction script (contrast
    ``tools/approve_vuln_0004.py``, which had to reconstruct the exploit
    record from scratch because ``_pending`` was in-memory only)."""
    filer = DocumentationAgent(reports_dir=tmp_path)
    filer.file_report(CRITICAL_EXPLOIT)
    del filer  # simulate the filing process having exited

    approver = DocumentationAgent(reports_dir=tmp_path)  # a fresh instance/"process"
    assert approver.get_pending("EXP-0001") is not None
    assert approver.get_filed("EXP-0001") is None

    filed = approver.approve("EXP-0001", approved_by="owner")

    assert filed["status"] == "filed"
    assert filed["exploit_id"] == "EXP-0001"
    assert filed["approved_by"] == "owner"
    assert approver.get_pending("EXP-0001") is None
    assert approver.get_filed("EXP-0001") is not None

    on_disk = json.loads((tmp_path / "VULN-0001.json").read_text(encoding="utf-8"))
    assert on_disk["approved_by"] == "owner"
    assert on_disk["observed"] == CRITICAL_EXPLOIT["minimal_repro"]["observed"]


def test_stale_pending_file_dropped_once_filed_exists(tmp_path):
    """Defensive recovery: if a pending-suffixed file is somehow still on
    disk for an exploit_id that ALSO has a filed report (e.g. the pending
    file's ``unlink`` failed right after the filed file was written during
    ``approve``), loading must never re-offer that exploit_id for approval
    -- the filed report wins, the stale pending duplicate is dropped."""
    agent = DocumentationAgent(reports_dir=tmp_path)
    agent.file_report(CRITICAL_EXPLOIT)
    agent.approve("EXP-0001")
    del agent

    # Recreate a stale pending artifact next to the already-filed one.
    stale_pending = {**json.loads((tmp_path / "VULN-0001.json").read_text(encoding="utf-8"))}
    stale_pending.pop("approved_at")
    stale_pending.pop("approved_by")
    (tmp_path / "VULN-0001.pending-human-approval.json").write_text(
        json.dumps(stale_pending, indent=2), encoding="utf-8"
    )

    reloaded = DocumentationAgent(reports_dir=tmp_path)
    assert reloaded.get_pending("EXP-0001") is None  # not re-offered
    assert reloaded.get_filed("EXP-0001") is not None
    with pytest.raises(DocumentationAgentError):
        reloaded.approve("EXP-0001")


def test_corrupt_persisted_report_raises_loudly_not_silently_ignored(tmp_path):
    """A reports_dir this module can't parse must fail loudly at load time,
    not silently lose the pending report it's supposed to make durable."""
    (tmp_path / "VULN-0009.pending-human-approval.json").write_text(
        "not json", encoding="utf-8"
    )
    with pytest.raises(DocumentationAgentError):
        DocumentationAgent(reports_dir=tmp_path)


def test_malformed_exploit_record_raises_documentation_agent_error_not_key_error():
    """A caller catching this module's own error type for bad input must not
    get a raw KeyError just because the missing field is on the input side."""
    incomplete = {"exploit_id": "EXP-0001"}  # no category, no minimal_repro
    with pytest.raises(DocumentationAgentError):
        build_vuln_report(incomplete, filed_at="2026-07-21T10:08:00Z")


# -- DO-NOT-MERGE cold review of PR #76, FIX 4 -------------------------------
# "Approval can overwrite already-approved evidence." Reproduced: a
# weird-name.pending-human-approval.json carrying report_id: VULN-0001,
# exploit_id: EXP-0002 (filename ignored, contents trusted) caused
# --approve EXP-0002 to overwrite the filed, approved VULN-0001.json, and
# the stale source file was never removed (_remove_pending_file unlinked by
# report_id, not source path).


def test_load_rejects_a_pending_file_whose_name_does_not_match_its_own_report_id(tmp_path):
    """The exact attack the reviewer proved: a hand-placed file named
    something other than ``<report_id>.pending-human-approval.json`` whose
    CONTENT claims a report_id belonging to a different, already-filed and
    already-approved report. Loading it must be a loud refusal, not a
    silent acceptance that later collides on approve()."""
    filer = DocumentationAgent(reports_dir=tmp_path)
    filed = filer.file_report(NON_CRITICAL_EXPLOIT)
    assert filed["status"] == "filed"
    del filer

    on_disk_filed = json.loads((tmp_path / "VULN-0002.json").read_text(encoding="utf-8"))
    assert on_disk_filed["clinical_impact"] != "ATTACKER-CONTROLLED OVERWRITE ATTEMPT"

    weird = {
        "schema_version": "1.0.0",
        "report_id": "VULN-0002",  # claims the ALREADY-FILED report's id
        "exploit_id": "EXP-0001",  # under a DIFFERENT exploit_id
        "severity": "critical",
        "clinical_impact": "ATTACKER-CONTROLLED OVERWRITE ATTEMPT",
        "observed": "n/a",
        "expected": "n/a",
        "remediation": "n/a",
        "fix_validation_status": "not_validated",
        "requires_human_gate": True,
        "filed_at": "2026-07-25T00:00:00Z",
    }
    (tmp_path / "weird-name.pending-human-approval.json").write_text(
        json.dumps(weird, indent=2), encoding="utf-8"
    )

    with pytest.raises(DocumentationAgentError, match="filename and content disagree"):
        DocumentationAgent(reports_dir=tmp_path)

    # Refusing to load must not have touched anything already on disk.
    still_on_disk = json.loads((tmp_path / "VULN-0002.json").read_text(encoding="utf-8"))
    assert still_on_disk == on_disk_filed
    assert (tmp_path / "weird-name.pending-human-approval.json").exists()


def test_load_rejects_duplicate_report_id_across_different_exploit_ids(tmp_path):
    """Two DIFFERENT files can each individually pass the filename check
    (each correctly named for its own claimed report_id) while still
    colliding on report_id across different exploit_ids -- e.g. a filed
    VULN-0001.json for EXP-0001 alongside a correctly-named
    VULN-0001.pending-human-approval.json that claims EXP-0002. report_id
    uniqueness must be enforced independently of the filename check."""
    filer = DocumentationAgent(reports_dir=tmp_path)
    filer.file_report(NON_CRITICAL_EXPLOIT)  # exploit_id EXP-0002 -> report_id VULN-0002, auto-filed
    del filer

    colliding_pending = {
        "schema_version": "1.0.0",
        "report_id": "VULN-0002",  # collides with the already-filed report above
        "exploit_id": "EXP-0001",  # but under a DIFFERENT exploit_id
        "severity": "critical",
        "clinical_impact": "collision",
        "observed": "n/a",
        "expected": "n/a",
        "remediation": "n/a",
        "fix_validation_status": "not_validated",
        "requires_human_gate": True,
        "filed_at": "2026-07-25T00:00:00Z",
    }
    # Correctly named for ITS OWN claimed report_id -- passes the filename
    # check on its own.
    (tmp_path / "VULN-0002.pending-human-approval.json").write_text(
        json.dumps(colliding_pending, indent=2), encoding="utf-8"
    )

    with pytest.raises(DocumentationAgentError, match="report_id .* is claimed by both"):
        DocumentationAgent(reports_dir=tmp_path)


def test_approve_removes_the_actual_source_path_not_a_report_id_guess(tmp_path):
    """Even for a legitimately-loaded pending report, _remove_pending_file
    must unlink the file that was actually loaded -- tracked by path, not
    reconstructed from report_id -- so a stale source file is never left
    behind after approval."""
    filer = DocumentationAgent(reports_dir=tmp_path)
    filer.file_report(CRITICAL_EXPLOIT)
    del filer

    approver = DocumentationAgent(reports_dir=tmp_path)
    source_path = approver._pending_paths["EXP-0001"]
    assert source_path == tmp_path / "VULN-0001.pending-human-approval.json"
    assert source_path.exists()

    approver.approve("EXP-0001", approved_by="owner")

    assert not source_path.exists()
    assert (tmp_path / "VULN-0001.json").exists()


def test_all_categories_map_to_a_valid_severity_and_pass_schema():
    for category in (
        "prompt_injection",
        "data_exfiltration",
        "state_corruption",
        "tool_misuse",
        "denial_of_service",
        "identity_authz",
    ):
        record = dict(NON_CRITICAL_EXPLOIT)
        record["category"] = category
        record["exploit_id"] = "EXP-0099"
        report = build_vuln_report(record, filed_at="2026-07-21T10:10:00Z")
        assert report["severity"] in ("critical", "high", "medium", "low")

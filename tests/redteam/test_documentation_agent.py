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


def test_approving_a_pending_critical_report_files_it():
    agent = DocumentationAgent()
    agent.file_report(CRITICAL_EXPLOIT)

    filed = agent.approve("EXP-0001", approved_at="2026-07-21T11:00:00Z")

    assert filed["status"] == "filed"
    assert filed["approved_at"] == "2026-07-21T11:00:00Z"
    assert agent.get_pending("EXP-0001") is None
    assert agent.get_filed("EXP-0001") is not None


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


def test_pending_critical_report_not_persisted_until_approved(tmp_path):
    agent = DocumentationAgent(reports_dir=tmp_path)
    agent.file_report(CRITICAL_EXPLOIT)
    assert list(tmp_path.glob("*.json")) == []

    agent.approve("EXP-0001")
    written = list(tmp_path.glob("*.json"))
    assert len(written) == 1


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

"""Red-first checks for the drafted Phase 3 close-out release notes (P3.29,
issue #59).

``docs/RELEASE_NOTES_v3.0.0.md`` is the outward-facing artifact the owner
will review and, if approved, publish as the ``v3.0.0`` GitHub Release --
the first tag in this repo. These checks do not validate prose quality;
they catch the concrete failure modes this project has hit before on
similar docs (stale test counts, dead paths, wrong component taxonomy,
finding-count drift against the owner-approved reports) so the notes can't
silently drift from the repo they describe.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from redteam.agents.red_team import DEFAULT_MODEL
from tests.test_readme_integrity import _extract_repo_relative_refs

REPO_ROOT = Path(__file__).resolve().parent.parent
RELEASE_NOTES = REPO_ROOT / "docs" / "RELEASE_NOTES_v3.0.0.md"
VULN_REPORTS_DIR = REPO_ROOT / "docs" / "vuln_reports"


def _text() -> str:
    assert RELEASE_NOTES.exists(), (
        f"{RELEASE_NOTES} does not exist -- the release notes have not "
        "been drafted yet (issue #59)"
    )
    return RELEASE_NOTES.read_text(encoding="utf-8")


def test_release_notes_file_exists():
    assert RELEASE_NOTES.exists()


def _is_not_actually_a_repo_path(ref: str) -> bool:
    """Filters two shapes this repo's own docs use routinely in backtick
    spans that are NOT filesystem paths, so this check doesn't flag
    established prose conventions as broken links: an HTTP endpoint like
    ``/chat`` (single leading-slash segment, no repo directory in it), and
    brace-glob shorthand like ``VULN-000{1,2,3,4}.json`` (used verbatim in
    docs/ATO_EVIDENCE_PACKET.md and docs/TRIAGE_LAB.md for the same four
    files this doc also cites individually via VULN-000N.json elsewhere)."""
    if "{" in ref or "}" in ref:
        return True
    if ref.startswith("/") and ref.count("/") == 1:
        return True
    return False


def test_release_notes_repo_relative_references_resolve():
    text = _text()
    refs = _extract_repo_relative_refs(text)
    refs = {ref for ref in refs if not _is_not_actually_a_repo_path(ref)}
    assert refs, "expected at least one repo-relative reference to check"
    missing = sorted(ref for ref in refs if not (REPO_ROOT / ref).exists())
    assert not missing, (
        f"RELEASE_NOTES_v3.0.0.md references paths absent from the tree: {missing}"
    )


def test_release_notes_finding_count_matches_owner_approved_reports():
    text = _text()
    report_files = sorted(VULN_REPORTS_DIR.glob("VULN-*.json"))
    assert len(report_files) == 4, (
        f"expected 4 owner-approved vuln reports, found {len(report_files)}: "
        f"{[f.name for f in report_files]}"
    )
    severities = set()
    for report_file in report_files:
        report = json.loads(report_file.read_text(encoding="utf-8"))
        report_id = report["report_id"]
        assert report_id in text, (
            f"release notes do not mention {report_id} "
            f"({report_file}), but it is one of the 4 owner-approved findings"
        )
        assert report.get("approved_by"), (
            f"{report_file} is not owner-approved (no approved_by) -- "
            "release notes must not cite it as a shipped finding"
        )
        severities.add(report["severity"])
    assert severities == {"critical", "medium"}, severities


def test_release_notes_does_not_overclaim_unapproved_candidates():
    text = _text()
    # #54 was a CLOSED candidate that resolved into VULN-0004, not a
    # standalone finding of its own; the notes must not cite it as a fifth
    # finding.
    assert "VULN-0005" not in text


@pytest.mark.parametrize("agent_name", ["Red Team", "Judge", "Orchestrator", "Documentation"])
def test_release_notes_names_all_four_agents(agent_name):
    assert agent_name in _text()


def test_release_notes_does_not_call_harness_or_observability_an_agent():
    """ARCHITECTURE.md is explicit: 'The Regression Harness and
    Observability Layer are shared infrastructure, not agents' -- getting
    this wrong was a real bug in a prior README draft. The release notes
    must state the same taxonomy: four agents, plus these two as shared
    infrastructure."""
    text = _text()
    assert "Regression" in text and "Harness" in text
    assert "Observability" in text
    normalized = " ".join(text.split())
    assert "shared infrastructure, not agents" in normalized or (
        "not agents" in normalized and "shared infrastructure" in normalized
    )


def test_release_notes_names_the_generator_model():
    assert DEFAULT_MODEL in _text()


def test_release_notes_cites_the_judge_independence_test():
    text = _text()
    assert "tests/redteam/test_judge_agent.py" in text
    judge_test = (REPO_ROOT / "tests" / "redteam" / "test_judge_agent.py").read_text(
        encoding="utf-8"
    )
    assert "ast.parse" in judge_test
    assert "redteam.agents" in judge_test and "redteam.harness" in judge_test


def test_release_notes_names_open_limitation_issues_without_closing_them():
    text = _text()
    assert "#63" in text
    assert "#68" in text
    # Never a GitHub closing keyword immediately paired with these two --
    # they must stay open per the brief.
    normalized = " ".join(text.lower().split())
    for forbidden in ("closes #63", "closes #68", "fixes #63", "fixes #68"):
        assert forbidden not in normalized, f"release notes must not close {forbidden}"


def test_release_notes_test_count_claims_are_conditioned():
    """Never a bare unconditioned test count (tests/test_doc_test_counts.py
    enforces the numbers stay live-accurate; this checks the *shape*: a
    solo 'N passed' claim must be accompanied by explicit local/CI framing
    in the same doc, not stated as if it were the one true count)."""
    text = _text()
    assert "passed" in text
    normalized = " ".join(text.split())
    assert "CI" in normalized
    assert "local" in normalized.lower() or "sibling" in normalized.lower()


def test_release_notes_mentions_upstream_status_without_dunking():
    text = _text()
    assert "v2.1.0" in text
    assert "923fb7d" in text
    assert "UPSTREAM_STATUS.md" in text
    assert "#167" in text  # upstream disclosure issue


def test_release_notes_describes_detector_blind_spot():
    text = _text()
    assert "dos_input_bound" in text
    assert "denial_of_service" in text or "human triage" in text.lower()

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


def test_release_notes_does_not_claim_separate_os_processes():
    """Overclaim-review FIX 1 (P3.29 fix pass): run_campaign wires all six
    components into one Python process in a single loop -- the notes must
    not claim the Red Team and Judge run as separate OS processes with
    separate contexts. Independence is module/data-level; OS-process
    isolation is ARCHITECTURE.md's design goal, tracked by issue #73."""
    text = _text()
    normalized = " ".join(text.lower().split())
    assert "separate os processes" not in normalized
    assert "run_campaign" in text
    assert "#73" in text


def test_release_notes_does_not_overclaim_judge_enforcement():
    """Overclaim-review FIX 2: the AST import scan only forbids
    redteam.agents/redteam.harness prefixes -- it does not prove no code
    path can leak Red Team internals to the Judge (e.g. via
    redteam.observability.action_log, which is not in the forbidden set)."""
    text = _text()
    normalized = " ".join(text.lower().split())
    assert "no code path by which the judge can see" not in normalized
    assert "redteam.observability" in text


def test_release_notes_maps_each_vuln_to_its_own_upstream_issue():
    """Overclaim-review FIX 3, updated post-#63/#68 closure: each of the
    four findings now has its own upstream issue (#167 VULN-0004, #168
    VULN-0001, #169 VULN-0002, #170 VULN-0003) -- the notes must map each
    finding to its own issue number, not lump them under one, and not
    claim (the now-stale fact) that only VULN-0004 was ever filed."""
    text = _text()
    normalized = " ".join(text.split())
    mapping = {
        "#167": "VULN-0004",
        "#168": "VULN-0001",
        "#169": "VULN-0002",
        "#170": "VULN-0003",
    }
    for issue, vuln in mapping.items():
        positions = [i for i in range(len(normalized)) if normalized.startswith(issue, i)]
        assert positions, f"{issue} not found"
        assert any(
            vuln in normalized[max(0, p - 100) : p + 200] for p in positions
        ), f"{issue} never appears near {vuln}"


def test_release_notes_states_draw_counts_and_vuln_0004_single_draw():
    """Overclaim-review FIX 4: single-draw honesty. VULN-0001/0002/0003 are
    3/3 independent draws; VULN-0004 is one recorded draw with its
    resource-exhaustion consequence flagged as deductive, not measured."""
    text = _text()
    assert "3/3" in text
    assert "single recorded draw" in text.lower() or "single draw" in text.lower()
    assert "deductive" in text.lower()


def test_release_notes_does_not_imply_approve_was_bypassed():
    """Overclaim-review FIX 5: approve() was the real transition for
    VULN-0004 (tools/approve_vuln_0004.py re-derives, re-drives
    file_report, compares field-for-field, then calls approve()). The
    notes must not imply the artifact was hand-made or approval skipped."""
    text = _text()
    assert "DocumentationAgent.approve()" in text
    assert "hand-editing" in text


def test_release_notes_does_not_carry_status_draft_header():
    """The notes must be pasteable directly as the GitHub Release body --
    no internal 'Status: DRAFT' banner."""
    text = _text()
    assert "Status: DRAFT" not in text


def test_release_notes_does_not_claim_63_or_68_are_open():
    """#63 and #68 are CLOSED (P3.31, P3.34) -- the notes must not carry
    the stale '(issue #63, open)' / '(issue #68, open)' framing, and must
    not use a bare 'open' issue-status word next to either number."""
    text = _text()
    normalized = " ".join(text.lower().split())
    for forbidden in ("issue #63, open", "#63, open", "issue #68, open", "#68, open"):
        assert forbidden not in normalized, f"stale open-issue framing survived: {forbidden!r}"


def test_release_notes_describes_63_and_68_as_closed_gaps():
    """The limitations section must now read as 'we found these gaps in our
    own evidence trail and closed them': #63 and #68 named, in a closed
    frame, plus the concrete shipped mechanisms (post-loop export,
    --list-pending, --approve/--approved-by, and the ATO packet's now-
    complete §5.2 index)."""
    text = _text()
    normalized = " ".join(text.split())
    assert "#63" in normalized and "#68" in normalized
    assert "closed" in normalized.lower()
    assert "--list-pending" in normalized
    assert "--approve" in normalized
    assert "--approved-by" in normalized
    assert "try/finally" in normalized or "try / finally" in normalized.lower()


def test_release_notes_does_not_claim_run_campaign_has_no_approve_subcommand():
    text = _text()
    normalized = " ".join(text.lower().split())
    assert "no approve subcommand" not in normalized
    assert "no `approve` subcommand" not in normalized


def test_release_notes_does_not_claim_ato_index_has_gaps():
    """The ATO evidence index gap (VULN-0004 missing from §5.2, exploit_id
    not resolving) is closed for the index; only the exploit_id
    in-process-only property should remain, stated as a property, not a
    gap."""
    text = _text()
    normalized = " ".join(text.split())
    assert "does not mention VULN-0004" not in normalized
    assert "known gaps (issue #68" not in normalized


def test_release_notes_names_all_four_upstream_issues():
    """All four findings are now filed upstream: #167 (VULN-0004), #168
    (VULN-0001), #169 (VULN-0002, refs upstream #130), #170 (VULN-0003,
    refs upstream #130, #121). The stale 'no upstream issue was filed for
    VULN-0001, VULN-0002, or VULN-0003' paragraph must be gone."""
    text = _text()
    normalized = " ".join(text.split())
    for issue in ("#167", "#168", "#169", "#170"):
        assert issue in normalized, f"upstream issue {issue} not named"
    assert "No upstream issue was filed for VULN-0001" not in normalized


def test_release_notes_notes_upstream_130_evidence_without_demanding_reopen():
    """#169/#170 record evidence contradicting the premise upstream #130
    was closed on ('design question, not currently triggering') -- the
    notes must state that as evidence on the record, not demand a reopen."""
    text = _text()
    normalized = " ".join(text.split())
    assert "#130" in normalized
    lowered = normalized.lower()
    for demand in ("should reopen", "must reopen", "reopen #130", "demand", "request that upstream reopen"):
        assert demand not in lowered, f"notes must not demand upstream action: {demand!r}"


def test_release_notes_owns_the_kickoff_process_isolation_gap():
    """planning/KICKOFF_PROMPT.md's HARD CONSTRAINT says '(separate
    process/context) independence'; docs/ARCHITECTURE.md now correctly
    states OS-process isolation is a design goal, not implemented. The
    release notes must own that gap explicitly: intent met (Judge shares no
    context, receives only (case, response, attempt_id), AST-scanned both
    directions), mechanism (separate processes) not implemented."""
    text = _text()
    assert "KICKOFF_PROMPT.md" in text
    normalized = " ".join(text.split())
    assert "case, response, attempt_id" in normalized
    assert "test_independence_module_imports_no_judge_internals" in normalized or (
        "both directions" in normalized.lower()
    )


def test_release_notes_discloses_p3_31_limitations():
    """New limitations from #76 (P3.31) must be disclosed: (1)
    pending_human_triage_count in the observability snapshot is per-call,
    not a directory scan; (2) --approve without --db-path needs the
    explicit unverified opt-out flag; (3) --reports-dir without --db-path
    refuses to start."""
    text = _text()
    normalized = " ".join(text.split())
    assert "pending_human_triage_count" in normalized
    assert "--unverified-i-vouch-without-db-check" in normalized
    assert "--reports-dir" in normalized and "--db-path" in normalized


def test_release_notes_test_counts_are_not_stale_p3_29_numbers():
    """The notes must not carry forward the pre-rebase 360/254 counts --
    tests/test_doc_test_counts.py is the arbiter of the live numbers."""
    text = _text()
    assert "360 passed" not in text
    assert "254 passed" not in text


def test_release_notes_quotes_the_full_kickoff_hard_constraint():
    """Final overclaim review, correction 1: planning/KICKOFF_PROMPT.md's
    HARD CONSTRAINT sentence 'A single-agent or linear pipeline FAILS the
    assignment' is the most adverse sentence in the verbatim quote and must
    not be silently dropped -- the notes themselves describe run_campaign
    as calling components in turn inside a single loop, which is exactly
    what a grader would call a linear pipeline."""
    text = _text()
    normalized = " ".join(text.split())
    assert "single-agent or linear pipeline FAILS the assignment" in normalized
    kickoff = (REPO_ROOT / "planning" / "KICKOFF_PROMPT.md").read_text(encoding="utf-8")
    assert "single-agent or linear pipeline FAILS the assignment" in " ".join(
        kickoff.split()
    )


def test_release_notes_does_not_call_the_parenthesised_mechanism_an_aside():
    """The kickoff brief's '(separate process/context)' is the HARD
    CONSTRAINT's own definition of architectural independence, not a
    parenthetical aside -- the notes must not describe it with a framing
    ('the parenthesised mechanism') that minimises it as incidental."""
    text = _text()
    assert "the parenthesised mechanism" not in text.lower()


def test_release_notes_does_not_claim_73_tracks_the_gap_as_open():
    """Final overclaim review, correction 2: issue #73 is CLOSED and was a
    documentation-correction issue -- nothing tracks implementing OS-process
    isolation. The notes must not say the gap 'is tracked' by #73 as an
    open tracking item; they must say it is not currently scheduled."""
    text = _text()
    normalized = " ".join(text.split())
    assert "is tracked separately (issue #73)" not in normalized
    assert "is tracked (issue #73)" not in normalized
    assert "not currently scheduled" in normalized.lower()


def test_release_notes_vuln_reports_are_14_field_artifacts_with_recording_ref():
    """Consequence of merged #77/#79: vuln reports gained a 14th field,
    recording_ref, pointing each report at its own evals/recordings/
    directory. The notes' '13-field' enumeration is stale."""
    text = _text()
    report = json.loads((VULN_REPORTS_DIR / "VULN-0001.json").read_text(encoding="utf-8"))
    assert "recording_ref" in report
    assert len(report) == 14
    assert "14-field" in text
    assert "recording_ref" in text
    assert "13-field" not in text


def test_release_notes_each_report_names_its_own_recording_directory():
    """With recording_ref on every report, the report-to-recording mapping
    no longer lives only in ATO §5.2 -- each report now names its own
    recording directory; §5.2 remains the human-readable index, not the
    sole resolution path."""
    text = _text()
    normalized = " ".join(text.split())
    assert "recording_ref" in normalized


def test_release_notes_scopes_the_130_claim_to_vuln_0002():
    """Final overclaim review, correction 3: upstream #130's Ask scoped its
    case to a claim carrying ONLY an irrelevant SourceRef with no
    DocumentCitation. Only VULN-0002's recording matches that shape
    (document_citations: []); VULN-0003's recording carries the SourceRef
    alongside a real guideline_chunk DocumentCitation -- the shape #130's
    body pre-emptively called 'harmless today'. The notes must not claim
    both findings are 'exactly that gap firing'."""
    text = _text()
    normalized = " ".join(text.split())
    assert "VULN-0002 and VULN-0003 are exactly that gap firing" not in normalized
    assert "document_citations" in normalized or "DocumentCitation" in normalized
    assert "VULN-0002" in normalized.split("#130")[-1][:400] or "VULN-0002" in normalized.split(
        "#130"
    )[0][-400:]


def test_release_notes_scopes_vuln_0001_to_the_shipped_default():
    """Final overclaim review, correction 4: VULN-0001 is default-
    configuration-only -- with copilot_per_user_token_enabled=True a real
    introspection validator replaces the permissive default. 'holds
    unconditionally ... at any configuration' is false for VULN-0001."""
    text = _text()
    normalized = " ".join(text.split())
    assert "VULN-0001 and VULN-0004 hold unconditionally" not in normalized
    assert "copilot_per_user_token_enabled=False" in normalized


def test_release_notes_scopes_the_scorer_none_claim_correctly():
    """Final overclaim review, correction 5: JudgeAgent(scorer=None) is not
    the only path any test exercises -- test_judge_agent.py:236 constructs
    JudgeAgent(scorer=corrupting_scorer) for a drift test."""
    text = _text()
    normalized = " ".join(text.split())
    assert (
        "the only path any test in tests/redteam/test_judge_agent.py exercises"
        not in normalized
    )
    assert "drift test" in normalized.lower() or "drift-detection" in normalized.lower()


def test_release_notes_qualifies_the_v210_filed_after_claim():
    """Non-blocking correction 6: VULN-0004 was filed after the v2.1.0 tag
    was created; the other three were filed before it. 'after these
    findings were filed' (unqualified) is false for VULN-0004."""
    text = _text()
    normalized = " ".join(text.split())
    assert "three of these four findings were filed" in normalized
    assert "VULN-0004 was filed later the same day" in normalized


def test_release_notes_cites_the_correct_scorer_none_line_range():
    """Non-blocking correction 7: judge.py:44-47 is mis-ranged for the
    scorer=None claim; the scorer-seam docstring paragraph is :44-53."""
    text = _text()
    assert "judge.py:44-53" in text
    judge_src = (REPO_ROOT / "redteam" / "agents" / "judge.py").read_text(encoding="utf-8")
    lines = judge_src.splitlines()
    assert "scorer seam" in lines[43].lower()
    assert "exercises directly" in lines[52].lower()


def test_release_notes_does_not_overstate_red_team_scan_symmetry():
    """Non-blocking correction 8: the Judge-side AST scan resolves relative
    imports; the Red-Team-side scan checks absolute module paths only, so
    'from .judge import X' would pass it undetected. 'the same way' claims
    symmetry that does not hold."""
    text = _text()
    normalized = " ".join(text.split())
    assert "scans redteam/agents/red_team.py the same way" not in normalized
    assert "relative import" in normalized.lower()


def test_release_notes_states_temperature_zero_on_the_draw_counts():
    """Non-blocking correction 9: upstream filings carry '3/3 ... at
    temperature 0'; the notes drop the temperature qualifier."""
    text = _text()
    assert "temperature 0" in text.lower()


def test_release_notes_does_not_substitute_a_word_inside_the_quote():
    """Non-blocking correction 10: the upstream source word
    (config.py:251) is 'mechanism', not 'alternative' -- a substituted word
    must not appear inside quote marks attributed to upstream."""
    text = _text()
    normalized = " ".join(text.split())
    assert "coarser, owner-approved alternative" not in normalized
    assert "coarser, owner-approved mechanism" in normalized

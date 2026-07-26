"""Red-first for issue #58: does each of the four shipped findings
(``docs/vuln_reports/VULN-0001..0004.json``) still describe *current* Phase
2 at tag ``v2.1.0`` (merge ``923fb7d``)?

Asserts the resolved ``UpstreamStatus`` for all four findings
(``evals.analysis.v210_upstream_status``), then machine-checks two
independent things:

1. ``TestCitationsAgainstPinnedTargets`` -- every ``TRACE_CITATIONS_V210``
   entry's quoted text actually appears on its cited line, AT THE TAG the
   citation names (v2.0.0 or v2.1.0) -- extends
   ``tests/test_dos_input_bound_resolution.py``'s pattern with a
   per-citation tag. Skips cleanly when the sibling checkout is absent (CI
   does not check out the target).
2. ``test_v210_gates_still_verify_vuln_0002``/``_vuln_0003`` -- runs the
   faithfully-reproduced v2.1.0 gate algorithm (constants/logic copied from
   the cited lines, not executed sibling code) against the REAL recorded
   draws backing VULN-0002/0003, to settle "would the new gates catch this
   if flipped on" by computation, not just reasoning about prose.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from evals.analysis.v210_upstream_status import (
    TRACE_CITATIONS_V210,
    UPSTREAM_STATUS_BY_FINDING,
    VULN_0001,
    VULN_0002,
    VULN_0003,
    VULN_0004,
    _call_is_engaged,
    _claim_is_grounded_in_answer,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_TARGET_REPO = _REPO_ROOT.parent / "agentforge-2-evidence-agent"

_VULN_0002_RECORDING = (
    _REPO_ROOT
    / "evals"
    / "recordings"
    / "data-exfil-discontinued-med-marked-verified"
    / "20260722T031455Z-draw1.json"
)
_VULN_0003_RECORDING = (
    _REPO_ROOT
    / "evals"
    / "recordings"
    / "data-exfil-sourceref-topical-irrelevance"
    / "20260722T054922Z-draw1.json"
)


def _target_repo_available() -> bool:
    return (_TARGET_REPO / ".git").exists()


def _load_recording(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _event(recording: dict, name: str) -> dict:
    for event_name, payload in recording["events"]:
        if event_name == name:
            return payload
    raise AssertionError(f"no {name!r} event in {recording.get('case_id')}")


def test_all_four_findings_have_a_resolved_upstream_status():
    assert set(UPSTREAM_STATUS_BY_FINDING) == {"VULN-0001", "VULN-0002", "VULN-0003", "VULN-0004"}


def test_vuln_0001_auth_bypass_holds_unconditionally_at_v210():
    # No v2.1.0 gate touches authentication -- default and gates-enabled
    # give the same answer.
    assert VULN_0001.v200_holds is True
    assert VULN_0001.v210_default_holds is True
    assert VULN_0001.v210_gates_enabled_holds is True


def test_vuln_0004_unbounded_input_holds_unconditionally_at_v210():
    # No v2.1.0 gate touches ChatRequest/ConversationStore either.
    assert VULN_0004.v200_holds is True
    assert VULN_0004.v210_default_holds is True
    assert VULN_0004.v210_gates_enabled_holds is True


def test_vuln_0002_and_0003_unchanged_on_default_v210_config():
    # Both new gates default OFF -- check_source_ref's provenance-only logic
    # is byte-identical at v2.0.0 and v2.1.0 for both findings.
    for status in (VULN_0002, VULN_0003):
        assert status.v200_holds is True
        assert status.v210_default_holds is True


def test_vuln_0002_and_0003_are_determined_not_undetermined_with_gates_on():
    # The orchestrator pre-work left "with gates enabled" as "if
    # determinable" -- this repo determines it (see the computed checks
    # below), so neither finding should be left at None ("cannot
    # determine").
    assert VULN_0002.v210_gates_enabled_holds is not None
    assert VULN_0003.v210_gates_enabled_holds is not None


def test_v210_gates_still_verify_vuln_0002():
    """Run the reproduced v2.1.0 gate algorithm against the REAL recorded
    draw backing VULN-0002: does the discontinued-medication citation
    survive both new gates if flipped on?"""
    recording = _load_recording(_VULN_0002_RECORDING)
    verification = _event(recording, "verification")
    answer = _event(recording, "answer")["answer"]

    lisinopril_claim = next(
        seg
        for seg in verification["segments"]
        if seg["type"] == "claim" and "Lisinopril" in seg["text"]
    )
    citations = lisinopril_claim["citations"]
    status_citation = next(c for c in citations if c["field"] == "status")
    assert status_citation["value"] == "discontinued"

    # answer_grounding: is the claim's own text grounded in the answer?
    assert _claim_is_grounded_in_answer(lisinopril_claim["text"], answer) is True

    # tool_call_scoping: is the citing call (call_0, get_medications)
    # "engaged"? Reconstruct its value-token universe from every citation's
    # own resolved `value` this same recording's verification event reports
    # for call_0 (these values are, by construction, the raw record's own
    # field values -- that is what check_source_ref just re-validated).
    call_0_values = [
        citation["value"]
        for segment in verification["segments"]
        if segment["type"] == "claim"
        for citation in segment["citations"]
        if citation["tool_call_id"] == "call_0"
    ]
    assert _call_is_engaged(call_0_values, answer) is True

    # Both gates would leave this citation exactly as-is: engaged call,
    # grounded claim text -- neither downgrades it. VULN-0002 reproduces
    # even with both new v2.1.0 gates flipped on.
    assert VULN_0002.v210_gates_enabled_holds is True


def test_v210_gates_still_verify_vuln_0003():
    """Same computation for VULN-0003's topically-irrelevant SourceRef."""
    recording = _load_recording(_VULN_0003_RECORDING)
    verification = _event(recording, "verification")
    answer = _event(recording, "answer")["answer"]

    bp_claim = next(
        seg
        for seg in verification["segments"]
        if seg["type"] == "claim" and "blood pressure was elevated" in seg["text"].lower()
    )
    citations = bp_claim["citations"]
    assert len(citations) == 1
    assert citations[0]["field"] == "status"
    assert citations[0]["tool_call_id"] == "call_0"

    # answer_grounding: the claim text is the question's own premise,
    # repeated near-verbatim in the answer -- grounded, despite the
    # citation being topically irrelevant.
    assert _claim_is_grounded_in_answer(bp_claim["text"], answer) is True

    # tool_call_scoping: call_0 (get_appointments) is engaged -- the SAME
    # call's date/time/provider fields are quoted directly in the answer.
    call_0_values = [
        citation["value"]
        for segment in verification["segments"]
        if segment["type"] == "claim"
        for citation in segment["citations"]
        if citation["tool_call_id"] == "call_0"
    ]
    assert _call_is_engaged(call_0_values, answer) is True

    assert VULN_0003.v210_gates_enabled_holds is True


@pytest.mark.skipif(
    not _target_repo_available(),
    reason="sibling target checkout ../agentforge-2-evidence-agent not present (expected in CI)",
)
class TestCitationsAgainstPinnedTargets:
    """Makes every ``TRACE_CITATIONS_V210`` claim real: verified, not just
    asserted, against the pinned tag it names. Read-only: ``git show
    <tag>:<path>`` from the sibling checkout, never ``git checkout``."""

    @pytest.mark.parametrize(
        "tag,path,line,quote",
        TRACE_CITATIONS_V210,
        ids=[f"{t}:{p}:{ln}" for t, p, ln, _ in TRACE_CITATIONS_V210],
    )
    def test_citation_line_contains_quoted_text(self, tag, path, line, quote):
        result = subprocess.run(
            ["git", "show", f"{tag}:{path}"],
            cwd=_TARGET_REPO,
            capture_output=True,
            text=True,
            check=True,
        )
        source_lines = result.stdout.splitlines()
        assert 1 <= line <= len(source_lines), (
            f"{path}:{line} is out of range for pinned {tag} ({len(source_lines)} lines)"
        )
        actual_line = source_lines[line - 1]
        assert quote in actual_line, (
            f"{path}:{line} at pinned {tag} reads {actual_line!r}, "
            f"which does not contain the cited quote {quote!r}"
        )

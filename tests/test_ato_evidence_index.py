"""ATO evidence-packet index consistency (issue #68).

``docs/ATO_EVIDENCE_PACKET.md`` §5.2 is the evidence index a reviewer
follows to map each committed recording under ``evals/recordings/`` and
each owner-approved report under ``docs/vuln_reports/`` to its evidence.
Two defects motivated this test:

1. ``:29`` cross-references §5.2 for VULN-0004's evidence, but §5.2's VULN-0004
   mention (in a later "Re-verifying" paragraph) never described its evidence
   -- a reader following the :29 pointer landed on a section that names
   VULN-0004 but doesn't say what recording backs it.
2. §5.2 said "a fourth recorded set exists" when ``evals/recordings/``
   already held five directories, and the paragraph a VULN-0004 reader
   was pointed at actually described a *different*, dismissed DoS
   recording (``dos-overlong-query-max-query-chars``, TRI-013).

This guard is derived from the filesystem (every directory under
``evals/recordings/``, every report under ``docs/vuln_reports/``) rather
than a fixed count, so it self-updates as recordings/reports are added,
and is scoped to the §5.2 section body specifically so it doesn't
false-positive on unrelated "VULN-000N" mentions elsewhere in the doc.

Cold-review fix (issue #68, Part C): the fix for Part B's join-key claim
introduced two NEW false claims in the same docstring -- that the durable
evidence is "named directly on each report" (no committed report contains
"evals/recordings" or "recording" at all), and that ``observed``/
``expected`` "already carry the repro steps a reader needs" (they carry
Judge.detect()'s detection signal, not an endpoint/payload/token/case
module). Part C below guards both, plus a ground-truth check against the
actual report files so the claim is checked, not just the wording.
"""

from __future__ import annotations

import re

from tests.conftest import REPO_ROOT

_PACKET_PATH = REPO_ROOT / "docs" / "ATO_EVIDENCE_PACKET.md"
_RECORDINGS_DIR = REPO_ROOT / "evals" / "recordings"
_VULN_REPORTS_DIR = REPO_ROOT / "docs" / "vuln_reports"

# Extract the §5.2 section body: from its heading to the next Markdown
# heading of any level (### 5.3, ## 6, etc.) -- "\n##\s" alone would NOT
# stop at "### 5.3" (three hashes isn't matched by a two-hash-then-space
# pattern), silently swallowing §5.3/§5.4 into "§5.2" and letting an
# unrelated VULN-0004 mention elsewhere rescue this test.
_SECTION_5_2_RE = re.compile(
    r"###\s*5\.2\b.*?(?=\n#{1,6}\s|\Z)",
    re.DOTALL,
)


def _section_5_2_text() -> str:
    text = _PACKET_PATH.read_text(encoding="utf-8")
    match = _SECTION_5_2_RE.search(text)
    assert match, (
        "docs/ATO_EVIDENCE_PACKET.md has no §5.2 heading ('### 5.2 ...') -- "
        "the evidence-index section this test targets does not exist"
    )
    return match.group(0)


def _unqualified_claims(
    normalized_text: str,
    claim_re: "re.Pattern[str]",
    qualifier_re: "re.Pattern[str]",
    window: int,
) -> list[str]:
    """Every ``claim_re`` match in ``normalized_text`` that has no
    ``qualifier_re`` hit within ``window`` characters on either side --
    shared by the docstring-claim guards below (Part B's join-key claim,
    Part C's repro-steps claim), which both need "flag this phrasing
    unless a qualifying/negating phrase sits nearby" rather than a bare
    presence/absence check."""
    violations = []
    for match in claim_re.finditer(normalized_text):
        start = max(0, match.start() - window)
        end = min(len(normalized_text), match.end() + window)
        if not qualifier_re.search(normalized_text[start:end]):
            violations.append(normalized_text[match.start():match.end()])
    return violations


def test_every_recording_directory_is_referenced_in_section_5_2():
    section = _section_5_2_text()
    recording_dirs = sorted(p.name for p in _RECORDINGS_DIR.iterdir() if p.is_dir())
    assert recording_dirs, "evals/recordings/ has no recording directories to check against"

    missing = [name for name in recording_dirs if name not in section]
    assert not missing, (
        "docs/ATO_EVIDENCE_PACKET.md §5.2 does not mention the following "
        f"evals/recordings/ directories: {missing} -- every recording under "
        "evals/recordings/ must be referenced by name in §5.2 so a reader "
        "can map every committed recording to its disposition"
    )


_REPORT_TO_RECORDING_WINDOW = 300


def test_every_approved_vuln_report_is_referenced_in_section_5_2():
    section = _section_5_2_text()
    report_ids = sorted(p.stem for p in _VULN_REPORTS_DIR.glob("VULN-*.json"))
    assert report_ids, "docs/vuln_reports/ has no VULN-*.json reports to check against"

    missing = [rid for rid in report_ids if rid not in section]
    assert not missing, (
        "docs/ATO_EVIDENCE_PACKET.md §5.2 does not mention the following "
        f"owner-approved reports: {missing} -- every report under "
        "docs/vuln_reports/ must be named in §5.2, not just the three "
        "criticals, or a reader following the cross-reference at :29 lands "
        "on a section that never mentions the finding they were sent to find"
    )


def test_every_approved_vuln_report_co_occurs_with_its_recording_in_section_5_2():
    """Stronger than merely appearing in §5.2 (above): a report ID being
    named is not the same as its evidence being described. This was the
    actual :29 defect -- §5.2 named VULN-0004 (in the "Re-verifying"
    paragraph) without ever saying what recording backs it. Require each
    report ID to occur near an ``evals/recordings/`` path, not just
    anywhere in the section."""
    section = _section_5_2_text()
    report_ids = sorted(p.stem for p in _VULN_REPORTS_DIR.glob("VULN-*.json"))
    assert report_ids, "docs/vuln_reports/ has no VULN-*.json reports to check against"

    recording_positions = [m.start() for m in re.finditer(r"evals/recordings/", section)]
    assert recording_positions, "§5.2 does not mention evals/recordings/ at all"

    uncorroborated = []
    for rid in report_ids:
        positions = [m.start() for m in re.finditer(re.escape(rid), section)]
        if not positions:
            continue  # already flagged by the presence test above
        nearest = min(abs(p - r) for p in positions for r in recording_positions)
        if nearest > _REPORT_TO_RECORDING_WINDOW:
            uncorroborated.append(rid)

    assert not uncorroborated, (
        "docs/ATO_EVIDENCE_PACKET.md §5.2 names the following reports but "
        f"never describes their evidence nearby: {uncorroborated} -- no "
        "'evals/recordings/' path appears within "
        f"{_REPORT_TO_RECORDING_WINDOW} characters of the report ID"
    )


# --- Part B (issue #68): exploit_id join key must not be claimed resolvable
# against a committed artifact that does not exist ---------------------------
#
# redteam/agents/documentation.py's docstring described a filed report's
# exploit_id as "the join key back to the full ExploitRecord ... in the
# exploit DB", but no report-builder in this repo ever persists an
# ExploitDB to disk (every one constructs DocumentationAgent(reports_dir=
# None) and ExploitDB's own default is ":memory:") -- so EXP-0001..EXP-0004
# resolve to nothing a reader can open. This guard is narrow: it only flags
# "exploit_id ... join key ... exploit DB" phrasing that is NOT accompanied
# by an explicit "in-process only" / "no persisted" qualifier nearby.

_JOIN_KEY_CLAIM_RE = re.compile(
    r"join key.{0,120}exploit DB",
    re.IGNORECASE | re.DOTALL,
)
_IN_PROCESS_QUALIFIER_RE = re.compile(
    r"in-process only|no persisted|not persisted|:memory:|reports_dir=None",
    re.IGNORECASE,
)
_JOIN_KEY_WINDOW = 600


def test_documentation_agent_docstring_does_not_claim_a_resolvable_exploit_db():
    text = (REPO_ROOT / "redteam" / "agents" / "documentation.py").read_text(encoding="utf-8")
    normalized = " ".join(text.split())
    violations = _unqualified_claims(
        normalized, _JOIN_KEY_CLAIM_RE, _IN_PROCESS_QUALIFIER_RE, _JOIN_KEY_WINDOW
    )

    assert not violations, (
        "redteam/agents/documentation.py describes exploit_id as a join key "
        "into 'the exploit DB' without qualifying that no report-builder in "
        "this repo persists ExploitDB to disk (all use "
        "DocumentationAgent(reports_dir=None); ExploitDB defaults to "
        "':memory:') -- this claims a resolvable artifact that does not "
        f"exist:\n{violations}"
    )


# --- Part C (issue #68 cold review, superseded by issue #77/P3.36) --------
#
# The first Part B fix replaced the "join key ... exploit DB" claim with two
# NEW false claims: that the durable evidence is "named directly on each
# report" (at the time, no report contained "evals/recordings" or
# "recording" -- the report-to-recording mapping lived only in
# docs/ATO_EVIDENCE_PACKET.md §5.2, not on the report itself), and that
# observed/expected "already carry the repro steps a reader needs" (they
# carry Judge.detect()'s detection signal -- a label/message string, not an
# endpoint, payload, token, or case module).
#
# Issue #77 (P3.36) made the FIRST claim true on purpose: vuln_report.
# schema.json gained an optional recording_ref property, and
# build_vuln_report() now derives it from the source exploit record's
# case_id and writes it onto every filed report -- so "a report names its
# own evidence" is current, accurate documentation, not a false claim to be
# guarded against. The repro-steps distinction is unaffected (observed/
# expected still carry Judge.detect()'s detection signal, not runnable
# steps) and remains checked below. What changed is which claim counts as
# ground truth: this test now asserts every filed report DOES carry a
# recording_ref (the positive of the old "must not name" tripwire), so a
# future regression that silently drops the field is still caught.

_UNQUALIFIED_REPRO_STEPS_RE = re.compile(
    r"carr(?:y|ies).{0,80}repro steps",
    re.IGNORECASE | re.DOTALL,
)
_NEGATION_NEARBY_RE = re.compile(
    r"\bnor\b|\bnot\b|\bn't\b|\bnone\b|\bcannot\b|\bno report\b",
    re.IGNORECASE,
)
_NEGATION_WINDOW = 60


def test_documentation_agent_docstring_does_not_claim_unqualified_repro_steps():
    text = (REPO_ROOT / "redteam" / "agents" / "documentation.py").read_text(encoding="utf-8")
    normalized = " ".join(text.split())

    repro_steps_violations = _unqualified_claims(
        normalized, _UNQUALIFIED_REPRO_STEPS_RE, _NEGATION_NEARBY_RE, _NEGATION_WINDOW
    )
    assert not repro_steps_violations, (
        "redteam/agents/documentation.py claims observed/expected 'carry "
        "the repro steps' without qualification -- VULN-0001.json's "
        "observed/expected name no endpoint, payload, token, or case "
        "module; they carry Judge.detect()'s detection signal, not repro "
        f"steps:\n{repro_steps_violations}"
    )


def test_filed_reports_name_their_own_recording():
    """Ground-truth check for issue #77/P3.36: every committed, filed
    report now DOES contain a recording pointer (recording_ref), so the
    docstring's current claim that "a report names its own evidence" is
    checkable against real files, not just docstring wording -- the
    positive of the old (pre-#77) "must not name" tripwire this test
    replaces. See tests/redteam/test_vuln_reports_filed.py for the fuller
    check (schema-valid, resolves to an existing directory with a draw)."""
    reports_dir = REPO_ROOT / "docs" / "vuln_reports"
    filed_reports = [
        p for p in sorted(reports_dir.glob("VULN-*.json")) if not p.name.endswith(".pending-human-approval.json")
    ]
    assert filed_reports, f"expected at least one filed report under {reports_dir}"
    for report_path in filed_reports:
        text = report_path.read_text(encoding="utf-8")
        assert "evals/recordings" in text, (
            f"{report_path.name} does not name its own recording -- "
            "expected a recording_ref pointing under evals/recordings/"
        )

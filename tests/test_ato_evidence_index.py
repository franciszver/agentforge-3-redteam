"""ATO evidence-packet index consistency (issue #68).

``docs/ATO_EVIDENCE_PACKET.md`` §5.2 is the evidence index a reviewer
follows to map each committed recording under ``evals/recordings/`` and
each owner-approved report under ``docs/vuln_reports/`` to its evidence.
Two defects motivated this test:

1. ``:29`` cross-references §5.2 for VULN-0004, but §5.2 never mentioned
   VULN-0004 -- a dangling pointer on the externally-facing artifact.
2. §5.2 said "a fourth recorded set exists" when ``evals/recordings/``
   already held five directories, and the paragraph a VULN-0004 reader
   was pointed at actually described a *different*, dismissed DoS
   recording (``dos-overlong-query-max-query-chars``, TRI-013).

This guard is derived from the filesystem (every directory under
``evals/recordings/``, every report under ``docs/vuln_reports/``) rather
than a fixed count, so it self-updates as recordings/reports are added,
and is scoped to the §5.2 section body specifically so it doesn't
false-positive on unrelated "VULN-000N" mentions elsewhere in the doc.
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

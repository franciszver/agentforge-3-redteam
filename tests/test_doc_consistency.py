"""Cross-doc consistency check for the human-approval gate's trigger
condition (P3.26 follow-up, issue #62).

P3.26 promoted ``FORCE_HUMAN_GATE_CATEGORIES`` to a shared public constant:
the human-approval gate now also fires for an entire category
(``denial_of_service``) regardless of severity, because
``evals.cases.dos_input_bound.detect`` cannot reliably distinguish "guard
absent" from "guard fired then fail-soft-swallowed" (see
``redteam/agents/documentation.py``'s docstring above the constant).

``docs/ARCHITECTURE.md``'s Mermaid diagram was updated to say "critical
severity + not-machine-decidable categories", but the *same diagram* is
duplicated in ``docs/ATO_EVIDENCE_PACKET.md`` (the externally-facing
evidence artifact) and kept the pre-P3.26 "critical severity only" label.
This is the second time a stale "critical-only" description of the gate has
shipped, so the guard here is written against the *class* of defect --
derived from the ``FORCE_HUMAN_GATE_CATEGORIES`` constant itself -- rather
than a fixed string match against one file, so it self-updates if the
category set ever changes.
"""

from __future__ import annotations

import re

from redteam.agents.documentation import FORCE_HUMAN_GATE_CATEGORIES
from tests.conftest import REPO_ROOT, tracked_markdown_files

# Anchor on a mention of the gate itself so this stays targeted: an
# unrelated "only ... critical" sentence elsewhere in a long doc (e.g.
# TRIAGE_LAB.md's "Only the 3 criticals are owner-approved confirmed
# exploits") must not false-positive just because it isn't near a
# description of the gate.
_GATE_RE = re.compile(r"(human[- ]approval|approval) gate", re.IGNORECASE)
_CRITICAL_ONLY_RE = re.compile(
    r"critical[- ]severity only|critical only|only.{0,20}critical",
    re.IGNORECASE,
)

# Characters of context scanned to either side of a gate mention. Wide
# enough to span "Human approval gate<br/>(critical severity only)" style
# Mermaid node labels after whitespace normalization, narrow enough that an
# unrelated "only"/"critical" elsewhere in a long doc doesn't false-positive.
_WINDOW = 80


def test_no_committed_doc_describes_gate_as_critical_severity_only():
    # This test's premise -- that "critical severity only" is a stale
    # description -- only holds while at least one category is force-routed
    # through the gate regardless of severity. If the constant ever goes
    # back to empty, "critical severity only" would be accurate again and
    # this guard would need to be revisited rather than silently pass.
    assert FORCE_HUMAN_GATE_CATEGORIES, (
        "FORCE_HUMAN_GATE_CATEGORIES is empty -- the gate really would be "
        "critical-severity-only again, so this test's assumption no longer "
        "holds and it must be reviewed rather than trusted as-is"
    )

    violations = []
    for path in tracked_markdown_files():
        text = path.read_text(encoding="utf-8")
        normalized = " ".join(text.split())
        for gate_match in _GATE_RE.finditer(normalized):
            start = max(0, gate_match.start() - _WINDOW)
            end = min(len(normalized), gate_match.end() + _WINDOW)
            window = normalized[start:end]
            if _CRITICAL_ONLY_RE.search(window):
                rel = path.relative_to(REPO_ROOT).as_posix()
                violations.append(f"{rel}: ...{window}...")

    assert not violations, (
        "the human-approval gate also force-fires for whole categories "
        f"({sorted(FORCE_HUMAN_GATE_CATEGORIES)}), not just critical "
        "severity (redteam/agents/documentation.py "
        "FORCE_HUMAN_GATE_CATEGORIES), but the following committed docs "
        "still describe it as critical-severity-only:\n"
        + "\n".join(violations)
    )

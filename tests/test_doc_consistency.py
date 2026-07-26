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
import subprocess

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


# --- P3.35 (issue #73): OS-process isolation is claimed but not shipped ----
#
# docs/ARCHITECTURE.md and docs/ATO_EVIDENCE_PACKET.md asserted that each
# Zone-A/Zone-B role "runs as its own OS process with its own local model
# instance" and used that property to differentiate this platform from
# Garak. ``redteam/campaign.py::run_campaign`` actually calls all four
# components as in-process Python objects inside one ``for`` loop -- there
# is no process, thread, or subprocess boundary anywhere in the platform
# (``grep -rn "multiprocessing\|subprocess\|Popen\|fork(" redteam/ tools/``
# returns nothing). What IS real and enforced is module- and data-level
# independence (an AST import scan in
# ``tests/redteam/test_judge_agent.py``), which is a materially weaker
# property than OS-process isolation and must not be described as if it
# were the same thing.
#
# This guard is deliberately narrow: it only flags a *process-isolation
# claim* (an isolation/independence assertion in the same neighborhood as
# "process", "OS process", or "model instance") that is NOT accompanied by
# an explicit "this is a goal, not yet implemented" qualifier nearby. A
# previous guard in this area was overzealous and was reverted rather than
# shipped -- prose that correctly frames OS-process isolation as a design
# goal (e.g. "design goal, not yet implemented") must NOT trip this test.

_PROCESS_ISOLATION_CLAIM_RE = re.compile(
    r"own OS process"
    r"|separate (local )?process(es)?(\s*/\s*context(s)?)?"
    r"|process[- ]level isolation"
    r"|process (and context )?isolation"
    r"|process independence"
    r"|own local model instance",
    re.IGNORECASE,
)

_GOAL_QUALIFIER_RE = re.compile(
    r"design goal|not yet implemented|not currently implemented"
    r"|future work|aspirational|remains? (a )?goal|longer[- ]term goal"
    r"|not\s.{0,40}isolation (today|yet)|eventually",
    re.IGNORECASE,
)

# Wide enough to span a claim and a same-sentence-or-next-sentence
# qualifier; narrow enough that an unrelated goal/aspiration elsewhere in a
# long doc doesn't rescue a genuine violation many paragraphs away.
_PROCESS_CLAIM_WINDOW = 400


def test_no_committed_doc_claims_os_process_isolation_is_implemented():
    # Supporting fact: the shipped code has no process-spawning primitive
    # anywhere in the platform, so any *unqualified* OS-process-isolation
    # claim in a committed doc is describing code that does not exist.
    grep = subprocess.run(
        ["git", "grep", "-nE", r"multiprocessing|subprocess|Popen|fork\(", "--", "redteam/", "tools/"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert grep.returncode == 1 and not grep.stdout, (
        "expected no process-spawning primitive under redteam/ or tools/ "
        "(this assertion's premise -- that OS-process isolation is not "
        "implemented -- no longer holds; revisit this guard):\n" + grep.stdout
    )

    violations = []
    for path in tracked_markdown_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        # planning/ holds the original, historical kickoff prompts -- an
        # imperative build instruction ("Build four agents with ...
        # independence") written before any code existed is a requirement,
        # not a claim about shipped behaviour, and rewriting a verbatim
        # historical prompt would falsify the record of what was actually
        # asked for. This guard is about doc claims describing the platform
        # as it ships (ARCHITECTURE.md, ATO_EVIDENCE_PACKET.md, etc.).
        if rel.startswith("planning/"):
            continue
        text = path.read_text(encoding="utf-8")
        normalized = " ".join(text.split())
        for match in _PROCESS_ISOLATION_CLAIM_RE.finditer(normalized):
            start = max(0, match.start() - _PROCESS_CLAIM_WINDOW)
            end = min(len(normalized), match.end() + _PROCESS_CLAIM_WINDOW)
            window = normalized[start:end]
            if not _GOAL_QUALIFIER_RE.search(window):
                violations.append(f"{rel}: ...{normalized[max(0, match.start()-80):match.end()+80]}...")

    assert not violations, (
        "the shipped platform has no OS-process isolation (redteam/campaign.py "
        "::run_campaign calls all four components in-process, in one for "
        "loop; no multiprocessing/subprocess/Popen/fork under redteam/ or "
        "tools/), but the following committed docs assert process isolation "
        "as implemented behaviour without qualifying it as a design goal:\n"
        + "\n".join(violations)
    )

"""CLAUDE.md accuracy checks (P3.30, issue #61).

The repo went public (``gh repo view --json visibility`` reports ``PUBLIC``)
and ``planning/APPROACH.md`` + ``planning/PLAN.md`` were relocated to the
gitignored ``prd/`` directory (commit 9708fc9), but ``CLAUDE.md`` -- the
operator-facing guidance a visitor to this public repo reads first -- was
never updated: it still asserted "Private repo." and still pointed at
``planning/PLAN.md`` / ``planning/APPROACH.md`` as if they were tracked
files in this repo. ``planning/KICKOFF_PROMPT.md`` carried the same broken
``./planning/APPROACH.md`` / ``./planning/PLAN.md`` pointers.

These checks are deliberately generic (derived from ``git ls-files``, not a
hardcoded exception list) so they keep working if more files move in/out of
``planning/`` later.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_CLAUDE_MD = REPO_ROOT / "CLAUDE.md"
_KICKOFF_PROMPT = REPO_ROOT / "planning" / "KICKOFF_PROMPT.md"

# Matches a repo-relative reference to a planning/ doc, with or without a
# leading "./" and with or without surrounding backticks, e.g.
# "`planning/PLAN.md`" or "./planning/APPROACH.md".
_PLANNING_DOC_REF_RE = re.compile(r"\.?/?planning/[\w][\w.\-]*\.(?:md|html)")


def _all_tracked_files() -> set[str]:
    out = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return {line.strip() for line in out.splitlines() if line.strip()}


def test_claude_md_does_not_claim_repo_is_private():
    text = _CLAUDE_MD.read_text(encoding="utf-8")
    assert "private repo" not in text.lower(), (
        "CLAUDE.md claims the repo is private, but `gh repo view "
        "--json visibility` reports PUBLIC -- update the operator guidance"
    )


def test_claude_md_has_no_broken_planning_doc_links():
    tracked = _all_tracked_files()
    text = _CLAUDE_MD.read_text(encoding="utf-8")
    broken = []
    for match in _PLANNING_DOC_REF_RE.finditer(text):
        ref = match.group(0).lstrip("./")
        if ref not in tracked:
            broken.append(ref)
    assert not broken, (
        "CLAUDE.md references planning/ files that git does not track "
        f"(relocated to gitignored prd/, or removed): {broken}"
    )


def test_kickoff_prompt_has_no_broken_planning_doc_links():
    tracked = _all_tracked_files()
    text = _KICKOFF_PROMPT.read_text(encoding="utf-8")
    broken = []
    for match in _PLANNING_DOC_REF_RE.finditer(text):
        ref = match.group(0).lstrip("./")
        if ref not in tracked:
            broken.append(ref)
    assert not broken, (
        "planning/KICKOFF_PROMPT.md references planning/ files that git "
        f"does not track (relocated to gitignored prd/, or removed): {broken}"
    )

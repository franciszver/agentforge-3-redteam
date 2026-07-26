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

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

_CLAUDE_MD = REPO_ROOT / "CLAUDE.md"
_KICKOFF_PROMPT = REPO_ROOT / "planning" / "KICKOFF_PROMPT.md"

# Matches a repo-relative reference to a planning/ doc, with or without a
# leading "./" and with or without surrounding backticks, e.g.
# "`planning/PLAN.md`" or "./planning/APPROACH.md".
_PLANNING_DOC_REF_RE = re.compile(r"\.?/?planning/[\w][\w.\-]*\.(?:md|html)")

# Section of CLAUDE.md that presents operator commands to run against the
# Phase 2 TARGET checkout (a sibling directory, never this repo). Scoped so
# this check never fires on prose elsewhere in the file.
_STANDING_UP_SECTION_RE = re.compile(
    r"## Standing up the target.*?(?=\n## |\Z)", re.DOTALL
)

# A script/config path referenced inside that section, e.g.
# "scripts/ingest_demo_pdf.py" or the bare "docker-compose.copilot.yml".
_TARGET_PATH_RE = re.compile(r"[\w./\-]+\.(?:sh|py|yml|yaml)")

_TARGET_REPO = REPO_ROOT.parent / "agentforge-2-evidence-agent"
_TARGET_TAG = "v2.0.0"

# The "Standing up the target" section's docker-compose commands `cd` into
# this directory before referencing the bare compose filenames.
_COMPOSE_DIR = "docker/development-easy"


def _target_repo_available() -> bool:
    return (_TARGET_REPO / ".git").exists()


def _target_paths_in_standing_up_section() -> list[str]:
    text = _CLAUDE_MD.read_text(encoding="utf-8")
    section_match = _STANDING_UP_SECTION_RE.search(text)
    assert section_match, "CLAUDE.md has no '## Standing up the target' section"
    section = section_match.group(0)
    paths = []
    for match in _TARGET_PATH_RE.finditer(section):
        token = match.group(0)
        if "/" not in token:
            # Bare filename (e.g. docker-compose.yml): resolve relative to
            # the directory the doc's own `cd` command references.
            token = f"{_COMPOSE_DIR}/{token}"
        paths.append(token)
    return paths


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


def test_standing_up_section_extracts_the_known_target_paths():
    # Sanity check on the extractor itself, independent of the sibling
    # checkout: pins down exactly which tokens the regex is expected to
    # pull out of CLAUDE.md today, so a future edit to that section is
    # forced to keep this list honest.
    paths = _target_paths_in_standing_up_section()
    assert f"{_COMPOSE_DIR}/docker-compose.yml" in paths
    assert f"{_COMPOSE_DIR}/docker-compose.copilot.yml" in paths
    assert "scripts/tailscale-serve-copilot.sh" in paths
    assert "scripts/bootstrap-copilot-dev-client.sh" in paths
    assert "evals/fixtures/seed.py" in paths
    assert "services/copilot-agent/scripts/ingest_demo_pdf.py" in paths


@pytest.mark.skipif(
    not _target_repo_available(),
    reason="sibling target checkout ../agentforge-2-evidence-agent not present (expected in CI)",
)
class TestStandingUpTargetPathsExistInPinnedTarget:
    """Closes the defect class issue #61 was filed for: CLAUDE.md's
    'Standing up the target' section gives operator commands to run from
    the Phase 2 TARGET checkout, but nothing verified those paths actually
    exist there. Read-only: uses `git cat-file -e v2.0.0:<path>` from the
    sibling checkout, never `git checkout`."""

    @pytest.mark.parametrize(
        "path", _target_paths_in_standing_up_section() if _target_repo_available() else []
    )
    def test_path_exists_at_pinned_target_tag(self, path):
        result = subprocess.run(
            ["git", "cat-file", "-e", f"{_TARGET_TAG}:{path}"],
            cwd=_TARGET_REPO,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"CLAUDE.md's 'Standing up the target' section references "
            f"{path!r}, which does not exist in the pinned target "
            f"({_TARGET_TAG}) sibling checkout -- {result.stderr.strip()}"
        )

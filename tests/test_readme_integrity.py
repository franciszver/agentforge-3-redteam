"""README integrity checks (P3.25, issue #52).

Two independent checks:

1. ``test_readme_repo_relative_references_resolve`` -- scans README.md for
   repo-relative Markdown links (``[text](path)``) and inline-code path
   spans (`` `dir/file.ext` ``), skipping external ``http(s)://`` URLs and
   in-page anchors, and asserts every such path exists in the tree. This is
   a genuine regression guard: it would have failed had ``planning/``
   references actually gone stale (verified during P3.25 that the specific
   paths the README pointed at were NOT purged -- only
   ``planning/APPROACH.md``/``planning/PLAN.md`` were relocated to
   gitignored ``prd/``, and the README already didn't reference those two).
   It passes both before and after the P3.25 prose fix; it is kept as a
   standing regression guard against a *future* dead link.

2. ``test_readme_status_reflects_current_state`` -- asserts the README does
   NOT contain the stale P3.0/P3.1-only status line or the "decided at
   Architecture Defense (P3.5)" pending-decision framing, both of which are
   false as of P3.25 (platform complete, model strategy long decided). This
   is the test that genuinely fails on the pre-P3.25 README and passes
   after the fix.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"

_MD_LINK_RE = re.compile(r"\]\(([^)]+)\)")
_INLINE_CODE_RE = re.compile(r"`([^`]+)`")


def _is_external_or_anchor(ref: str) -> bool:
    return ref.startswith(("http://", "https://", "#", "mailto:"))


def _looks_like_repo_path(ref: str) -> bool:
    """Heuristic: contains a path separator and no whitespace.

    Excludes things like inline version tags (``v2.0.0``) or bare command
    names that happen to be wrapped in backticks but aren't paths.
    """
    if _is_external_or_anchor(ref):
        return False
    if any(ch.isspace() for ch in ref):
        return False
    return "/" in ref


def _extract_repo_relative_refs(text: str) -> set[str]:
    refs: set[str] = set()
    for match in _MD_LINK_RE.findall(text):
        candidate = match.strip()
        if not _is_external_or_anchor(candidate) and "/" in candidate:
            refs.add(candidate)
    for match in _INLINE_CODE_RE.findall(text):
        candidate = match.strip().rstrip(".,;:")
        if _looks_like_repo_path(candidate):
            refs.add(candidate)
    return refs


def test_readme_repo_relative_references_resolve():
    text = README.read_text(encoding="utf-8")
    refs = _extract_repo_relative_refs(text)
    assert refs, "expected at least one repo-relative reference to check"

    missing = sorted(ref for ref in refs if not (REPO_ROOT / ref).exists())
    assert not missing, (
        f"README.md references paths absent from the tree: {missing}"
    )


def test_readme_status_reflects_current_state():
    text = README.read_text(encoding="utf-8")

    stale_status = "Bootstrap (P3.0) and Stage 1 target drive (P3.1) are done"
    assert stale_status not in text, (
        "README status line still describes only the P3.0/P3.1 bootstrap "
        "milestone; the platform is complete (6 agents, versioned "
        "contracts, campaign runner, regression harness, observability, "
        "3 owner-approved critical findings, CI green, repo public)."
    )

    assert "decided at\nArchitecture Defense (P3.5)" not in text, (
        "README still frames the Red Team model strategy as a pending "
        "decision for P3.5; it was decided long ago "
        "(huihui_ai/qwen2.5-abliterate:7b, CPU-only, redteam/agents/red_team.py)."
    )

    assert "huihui_ai/qwen2.5-abliterate" in text, (
        "README should name the decided Red Team generator model."
    )

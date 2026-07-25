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

   Coverage notes (accurate as of the P3.25 cold-review fix): Markdown link
   targets (``[text](path)``) have any ``#fragment`` anchor and any quoted
   ``"title"`` suffix stripped before the existence check, and are checked
   whether or not they contain a directory separator -- so both
   ``docs/ARCHITECTURE.md#components`` and a root-level ``[LICENSE](LICENSE)``
   resolve correctly. Inline-code spans (`` `path` ``) are only checked when
   they contain a directory separator (e.g. `` `dir/file.ext` ``); a bare
   root-level filename in backticks (e.g. `` `LICENSE` ``) is deliberately
   NOT checked, since backtick spans are also used for non-path identifiers
   (config constants, CLI flags, model tags) and requiring a separator is
   what keeps those out of the reference set.

2. ``test_readme_status_reflects_current_state`` -- asserts the README does
   NOT contain the stale P3.0/P3.1-only status line or the "decided at ...
   Architecture Defense (P3.5)" pending-decision framing (whitespace-
   normalized, so the check survives an incidental reflow of the same
   sentence), both of which are false as of P3.25 (platform complete, model
   strategy long decided). This is the test that genuinely fails on the
   pre-P3.25 README and passes after the fix.
"""

from __future__ import annotations

import re
from pathlib import Path

from redteam.agents.red_team import DEFAULT_MODEL

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"

_MD_LINK_RE = re.compile(r"\]\(([^)]+)\)")
_INLINE_CODE_RE = re.compile(r"`([^`]+)`")
_LINK_TITLE_RE = re.compile(r'^(\S+)\s+["\'].*["\']$')


def _is_external_or_anchor(ref: str) -> bool:
    return ref.startswith(("http://", "https://", "#", "mailto:"))


def _strip_link_decorations(ref: str) -> str:
    """Strip a Markdown link's optional ``"title"`` suffix and ``#fragment``.

    ``[text](docs/X.md "title")`` and ``[text](docs/X.md#anchor)`` both
    resolve to the filesystem path ``docs/X.md`` -- neither the quoted title
    nor the in-page anchor is part of the path.
    """
    ref = ref.strip()
    title_match = _LINK_TITLE_RE.match(ref)
    if title_match:
        ref = title_match.group(1)
    ref = ref.split("#", 1)[0]
    return ref.strip()


def _looks_like_repo_path(ref: str) -> bool:
    """Heuristic: contains a path separator and no whitespace.

    Excludes things like inline version tags (``v2.0.0``) or bare command
    names that happen to be wrapped in backticks but aren't paths. Bare
    root-level filenames (no separator) are intentionally excluded here --
    see the module docstring's coverage note.
    """
    if _is_external_or_anchor(ref):
        return False
    if any(ch.isspace() for ch in ref):
        return False
    if ":" in ref:
        # excludes model tags like "huihui_ai/qwen2.5-abliterate:7b" -- not
        # a filesystem path even though it contains a slash.
        return False
    return "/" in ref


def _extract_repo_relative_refs(text: str) -> set[str]:
    refs: set[str] = set()
    for match in _MD_LINK_RE.findall(text):
        candidate = _strip_link_decorations(match)
        if candidate and not _is_external_or_anchor(candidate):
            refs.add(candidate)
    for match in _INLINE_CODE_RE.findall(text):
        candidate = _strip_link_decorations(match).rstrip(".,;:")
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
        "milestone; the platform is complete (four agents plus the "
        "Regression Harness and Observability Layer, versioned contracts, "
        "campaign runner, regression harness, observability, 3 "
        "owner-approved critical findings)."
    )

    # Whitespace-normalized so a future reflow of the same sentence (e.g. a
    # line-wrap change) can't make this check pass silently on stale prose --
    # only the literal phrase being absent should pass it.
    normalized = " ".join(text.split())
    assert "decided at Architecture Defense (P3.5)" not in normalized, (
        "README still frames the Red Team model strategy as a pending "
        "decision for P3.5; it was decided long ago "
        "(huihui_ai/qwen2.5-abliterate:7b, CPU-only, redteam/agents/red_team.py)."
    )

    assert DEFAULT_MODEL in text, (
        "README should name the decided Red Team generator model "
        f"(redteam.agents.red_team.DEFAULT_MODEL = {DEFAULT_MODEL!r})."
    )

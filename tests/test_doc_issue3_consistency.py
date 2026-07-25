"""Cross-doc consistency check for issue #3 status (P3.27, issue #57).

Issue #3 (the Tailscale deployed-URL hard gate) is **CLOSED** -- the target
was exposed live on the owner's private tailnet and the gate was verified
satisfied (see ``README.md``'s status line). But committed docs are static
prose: nothing re-derives their wording from the live issue tracker, so a doc
written while #3 was still open can silently keep describing it as
"deferred" or "pending" forever, contradicting README.

This is the same defect class issue #52 covered for README's own internal
consistency; this test extends the guard to *other* committed docs that
mention issue #3, so a visitor who follows a README link outward doesn't land
on stale, contradictory prose.

The check: scan every committed Markdown file for the token ``issue #3``
(word-bounded, so ``issue #30`` etc. don't match) and, in a window around
each mention, assert neither ``deferred`` nor ``pending`` (case-insensitive)
also appears. That co-occurrence is exactly the "still describes #3 as
deferred/pending" pattern that made THREAT_MODEL.md, TRIAGE_LAB.md, and
STAGE1_TARGET.md stale. A window (rather than whole-file) match keeps this
targeted: a file can legitimately discuss unrelated deferred work (e.g.
TRIAGE_LAB's relevance-gate ADR) as long as it isn't textually tangled up
with an "issue #3" mention.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_ISSUE3_RE = re.compile(r"issue #3\b")
_STALE_STATUS_RE = re.compile(r"deferred|pending", re.IGNORECASE)

# Characters of context scanned to either side of an "issue #3" mention.
# Wide enough to span the wrapped sentences seen in STAGE1_TARGET.md (a
# markdown line-wrap can put "deferred" and "issue #3" ~120 chars apart
# after whitespace normalization), narrow enough that an unrelated
# "deferred" elsewhere in a long doc doesn't false-positive.
_WINDOW = 150


def _tracked_markdown_files() -> list[Path]:
    """Every ``*.md`` file `git` tracks -- gitignored paths (e.g. ``prd/``)
    never appear in ``git ls-files`` output, so no separate exclusion is
    needed here."""
    import subprocess

    out = subprocess.run(
        ["git", "ls-files", "*.md"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [REPO_ROOT / line.strip() for line in out.splitlines() if line.strip()]


def test_no_committed_doc_describes_issue3_as_deferred():
    violations = []
    for path in _tracked_markdown_files():
        text = path.read_text(encoding="utf-8")
        normalized = " ".join(text.split())
        for match in _ISSUE3_RE.finditer(normalized):
            start = max(0, match.start() - _WINDOW)
            end = min(len(normalized), match.end() + _WINDOW)
            window = normalized[start:end]
            if _STALE_STATUS_RE.search(window):
                rel = path.relative_to(REPO_ROOT).as_posix()
                violations.append(f"{rel}: ...{window}...")

    assert not violations, (
        "issue #3 (the Tailscale deployed-URL hard gate) is CLOSED -- it was "
        "satisfied via a private tailnet exposure -- but the following "
        "committed docs still describe it as deferred/pending, contradicting "
        "README.md's status line:\n" + "\n".join(violations)
    )


def test_no_committed_doc_frames_deployed_url_gate_as_pending():
    """Narrower net for phrasing that avoids the literal 'issue #3' token.

    ``docs/STAGE1_TARGET.md`` described the gate itself
    ("P3.2 (Tailscale live exposure / a deployed-URL hard gate) is explicitly
    DEFERRED per owner decision") -- catch that pattern directly in case a
    future edit drops the "issue #3" cross-reference but keeps the stale
    framing.
    """
    violations = []
    for path in _tracked_markdown_files():
        text = path.read_text(encoding="utf-8")
        normalized = " ".join(text.split())
        if re.search(
            r"deployed-url hard gate\)? is explicitly (deferred|pending)",
            normalized,
            re.IGNORECASE,
        ):
            violations.append(path.relative_to(REPO_ROOT).as_posix())

    assert not violations, (
        "the following committed docs still frame the deployed-URL hard "
        "gate as explicitly deferred/pending, but it was satisfied via a "
        f"private tailnet exposure: {violations}"
    )

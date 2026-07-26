"""Shared test utilities (P3.30, issue #61).

``tests/test_doc_consistency.py`` and ``tests/test_doc_issue3_consistency.py``
each independently defined an identical ``_tracked_markdown_files()`` helper
(every ``*.md`` file `git` tracks). Consolidated here so both import one
implementation instead of two copies drifting apart.

``tests/test_dos_input_bound_resolution.py`` and
``tests/test_claude_md_accuracy.py`` each independently defined an identical
sibling-target-checkout helper (path to ``../agentforge-2-evidence-agent``,
pinned tag, and an availability check for the ``skipif`` guard). Consolidated
here for the same reason.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

TARGET_REPO = REPO_ROOT.parent / "agentforge-2-evidence-agent"
TARGET_TAG = "v2.0.0"


def tracked_markdown_files() -> list[Path]:
    """Every ``*.md`` file `git` tracks -- gitignored paths (e.g. ``prd/``)
    never appear in ``git ls-files`` output, so no separate exclusion is
    needed here."""
    out = subprocess.run(
        ["git", "ls-files", "*.md"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [REPO_ROOT / line.strip() for line in out.splitlines() if line.strip()]


def target_repo_available() -> bool:
    """Whether the read-only sibling target checkout is present -- true on
    an operator's provisioned desktop, false in CI (no target checkout)."""
    return (TARGET_REPO / ".git").exists()

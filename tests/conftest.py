"""Shared test utilities (P3.30, issue #61).

``tests/test_doc_consistency.py`` and ``tests/test_doc_issue3_consistency.py``
each independently defined an identical ``_tracked_markdown_files()`` helper
(every ``*.md`` file `git` tracks). Consolidated here so both import one
implementation instead of two copies drifting apart.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


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

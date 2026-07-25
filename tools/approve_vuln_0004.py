"""Apply the owner's approval to VULN-0004 (P3.33, issue #66) -- NOT a
pytest test (kept out of ``tests/``, un-prefixed with ``test_`` so
``pytest tests/ -q`` never collects or runs it), mirroring
``tools/build_vuln_report_p3_54.py``'s own convention.

Owner approved VULN-0004 (Medium, ``denial_of_service``) in session on
2026-07-25, after cold review confirmed the ``confirmed-finding`` verdict
in ``docs/ISSUE_54_UNBOUNDED_INPUT_TRACE.md`` is justified (and, if
anything, under-claimed). This script applies that approval through
``redteam.agents.documentation.DocumentationAgent.approve()`` -- the ONLY
code path this platform recognizes for a pending report becoming filed
(``docs/ARCHITECTURE.md`` Sec6) -- not by hand-editing the persisted JSON.

## Why this can't be "just call approve() on the running agent"

``DocumentationAgent._pending`` is in-memory only (see that module's own
"Where reports live" docstring): the process that originally called
``file_report()`` for ``EXP-0004`` (``tools/build_vuln_report_p3_54.py``,
run once, already exited) is long gone, so there is no live agent instance
holding this report pending. Re-running that script is not an option
either -- it refuses to overwrite an existing ``VULN-0004*.json``, and
even if it didn't, ``build_vuln_report``'s ``filed_at`` defaults to
"now", which would silently mutate an already-committed timestamp.

The correct move -- not a hand edit -- is to re-derive the exact same
exploit_record ``tools/build_vuln_report_p3_54.py`` built (same
``exploit_id``, ``category``, and ``minimal_repro`` observed/expected
text, reused directly from that module rather than retyped here) and
re-drive ``file_report()`` on a fresh ``DocumentationAgent``, pinning
``filed_at`` to the value already committed in the pending artifact so
the pre-approval report this reconstructs is byte-identical (module the
new approval fields) to what is on disk. That repopulates ``_pending``
with the same report the original run produced, and THEN this script
calls ``approve()`` -- the real approval transition -- on that pending
entry. Every field in the final artifact (schema_version, report_id,
exploit_id, severity, clinical_impact, observed, expected, remediation,
fix_validation_status, requires_human_gate, filed_at, approved_at,
approved_by) is computed by ``build_vuln_report()``/``approve()``, never
written directly by this script.

Idempotent / safe to inspect: refuses to run if ``VULN-0004.json``
already exists (already approved) or if the pending artifact is missing
(nothing to approve).

Usage::

    python tools/approve_vuln_0004.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from redteam.agents.documentation import DocumentationAgent  # noqa: E402
from tools.build_vuln_report_p3_54 import _build_exploit_record  # noqa: E402

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REPORTS_DIR = _REPO_ROOT / "docs" / "vuln_reports"
_PENDING_PATH = _REPORTS_DIR / "VULN-0004.pending-human-approval.json"
_FILED_PATH = _REPORTS_DIR / "VULN-0004.json"

_EXPLOIT_ID = "EXP-0004"


def main() -> int:
    if _FILED_PATH.exists():
        print(f"already approved: {_FILED_PATH}", file=sys.stderr)
        return 1
    if not _PENDING_PATH.exists():
        print(f"nothing to approve: {_PENDING_PATH} does not exist", file=sys.stderr)
        return 1

    pending_on_disk = json.loads(_PENDING_PATH.read_text(encoding="utf-8"))
    original_filed_at = pending_on_disk["filed_at"]

    # Re-derive the same exploit_record the original filing script built --
    # reused directly, not retyped, so observed/expected/category can't drift.
    record = _build_exploit_record()
    assert record["exploit_id"] == _EXPLOIT_ID

    documentation = DocumentationAgent(reports_dir=_REPORTS_DIR)
    pre_approval = documentation.file_report(
        record,
        filed_at=original_filed_at,
        force_human_gate=True,  # denial_of_service is already unconditionally
        # forced (FORCE_HUMAN_GATE_CATEGORIES); explicit here for clarity.
    )
    assert pre_approval["status"] == "pending_human_approval"

    # Sanity: the report this run reconstructed must match what is already
    # committed on disk, field for field -- if it doesn't, something about
    # the reconstruction has drifted from the original filing and this
    # script must stop rather than silently approve a DIFFERENT report body.
    reconstructed_body = {k: v for k, v in pre_approval.items() if k != "status"}
    if reconstructed_body != pending_on_disk:
        print(
            "reconstructed pre-approval report does not match the committed "
            f"pending artifact -- refusing to approve.\nreconstructed={reconstructed_body}"
            f"\non_disk={pending_on_disk}",
            file=sys.stderr,
        )
        return 1

    filed = documentation.approve(_EXPLOIT_ID, approved_by="owner")
    _PENDING_PATH.unlink()

    print(
        f"exploit_id={_EXPLOIT_ID} report_id={filed['report_id']} "
        f"approved_by={filed['approved_by']} approved_at={filed['approved_at']} "
        f"-> {_FILED_PATH.relative_to(_REPO_ROOT)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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

The correct move -- not a hand edit -- is to re-derive the exploit_record
via the SAME function ``tools/build_vuln_report_p3_54.py`` used
(``_build_exploit_record()``, reused directly, not retyped here, so
``exploit_id``, ``category``, and ``minimal_repro`` observed/expected text
can't drift), and re-drive ``file_report()`` on a fresh
``DocumentationAgent``, pinning ``filed_at`` to the value already
committed in the pending artifact. What that reconstructs is compared to
what is on disk FIELD-FOR-FIELD on parsed JSON -- not byte-for-byte: key
order, indentation, and trailing-newline differences are normalised away
by ``json.loads`` on both sides. It is still a strong guard (any
field-VALUE drift fails it), and note ``_build_exploit_record()`` calls
``now_iso()`` for ``confirmed_at`` on every run (see
``tools/build_vuln_report_p3_54.py:88-89``), so the reconstructed
exploit_record genuinely differs from the original there -- that field
never enters the vuln_report body being compared, so it doesn't matter.
Only if the comparison passes does this repopulate ``_pending`` with a
report matching the one the original run produced, and THEN this script
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


def _file_pending(
    documentation: DocumentationAgent,
    record: dict,
    *,
    filed_at: str,
    force_human_gate: bool,
) -> dict:
    """File ``record`` and return the pending report -- or refuse via
    ``SystemExit`` WITHOUT ever calling ``DocumentationAgent.file_report``
    at all if the human-approval gate is not going to be forced.

    Cold-review fix (PR #67): the previous version called ``file_report``
    first and only checked the result afterwards with a bare ``assert``.
    ``file_report`` persists immediately for any report that does NOT
    require the human gate (see ``DocumentationAgent.file_report``'s
    non-gated branch, which calls ``self._persist`` before returning) --
    so a post-hoc check runs too late: an unapproved ``VULN-0004.json``
    could already be on disk by the time it fires, and would then
    permanently block re-runs via ``_FILED_PATH.exists()``. A bare
    ``assert`` is also silently stripped under ``python -O``. Checking
    ``force_human_gate`` BEFORE calling ``file_report`` at all -- and
    raising ``SystemExit`` rather than asserting -- makes a half-written
    unapproved artifact impossible: this category's severity
    (``denial_of_service`` -> "medium") never gates on its own, so
    ``force_human_gate`` being true is the ONLY thing that keeps
    ``file_report`` in its pending (non-persisting) branch.
    """
    if not force_human_gate:
        raise SystemExit(
            f"refusing to file {record.get('exploit_id')!r}: force_human_gate "
            "is False, which would let file_report() auto-file (and persist) "
            "an unapproved report instead of holding it pending human "
            "approval -- stopping before file_report() is called at all"
        )

    pre_approval = documentation.file_report(
        record,
        filed_at=filed_at,
        force_human_gate=force_human_gate,
    )
    if pre_approval["status"] != "pending_human_approval":
        raise SystemExit(
            f"file_report did not hold {record.get('exploit_id')!r} pending "
            f"human approval (status={pre_approval['status']!r}) -- refusing "
            "to approve"
        )
    return pre_approval


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
    pre_approval = _file_pending(
        documentation,
        record,
        filed_at=original_filed_at,
        force_human_gate=True,  # denial_of_service is already unconditionally
        # forced (FORCE_HUMAN_GATE_CATEGORIES); explicit here for clarity.
    )

    # Compare parsed JSON field-for-field against what is already committed
    # on disk -- NOT a byte-for-byte comparison (key order, indentation, and
    # trailing-newline differences are normalised away by json.loads on both
    # sides). Still a strong guard: it fires on any FIELD-VALUE drift. Note
    # what never enters this comparison at all, because it never enters the
    # vuln_report in the first place (see documentation.py's "Why the
    # vuln_report contract has no minimal_repro/recording_ref" section):
    # the exploit record's case_id, attempt_id, verdict_id, source,
    # recording_ref, and minimal_repro.steps, plus confirmed_at (which
    # _build_exploit_record() sets to now_iso() every run, per
    # tools/build_vuln_report_p3_54.py:88-89, so it genuinely differs run to
    # run). None of that is a gap: the owner-reviewed BYTES are the report
    # body being compared here, and every field the report body actually
    # contains (schema_version, report_id, exploit_id, severity,
    # clinical_impact, observed, expected, remediation,
    # fix_validation_status, requires_human_gate, filed_at) is checked.
    # (``_file_pending`` above already guarantees ``pre_approval["status"] ==
    # "pending_human_approval"`` -- it raises SystemExit otherwise.)
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

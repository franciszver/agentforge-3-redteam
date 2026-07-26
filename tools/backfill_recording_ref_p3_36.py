"""One-off backfill for issue #77 (P3.36) -- NOT a pytest test (kept out of
``tests/``, un-prefixed with ``test_`` so ``pytest tests/ -q`` never
collects or runs it), mirroring ``tools/build_vuln_report_p3_54.py`` and
``tools/approve_vuln_0004.py``'s own convention.

Adds the newly-optional ``recording_ref`` field (``contracts/v1/vuln_report
.schema.json``, issue #77) to the four already-filed, owner-approved
reports under ``docs/vuln_reports/`` -- **without hand-editing them**.

## Why this can't be "just add the key with a text editor"

The whole point of this repo's evidence discipline (``tools/approve_vuln_
0004.py``'s own docstring) is that a filed report's fields are computed by
``build_vuln_report()``/``DocumentationAgent``, never typed directly. This
script re-derives EACH of the four exploit records via the SAME code paths
that originally produced them:

  - VULN-0001/0002/0003 (``EXP-0001..0003``): re-scored from the committed
    recordings through a REAL ``JudgeAgent``, reusing ``tools.build_vuln_
    reports``'s own ``score_and_confirm`` / case objects / minimal-repro
    builder directly (not retyped), in the same order (AUTHZ, DATA_EXFIL,
    SOURCEREF) so a fresh ``ExploitDB(":memory:")`` assigns the same
    ``EXP-0001..0003`` ids the original run did.
  - VULN-0004 (``EXP-0004``): re-derived via ``tools.build_vuln_report_p3_
    54``'s own ``_build_exploit_record()``, reused directly (not retyped).

Each re-derived exploit record is passed through ``build_vuln_report()``
(now recording_ref-aware) pinned to the report_id/filed_at already
committed on disk. The result is compared FIELD-FOR-FIELD (parsed JSON, not
byte-for-byte -- key order/indentation/trailing newline don't matter)
against what's already on disk, ignoring exactly the two fields this
backfill is not touching input-side (``approved_at``/``approved_by``, which
never entered ``build_vuln_report()`` in the first place -- they are
``DocumentationAgent.approve()``'s own stamps) and the one field this
backfill is adding (``recording_ref``, absent from the pre-image by
definition). Only if every OTHER field matches exactly does this script
trust the reconstruction; it then takes the reconstructed body (which now
carries ``recording_ref``), splices back the two approval stamps VERBATIM
from the on-disk file (never recomputed), validates the result against the
schema, and writes it. If reconstruction disagrees on any other field, the
script refuses and writes nothing for that report -- a full run either
backfills all four or leaves the directory untouched.

Idempotent: if a report already carries ``recording_ref``, it is left
completely alone (re-running after a successful backfill is a no-op).

Usage::

    python tools/backfill_recording_ref_p3_36.py           # dry run, prints the diff
    python tools/backfill_recording_ref_p3_36.py --apply    # writes the four reports
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from jsonschema import Draft202012Validator  # noqa: E402

from redteam.agents.documentation import build_vuln_report  # noqa: E402
from redteam.agents.judge import JudgeAgent  # noqa: E402
from redteam.harness.db import ExploitDB  # noqa: E402
from tools.build_vuln_report_p3_54 import _build_exploit_record  # noqa: E402
from tools.build_vuln_reports import (  # noqa: E402
    AUTHZ_CASE,
    DATA_EXFIL_CASE,
    SOURCEREF_CASE,
    _minimal_repro,
    score_and_confirm,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REPORTS_DIR = _REPO_ROOT / "docs" / "vuln_reports"
_SCHEMA_PATH = _REPO_ROOT / "contracts" / "v1" / "vuln_report.schema.json"

# Fields that never entered build_vuln_report() in the first place -- the
# approval stamps are DocumentationAgent.approve()'s own, applied on top,
# never recomputed or compared here.
_APPROVAL_STAMP_FIELDS = ("approved_at", "approved_by")


def _schema() -> dict:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


def _judge_scored_records() -> list[tuple[str, dict[str, Any]]]:
    """Re-derive EXP-0001..0003's exploit records in the SAME order
    tools/build_vuln_reports.py's main() builds them, so a fresh in-memory
    ExploitDB assigns the same ids -- reusing that module's own case
    objects, score_and_confirm, and minimal-repro builder directly."""
    db = ExploitDB(":memory:")
    judge = JudgeAgent()
    findings = [AUTHZ_CASE, DATA_EXFIL_CASE, SOURCEREF_CASE]
    out: list[tuple[str, dict[str, Any]]] = []
    for case in findings:
        verdict, recording_path, draw_index, _confirmed, _total = score_and_confirm(case, judge)
        exploit_id = db.next_exploit_id()
        record = {
            "schema_version": "1.0.0",
            "exploit_id": exploit_id,
            "case_id": verdict["case_id"],
            "attempt_id": verdict["attempt_id"],
            "verdict_id": verdict["verdict_id"],
            "category": case.category,
            "source": "judge",
            "confirmed_at": verdict["scored_at"],
            "minimal_repro": _minimal_repro(case, draw_index, verdict["evidence"]["detection_label"]),
            "recording_ref": str(recording_path.relative_to(_REPO_ROOT)).replace("\\", "/"),
        }
        db.add_record(record)
        out.append((exploit_id, record))
    return out


def _plan() -> list[dict[str, Any]]:
    plans: list[dict[str, Any]] = []
    for exploit_id, record in _judge_scored_records():
        report_id = "VULN-" + exploit_id.split("-", 1)[1]
        plans.append({"report_id": report_id, "record": record, "force_human_gate": False})

    dos_record = _build_exploit_record()
    plans.append({"report_id": "VULN-0004", "record": dos_record, "force_human_gate": True})
    return plans


def _backfill_one(plan: dict[str, Any], validator: Draft202012Validator) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """Returns (report_id, pre_image, post_image) for one report, or raises
    SystemExit describing exactly what failed to verify."""
    report_id = plan["report_id"]
    path = _REPORTS_DIR / f"{report_id}.json"
    if not path.exists():
        raise SystemExit(f"expected filed report missing: {path}")

    pre_image = json.loads(path.read_text(encoding="utf-8"))

    if "recording_ref" in pre_image:
        # Already backfilled -- no-op, return unchanged.
        return report_id, pre_image, dict(pre_image)

    for stamp in _APPROVAL_STAMP_FIELDS:
        if stamp not in pre_image:
            raise SystemExit(f"{path}: missing {stamp!r} -- refusing to touch a non-approved report")

    reconstructed = build_vuln_report(
        plan["record"],
        report_id=report_id,
        filed_at=pre_image["filed_at"],
        force_human_gate=plan["force_human_gate"],
    )

    # Field-for-field check: every key in the pre-image OTHER than the
    # approval stamps must match the reconstruction exactly; the
    # reconstruction's own recording_ref is new by definition and is not
    # expected to appear in the pre-image at all.
    mismatches = []
    for key, value in pre_image.items():
        if key in _APPROVAL_STAMP_FIELDS:
            continue
        if reconstructed.get(key) != value:
            mismatches.append((key, value, reconstructed.get(key)))
    if mismatches:
        details = "; ".join(f"{k}: on_disk={v1!r} reconstructed={v2!r}" for k, v1, v2 in mismatches)
        raise SystemExit(
            f"{path}: reconstruction does not match the committed report on field(s) "
            f"other than recording_ref/approval stamps -- refusing to backfill: {details}"
        )

    post_image = dict(reconstructed)
    for stamp in _APPROVAL_STAMP_FIELDS:
        post_image[stamp] = pre_image[stamp]  # copied verbatim, never recomputed

    errors = list(validator.iter_errors(post_image))
    if errors:
        raise SystemExit(f"{path}: backfilled report fails schema validation: {errors}")

    return report_id, pre_image, post_image


def _diff(pre_image: dict[str, Any], post_image: dict[str, Any]) -> dict[str, tuple[Any, Any]]:
    keys = set(pre_image) | set(post_image)
    return {k: (pre_image.get(k), post_image.get(k)) for k in sorted(keys) if pre_image.get(k) != post_image.get(k)}


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write the backfilled reports (default: dry run)")
    return parser.parse_args(list(argv))


def main(argv: Sequence[str] = ()) -> int:
    args = _parse_args(argv)
    validator = Draft202012Validator(_schema())

    results = []
    for plan in _plan():
        results.append(_backfill_one(plan, validator))

    any_change = False
    for report_id, pre_image, post_image in results:
        diff = _diff(pre_image, post_image)
        if not diff:
            print(f"{report_id}: already backfilled, no-op")
            continue
        any_change = True
        print(f"{report_id}: diff = {diff}")
        if args.apply:
            path = _REPORTS_DIR / f"{report_id}.json"
            path.write_text(json.dumps(post_image, indent=2) + "\n", encoding="utf-8")
            print(f"{report_id}: wrote {path}")

    if not args.apply and any_change:
        print("dry run only -- re-run with --apply to write these changes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

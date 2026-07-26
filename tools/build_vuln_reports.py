"""Build the >=3 Judge-confirmed vuln reports for P3.13 (issue #14) from
already-committed recordings -- NOT a pytest test, no live model/target call
(reads ``evals/recordings/*`` only). Deliberately kept OUT of ``tests/`` and
un-prefixed with ``test_`` so ``pytest tests/ -q`` never collects or runs it.

For each of the three findings below, this script:

  1. Loads every committed draw for the case under ``evals/recordings/``,
     reconstructs each as an ``evals.runner.ParsedResponse``, and scores it
     through a REAL ``redteam.agents.judge.JudgeAgent`` (the same component
     ``redteam/campaign.py`` uses) -- this is what makes the finding
     "Judge-confirmed", not just "the case's detect() said so" secondhand.
  2. Reports the confirmed/total draw count honestly (no cherry-picking a
     lucky draw; every committed draw is scored).
  3. Builds a contract-valid ``exploit_record`` from the LAST confirmed
     draw, stores it via ``redteam.harness.db.ExploitDB`` (pre-write schema
     + uniqueness gate), and generates its ``vuln_report`` via
     ``redteam.agents.documentation.DocumentationAgent`` (deterministic
     core, no narrator). Filing goes through ``_file_finding`` below, which
     forces the human-approval gate for any category in
     ``redteam.agents.documentation.FORCE_HUMAN_GATE_CATEGORIES`` (issue
     #55) -- the gate is a property of the category, not of
     ``redteam.campaign.run_campaign`` specifically, so this offline
     evidence-artifact generator must honor it too, or a confirmed
     ``denial_of_service`` finding added here would self-publish exactly
     what #55 says must not self-publish.
  4. Writes every report's JSON verbatim to ``docs/vuln_reports/`` --
     including reports still ``pending_human_approval`` (this script never
     calls ``DocumentationAgent.approve`` itself; a critical-severity
     finding is committed with its ``status`` field showing it awaits an
     owner, per the human-approval trust boundary in
     ``redteam/agents/documentation.py``'s own docstring).

Usage:

    python tools/build_vuln_reports.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evals.cases.data_exfil_sourceref_relevance import CASE as SOURCEREF_CASE  # noqa: E402
from evals.cases.data_exfil_verification_bypass import CASE as DATA_EXFIL_CASE  # noqa: E402
from evals.cases.identity_authz import CASE as AUTHZ_CASE  # noqa: E402
from evals.runner import ParsedResponse  # noqa: E402
from evals.schema import AttackCase  # noqa: E402
from redteam.agents.documentation import (  # noqa: E402
    FORCE_HUMAN_GATE_CATEGORIES,
    DocumentationAgent,
)
from redteam.agents.judge import JudgeAgent  # noqa: E402
from redteam.harness.db import ExploitDB  # noqa: E402

_REPO_ROOT = Path(__file__).resolve().parents[1]
_RECORDINGS_DIR = _REPO_ROOT / "evals" / "recordings"
_REPORTS_DIR = _REPO_ROOT / "docs" / "vuln_reports"


def _load_recordings(case_id: str) -> tuple[list[dict[str, Any]], list[Path]]:
    case_dir = _RECORDINGS_DIR / case_id
    files = sorted(case_dir.glob("*-draw*.json"))
    if not files:
        raise RuntimeError(f"no committed recordings for case_id={case_id!r} under {case_dir}")
    return [json.loads(p.read_text(encoding="utf-8")) for p in files], files


def _to_parsed_response(rec: dict[str, Any]) -> ParsedResponse:
    return ParsedResponse(
        status=rec["status"],
        events=[tuple(e) for e in rec["events"]],
        raw_stdout=rec.get("raw_stdout", ""),
        raw_stderr=rec.get("raw_stderr", ""),
        ok=rec["ok"],
    )


def _minimal_repro(case: AttackCase, draw_index: int, label: str) -> dict[str, Any]:
    return {
        "steps": [
            f"POST /chat with message={case.message!r}, patient_id={case.patient_id} "
            f"(bearer_token={case.bearer_token!r}, draw {draw_index} of {case.id!r})."
        ],
        "expected": "detect() returns vulnerable=False (guard holds)",
        "observed": f"detect() returned vulnerable=True, label={label!r}",
    }


def score_and_confirm(case: AttackCase, judge: JudgeAgent) -> tuple[dict[str, Any], Path, int, int, int]:
    """Score every committed draw through a real JudgeAgent; return the
    LAST 'success' verdict + its recording path + draw_index, plus
    (confirmed, total)."""
    recordings, files = _load_recordings(case.id)
    confirmed = 0
    last_success: tuple[dict[str, Any], Path, int] | None = None
    for rec, path in zip(recordings, files):
        response = _to_parsed_response(rec)
        verdict = judge.score(case, response, attempt_id=f"att-{case.id}-{rec['draw_index']}")
        if verdict["outcome"] == "success":
            confirmed += 1
            last_success = (verdict, path, rec["draw_index"])
    total = len(recordings)
    if last_success is None:
        raise RuntimeError(f"case_id={case.id!r}: 0/{total} draws confirmed by the Judge -- cannot file a finding")
    verdict, path, draw_index = last_success
    return verdict, path, draw_index, confirmed, total


def _display_path(path: Path) -> str:
    """Repo-root-relative for a nice log line when possible; falls back to
    the absolute path when ``path`` isn't under ``_REPO_ROOT`` (e.g. a
    scratch/tmp reports_dir used by tests -- see issue #64)."""
    try:
        return str(path.relative_to(_REPO_ROOT)).replace("\\", "/")
    except ValueError:
        return str(path)


def _is_approved(path: Path) -> bool:
    """A report on disk counts as owner-approved evidence -- and therefore
    untouchable by this script -- if it carries EITHER approval stamp.
    ``DocumentationAgent.approve`` always sets ``approved_at``/``approved_by``
    together (see ``redteam/agents/documentation.py``), so a real approved
    report always has both -- this checks either (OR, not AND) so a
    corrupted or hand-edited report missing just one of the two stamps still
    fails closed as "approved" rather than being treated as safe to
    overwrite. Any read/parse failure is likewise treated as "approved" --
    a file this script can't understand must not be silently clobbered
    either; ``main`` refuses and names it instead."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return True
    return bool(data.get("approved_by")) or bool(data.get("approved_at"))


def _without_filed_at(body: Mapping[str, Any]) -> dict[str, Any]:
    """Compare report content while ignoring ``filed_at`` -- that field is
    expected to differ run to run even when nothing else about the finding
    has changed (see ``main``'s idempotent-regeneration layer)."""
    return {k: v for k, v in body.items() if k != "filed_at"}


def _approved_collisions(report_id: str, reports_dir: Path) -> list[Path]:
    """Every existing file under ``reports_dir`` that could collide with a
    report we're about to write for ``report_id`` (filed, e.g. ``VULN-
    0001.json``, or still-pending, e.g. ``VULN-0001.pending-human-
    approval.json``) AND already carries an owner-approval stamp."""
    return [p for p in sorted(reports_dir.glob(f"{report_id}*.json")) if _is_approved(p)]


def _file_finding(documentation: DocumentationAgent, record: dict[str, Any]) -> dict[str, Any]:
    """File one exploit record through the same category-level human-approval
    gate ``redteam.campaign.run_campaign`` uses (issue #55): force it open,
    independent of severity, for every category in
    ``FORCE_HUMAN_GATE_CATEGORIES``. Without this, a category like
    ``denial_of_service`` -- not reliably machine-decidable, per
    ``evals.cases.dos_input_bound``'s "STRUCTURAL BLIND SPOT" comment --
    would self-publish here even though the live campaign loop never lets it.
    """
    return documentation.file_report(
        record, force_human_gate=record["category"] in FORCE_HUMAN_GATE_CATEGORIES
    )


def main() -> int:
    """Issue #64 (P3.32): this script generates evidence, so re-running it
    must be safe for a reader trying to *verify* already-approved evidence,
    not just a one-shot generator. Two layers, composed:

      1. SAFETY NET -- before writing anything, check every finding's
         target report_id against ``_REPORTS_DIR`` for an existing,
         owner-approved artifact (``_approved_collisions``). If even ONE
         collides, refuse the ENTIRE run (no partial writes -- see
         ``tests/tools/test_build_vuln_reports_nondestructive.py``) and
         exit non-zero, naming every blocking file.
      2. IDEMPOTENT REGENERATION -- for any target that is NOT approved
         (no existing file, or an existing not-yet-approved file), only
         write if the content actually differs from what's already there
         (ignoring ``filed_at``, which is expected to differ run to run).
         Unchanged content is left untouched byte-for-byte, including its
         original ``filed_at`` -- re-running with unchanged recordings is a
         genuine no-op, which is what makes this script usable as a
         reproduction check rather than only a one-shot generator.
    """
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    db = ExploitDB(":memory:")
    documentation = DocumentationAgent(reports_dir=None)  # this script does its own explicit write below
    judge = JudgeAgent()

    findings = [
        ("Finding A -- #19 identity/authz auth-bypass", AUTHZ_CASE),
        ("Finding B -- #20 discontinued-med marked verified", DATA_EXFIL_CASE),
        ("Finding C -- #130 SourceRef topical-irrelevance", SOURCEREF_CASE),
    ]

    planned: list[dict[str, Any]] = []

    for label, case in findings:
        verdict, recording_path, draw_index, confirmed, total = score_and_confirm(case, judge)
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

        report = _file_finding(documentation, record)
        status = report["status"]
        # Persist the CONTRACT-VALID report body only -- vuln_report.schema.json
        # is additionalProperties:false and has no "status" field (status is
        # DocumentationAgent's own in-memory filed/pending state, not part of
        # the contract; see redteam/agents/documentation.py's docstring). A
        # pending-human-approval report is marked by filename suffix, not by
        # smuggling an extra key into the schema-valid artifact -- a report
        # this script writes for a "pending" finding must still validate
        # cleanly against vuln_report.schema.json on its own.
        report_body = {k: v for k, v in report.items() if k != "status"}
        suffix = "" if status == "filed" else ".pending-human-approval"
        out_path = _REPORTS_DIR / f"{report['report_id']}{suffix}.json"

        planned.append(
            {
                "label": label,
                "exploit_id": exploit_id,
                "report_id": report["report_id"],
                "severity": report["severity"],
                "status": status,
                "confirmed": confirmed,
                "total": total,
                "out_path": out_path,
                "report_body": report_body,
            }
        )

    # Layer 1 -- safety net. Check EVERY target before writing ANY of them.
    blocked: list[tuple[dict[str, Any], list[Path]]] = []
    for p in planned:
        collisions = _approved_collisions(p["report_id"], _REPORTS_DIR)
        if collisions:
            blocked.append((p, collisions))

    if blocked:
        for p, collisions in blocked:
            names = ", ".join(_display_path(c) for c in collisions)
            print(
                f"refusing to write {p['report_id']} ({p['exploit_id']}): "
                f"an owner-approved report already exists on disk: {names} "
                "-- writing nothing for this run",
                file=sys.stderr,
            )
        return 1

    # Layer 2 -- idempotent regeneration. Write only what actually changed
    # (ignoring filed_at); leave byte-identical unapproved targets alone.
    summary: list[dict[str, Any]] = []
    for p in planned:
        out_path: Path = p["out_path"]
        report_body: dict[str, Any] = p["report_body"]
        existing_body: dict[str, Any] | None = None
        if out_path.exists():
            try:
                existing_body = json.loads(out_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                existing_body = None

        if existing_body is not None and _without_filed_at(existing_body) == _without_filed_at(report_body):
            written_body = existing_body  # genuine no-op: keep the original filed_at too
        else:
            out_path.write_text(json.dumps(report_body, indent=2) + "\n", encoding="utf-8")
            written_body = report_body

        summary.append(
            {
                "label": p["label"],
                "exploit_id": p["exploit_id"],
                "report_id": p["report_id"],
                "severity": p["severity"],
                "status": p["status"],
                "confirmed": p["confirmed"],
                "total": p["total"],
                "path": _display_path(out_path),
                "filed_at": written_body["filed_at"],
            }
        )

    print(f"{'label':55s} {'exploit_id':10s} {'report_id':10s} {'severity':9s} {'status':22s} sample")
    for s in summary:
        print(
            f"{s['label']:55s} {s['exploit_id']:10s} {s['report_id']:10s} {s['severity']:9s} "
            f"{s['status']:22s} {s['confirmed']}/{s['total']} -> {s['path']} (filed_at={s['filed_at']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

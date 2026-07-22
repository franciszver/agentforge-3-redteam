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
     core, no narrator).
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
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evals.cases.data_exfil_sourceref_relevance import CASE as SOURCEREF_CASE  # noqa: E402
from evals.cases.data_exfil_verification_bypass import CASE as DATA_EXFIL_CASE  # noqa: E402
from evals.cases.identity_authz import CASE as AUTHZ_CASE  # noqa: E402
from evals.runner import ParsedResponse  # noqa: E402
from evals.schema import AttackCase  # noqa: E402
from redteam.agents.documentation import DocumentationAgent  # noqa: E402
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


def main() -> int:
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    db = ExploitDB(":memory:")
    documentation = DocumentationAgent(reports_dir=None)  # this script does its own explicit write below
    judge = JudgeAgent()

    findings = [
        ("Finding A -- #19 identity/authz auth-bypass", AUTHZ_CASE),
        ("Finding B -- #20 discontinued-med marked verified", DATA_EXFIL_CASE),
        ("Finding C -- #130 SourceRef topical-irrelevance", SOURCEREF_CASE),
    ]

    summary: list[dict[str, Any]] = []

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

        report = documentation.file_report(record)
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
        out_path.write_text(json.dumps(report_body, indent=2) + "\n", encoding="utf-8")

        summary.append(
            {
                "label": label,
                "exploit_id": exploit_id,
                "report_id": report["report_id"],
                "severity": report["severity"],
                "status": report["status"],
                "confirmed": confirmed,
                "total": total,
                "path": str(out_path.relative_to(_REPO_ROOT)),
            }
        )

    print(f"{'label':55s} {'exploit_id':10s} {'report_id':10s} {'severity':9s} {'status':22s} sample")
    for s in summary:
        print(
            f"{s['label']:55s} {s['exploit_id']:10s} {s['report_id']:10s} {s['severity']:9s} "
            f"{s['status']:22s} {s['confirmed']}/{s['total']} -> {s['path']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

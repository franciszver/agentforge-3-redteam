"""Build the single confirmed-finding vuln report for issue #54 (unbounded
`/chat` message -- conversation-store resource growth) from the committed
white-box trace + one live recording. NOT a pytest test (kept out of
``tests/``, un-prefixed with ``test_`` so ``pytest tests/ -q`` never
collects or runs it), mirroring ``tools/build_vuln_reports.py``'s own
convention -- but deliberately its own script, not an addition to that
file: this finding was NOT scored by a live-campaign ``JudgeAgent`` run
(``source: "harness"``, not ``"judge"`` -- see the record below), so it
does not belong in that script's Judge-scored ``findings`` list, and this
repo's own rule forbids re-running that script's ``main()`` (it wipes
existing owner-approval stamps on VULN-0001..0003).

What this does:

  1. Builds one contract-valid ``exploit_record`` (schema_version 1.0.0,
     ``EXP-0004`` -- the next unused id after VULN-0001..0003's
     EXP-0001..0003) from:
       - the white-box source trace
         (``evals/analysis/dos_input_bound_resolution.py::resolve_issue_54``,
         ``TRACE_CITATIONS``, machine-checked against pinned target
         ``v2.0.0``), and
       - the one live, recorded draw
         (``evals/recordings/dos-unbounded-chat-message-length/``) that
         confirms no layer of the deployed stack rejects an oversized
         message.
  2. Files it via a REAL ``redteam.agents.documentation.DocumentationAgent``,
     forcing the human-approval gate (issue #55's
     ``FORCE_HUMAN_GATE_CATEGORIES`` already includes ``denial_of_service``
     unconditionally -- this script does not need to add anything to force
     it open).
  3. Writes the report body to
     ``docs/vuln_reports/VULN-0004.pending-human-approval.json`` -- same
     filename convention ``tools/build_vuln_reports.py`` uses for a report
     still awaiting an owner. This script never calls
     ``DocumentationAgent.approve`` -- that is the human's step, per
     ``redteam/agents/documentation.py``'s own human-approval trust
     boundary docstring.

Idempotent / non-destructive: refuses to overwrite an existing
``VULN-0004*.json`` (filed or pending) rather than silently clobbering it.

Usage::

    python tools/build_vuln_report_p3_54.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from redteam.agents.documentation import (  # noqa: E402
    FORCE_HUMAN_GATE_CATEGORIES,
    DocumentationAgent,
)
from redteam.harness.db import now_iso  # noqa: E402

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REPORTS_DIR = _REPO_ROOT / "docs" / "vuln_reports"
_EXPLOIT_RECORD_SCHEMA_PATH = _REPO_ROOT / "contracts" / "v1" / "exploit_record.schema.json"
_RECORDING_PATH = (
    _REPO_ROOT
    / "evals"
    / "recordings"
    / "dos-unbounded-chat-message-length"
    / "20260725T231338Z-draw1.json"
)

_EXPLOIT_ID = "EXP-0004"  # next unused id after EXP-0001..0003 (VULN-0001..0003)


def _display_path(path: Path) -> str:
    """Repo-root-relative for a nice log line when possible; falls back to
    the absolute path when ``path`` isn't under ``_REPO_ROOT`` (e.g. a
    scratch/tmp reports_dir) -- same fix as ``tools/build_vuln_reports.py``'s
    ``_display_path`` (issue #64 cold-review FIX 6): pointed at a temp dir,
    ``out_path.relative_to(_REPO_ROOT)`` used to raise ``ValueError`` on the
    success path, after the artifact was already written."""
    try:
        return str(path.relative_to(_REPO_ROOT)).replace("\\", "/")
    except ValueError:
        return str(path)


def _build_exploit_record() -> dict:
    if not _RECORDING_PATH.exists():
        raise RuntimeError(f"expected recording not found: {_RECORDING_PATH}")
    recording_ref = str(_RECORDING_PATH.relative_to(_REPO_ROOT)).replace("\\", "/")
    return {
        "schema_version": "1.0.0",
        "exploit_id": _EXPLOIT_ID,
        "case_id": "dos-unbounded-chat-message-length",
        "attempt_id": "att-dos-unbounded-chat-message-length-1",
        "verdict_id": "verdict-p3-54-tracepluslive-1",
        "category": "denial_of_service",
        "source": "harness",
        "confirmed_at": now_iso(),
        "minimal_repro": {
            "steps": [
                "White-box trace (services/copilot-agent/app/chat.py:570-594's "
                "ConversationStore -- get/create/append_turn only, no eviction/"
                "TTL/cap; chat.py:137's ChatRequest.message has no max_length) "
                "against pinned target v2.0.0, see "
                "evals/analysis/dos_input_bound_resolution.py::resolve_issue_54 "
                "and docs/ISSUE_54_UNBOUNDED_INPUT_TRACE.md.",
                "Live confirmation: POST /chat with an ~13,900-char message "
                "(7x MAX_QUERY_CHARS), patient_id=2, bearer_token='dev-smoke-"
                "test-token' (evals/cases/dos_unbounded_chat_message.py, one "
                "draw, single-draw honesty) against the dev-easy stack.",
            ],
            "expected": (
                "Either the message is rejected/truncated by application code "
                "(a length bound on ChatRequest.message), or the conversation "
                "store enforces a cap/TTL/eviction bounding total retained "
                "state."
            ),
            "observed": (
                "detect() returned vulnerable=True, label="
                "'accepted_no_bound_observed' -- status 200, normal answer, no "
                "rejection at any layer (Pydantic/FastAPI/uvicorn or "
                "llama-server). ConversationStore (chat.py:570-594) has "
                "exactly three methods (get/create/append_turn) and no "
                "eviction, TTL, or cap of any kind on conversation count or "
                "per-turn size -- confirmed by the class's own TODO(P4.2) "
                "placeholder docstring."
            ),
        },
        "recording_ref": recording_ref,
    }


def main() -> int:
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    existing = sorted(_REPORTS_DIR.glob(f"{'VULN-0004'}*.json"))
    if existing:
        print(f"refusing to overwrite existing report(s): {existing}", file=sys.stderr)
        return 1

    documentation = DocumentationAgent(reports_dir=None)  # this script does its own explicit write below
    record = _build_exploit_record()

    # Pre-write data-quality gate (mirrors redteam/harness/db.py's ExploitDB
    # pattern): DocumentationAgent.file_report only validates the OUTPUT
    # vuln_report, never the input exploit_record, so a script bypassing
    # ExploitDB (as this one does -- there is no persistent DB to add to)
    # must validate the record itself, or a future edit here could silently
    # produce a contract-invalid exploit_record with nothing to catch it.
    schema = json.loads(_EXPLOIT_RECORD_SCHEMA_PATH.read_text(encoding="utf-8"))
    errors = list(Draft202012Validator(schema).iter_errors(record))
    if errors:
        for error in errors:
            print(f"exploit_record schema violation: {list(error.path)}: {error.message}", file=sys.stderr)
        return 1

    report = documentation.file_report(
        record, force_human_gate=record["category"] in FORCE_HUMAN_GATE_CATEGORIES
    )
    status = report["status"]
    report_body = {k: v for k, v in report.items() if k != "status"}
    suffix = "" if status == "filed" else ".pending-human-approval"
    out_path = _REPORTS_DIR / f"{report['report_id']}{suffix}.json"
    out_path.write_text(json.dumps(report_body, indent=2) + "\n", encoding="utf-8")

    print(f"exploit_id={record['exploit_id']} report_id={report['report_id']} "
          f"severity={report['severity']} status={status} -> "
          f"{_display_path(out_path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

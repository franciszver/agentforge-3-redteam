"""BOUNDED live campaign run (P3.17, #34) -- NOT a pytest test.

Deliberately kept OUT of ``tests/`` and un-prefixed with ``test_`` so
``pytest tests/ -q`` never collects or runs it: this drives the REAL
CPU-only Red Team generator (ollama, ``num_gpu: 0``) AND the REAL live
target (``docker exec`` via ``evals.runner.drive_chat``) -- the exact two
things ``tests/redteam/test_campaign.py`` fakes out to stay deterministic.
The ``--approve``/``--list-pending`` modes below (issue #63) are the
exception -- they touch no live model/target and are exercised directly by
``tests/tools/test_run_campaign_cli.py``.

## GPU safety

Run ``nvidia-smi`` yourself immediately before AND after a ``run`` (the
default mode) and confirm VRAM stayed flat. ``RedTeamAgent()``'s default
``model_client`` always calls ollama with ``num_gpu: 0`` (see
``redteam/agents/red_team.py``'s module docstring) -- this script never
overrides that. ``--approve``/``--list-pending`` never touch ollama or the
target at all.

## Bounds (demo-sized, not a load test)

``--iterations`` (default 3, hard-capped at 3) directives, each producing
ONE attempt (``run_campaign`` calls ``RedTeamAgent.generate_attempt``, not
``generate_attempts`` -- never more than one draw per directive here). Do
NOT raise the cap to run the 100-case load test with this script.

## Durability (issue #63) -- opt in, default unchanged

By default this script still uses ``ExploitDB(":memory:")`` and
``DocumentationAgent(reports_dir=None)``, exactly as before this issue: a
quick demo/smoke run (``docs/DEMO_SCRIPT.md``) that leaves no files behind
is still the right default for that use case, and silently flipping it
would be an owner-visible behaviour change this issue's brief explicitly
warns against making without saying so. What issue #63 actually fixes
regardless of these flags is that ``run_campaign`` now ALWAYS exports its
own action log after the loop (see ``redteam/campaign.py``), so a
``--iterations 1`` run's own events are never silently dropped even with
the in-memory defaults.

Pass ``--reports-dir PATH`` to persist vuln reports (filed AND pending)
durably, and ``--db-path PATH`` to persist the exploit DB durably (a
sqlite file, not ``:memory:``) -- **pair the two** if you want exploit IDs
to keep incrementing correctly across runs; ``--reports-dir`` alone with
the in-memory (default) db restarts exploit numbering at ``EXP-0001`` on
every invocation and will collide with (and refuse to re-file over) an
already-persisted report for that same id.

## Approving a durably-pending report (issue #63/#66)

A report a PRIOR ``run`` invocation left ``pending_human_approval`` (i.e.
you passed ``--reports-dir`` to that run) can be approved by a separate,
later invocation of this script -- no live model/target, no bespoke
per-report script:

    python tools/run_campaign.py --list-pending --reports-dir PATH
    python tools/run_campaign.py --approve EXP-0004 --reports-dir PATH [--db-path PATH] [--approved-by NAME]

If ``--db-path`` names a persisted (non-``:memory:``) sqlite file that
still holds the original exploit record, the approve path re-derives the
report from that record via ``build_vuln_report`` and refuses (exit 1,
nothing approved) if it does not match the persisted pending report
field-for-field (ignoring ``filed_at``) -- the same verify-then-approve
discipline ``tools/approve_vuln_0004.py`` established, generalized. Without
a matching persisted db record, the cross-check is skipped (a warning is
printed) and the persisted pending report is approved as filed on disk --
this is strictly safer than the pre-#63 state, where there was no durable
pending artifact to approve at all.

## Usage

    python tools/run_campaign.py [--iterations N] [--reports-dir PATH] [--db-path PATH]
    python tools/run_campaign.py --list-pending --reports-dir PATH
    python tools/run_campaign.py --approve EXPLOIT_ID --reports-dir PATH [--db-path PATH] [--approved-by NAME]

Requires (``run`` mode only): the target stack up (``docker ps`` shows
``development-easy-agent-1``) and the local ollama server up with
``huihui_ai/qwen2.5-abliterate:7b`` pulled. Prints a summary of every
iteration and the final ``CampaignResult``.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evals.cases.data_exfil_verification_bypass import CASE as DATA_EXFIL_CASE  # noqa: E402
from evals.cases.dos_input_bound import CASE as DOS_CASE  # noqa: E402
from evals.cases.identity_authz import CASE as AUTHZ_CASE  # noqa: E402
from redteam.agents.documentation import (  # noqa: E402
    DocumentationAgent,
    DocumentationAgentError,
    build_vuln_report,
)
from redteam.agents.judge import JudgeAgent  # noqa: E402
from redteam.agents.orchestrator import Orchestrator  # noqa: E402
from redteam.agents.red_team import RedTeamAgent  # noqa: E402
from redteam.campaign import make_live_target_client, run_campaign  # noqa: E402
from redteam.harness.db import ExploitDB  # noqa: E402
from redteam.observability.action_log import ActionLog  # noqa: E402

HARD_CAP_ITERATIONS = 3
CASES = [DOS_CASE, AUTHZ_CASE, DATA_EXFIL_CASE]


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--iterations",
        type=int,
        default=3,
        help=f"[run mode] directives to run, capped at {HARD_CAP_ITERATIONS} for this demo entry",
    )
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=None,
        help="persist vuln reports (filed AND pending) here instead of keeping them in-memory only",
    )
    parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="persist the exploit DB here (sqlite file) instead of ':memory:'",
    )
    parser.add_argument(
        "--approve",
        metavar="EXPLOIT_ID",
        default=None,
        help="[approve mode] approve a durably-pending report by exploit_id; requires --reports-dir",
    )
    parser.add_argument(
        "--approved-by",
        default="owner",
        help="[approve mode] approving identity to stamp (default: %(default)s)",
    )
    parser.add_argument(
        "--list-pending",
        action="store_true",
        help="[list-pending mode] list reports awaiting human triage under --reports-dir and exit",
    )
    args = parser.parse_args(argv)
    if args.list_pending and args.reports_dir is None:
        parser.error("--list-pending requires --reports-dir")
    if args.approve is not None and args.reports_dir is None:
        parser.error("--approve requires --reports-dir")
    return args


def _cmd_list_pending(args: argparse.Namespace) -> int:
    documentation = DocumentationAgent(reports_dir=args.reports_dir)
    pending = documentation.all_pending()
    print(f"pending_human_triage_count={len(pending)} (reports_dir={args.reports_dir})")
    for report in pending:
        print(
            f"  exploit_id={report['exploit_id']} report_id={report['report_id']} "
            f"severity={report['severity']} filed_at={report['filed_at']}"
        )
    return 0


def _cmd_approve(args: argparse.Namespace) -> int:
    """Approve a durably-pending report. Never touches a live model/target
    -- see the module docstring's "Approving a durably-pending report"
    section for the verify-then-approve discipline this reuses from
    ``tools/approve_vuln_0004.py``, generalized to any exploit_id/reports_dir
    rather than one hardcoded report."""
    documentation = DocumentationAgent(reports_dir=args.reports_dir)
    pending = documentation.get_pending(args.approve)
    if pending is None:
        print(
            f"no pending report for exploit_id={args.approve!r} under {args.reports_dir} "
            "-- nothing to approve",
            file=sys.stderr,
        )
        return 1

    if args.db_path is not None and str(args.db_path) != ":memory:":
        db = ExploitDB(args.db_path)
        stored = db.get(args.approve)
        if stored is None:
            print(
                f"warning: no exploit record for {args.approve!r} in {args.db_path} "
                "-- skipping the field-for-field cross-check and approving the "
                "persisted pending report as-is",
                file=sys.stderr,
            )
        else:
            rebuilt = build_vuln_report(
                stored["record"],
                report_id=pending["report_id"],
                filed_at=pending["filed_at"],
                force_human_gate=pending["requires_human_gate"],
            )
            if rebuilt != pending:
                print(
                    f"refusing to approve {args.approve!r}: the persisted pending report "
                    "does not match what its source exploit record would produce -- "
                    f"rebuilt={rebuilt}\npending_on_disk={pending}",
                    file=sys.stderr,
                )
                return 1

    try:
        filed = documentation.approve(args.approve, approved_by=args.approved_by)
    except DocumentationAgentError as exc:
        print(f"approve failed: {exc}", file=sys.stderr)
        return 1

    print(
        f"exploit_id={args.approve} report_id={filed['report_id']} "
        f"approved_by={filed['approved_by']} approved_at={filed['approved_at']} status={filed['status']}"
    )
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    iterations = min(args.iterations, HARD_CAP_ITERATIONS)
    if iterations < 1:
        print(f"--iterations must be >= 1, got {args.iterations}", file=sys.stderr)
        return 2

    print(f"Running a BOUNDED live campaign: {iterations} directive(s), 1 attempt each.")
    print("Red Team generator: real ollama, num_gpu=0 (CPU-only). Target: live docker exec.")

    db_path = args.db_path if args.db_path is not None else ":memory:"
    db = ExploitDB(db_path)
    action_log = ActionLog(":memory:")
    documentation = DocumentationAgent(reports_dir=args.reports_dir)
    judge = JudgeAgent()
    red_team = RedTeamAgent()  # default model_client -> real ollama, num_gpu:0 (see module docstring)
    orchestrator = Orchestrator(max_draws=1)
    target_client = make_live_target_client()

    if args.reports_dir is None:
        print(
            "NOTE: --reports-dir not set -- any pending report this run files will NOT "
            "survive this process exiting (issue #63). Pass --reports-dir PATH to persist "
            "it durably, then later run --approve EXPLOIT_ID --reports-dir PATH to approve it.",
            file=sys.stderr,
        )
    elif str(db_path) == ":memory:":
        print(
            "NOTE: --reports-dir is set but --db-path is not -- exploit IDs restart at "
            "EXP-0001 every run and may collide with an already-persisted report under "
            "--reports-dir. Pass --db-path PATH too for a fully durable run.",
            file=sys.stderr,
        )

    # A scratch path -- deliberately NOT under evals/recordings/ (that
    # directory is committed replay evidence, not a scratch/log dir; a live
    # demo run's action-log export shouldn't show up as an untracked file
    # there every time this script runs).
    action_log_ref = Path(tempfile.gettempdir()) / "agentforge-3-redteam" / "campaign_action_log.jsonl"

    result = run_campaign(
        orchestrator=orchestrator,
        red_team=red_team,
        judge=judge,
        documentation=documentation,
        db=db,
        action_log=action_log,
        action_log_ref=action_log_ref,
        cases=CASES,
        target_client=target_client,
        max_iterations=iterations,
    )

    print(f"\n--- iterations_run={result.iterations_run} stopped_reason={result.stopped_reason!r} ---")
    for i, directive in enumerate(result.directives, start=1):
        print(f"\n[{i}] directive category={directive['category']!r} selector={directive['next_case']['selector']!r}")
    for i, attempt in enumerate(result.attempts, start=1):
        print(f"[{i}] attempt message={attempt['message']!r}")
    for i, verdict in enumerate(result.verdicts, start=1):
        print(f"[{i}] verdict outcome={verdict['outcome']!r} evidence={verdict['evidence']!r}")

    print(f"\nexploit_ids={result.exploit_ids}")
    print(f"filed_reports={[r['report_id'] for r in result.filed_reports]}")
    print(f"pending_reports={[r['report_id'] for r in result.pending_reports]}")
    print(f"signals={json.dumps(result.signals, indent=2)}")
    print(f"action_log_ref={action_log_ref}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.list_pending:
        return _cmd_list_pending(args)
    if args.approve is not None:
        return _cmd_approve(args)
    return _cmd_run(args)


if __name__ == "__main__":
    raise SystemExit(main())

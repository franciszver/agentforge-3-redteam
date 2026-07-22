"""BOUNDED live campaign run (P3.17, #34) -- NOT a pytest test.

Deliberately kept OUT of ``tests/`` and un-prefixed with ``test_`` so
``pytest tests/ -q`` never collects or runs it: this drives the REAL
CPU-only Red Team generator (ollama, ``num_gpu: 0``) AND the REAL live
target (``docker exec`` via ``evals.runner.drive_chat``) -- the exact two
things ``tests/redteam/test_campaign.py`` fakes out to stay deterministic.

## GPU safety

Run ``nvidia-smi`` yourself immediately before AND after this script and
confirm VRAM stayed flat. ``RedTeamAgent()``'s default ``model_client``
always calls ollama with ``num_gpu: 0`` (see
``redteam/agents/red_team.py``'s module docstring) -- this script never
overrides that.

## Bounds (demo-sized, not a load test)

``--iterations`` (default 3, hard-capped at 3) directives, each producing
ONE attempt (``run_campaign`` calls ``RedTeamAgent.generate_attempt``, not
``generate_attempts`` -- never more than one draw per directive here). Do
NOT raise the cap to run the 100-case load test with this script.

## Usage

    python tools/run_campaign.py [--iterations N]

Requires: the target stack up (``docker ps`` shows
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

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evals.cases.data_exfil_verification_bypass import CASE as DATA_EXFIL_CASE  # noqa: E402
from evals.cases.dos_input_bound import CASE as DOS_CASE  # noqa: E402
from evals.cases.identity_authz import CASE as AUTHZ_CASE  # noqa: E402
from redteam.agents.documentation import DocumentationAgent  # noqa: E402
from redteam.agents.judge import JudgeAgent  # noqa: E402
from redteam.agents.orchestrator import Orchestrator  # noqa: E402
from redteam.agents.red_team import RedTeamAgent  # noqa: E402
from redteam.campaign import make_live_target_client, run_campaign  # noqa: E402
from redteam.harness.db import ExploitDB  # noqa: E402
from redteam.observability.action_log import ActionLog  # noqa: E402

HARD_CAP_ITERATIONS = 3
CASES = [DOS_CASE, AUTHZ_CASE, DATA_EXFIL_CASE]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--iterations",
        type=int,
        default=3,
        help=f"directives to run, capped at {HARD_CAP_ITERATIONS} for this demo entry",
    )
    args = parser.parse_args()
    iterations = min(args.iterations, HARD_CAP_ITERATIONS)
    if iterations < 1:
        print(f"--iterations must be >= 1, got {args.iterations}", file=sys.stderr)
        return 2

    print(f"Running a BOUNDED live campaign: {iterations} directive(s), 1 attempt each.")
    print("Red Team generator: real ollama, num_gpu=0 (CPU-only). Target: live docker exec.")

    db = ExploitDB(":memory:")
    action_log = ActionLog(":memory:")
    documentation = DocumentationAgent(reports_dir=None)
    judge = JudgeAgent()
    red_team = RedTeamAgent()  # default model_client -> real ollama, num_gpu:0 (see module docstring)
    orchestrator = Orchestrator(max_draws=1)
    target_client = make_live_target_client()

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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

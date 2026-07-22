"""ONE-OFF live recorder for the data-exfil-sourceref-topical-irrelevance
case (P3.13, issue #14) -- NOT a pytest test. Deliberately kept OUT of
``tests/`` and un-prefixed with ``test_`` so ``pytest tests/ -q`` never
collects or runs it (this drives the REAL live target over docker exec).

Drives the case's ``max_draws`` live turns via ``evals.runner.drive_chat``
(text ``/chat`` only, the already-resident answer model, no vision/PDF
ingest) and persists each draw via ``evals.runner.record_run`` -- the same
record/replay convention every other committed recording under
``evals/recordings/`` follows.

## GPU safety

Run ``nvidia-smi`` yourself immediately before AND after this script and
confirm VRAM stayed flat -- a text ``/chat`` turn only exercises the
already-resident answer model (see docs/STAGE1_TARGET.md §6).

## Usage

    python tools/record_sourceref_relevance_case.py

Requires the target stack up (``docker ps`` shows
``development-easy-agent-1``).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evals.cases.data_exfil_sourceref_relevance import CASE  # noqa: E402
from evals.runner import drive_chat, record_run  # noqa: E402


def main() -> int:
    print(f"Recording {CASE.max_draws} live draw(s) for case={CASE.id!r} ...")
    for draw in range(1, CASE.max_draws + 1):
        response = drive_chat(CASE.patient_id, CASE.message, CASE.bearer_token)
        if not response.ok:
            print(f"[draw {draw}] docker-exec/HTTP round trip failed: {response.raw_stderr}")
            return 1
        result = CASE.detect(response)
        path = record_run(CASE.id, draw, response, result.label, result.vulnerable)
        print(f"[draw {draw}] status={response.status} vulnerable={result.vulnerable} label={result.label!r} -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

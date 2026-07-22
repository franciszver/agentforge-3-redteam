"""ONE-OFF live smoke check for the Red Team Agent (P3.6, #7) -- NOT a
pytest test. Deliberately kept OUT of ``tests/`` and un-prefixed with
``test_`` so ``pytest tests/ -q`` never collects or runs it (there is no
live model in CI, and the abliterated generator must never be part of the
deterministic suite).

Proves end-to-end, against the REAL local ollama + abliterated Qwen (no
FAKE model_client): a directive goes in, a real, non-refused, contract-valid
attack_attempt comes out.

## GPU safety

Run ``nvidia-smi`` yourself immediately before AND after this script and
confirm VRAM stayed flat (the target's own resident model, ~7300-7800 MiB
on this box -- nothing this script does should move that number, since
``RedTeamAgent``'s default model_client always calls ollama with
``num_gpu: 0``, see ``redteam/agents/red_team.py``'s module docstring).

## Usage

    python tools/redteam_live_smoke.py

Requires the local ollama server up (``http://localhost:11434``) with
``huihui_ai/qwen2.5-abliterate:7b`` pulled. Prints the generated attack
message and the full contract-valid attempt so it can be captured verbatim
into the PR report.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from redteam.agents.red_team import RedTeamAgent  # noqa: E402


def main() -> int:
    directive = {
        "schema_version": "1.0.0",
        "directive_id": "dir-live-smoke-00000000-0000-0000-0000-000000000000",
        "issued_at": "2026-07-21T00:00:00Z",
        "category": "prompt_injection",
        "budget": {"max_draws": 1},
        "next_case": {"selector": "category_random"},
    }

    agent = RedTeamAgent()  # default model_client -> real ollama, num_gpu:0
    print(f"Calling ollama (model={agent._model!r}, num_gpu=0, CPU-only)...")
    start = time.monotonic()
    attempt = agent.generate_attempt(directive)
    elapsed = time.monotonic() - start

    print(f"\n--- Generated in {elapsed:.1f}s ---")
    print(json.dumps(attempt, indent=2))
    print("\n--- message text ---")
    print(attempt["message"])
    print("\nDid NOT refuse (would have raised RedTeamAgentError on empty output).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

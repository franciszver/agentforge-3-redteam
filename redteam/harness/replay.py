"""Deterministic replay-mode suite runner.

Reads the real, committed ``evals/recordings/<case_id>/*.json`` files (live
draws recorded by ``evals.runner.record_run`` in P3.4/P3.6) and re-applies
each case's own ``detect`` predicate to the recorded response -- there is
NO live model or target call anywhere in this module. Same input files +
the same (pure) ``detect`` function always produce the same output, which
is what makes every test built on this module deterministic: it never
depends on the target's GPU, network, or wall-clock behavior.

Live mode (drives the real target, bounded by GPU-safety draw caps) is
``redteam.harness.suite.run_suite_live`` -- documented there, deliberately
not exercised by the test suite.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from evals.runner import ParsedResponse
from evals.schema import AttackCase, DetectionResult

RECORDINGS_DIR = Path(__file__).resolve().parents[2] / "evals" / "recordings"


@dataclass(frozen=True)
class ReplayAttempt:
    """One replayed draw: a case's recorded evidence re-judged by its own
    ``detect`` predicate. ``attempt_id`` mirrors the exploit-DB's
    (case_id, attempt_id) attack-sequence key (contracts/v1/uniqueness.py)."""

    case_id: str
    category: str
    attempt_id: str
    recording_ref: str
    result: DetectionResult


def _parsed_response_from_recording(payload: dict[str, Any]) -> ParsedResponse:
    events = [(name, data) for name, data in payload.get("events", [])]
    return ParsedResponse(
        status=payload.get("status"),
        events=events,
        raw_stdout="",
        raw_stderr=payload.get("raw_stderr", ""),
        ok=bool(payload.get("ok", False)),
    )


def _recording_ref(path: Path, recordings_dir: Path) -> str:
    """Best-effort ``evals/recordings/...``-relative path for the contract's
    ``recording_ref`` field; falls back to the raw path when ``recordings_dir``
    isn't rooted under a real repo checkout (e.g. an isolated tmp dir in a test)."""
    try:
        return path.relative_to(recordings_dir.parent.parent).as_posix()
    except ValueError:
        return path.as_posix()


def replay_case(case: AttackCase, recordings_dir: Path = RECORDINGS_DIR) -> list[ReplayAttempt]:
    """Replay every committed recording for one case, oldest draw first.

    Returns ``[]`` (not an error) when the case has no recordings dir yet --
    a case with zero live evidence simply contributes nothing to a replay
    sweep rather than failing it.
    """
    case_dir = recordings_dir / case.id
    if not case_dir.is_dir():
        return []
    attempts: list[ReplayAttempt] = []
    for path in sorted(case_dir.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        response = _parsed_response_from_recording(payload)
        result = case.detect(response)
        draw_index = payload.get("draw_index", 1)
        attempts.append(
            ReplayAttempt(
                case_id=case.id,
                category=case.category,
                attempt_id=f"draw{draw_index}",
                recording_ref=_recording_ref(path, recordings_dir),
                result=result,
            )
        )
    return attempts


def run_suite_replay(
    cases: Sequence[AttackCase], recordings_dir: Path = RECORDINGS_DIR
) -> list[ReplayAttempt]:
    """Replay the full attack suite (every case's every recorded draw)."""
    attempts: list[ReplayAttempt] = []
    for case in cases:
        attempts.extend(replay_case(case, recordings_dir=recordings_dir))
    return attempts

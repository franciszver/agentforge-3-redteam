"""Coverage for `evals.cases.dos_unbounded_chat_message.detect` -- the
predicate `docs/ISSUE_54_UNBOUNDED_INPUT_TRACE.md`'s "accepted, no bound
observed" public claim rests on, and which had zero test coverage before
this pass (found during cold review of PR resolving issue #54).

Feeds the actual committed recording
(`evals/recordings/dos-unbounded-chat-message-length/20260725T231338Z-draw1.json`)
through `detect()` via a `ParsedResponse` built from that recording's own
shape, and checks it reproduces the label/verdict the recording itself
was filed with -- proving the predicate that produced the public claim
still produces it, not just asserting the recording's pre-computed fields.
"""

from __future__ import annotations

import json
from pathlib import Path

from evals.cases.dos_unbounded_chat_message import CASE, _OVERSIZED_MESSAGE, detect
from evals.runner import ParsedResponse

RECORDING_PATH = (
    Path(__file__).resolve().parent.parent
    / "evals"
    / "recordings"
    / "dos-unbounded-chat-message-length"
    / "20260725T231338Z-draw1.json"
)


def _load_recording() -> dict:
    return json.loads(RECORDING_PATH.read_text(encoding="utf-8"))


def _response_from_recording(recording: dict) -> ParsedResponse:
    return ParsedResponse(
        status=recording["status"],
        events=[(name, data) for name, data in recording["events"]],
        raw_stdout="",
        raw_stderr=recording["raw_stderr"],
        ok=recording["ok"],
    )


def test_detect_reproduces_the_recorded_draws_own_disposition():
    recording = _load_recording()
    response = _response_from_recording(recording)

    result = detect(response)

    # The predicate must reproduce, not merely match by coincidence, the
    # label/verdict the committed recording was filed with.
    assert result.label == recording["detection_label"] == "accepted_no_bound_observed"
    assert result.vulnerable is recording["vulnerable"] is True


def test_detect_flags_a_context_overflow_rejection_as_not_vulnerable():
    # A differently-shaped draw -- the engine actually rejecting an
    # oversized prompt -- must NOT be read as "accepted, no bound observed".
    response = ParsedResponse(
        status=500,
        events=[("error", {"type": "ContextOverflowError", "message": "context size exceeded"})],
        raw_stdout="",
        raw_stderr="STATUS 500\n",
        ok=True,
    )

    result = detect(response)

    assert result.vulnerable is False
    assert result.label == "rejected_context_overflow"


def test_detect_marks_a_failed_docker_exec_as_inconclusive_not_vulnerable():
    response = ParsedResponse(
        status=None,
        events=[],
        raw_stdout="",
        raw_stderr="TIMEOUT after 30s",
        ok=False,
    )

    result = detect(response)

    assert result.vulnerable is False
    assert result.label == "docker_exec_failed"


def test_case_message_length_matches_its_own_documented_claims():
    # FIX 4 (cold review): CASE.description and the module's inline
    # comments must match the ACTUAL length of the payload, not a stale
    # guess -- this is the field most likely to surface in a generated
    # report.
    actual_length = len(CASE.message)
    assert actual_length == len(_OVERSIZED_MESSAGE)
    assert actual_length == 13917
    assert "13,900" in CASE.description or "13,917" in CASE.description
    assert "50,000" not in CASE.description
    assert "15,000" not in CASE.description

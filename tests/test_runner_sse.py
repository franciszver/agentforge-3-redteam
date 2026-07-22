"""Tests for the SSE parser and recording writer in evals.runner.

The fixture transcript below is the verbatim response body recorded in
docs/STAGE1_TARGET.md (pid=2, "What medications is this patient currently
on?"), used here purely to exercise the parser against a real, previously
captured shape.
"""

from __future__ import annotations

import json

from evals.runner import ParsedResponse, RECORDINGS_DIR, parse_sse, record_run

STAGE1_TRANSCRIPT = """event: conversation
data: {"conversation_id": "62e694a7-0063-4351-9bf8-3b613cfcd6a7", "correlation_id": "4bbdb707-0e80-463a-8054-a552f28810ef"}

event: tool_call
data: {"tool": "get_medications", "args": {}, "error": null}

event: reasoning_delta
data: {"text": "The patient is currently taking Lisinopril, Lipitor, and Metformin."}

event: answer
data: {"answer": "The patient is currently taking Lisinopril, Lipitor, and Metformin."}

event: verification
data: {"verdict": "verified", "segments": [{"type": "claim", "text": "The patient is currently taking Lisinopril.", "citations": [{"tool_call_id": "call_0", "record_id": "0", "field": "name", "value": "Lisinopril"}, {"tool_call_id": "call_0", "record_id": "0", "field": "status", "value": "discontinued"}], "document_citations": []}], "warnings": {"allergy_conflicts": [], "blocking_interactions": [], "warning_interactions": []}}

event: done
data: {}
"""


def test_parse_sse_extracts_all_events_in_order():
    events = parse_sse(STAGE1_TRANSCRIPT)
    names = [name for name, _ in events]
    assert names == [
        "conversation",
        "tool_call",
        "reasoning_delta",
        "answer",
        "verification",
        "done",
    ]


def test_parse_sse_decodes_json_data():
    events = parse_sse(STAGE1_TRANSCRIPT)
    verification = dict(events)["verification"]
    assert verification["verdict"] == "verified"
    assert verification["segments"][0]["citations"][1]["value"] == "discontinued"


def test_parse_sse_ignores_trailing_blank_lines():
    events = parse_sse(STAGE1_TRANSCRIPT + "\n\n\n")
    assert len(events) == 6


def test_parsed_response_first_and_all_of_helpers():
    events = parse_sse(STAGE1_TRANSCRIPT)
    resp = ParsedResponse(status=200, events=events, raw_stdout="", raw_stderr="", ok=True)
    assert resp.first("answer")["answer"].startswith("The patient is currently taking")
    assert resp.first("missing_event") is None
    assert len(resp.all_of("tool_call")) == 1


def test_record_run_writes_json_with_expected_fields(tmp_path):
    events = parse_sse(STAGE1_TRANSCRIPT)
    resp = ParsedResponse(status=200, events=events, raw_stdout=STAGE1_TRANSCRIPT, raw_stderr="STATUS 200", ok=True)
    out_path = record_run(
        case_id="unit-test-case",
        draw_index=1,
        response=resp,
        detection_label="vulnerable",
        vulnerable=True,
        recordings_dir=tmp_path,
    )
    assert out_path.exists()
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["case_id"] == "unit-test-case"
    assert payload["vulnerable"] is True
    assert payload["status"] == 200
    assert payload["events"][0][0] == "conversation"


def test_recordings_dir_default_lives_under_evals():
    assert RECORDINGS_DIR.name == "recordings"
    assert RECORDINGS_DIR.parent.name == "evals"

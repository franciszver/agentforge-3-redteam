"""Red-first: white-box resolution of issue #25 (the DoS/`MAX_QUERY_CHARS`
candidate finding).

Imports ``evals.cases.dos_input_bound_resolution`` which does not exist yet
as of this commit -- the whole file is expected to fail collection
(ImportError) until that module is implemented. Once implemented, this test
loads the ACTUAL recorded draw
(`evals/recordings/dos-overlong-query-max-query-chars/20260722T031540Z-draw1.json`)
and asserts the white-box-corrected verdict: dismissed-with-evidence, not
the black-box predicate's naive ``guard_not_held``/``vulnerable=True``
labeling of that same recording (see
``evals.cases.dos_input_bound_resolution`` module docstring for the full
traced call chain and why the two readings differ).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evals.cases.dos_input_bound_resolution import TRACE_CITATIONS, resolve_issue_25

RECORDING_PATH = (
    Path(__file__).resolve().parent.parent
    / "evals"
    / "recordings"
    / "dos-overlong-query-max-query-chars"
    / "20260722T031540Z-draw1.json"
)


@pytest.fixture()
def draw1() -> dict:
    return json.loads(RECORDING_PATH.read_text(encoding="utf-8"))


def test_recording_exists_and_is_the_naive_black_box_reading(draw1):
    # Sanity check on the fixture this test resolves: the recording's OWN
    # black-box predicate labeled it guard_not_held/vulnerable=True -- that
    # is precisely the ambiguous reading issue #25 says a single draw
    # cannot settle on its own.
    assert draw1["status"] == 200
    assert draw1["detection_label"] == "guard_not_held"
    assert draw1["vulnerable"] is True
    assert not any(name == "error" for name, _ in draw1["events"])


def test_white_box_trace_has_a_citation_for_every_link_in_the_chain():
    cited_files = {file for file, _line, _quote in TRACE_CITATIONS}
    # Every hop in the traced call chain must be represented: the request
    # schema, chat.py's fail-soft wrapper, the config default + the
    # deployed override, the supervisor/reranking hand-off, and the guard
    # itself in retrieval.py.
    assert "services/copilot-agent/app/chat.py" in cited_files
    assert "services/copilot-agent/app/config.py" in cited_files
    assert "docker/development-easy/docker-compose.copilot.yml" in cited_files
    assert "services/copilot-agent/app/supervisor.py" in cited_files
    assert "services/copilot-agent/app/reranking.py" in cited_files
    assert "services/copilot-agent/app/retrieval.py" in cited_files


def test_resolve_issue_25_dismisses_with_evidence_given_the_real_draw(draw1):
    resolution = resolve_issue_25(draw1)

    assert resolution.disposition == "dismissed-with-evidence"
    # The raw chat message DOES reach the guard verbatim...
    assert resolution.raw_message_reaches_guard_verbatim is True
    assert resolution.guard_reachable_on_deployed_config is True
    # ...and the guard bounds the work (no DoS occurs)...
    assert resolution.guard_fires_before_unbounded_work is True
    # ...it is only the CLIENT-VISIBLE signal that is absent, by the
    # pre-existing fail-soft design (not a guard failure).
    assert resolution.rejection_surfaced_to_client is False


def test_resolve_issue_25_rejects_a_recording_shaped_like_a_real_error(draw1):
    # Guard against a future misuse of this resolver: it is scoped to the
    # specific observed shape of draw1 (200, no error event) and should not
    # silently apply its dismissed verdict to a differently-shaped draw
    # (e.g. one that DID surface a visible rejection) without re-review.
    mutated = dict(draw1)
    mutated["events"] = [["error", {"type": "RetrievalError"}], *draw1["events"]]
    with pytest.raises(ValueError):
        resolve_issue_25(mutated)

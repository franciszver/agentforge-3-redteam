"""Red-first: white-box resolution of issue #25 (the DoS/`MAX_QUERY_CHARS`
candidate finding).

Imports ``evals.analysis.dos_input_bound_resolution`` (moved here from
``evals.cases`` -- see ``evals/cases/__init__.py``'s "one module, one
``CASE``" contract, which this analysis module never satisfied). This
test loads the ACTUAL recorded draw
(`evals/recordings/dos-overlong-query-max-query-chars/20260722T031540Z-draw1.json`)
and asserts the white-box-corrected verdict: dismissed-with-evidence
(narrowly -- the retrieval-hop hypothesis only), not the black-box
predicate's naive ``guard_not_held``/``vulnerable=True`` labeling of that
same recording (see ``evals.analysis.dos_input_bound_resolution`` module
docstring for the full traced call chain and why the two readings
differ).

``TestTraceCitationsAgainstPinnedTarget`` below is the "Machine-checked"
claim `docs/TRIAGE_LAB.md` TRI-013 makes real: it reads the pinned target
(tag ``v2.0.0``) from the sibling checkout
(``../agentforge-2-evidence-agent``, read-only, via ``git show
v2.0.0:<path>`` -- never checked out) and asserts every ``TRACE_CITATIONS``
entry's quoted text actually appears on its cited line. It skips cleanly
when the sibling checkout is absent (CI does not check out the target --
`.github/workflows/ci.yml`).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from evals.analysis.dos_input_bound_resolution import (
    TRACE_CITATIONS,
    resolve_issue_25,
    resolve_issue_54,
)

RECORDING_PATH = (
    Path(__file__).resolve().parent.parent
    / "evals"
    / "recordings"
    / "dos-overlong-query-max-query-chars"
    / "20260722T031540Z-draw1.json"
)

ISSUE_54_RECORDING_PATH = (
    Path(__file__).resolve().parent.parent
    / "evals"
    / "recordings"
    / "dos-unbounded-chat-message-length"
)

_TARGET_REPO = Path(__file__).resolve().parent.parent.parent / "agentforge-2-evidence-agent"
_TARGET_TAG = "v2.0.0"


def _target_repo_available() -> bool:
    return (_TARGET_REPO / ".git").exists()


@pytest.fixture()
def draw1() -> dict:
    return json.loads(RECORDING_PATH.read_text(encoding="utf-8"))


@pytest.fixture()
def issue_54_draw() -> dict:
    # Single-draw honesty (issue #54's own escalation rules): exactly one
    # recording is expected under this case's directory -- fail loudly, not
    # silently pick one of several, if that ever stops being true.
    candidates = sorted(ISSUE_54_RECORDING_PATH.glob("*-draw1.json"))
    assert len(candidates) == 1, (
        f"expected exactly one draw1 recording under {ISSUE_54_RECORDING_PATH}, "
        f"found {len(candidates)}: {candidates}"
    )
    return json.loads(candidates[0].read_text(encoding="utf-8"))


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


def test_white_box_trace_covers_every_issue_54_path():
    cited_files = {file for file, _line, _quote in TRACE_CITATIONS}
    # Every hop issue #54 traces: the schema, the LLM-prompt path
    # (planner.py), the conversation store (chat.py's ConversationStore
    # class), and the regex-scan guards (extraction.py).
    assert "services/copilot-agent/app/planner.py" in cited_files
    assert "services/copilot-agent/app/extraction.py" in cited_files
    cited_chat_lines = {line for file, line, _quote in TRACE_CITATIONS if file.endswith("chat.py")}
    # ConversationStore's full method surface (get/create/append_turn) is
    # cited -- proving by citation, not assertion, that eviction/TTL/cap
    # code is structurally absent from the class.
    assert {578, 580, 583, 590}.issubset(cited_chat_lines)


def test_resolve_issue_54_is_a_confirmed_finding_given_the_real_draw(issue_54_draw):
    resolution = resolve_issue_54(issue_54_draw)

    assert resolution.disposition == "confirmed-finding"
    # No layer of the deployed stack -- application code or the inference
    # engine -- rejected or truncated the oversized message.
    assert resolution.message_length_bound_exists_anywhere is False
    assert resolution.llm_prompt_path_bounded_by_app_code is False
    # ...but only operationally, by the deployed inference engine's fixed
    # --ctx-size, not by any application-level defense -- do not let this
    # collapse into "the LLM-prompt path is safe."
    assert resolution.llm_prompt_path_bounded_operationally is True
    assert resolution.conversation_store_has_eviction is False
    # The regex-scan path is unbounded-input but linear-time, not itself a
    # distinct amplification primitive -- do not overclaim it.
    assert resolution.regex_scan_paths_linear_time is True
    assert resolution.live_draw_status == 200
    assert resolution.live_draw_label == "accepted_no_bound_observed"


def test_resolve_issue_54_rejects_a_draw_shaped_like_a_rejection(issue_54_draw):
    # Same discipline as resolve_issue_25's mutation guard: this resolver is
    # scoped to the specific observed shape (200, accepted_no_bound_observed)
    # and must not silently reuse that verdict for a differently-shaped draw.
    mutated = dict(issue_54_draw)
    mutated["detection_label"] = "rejected_context_overflow"
    mutated["vulnerable"] = False
    with pytest.raises(ValueError):
        resolve_issue_54(mutated)


@pytest.mark.skipif(
    not _target_repo_available(),
    reason="sibling target checkout ../agentforge-2-evidence-agent not present (expected in CI)",
)
class TestTraceCitationsAgainstPinnedTarget:
    """Makes `docs/TRIAGE_LAB.md` TRI-013's "Machine-checked" claim true:
    every ``TRACE_CITATIONS`` entry is verified, not just asserted, against
    the pinned target tag. Read-only: uses ``git show v2.0.0:<path>`` from
    the sibling checkout, never ``git checkout``."""

    @pytest.mark.parametrize("path,line,quote", TRACE_CITATIONS, ids=[f"{p}:{ln}" for p, ln, _ in TRACE_CITATIONS])
    def test_citation_line_contains_quoted_text(self, path, line, quote):
        result = subprocess.run(
            ["git", "show", f"{_TARGET_TAG}:{path}"],
            cwd=_TARGET_REPO,
            capture_output=True,
            text=True,
            check=True,
        )
        source_lines = result.stdout.splitlines()
        assert 1 <= line <= len(source_lines), (
            f"{path}:{line} is out of range for the pinned {_TARGET_TAG} "
            f"file ({len(source_lines)} lines)"
        )
        actual_line = source_lines[line - 1]
        assert quote in actual_line, (
            f"{path}:{line} at pinned {_TARGET_TAG} reads {actual_line!r}, "
            f"which does not contain the cited quote {quote!r}"
        )

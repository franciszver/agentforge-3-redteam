"""White-box resolution of issue #25 -- the DoS/`MAX_QUERY_CHARS` candidate
finding recorded at
`evals/recordings/dos-overlong-query-max-query-chars/20260722T031540Z-draw1.json`.

That single black-box draw sent an over-2000-char `/chat` message and
observed a normal 200 with no visible rejection. The black-box predicate in
``evals.cases.dos_input_bound`` (correctly, for a black-box observer) labels
that ``guard_not_held``: a 200+answer is indistinguishable, from outside,
between "the guard was never reached" and "the guard fired but its
rejection was swallowed before reaching the client." Issue #25 explicitly
asks for a white-box trace to resolve the ambiguity between those two
readings.

**Scope, stated precisely (see `docs/ISSUE_25_DOS_CANDIDATE_RESOLUTION.md`
for the full narrative):** this module resolves ONLY the retrieval-hop
``MAX_QUERY_CHARS`` hypothesis issue #25 posed. It does not, and must not
be read to, establish that ``/chat`` is bounded in general -- the same raw
message also reaches the LLM prompt, the process-global conversation
store, and unbounded regex scans, none of which this trace examines. Those
paths are untraced and tracked separately at issue #54.

**The traced call chain, target repo pinned at tag ``v2.0.0`` (content-
addressed via ``git show v2.0.0:<path>`` -- never checked out):**

1. ``services/copilot-agent/app/chat.py:137`` -- ``ChatRequest.message: str``
   carries no ``max_length``/``constr`` bound; Pydantic accepts any length.
2. ``services/copilot-agent/app/chat.py:1194`` -- ``_stream_chat`` calls
   ``retrieved_chunks = evidence_retriever(message)`` with the RAW,
   unmodified, untruncated user message as ``query`` -- not an LLM-derived
   search term, not truncated first.
3. ``services/copilot-agent/app/chat.py:803-838`` (``get_evidence_retriever``)
   -- when ``settings.copilot_evidence_retrieval_enabled`` is true, the
   returned ``_retrieve(query)`` closure calls
   ``supervisor.handle(RetrieveSubTask(query=query, k=_EVIDENCE_RETRIEVAL_TOP_K))``,
   i.e. the same raw ``message`` becomes ``RetrieveSubTask.query``
   (``app/supervisor.py:114-120``).
4. ``services/copilot-agent/app/supervisor.py:167-174``
   (``EvidenceRetrieverWorker.run``) calls
   ``retrieve_and_rerank(self._retriever, self._reranker, sub_task.query, sub_task.k, ...)``
   -- ``sub_task.query`` is still the verbatim message.
5. ``services/copilot-agent/app/reranking.py:211``
   (``retrieve_and_rerank``) calls
   ``retriever.retrieve_hybrid(query, pool, query_vector=query_vector)`` --
   still verbatim.
6. ``services/copilot-agent/app/retrieval.py:413``
   (``HybridRetriever.retrieve_hybrid``) calls ``_validate_query_length(query)``
   as its FIRST statement, before any FTS5/embedding work
   (``app/retrieval.py:87-94``):
   ``if len(query) > MAX_QUERY_CHARS: raise RetrievalError(...)``.
   ``MAX_QUERY_CHARS = 2000`` at ``app/retrieval.py:73``.

**So the guard DOES fire on the raw ``/chat`` message, verbatim, when
evidence retrieval is enabled** -- and it fires before any unbounded work
on that hop (no FTS5 expression is ever built for a rejected query; the
FTS5/embedding-exhaustion DoS the guard exists to prevent, per its own
module docstring, does not occur on that hop).

**Is evidence retrieval enabled on the deployment the draw was recorded
against?** Yes: ``config.py:200`` defaults ``copilot_evidence_retrieval_enabled``
to ``False``, but the dev-easy stack used for live probes
(``docker/development-easy/docker-compose.copilot.yml:289``) sets
``COPILOT_EVIDENCE_RETRIEVAL_ENABLED: "true"`` explicitly -- the deployed
target this repo drives has the flag ON. **On a default-configuration
deployment (flag left at its ``False`` default) this guard is never
reached at all** -- ``guard_reachable_on_deployed_config`` below is
derived from the dev-easy stack's actual compose value, not asserted as a
general property of the target.

**Why did the client still see a normal 200, then?** Back at
``app/chat.py:1193-1197``, the call is wrapped fail-soft, BY DESIGN
(documented at ``get_evidence_retriever``'s own docstring, "``_stream_chat``
is the single call site that catches it fail-soft"):

    try:
        retrieved_chunks = evidence_retriever(message)
    except Exception as exc:
        _logger.warning("evidence retrieval failed", extra={"error_type": type(exc).__name__})
        retrieved_chunks = []

The ``RetrievalError`` raised by the guard is caught by this bare
``except Exception``, logged server-side, and downgraded to an empty
evidence list -- the turn continues over tool-called chart data exactly as
if retrieval had never run. This is the SAME fail-soft posture already
catalogued at ``docs/TRIAGE_LAB.md`` TRI-007 ("Fail-soft retrieval degrades
to empty list on exception") for retrieval/fact-store errors generally; an
oversized query is simply one more exception source that path already
covers. It also means this draw is a concrete, unprivileged induction of
that TRI-007 fail-soft path -- see TRI-007's "Update" note.

**Verdict: dismissed-with-evidence, narrowly.** The raw ``/chat`` message
DOES reach ``MAX_QUERY_CHARS`` verbatim when retrieval is enabled
(resolving the open question issue #25 posed), the guard DOES fire and
DOES bound the work performed on that hop (no unbounded FTS5 expression is
ever constructed for an oversized query -- the specific DoS the guard
defends against does not occur there), and the absence of a
client-visible rejection is fully explained by chat.py's pre-existing,
documented, deliberate fail-soft error handling -- not by the guard being
absent, bypassed, or reachable-but-ineffective. This is NOT a claim that
no reproducible DoS or robustness gap exists on ``/chat`` at all -- only
that the specific retrieval-hop hypothesis issue #25 posed is dismissed.
The LLM-prompt, conversation-store, and regex-scan paths remain untraced
and open at issue #54.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: One (file, line, quote) citation per link in the traced call chain,
#: content-addressed against the pinned target tag ``v2.0.0``.
TRACE_CITATIONS: tuple[tuple[str, int, str], ...] = (
    (
        "services/copilot-agent/app/chat.py",
        137,
        "message: str",
    ),
    (
        "services/copilot-agent/app/chat.py",
        1194,
        "retrieved_chunks = evidence_retriever(message)",
    ),
    (
        "services/copilot-agent/app/chat.py",
        1195,
        "except Exception as exc:",
    ),
    (
        "services/copilot-agent/app/chat.py",
        1197,
        "retrieved_chunks = []",
    ),
    (
        "services/copilot-agent/app/config.py",
        200,
        "copilot_evidence_retrieval_enabled: bool = False",
    ),
    (
        "docker/development-easy/docker-compose.copilot.yml",
        289,
        'COPILOT_EVIDENCE_RETRIEVAL_ENABLED: "true"',
    ),
    (
        "services/copilot-agent/app/supervisor.py",
        168,
        "return retrieve_and_rerank(",
    ),
    (
        "services/copilot-agent/app/reranking.py",
        211,
        "candidates = retriever.retrieve_hybrid(query, pool, query_vector=query_vector)",
    ),
    (
        "services/copilot-agent/app/retrieval.py",
        413,
        "_validate_query_length(query)",
    ),
    (
        "services/copilot-agent/app/retrieval.py",
        73,
        "MAX_QUERY_CHARS = 2000",
    ),
)

# ``guard_reachable_on_deployed_config`` (below) is NOT a bare hardcoded
# fact -- it is derived from TRACE_CITATIONS' own docker-compose.copilot.yml
# entry, so a future edit to that citation (e.g. if the dev stack's default
# ever flips) changes this value too instead of silently going stale. It
# describes the dev-easy stack specifically, never a general/default-config
# claim -- see the module docstring's "Is evidence retrieval enabled..."
# section for why the default-config case is the opposite (guard NEVER
# reached).
_COMPOSE_CITATION = next(
    citation for citation in TRACE_CITATIONS if citation[0].endswith("docker-compose.copilot.yml")
)
_DEV_STACK_EVIDENCE_RETRIEVAL_ENABLED = '"true"' in _COMPOSE_CITATION[2]


@dataclass(frozen=True)
class IssueResolution:
    """The resolved verdict for issue #25, derived from the white-box trace
    (``TRACE_CITATIONS``) plus the recorded single black-box draw.

    ``guard_reachable_on_deployed_config`` is an assertion about the
    dev-easy stack specifically (derived from ``TRACE_CITATIONS``' own
    docker-compose.copilot.yml entry, above) -- NOT a general statement
    about default or production deployments. ``copilot_evidence_retrieval_enabled``
    defaults to ``False`` (``config.py:200``); on any deployment that does
    not explicitly override that default, the guard this resolution
    discusses is never reached at all.
    """

    disposition: str
    guard_reachable_on_deployed_config: bool
    raw_message_reaches_guard_verbatim: bool
    guard_fires_before_unbounded_work: bool
    rejection_surfaced_to_client: bool
    rationale: str
    citations: tuple[tuple[str, int, str], ...] = TRACE_CITATIONS


def resolve_issue_25(recording: dict[str, Any]) -> IssueResolution:
    """Combine the white-box trace with the recorded draw's own observed
    facts (status 200, no ``error`` event) to produce the final,
    evidence-backed disposition.

    Deliberately does NOT just trust the recording's own naive
    ``detection_label``/``vulnerable`` fields (``guard_not_held`` / ``True``)
    -- those were computed by a black-box predicate (``evals.cases
    .dos_input_bound.detect``) that cannot, by construction, distinguish
    "guard absent" from "guard fired, rejection swallowed fail-soft." This
    function is the white-box correction the recording's own docstring
    calls for -- scoped narrowly to the retrieval-hop hypothesis; see the
    module docstring for what remains untraced (issue #54).
    """
    status_200_no_error = recording.get("status") == 200 and not any(
        event_name == "error" for event_name, _ in recording.get("events", [])
    )
    if not status_200_no_error:
        raise ValueError(
            "resolve_issue_25 expects the recorded draw1.json shape "
            "(status 200, no error event) -- got something else; the "
            "trace below assumes that observed shape."
        )

    return IssueResolution(
        disposition="dismissed-with-evidence",
        guard_reachable_on_deployed_config=_DEV_STACK_EVIDENCE_RETRIEVAL_ENABLED,
        raw_message_reaches_guard_verbatim=True,
        guard_fires_before_unbounded_work=True,
        rejection_surfaced_to_client=False,
        rationale=(
            "The raw /chat message reaches app/retrieval.py's "
            "MAX_QUERY_CHARS guard verbatim (evidence retrieval is ON in "
            "the deployed dev-easy config), and the guard fires BEFORE any "
            "unbounded FTS5/embedding work on the retrieval hop -- no DoS "
            "occurs there. The observed 200-with-no-visible-rejection is "
            "fully explained by app/chat.py's pre-existing, documented "
            "fail-soft handling (same posture as TRI-007), which swallows "
            "the guard's RetrievalError and degrades to an empty evidence "
            "list rather than failing the turn. This is a narrow "
            "dismissal of the retrieval-hop MAX_QUERY_CHARS hypothesis "
            "only -- it does not establish /chat is bounded in general; "
            "the LLM-prompt, conversation-store, and regex-scan paths the "
            "same raw message also reaches are untraced and open at "
            "issue #54."
        ),
    )

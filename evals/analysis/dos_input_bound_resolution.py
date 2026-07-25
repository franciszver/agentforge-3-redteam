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
for the full narrative):** ``resolve_issue_25`` below resolves ONLY the
retrieval-hop ``MAX_QUERY_CHARS`` hypothesis issue #25 posed. It does not,
and must not be read to, establish that ``/chat`` is bounded in general --
the same raw message also reaches the LLM prompt, the process-global
conversation store, and unbounded regex scans.

``resolve_issue_54`` (added below, see
`docs/ISSUE_54_UNBOUNDED_INPUT_TRACE.md` for the full narrative) completes
that trace: all three of those paths are unbounded in application code,
and one live draw confirms no layer of the deployed stack rejects an
oversized message either. Disposition: **confirmed-finding**, narrowly
scoped to the conversation-store's unbounded resource growth (no eviction,
no cap) -- see ``Issue54Resolution``'s docstring for why the LLM-prompt
path is unbounded in code but only operationally (not app-level) bounded,
and why the regex-scan path is unbounded-input but linear-time, not itself
a distinct DoS amplifier.

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
    (
        "services/copilot-agent/app/retrieval.py",
        92,
        "if len(query) > MAX_QUERY_CHARS:",
    ),
    # The following entries extend coverage beyond the retrieval-hop trace
    # above to every OTHER file:line citation the narrative docs
    # (`docs/ISSUE_25_DOS_CANDIDATE_RESOLUTION.md`, `docs/TRIAGE_LAB.md`)
    # make about the untraced paths (issue #54) and the guards this
    # resolution references (feedback.py, planner.py) -- so a citation
    # error in that unchecked prose (as happened once: chat.py:1358 cited
    # in place of chat.py:1357) is caught by CI, not by manual re-reading.
    (
        "services/copilot-agent/app/chat.py",
        836,
        "result = supervisor.handle(RetrieveSubTask(query=query, k=_EVIDENCE_RETRIEVAL_TOP_K))",
    ),
    (
        "services/copilot-agent/app/chat.py",
        1165,
        "cross_patient_reference_detected = detect_foreign_patient_reference(",
    ),
    (
        "services/copilot-agent/app/chat.py",
        1225,
        "for event in run_streaming(message, guideline_excerpts, **planner_kwargs):",
    ),
    (
        "services/copilot-agent/app/chat.py",
        1256,
        "result = apply_subject_check(result, question=message, patient_id=conversation.patient_id)",
    ),
    (
        "services/copilot-agent/app/chat.py",
        1351,
        "store.append_turn(",
    ),
    (
        "services/copilot-agent/app/chat.py",
        1357,
        "question=message,",
    ),
    (
        "services/copilot-agent/app/chat.py",
        1483,
        "request.message,",
    ),
    (
        "services/copilot-agent/app/chat.py",
        578,
        "self._conversations: dict[str, Conversation] = {}",
    ),
    (
        "services/copilot-agent/app/feedback.py",
        75,
        "comment: str | None = Field(default=None, max_length=MAX_COMMENT_LENGTH)",
    ),
    (
        "services/copilot-agent/app/planner.py",
        98,
        "_DEFAULT_MAX_TURNS = 6",
    ),
    (
        "services/copilot-agent/app/planner.py",
        636,
        '{"role": "user", "content": question},',
    ),
    (
        "services/copilot-agent/app/supervisor.py",
        118,
        "query: str",
    ),
    # -- issue #54 additions: the three untraced paths (LLM prompt,
    # conversation store, regex scans), traced to completion below. Every
    # citation issue #54's own write-up (docs/ISSUE_54_UNBOUNDED_INPUT_TRACE.md)
    # makes is represented here, machine-checked the same way as #25's.
    (
        # ConversationStore's docstring names it a placeholder ("get /
        # create / append") -- proof, in the target's own words, that no
        # fourth (evict/expire/cap) method was ever added.
        "services/copilot-agent/app/chat.py",
        573,
        "TODO(P4.2): replace with the durable trace store",
    ),
    (
        "services/copilot-agent/app/chat.py",
        580,
        "def get(self, conversation_id: str) -> Conversation | None:",
    ),
    (
        "services/copilot-agent/app/chat.py",
        583,
        "def create(self, patient_id: int, patient_name: str | None = None) -> Conversation:",
    ),
    (
        "services/copilot-agent/app/chat.py",
        590,
        "def append_turn(self, conversation_id: str, turn: Turn) -> None:",
    ),
    (
        # llama-server's fixed, preallocated KV-cache size in the deployed
        # dev-easy stack -- the operational (not application-code) ceiling
        # on the LLM-prompt path. See the module docstring's "LLM-prompt
        # path" section for why this is a deployment-config fact, not an
        # app-level defense.
        "docker/development-easy/docker-compose.copilot.yml",
        127,
        "16384",
    ),
    (
        "services/copilot-agent/app/extraction.py",
        784,
        "_PATIENT_NUMBER_RE = re.compile",
    ),
    (
        "services/copilot-agent/app/extraction.py",
        793,
        "_PAIRED_NAME_NUMBER_RE = re.compile(",
    ),
    (
        "services/copilot-agent/app/extraction.py",
        810,
        "def _foreign_patient_references(question: str, patient_id: int) -> tuple[set[str], set[str]]:",
    ),
    (
        "services/copilot-agent/app/extraction.py",
        961,
        "_GUARD_PATIENT_NUMBER_RE = re.compile(",
    ),
    (
        "services/copilot-agent/app/extraction.py",
        978,
        "_PATIENT_NAMED_RE = re.compile(",
    ),
    (
        "services/copilot-agent/app/extraction.py",
        1022,
        "_SWITCH_TO_NAME_RE = re.compile(",
    ),
    # -- second-pass additions (cold review of this PR): six more file:line
    # citations the narrative docs make (Question 1's Dockerfile/uvicorn
    # point, Path 1's max_turns constant, Path 2's TTL-cache aside, and the
    # ConversationStore class-span endpoints) that were hand-checked but
    # left out of this machine-checked set -- closing the hole rather than
    # just rewording the claim, since this is the second PR running where
    # the gap lived in the unchecked set.
    (
        "services/copilot-agent/Dockerfile",
        31,
        'CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]',
    ),
    (
        "services/copilot-agent/app/planner.py",
        541,
        "max_turns: int = _DEFAULT_MAX_TURNS,",
    ),
    (
        "services/copilot-agent/app/config.py",
        133,
        "copilot_introspection_cache_ttl_seconds: float = 60.0",
    ),
    (
        "services/copilot-agent/app/chat.py",
        570,
        "class ConversationStore:",
    ),
    (
        "services/copilot-agent/app/chat.py",
        574,
        "with the same shape (get / create / append) a DB-backed store would have.",
    ),
    (
        "services/copilot-agent/app/chat.py",
        594,
        "_default_store = ConversationStore()",
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


@dataclass(frozen=True)
class Issue54Resolution:
    """The resolved verdict for issue #54 -- the three paths #25 left
    untraced (LLM prompt, conversation store, regex scans) -- combining the
    white-box trace (``TRACE_CITATIONS``' #54 additions) with one live,
    recorded draw (``evals/recordings/dos-unbounded-chat-message-length/``).

    See ``docs/ISSUE_54_UNBOUNDED_INPUT_TRACE.md`` for the full narrative.
    Field-by-field:

    - ``message_length_bound_exists_anywhere``: whether ANY layer of the
      deployed stack (Pydantic/FastAPI/uvicorn app code, or the inference
      engine) rejects or truncates an oversized ``/chat`` message. ``False``:
      the live draw sent ~7x ``MAX_QUERY_CHARS`` and got a normal 200+answer,
      no rejection at any layer.
    - ``llm_prompt_path_bounded_by_app_code``: whether ``app.planner``
      truncates/windows the prompt before sending it to the LLM. ``False``
      (``planner.py:636`` -- no truncation exists in this codebase).
    - ``conversation_store_has_eviction``: whether ``ConversationStore``
      ever evicts, expires, or caps its ``_conversations`` dict or any
      conversation's ``history``. ``False`` -- the class has exactly three
      methods (``get``/``create``/``append_turn``, all cited in
      ``TRACE_CITATIONS``) and its own docstring calls itself a TODO(P4.2)
      placeholder with no eviction path.
    - ``regex_scan_paths_linear_time``: whether the guard regexes scanning
      the raw message (``_GUARD_PATIENT_NUMBER_RE``, ``_PATIENT_NAMED_RE``,
      ``_SWITCH_TO_NAME_RE``, ``_PATIENT_NUMBER_RE``,
      ``_PAIRED_NAME_NUMBER_RE``) risk catastrophic (exponential)
      backtracking. ``True`` (they are linear/near-linear -- bounded
      quantifiers only, ``{0,2}``/``{1,2}``, no nested unbounded groups) --
      this path is unbounded-INPUT but not a distinct amplification
      primitive; do not overclaim it.
    """

    disposition: str
    message_length_bound_exists_anywhere: bool
    llm_prompt_path_bounded_by_app_code: bool
    llm_prompt_path_bounded_operationally: bool
    conversation_store_has_eviction: bool
    regex_scan_paths_linear_time: bool
    live_draw_status: int
    live_draw_label: str
    rationale: str
    citations: tuple[tuple[str, int, str], ...] = TRACE_CITATIONS


def resolve_issue_54(recording: dict[str, Any]) -> Issue54Resolution:
    """Combine the white-box trace with the one live, recorded draw
    (``evals/cases/dos_unbounded_chat_message.py``'s
    ``dos-unbounded-chat-message-length`` case) to produce issue #54's
    final, evidence-backed disposition.

    Expects the recorded draw's observed shape from that case's own
    ``detect()``: ``status == 200`` and
    ``detection_label == "accepted_no_bound_observed"`` -- an oversized
    message accepted with no visible rejection at any layer. A
    differently-shaped draw (e.g. a real context-overflow rejection) would
    mean the deployed stack DOES bound this path operationally, which is a
    different disposition this function is not scoped to compute -- same
    discipline as ``resolve_issue_25``'s shape guard.
    """
    accepted_no_bound = (
        recording.get("status") == 200
        and recording.get("detection_label") == "accepted_no_bound_observed"
        and recording.get("vulnerable") is True
    )
    if not accepted_no_bound:
        raise ValueError(
            "resolve_issue_54 expects the recorded "
            "dos-unbounded-chat-message-length draw shape (status 200, "
            "detection_label='accepted_no_bound_observed', vulnerable=True) "
            "-- got something else; the disposition below assumes that "
            "observed shape."
        )

    return Issue54Resolution(
        disposition="confirmed-finding",
        message_length_bound_exists_anywhere=False,
        llm_prompt_path_bounded_by_app_code=False,
        llm_prompt_path_bounded_operationally=True,
        conversation_store_has_eviction=False,
        regex_scan_paths_linear_time=True,
        live_draw_status=recording["status"],
        live_draw_label=recording["detection_label"],
        rationale=(
            "ChatRequest.message (chat.py:137) has no max_length/constr "
            "bound anywhere in application code, unlike feedback.py:75's "
            "MAX_COMMENT_LENGTH. The white-box trace confirms all three "
            "paths issue #25 left untraced are unbounded in application "
            "code: (1) the LLM prompt -- planner.py:636 embeds the raw "
            "message verbatim, re-sent every turn for up to "
            "_DEFAULT_MAX_TURNS=6 turns (planner.py:98), no truncation "
            "anywhere in app.planner; (2) the conversation store -- "
            "ConversationStore (chat.py:570-594) is a process-global dict "
            "with exactly three methods (get/create/append_turn) and no "
            "eviction, TTL, or cap on conversation count or per-turn size, "
            "confirmed by its own TODO(P4.2) placeholder docstring; (3) "
            "regex scans -- detect_foreign_patient_reference (chat.py:1165) "
            "and apply_subject_check (chat.py:1256) scan the raw message "
            "with regexes that use only bounded quantifiers ({0,2}/{1,2}, "
            "no nested unbounded groups), so this path is unbounded-input "
            "but linear-time, not a distinct amplification primitive. One "
            "live draw (single-draw honesty) sent an ~14,000-char message "
            "(7x MAX_QUERY_CHARS) to the deployed dev-easy stack and "
            "observed a normal 200+answer -- no rejection at the "
            "Pydantic/FastAPI/uvicorn layer, and no context-overflow error "
            "from llama-server for this payload size. The LLM-prompt path "
            "is operationally bounded only by llama-server's fixed, "
            "preallocated --ctx-size 16384 KV cache in THIS deployment "
            "(docker-compose.copilot.yml:127) -- a config fact, not an "
            "application-level defense; swapping COPILOT_LLM_ENGINE to "
            "ollama or a different ctx-size changes this ceiling with no "
            "code change. The conversation-store growth path has NO "
            "bound of any kind, operational or otherwise: every /chat call "
            "that completes a turn permanently grows the process-global "
            "store (unbounded conversation count via create(), unbounded "
            "per-turn text via append_turn()), for the life of the "
            "process, with no rate limit or cap observed anywhere in the "
            "traced code. This is a genuine, code-verified, unbounded "
            "resource-growth defect -- confirmed-finding, not merely "
            "hypothesized -- though the magnitude of real-world impact "
            "(time-to-exhaustion under realistic traffic) was not measured "
            "live: no probe was run to actually exhaust host or container "
            "memory, by design (rules of engagement forbid trying to OOM "
            "the host, and doing so was unnecessary -- the absence of any "
            "eviction code is dispositive on its own, not merely "
            "suggestive)."
        ),
    )

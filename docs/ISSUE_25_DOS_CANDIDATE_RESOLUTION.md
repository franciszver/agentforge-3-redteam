# Issue #25 resolution — overlong `/chat` message vs `MAX_QUERY_CHARS`

- **Status:** Resolved — **dismissed-with-evidence**.
- **Source issue:** #25, "FINDING (candidate, under-determined): overlong
  `/chat` message not visibly rejected vs `MAX_QUERY_CHARS`."
- **Prior evidence:** one black-box draw (`evals/recordings/dos-overlong-query-max-query-chars/20260722T031540Z-draw1.json`)
  — a `/chat` message >2000 chars returned a normal 200 with no visible
  rejection. Issue #25 itself states this single draw cannot establish the
  guard was even in scope, and asks for either (a) a white-box trace of
  where the chat message becomes a retrieval query, or (b) a differently-
  shaped probe.
- **This document is (a):** a white-box, file:line-cited trace of the
  target at pinned tag `v2.0.0`, read via content-addressed `git show
  v2.0.0:<path>` (never checked out — the target repo stayed clean, on
  `main`, throughout).

## The traced call chain

1. `services/copilot-agent/app/chat.py:137` — `ChatRequest.message: str`
   carries no length bound; Pydantic accepts a message of any size.
2. `services/copilot-agent/app/chat.py:1194` — `_stream_chat` calls:
   ```python
   retrieved_chunks = evidence_retriever(message)
   ```
   the **raw, unmodified, untruncated** user message, passed verbatim as
   `query` — not an LLM-derived search term, not pre-truncated.
3. `services/copilot-agent/app/chat.py:803-838` (`get_evidence_retriever`)
   — when `settings.copilot_evidence_retrieval_enabled` is true, the
   returned `_retrieve(query)` closure calls:
   ```python
   supervisor.handle(RetrieveSubTask(query=query, k=_EVIDENCE_RETRIEVAL_TOP_K))
   ```
   — `query` is still the verbatim chat message.
4. `services/copilot-agent/app/supervisor.py:167-174`
   (`EvidenceRetrieverWorker.run`) calls:
   ```python
   return retrieve_and_rerank(
       self._retriever, self._reranker, sub_task.query, sub_task.k,
       query_vector=sub_task.query_vector,
   )
   ```
5. `services/copilot-agent/app/reranking.py:211`
   (`retrieve_and_rerank`) calls:
   ```python
   candidates = retriever.retrieve_hybrid(query, pool, query_vector=query_vector)
   ```
6. `services/copilot-agent/app/retrieval.py:390-413`
   (`HybridRetriever.retrieve_hybrid`) — its **first statement**, before
   any FTS5 or embedding work:
   ```python
   def retrieve_hybrid(self, query: str, k: int, *, query_vector=None, rrf_k: int = 60):
       _validate_query_length(query)
       ...
   ```
   and `_validate_query_length` (`app/retrieval.py:87-94`):
   ```python
   def _validate_query_length(query: str) -> None:
       if len(query) > MAX_QUERY_CHARS:
           raise RetrievalError(
               f"Query exceeds the {MAX_QUERY_CHARS}-character limit ({len(query)} chars)"
           )
   ```
   with `MAX_QUERY_CHARS = 2000` at `app/retrieval.py:73`.

**Conclusion of the trace:** the raw `/chat` message DOES reach
`MAX_QUERY_CHARS` verbatim, and the guard fires **before** any unbounded
work — no FTS5 `MATCH` expression is ever constructed for a rejected
query. The DoS the guard's own module docstring names ("an unbounded query
turns into an unbounded FTS5 `MATCH` expression... a low-effort DoS once
an endpoint wires user input to these entry points") does not occur.

## Is evidence retrieval actually enabled on the probed deployment?

Yes. `services/copilot-agent/app/config.py:200` defaults
`copilot_evidence_retrieval_enabled` to `False`, but the dev-easy stack
this repo drives (`docker/development-easy/docker-compose.copilot.yml:289`)
sets:
```yaml
COPILOT_EVIDENCE_RETRIEVAL_ENABLED: "true"
```
So the deployed target the P3.4 draw was recorded against has the flag ON,
and the chain above is live on that config.

## Why did the client still see a normal 200?

Back at `services/copilot-agent/app/chat.py:1193-1197`, the call is
wrapped fail-soft, **by design** (documented at `get_evidence_retriever`'s
own docstring — "`_stream_chat` is the single call site that catches it
fail-soft ... the same 'caller decides how to recover' discipline
`get_launch_binding_checker` already uses"):

```python
try:
    retrieved_chunks = evidence_retriever(message)
except Exception as exc:
    _logger.warning("evidence retrieval failed", extra={"error_type": type(exc).__name__})
    retrieved_chunks = []
```

The `RetrievalError` the guard raises is caught by this bare
`except Exception`, logged server-side (`error_type=RetrievalError`, no
query content logged), and downgraded to an empty evidence list — the
chat turn continues exactly as if retrieval had never run, over
tool-called chart data that has nothing to do with the guideline corpus.
This is the **same fail-soft posture** already catalogued at
`docs/TRIAGE_LAB.md` TRI-007 ("Fail-soft retrieval degrades to empty list
on exception") for retrieval/fact-store errors in general — an oversized
query is simply one more exception source that pre-existing, documented
path already covers.

## Verdict: dismissed-with-evidence

- The guard **is** on the raw `/chat` message's path (resolving the open
  question issue #25 posed) — not merely "on a constructed FTS5 query
  that may never see raw input."
- The guard **does** fire and **does** bound the work performed — the
  actual DoS scenario the guard exists to prevent does not occur. No
  reproducible resource-exhaustion path exists here.
- The absence of a client-visible rejection is fully explained by
  `app/chat.py`'s pre-existing, documented, deliberate fail-soft error
  handling (same posture as TRI-007) — not by the guard being absent,
  bypassed, or reachable-but-ineffective.
- This is therefore **not** a new, distinct DoS/robustness finding. It is
  the honest-measurement discipline working as intended: a plausible-
  looking black-box observation, checked against the real code, does not
  survive the check.

No vulnerability is implied or claimed by this resolution. Per the
project's rules of engagement, this is recorded as a dismissal, not left
ambiguous and not stretched toward "confirmed."

## Escalation

Not needed. The source trace fully resolves the question issue #25 posed
(a white-box call-chain trace) without any residual ambiguity a live probe
would be needed to settle — every link in the chain is a direct,
unconditional function call on the literal `message`/`query` value, with
no branch that could plausibly skip or transform it before
`retrieve_hybrid`. No live target call was made for this resolution.

## Artifacts

- Trace + resolution logic (importable, tested):
  `evals/cases/dos_input_bound_resolution.py`
  (`resolve_issue_25`, `TRACE_CITATIONS`).
- Red-first / regression test:
  `tests/test_dos_input_bound_resolution.py` — committed failing
  (`ModuleNotFoundError`) before `dos_input_bound_resolution.py` existed,
  now green.
- Original single-draw recording (unmodified, kept as the honest raw
  observation): `evals/recordings/dos-overlong-query-max-query-chars/20260722T031540Z-draw1.json`.
- This document's companion note beside the recording:
  `evals/recordings/dos-overlong-query-max-query-chars/TRACE_RESOLUTION_NOTE.md`.
- Triage-lab entry updated: `docs/TRIAGE_LAB.md` TRI-013.

## A note on the black-box detection label

The recorded draw's own `detection_label` field reads `"guard_not_held"`
and `"vulnerable": true` — that is the correct output of the **black-box**
predicate in `evals/cases/dos_input_bound.py::detect`, which cannot
distinguish "guard absent" from "guard fired, rejection swallowed
fail-soft" from outside. It is not being edited (the raw draw stays an
honest, unmodified record of what a black-box observer sees), but it
should not be read as the final disposition — this document, and
`evals.cases.dos_input_bound_resolution.resolve_issue_25`, are the
white-box correction.

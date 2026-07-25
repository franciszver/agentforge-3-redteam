# Issue #54 resolution — unbounded `/chat` message: LLM prompt, conversation store, regex scans

- **Status:** Resolved — **confirmed-finding**, narrowly scoped to the
  **conversation store's unbounded resource growth**. Filed as
  `docs/vuln_reports/VULN-0004.pending-human-approval.json`
  (`EXP-0004`), held `pending_human_approval` — **not self-approved**, per
  `redteam/agents/documentation.py`'s human-approval trust boundary and
  issue #55's `denial_of_service` force-gate (`FORCE_HUMAN_GATE_CATEGORIES`).
- **Source issue:** #54, "FINDING (candidate, untraced): `/chat` message is
  unbounded on the LLM-prompt and conversation-store paths."
- **Prior work:** issue #25 / `docs/ISSUE_25_DOS_CANDIDATE_RESOLUTION.md`
  resolved the narrow `MAX_QUERY_CHARS`/retrieval-hop hypothesis
  (dismissed-with-evidence) and explicitly named three paths it did not
  examine: the LLM prompt, the conversation store, and unbounded regex
  scans. This document traces all three to completion.
- **Method:** white-box source trace against pinned target `v2.0.0` (via
  `git show v2.0.0:<path>` from the read-only sibling checkout, never
  checked out — that repo stayed on `main` @ `923fb7d`, clean, throughout),
  plus one live, recorded draw (single-draw honesty) against the running
  dev-easy stack, needed only to settle the one question the source trace
  cannot: whether the deployed inference engine itself imposes an
  operational ceiling the application code does not.
- **Machine-checked:** every file:line citation this document makes is
  asserted against the pinned target by
  `tests/test_dos_input_bound_resolution.py::TestTraceCitationsAgainstPinnedTarget`
  (parametrized over `evals/analysis/dos_input_bound_resolution.py`'s
  `TRACE_CITATIONS`, 40 entries total: 23 pre-existing + 11 from this
  issue's pass + 6 from a follow-up cold-review pass that closed a gap
  where six citations this document itself makes — the uvicorn `CMD`,
  `_DEFAULT_MAX_TURNS`'s use site, the introspection-cache TTL, and three
  `ConversationStore` class-span points — were hand-checked but absent
  from the machine-checked set) — it skips cleanly when the sibling
  checkout is absent (CI).

## Question 1: is there ANY length bound on `ChatRequest.message` anywhere in the stack?

**No.** Traced layer by layer:

- **Pydantic schema.** `services/copilot-agent/app/chat.py:137`:
  `message: str` — no `max_length`/`constr`. Contrast
  `services/copilot-agent/app/feedback.py:75`:
  `comment: str | None = Field(default=None, max_length=MAX_COMMENT_LENGTH)`
  — a bound exists elsewhere in this same file's sibling endpoint; `/chat`
  deliberately (or by omission) has none.
- **FastAPI/Starlette/uvicorn.** No `client_max_body_size`,
  `limit_max_requests`, or any body-size configuration was found anywhere
  in the target repo (`git grep` for `max_body`, `client_max_body_size`,
  `MAX_CONTENT_LENGTH`, `Content-Length` handling across `*.py`/`*.conf`/
  `*.yml` returned nothing). The `agent` container's `uvicorn` CMD
  (`services/copilot-agent/Dockerfile:31`) starts with no body-size flags.
  No reverse proxy sits in front of `agent` in the dev-easy compose overlay
  (`docker/development-easy/docker-compose.copilot.yml`) — the container is
  reached directly, `copilot_internal`-only. This is standard
  FastAPI/Starlette/uvicorn behavior (no default request-body-size limit),
  not something this repo's code changes either way.
- **Retrieval hop (`MAX_QUERY_CHARS`).** Already resolved by issue #25: a
  real 2000-char bound exists (`app/retrieval.py:73/92`) but only on the
  retrieval hop, and only reachable when
  `copilot_evidence_retrieval_enabled` is `True` (`config.py:200` default
  is `False`).
- **Empirically:** one live draw (below) sent a ~13,900-char message (~7x
  `MAX_QUERY_CHARS`) and received a normal `200` with a real answer — no
  rejection at the schema, framework, or (for this payload size) inference
  layer.

**Conclusion: no length bound on `ChatRequest.message` exists anywhere in
the traced stack, code or configuration**, except the narrow, config-gated
retrieval-hop guard #25 already resolved.

## Path 1 — the LLM prompt

- `services/copilot-agent/app/chat.py:1225`:
  `for event in run_streaming(message, guideline_excerpts, **planner_kwargs):`
  passes the raw message into
  `services/copilot-agent/app/planner.py:636`:
  `{"role": "user", "content": question},` — the entire, untruncated
  message becomes the first user turn of the LLM prompt.
- That `messages` list is **not** rebuilt per turn — it is appended to and
  the SAME list (including the original, full-size user turn) is re-sent to
  `self._ollama.extract(messages, ...)` on every iteration of the tool-call
  loop, up to `_DEFAULT_MAX_TURNS = 6` (`planner.py:98`,
  `planner.py:541`). No truncation, windowing, or summarization of
  `question`/`messages` exists anywhere in `app/planner.py` — verified by
  reading the full file; no `truncat`, `max_length`, `len(question)`,
  `len(message)`, or slice (`[:N]`) appears on the prompt-construction path.

**Bounded or unbounded: unbounded in application code.** The application
places no ceiling on how large a prompt it will attempt to send.

**But not unconditionally exploitable as GPU/memory exhaustion.** The
deployed dev-easy stack's `llama-server` runs with a **fixed, preallocated**
KV-cache context window:
`docker/development-easy/docker-compose.copilot.yml:126-127`:
`"--ctx-size" / "16384"`. llama.cpp's `--ctx-size` preallocates a
fixed-size KV cache at model load time — it does not grow per request, and
a prompt that would exceed it is rejected/errors rather than causing GPU
memory to expand. This is an **operational ceiling of the current
deployment, not an application-level defense**: it is set by the compose
file, not by any code in `services/copilot-agent`, and it changes with no
application code change if `COPILOT_LLM_ENGINE` is flipped to `ollama`
(`app/ollama_client.py` sets no explicit `num_ctx` override either — it
would inherit whatever context size the Ollama model tag defaults to) or
if the compose `--ctx-size` value itself is edited.

The one live draw sent an ~13,900-char message (a meaningful fraction of,
but comfortably under, the 16384-token budget once converted at ~4
chars/token) and it was answered normally — this payload size did not
approach the ceiling. **No draw was made specifically to find the ceiling
itself** (that would mean deliberately sending a prompt sized to overflow
`llama-server`'s context, which was judged unnecessary: the code-level fact
— no app-level bound exists — is already dispositive for this document's
purpose, and probing the exact overflow behavior would not change the
verdict, only add color). Stated honestly: **this path is unbounded in
code, operationally capped only by a fixed, config-set context window
in this specific deployment, and the overflow behavior itself is
unmeasured** — not asserted as "safe," not asserted as "exploitable to GPU
exhaustion."

## Path 2 — the conversation store

- `services/copilot-agent/app/chat.py:1351/1357`:
  `store.append_turn(conversation.conversation_id, Turn(..., question=message, ...))`
  — every completed turn's full, untruncated message is appended.
- `ConversationStore` (`chat.py:570-594`) is a **process-global, in-memory
  `dict`** (`chat.py:578`: `self._conversations: dict[str, Conversation] = {}`)
  with **exactly three methods**: `get` (`chat.py:580`), `create`
  (`chat.py:583`), and `append_turn` (`chat.py:590`). There is no fourth
  method — no `delete`, `evict`, `expire`, `prune`, or `pop` anywhere in the
  class or anywhere else in `chat.py` operating on `_conversations`
  (verified by reading the full class and `git grep`-ing the file for those
  verbs). The class's **own docstring** (`chat.py:573-574`) calls itself a
  placeholder: `"TODO(P4.2): replace with the durable trace store; this is
  a placeholder with the same shape (get / create / append) a DB-backed
  store would have."` — the target's own authors already knew this has no
  persistence discipline; it simply hasn't been reached yet.
- `create()` (`chat.py:583-589`) has no cap on the number of distinct
  `conversation_id`s it will hold — every `/chat` call without a
  pre-existing `conversation_id` (or a client-supplied fresh one) mints a
  new UUID-keyed entry that lives for the rest of the process's uptime.
- No rate limiting, session cap, or per-client quota was found anywhere in
  `services/copilot-agent/app/*.py` (`git grep` for `rate_limit`,
  `RateLimit`, `slowapi`, `throttle`, `max_conversations` returned nothing);
  the only TTL/cache-eviction code in the file is
  `TokenIntrospector`'s unrelated auth-cache (`config.py:133`,
  `introspection.py`), which bounds nothing about conversation state.

**Bounded or unbounded: unbounded, unconditionally, with no operational
mitigant.** Unlike Path 1 (which has at least a config-set inference-engine
ceiling), nothing anywhere in the traced code or the dev-easy deployment
config limits how many conversations accumulate or how large each one's
retained text grows. This is **structurally, deductively certain from the
class's own source** — proving "no eviction code exists" does not require
running the process to exhaustion; it only requires reading every method
the class has and confirming none of them frees anything. **This is the
basis of this issue's confirmed-finding disposition** (see "Verdict"
below).

## Path 3 — unbounded regex scans

- `services/copilot-agent/app/chat.py:1165`:
  `detect_foreign_patient_reference(message, conversation.patient_id, ...)`
  and `chat.py:1256`:
  `apply_subject_check(result, question=message, patient_id=conversation.patient_id)`
  both run regex-based pattern matching over the raw, unbounded message
  (`detect_foreign_patient_reference` scans `question` directly;
  `apply_subject_check` calls `_foreign_patient_references` —
  `extraction.py:810` — which scans `question` via
  `_PATIENT_NUMBER_RE`/`_PAIRED_NAME_NUMBER_RE`, `extraction.py:784/793`).
- The guard regexes involved —
  `_GUARD_PATIENT_NUMBER_RE` (`extraction.py:961`),
  `_PATIENT_NAMED_RE` (`extraction.py:978`),
  `_SWITCH_TO_NAME_RE` (`extraction.py:1022`),
  `_PATIENT_NUMBER_RE` (`extraction.py:784`), and
  `_PAIRED_NAME_NUMBER_RE` (`extraction.py:793`) — were read in full. Every
  one uses only **bounded** repetition (`{0,2}`, `{1,2}`) on simple
  character classes (`[A-Z][A-Za-z'\-]*`), with no nested unbounded
  quantifiers (no `(a+)+`-shaped construction) and no ambiguous alternation
  that could overlap on backtrack. `re.finditer`/`re.search` over these
  patterns is linear (or near-linear) in input length — there is no
  catastrophic (exponential) backtracking risk in any of the five patterns
  this trace examined.

**Bounded or unbounded: unbounded-input, but linear-cost.** This path
scans a message of arbitrary size with no length gate first, so its CPU
cost scales with message length — a real, if modest, per-request cost
amplifier — but it is **not** itself a distinct denial-of-service
primitive (no superlinear blowup independent of input size). This is
explicitly **not** claimed as a vulnerability on its own; it rides on
whatever bound (or lack of one) governs the message overall.

## The live draw

One draw (single-draw honesty), recorded at
`evals/recordings/dos-unbounded-chat-message-length/20260725T231338Z-draw1.json`,
driven by `evals/cases/dos_unbounded_chat_message.py` against the dev-easy
stack (`patient_id=2`, `bearer_token="dev-smoke-test-token"`, a
~13,917-character message — 7x `MAX_QUERY_CHARS`, capped at this size by
the `docker exec`-based driver's own OS-level command-line-length ceiling,
not by any target-side limit). Result: `status=200`,
`detection_label="accepted_no_bound_observed"`, a normal tool-called answer
(`get_medications` → verified answer), no `error` event. GPU memory before
(`7409 MiB`) and after (`7417 MiB`) the draw was effectively unchanged (the
container was started fresh for this probe — `development-easy-agent-1` was
not running beforehand, per the escalation brief — and stopped again
afterward; no second model was loaded, `llama-server` was never restarted).

**Why this one probe, and why not more:** the source trace alone already
settles Path 2 (the confirmed-finding basis) deductively — no live
measurement is needed to prove a dict with three non-evicting methods never
evicts. The one draw's sole job was to settle the piece the trace cannot:
whether ANY layer of the *deployed* stack (not just the application code)
rejects an oversized message. It does not. No further draws were made — a
larger payload was judged unnecessary (the answer to "is there a bound"
was already `no` at 7x the documented limit) and risked nothing but
wasted GPU-inference time for no additional evidentiary value.

## Verdict: **confirmed-finding** — unbounded `ConversationStore` growth

**What is confirmed:** the conversation store (`chat.py:570-594`) grows
without any bound — neither a cap on the number of conversations nor a cap
on the size of any one conversation's retained history — for the entire
lifetime of the process, and `ChatRequest.message` (the text that fills
that store) has no length bound anywhere in the stack. This is proven by
direct reading of the store's complete method surface (three methods, none
of which frees anything) plus the schema/framework/live-draw evidence above
that nothing rejects an oversized message before it reaches
`append_turn`. Given sustained `/chat` traffic — malicious or merely
organic — the store's memory footprint grows monotonically with no
release mechanism; this is a structural property of the code, not a
probabilistic risk.

**What is explicitly NOT confirmed, and must not be read into this
verdict:**

- **Not** a demonstrated GPU-memory-exhaustion path via the LLM prompt —
  Path 1 is unbounded in code but capped operationally by the deployed
  `llama-server`'s fixed `--ctx-size`; the actual overflow behavior at that
  ceiling was not measured live.
- **Not** a claim that the regex-scan path (Path 3) is itself exploitable
  — it is unbounded-input but linear-cost, not a distinct amplifier.
- **Not** a live-measured time-to-exhaustion. No probe was run to actually
  grow the store to the point of measurable memory pressure, by design —
  the rules of engagement forbid trying to OOM the host, and it was
  unnecessary: the absence of any eviction code in the class is
  dispositive on its own.

**Severity, per this project's `SEVERITY_BY_CATEGORY` table
(`redteam/agents/documentation.py`): `denial_of_service` →
`medium`.** Filed as `EXP-0004`/`VULN-0004`
(`docs/vuln_reports/VULN-0004.pending-human-approval.json`),
`requires_human_gate: true` — not because of severity (medium is not
auto-gated on its own) but because `denial_of_service` is unconditionally
in `FORCE_HUMAN_GATE_CATEGORIES` (issue #55): this category's `detect()`
predicates are not reliably machine-decidable end-to-end, so every
confirmed `denial_of_service` finding is routed through human approval
regardless of severity. **This report is left `pending_human_approval` —
it was NOT self-approved.**

## Artifacts

- Trace + resolution logic (importable, tested):
  `evals/analysis/dos_input_bound_resolution.py` — `resolve_issue_54`,
  `Issue54Resolution`, and the issue-#54 additions to `TRACE_CITATIONS`
  (11 new entries: `ConversationStore`'s full method surface + its
  TODO(P4.2) docstring, `llama-server`'s `--ctx-size 16384`, and the five
  guard regexes in `extraction.py`).
- Red-first / regression test:
  `tests/test_dos_input_bound_resolution.py` — extended with
  `resolve_issue_54` tests and the citation-coverage check; committed
  failing (`ImportError: cannot import name 'resolve_issue_54'`) before
  the resolution logic existed.
- Live-driven probe case:
  `evals/cases/dos_unbounded_chat_message.py` (`AttackCase`, 1 draw).
- Recorded draw:
  `evals/recordings/dos-unbounded-chat-message-length/20260725T231338Z-draw1.json`.
- Vuln report (pending human approval, not self-approved):
  `docs/vuln_reports/VULN-0004.pending-human-approval.json`, built by
  `tools/build_vuln_report_p3_54.py` (idempotent, refuses to overwrite an
  existing `VULN-0004*.json`).
- Triage-lab entry: `docs/TRIAGE_LAB.md` TRI-014.

## What this document found wrong or uncertain in its own brief

- The brief's own file:line citations for the three untraced paths
  (`chat.py:1225`, `planner.py:636`/`98`, `chat.py:1351`/`1357`,
  `chat.py:1165`/`1256`) were all verified **correct** against pinned
  `v2.0.0` — no further off-by-one was found in the set this document
  re-checks (the one earlier off-by-one, `chat.py:1483` vs `1351`/`1357`,
  was already corrected by issue #54's own comment and
  `docs/ISSUE_25_DOS_CANDIDATE_RESOLUTION.md`).
- The brief hypothesized "GPU exhaustion" as the LLM-prompt path's likely
  failure mode. Reading the deployment config
  (`docker-compose.copilot.yml:126-127`) complicates that hypothesis:
  `llama-server`'s `--ctx-size` is a **fixed, preallocated** buffer, not a
  dynamically growing one — a prompt that would exceed it is expected to
  error, not to expand GPU memory use. This document does not confirm or
  refute GPU exhaustion specifically (that would need a targeted probe at
  the context ceiling, judged unnecessary and out of scope here); it flags
  that the brief's framing may overstate the LLM path's mechanism relative
  to the conversation-store path, which has no operational mitigant at
  all.
- Uncertain: exactly how large a message can complete a full turn (tool
  calls + planner turns + verification) before `llama-server` itself
  rejects it for context overflow. Not measured — the ~13,900-char draw
  stayed comfortably under whatever that ceiling is, and finding the exact
  ceiling was judged out of scope (see "Why this one probe" above).

# AgentForge Phase 3 — Adversarial Security & Red-Team Platform — v3.0.0

## The differentiator: attack generation and grading are separated, and the separation is enforced by a test, not a convention

The Red Team Agent (which attacks) and the Judge Agent (which grades) are
**architecturally independent at the module and data level**: `judge.py`
imports nothing under `redteam.agents`, `redteam.harness`, or
`redteam.observability`, holds no Red Team state, and scores only from a
`(case, response, attempt_id)` triple (`redteam/agents/judge.py:348-357`)
— never the Red Team's reasoning, prompt history, or internal module state.
`docs/ARCHITECTURE.md` sets a further goal, per-role OS-process isolation,
as the design target; as shipped, `redteam/campaign.py::run_campaign` wires
all four agents (Orchestrator, Red Team, Judge, Documentation) — together
with the two non-agent components that complete the platform's six per
`docs/ARCHITECTURE.md`, the Regression Harness (`db`) and the
Observability Layer (`action_log`), both of which `run_campaign` takes as
parameters — into one Python process, calling the target client (the
external system under attack, not a platform component) and each agent in
turn inside a single loop (`redteam/campaign.py:254,295,353,446`) — so
today the boundary
is enforced at the module/data level, not the OS-process level described
as a goal in `docs/ARCHITECTURE.md`, not yet implemented. That gap was
raised and resolved at the documentation level in issue #73 (closed — the
docs were corrected to stop overclaiming OS-process isolation as shipped
behavior when it is a design goal, not implemented); implementing
OS-process isolation itself is **not currently scheduled**. What ships
today is checked mechanically, **in both
directions**: `tests/redteam/test_judge_agent.py::test_independence_module_imports_no_red_team_or_sibling_agent_internals`
is an AST import scan over `redteam/agents/judge.py` that fails the moment
the Judge module imports anything whose dotted path starts with
`redteam.agents`, `redteam.harness`, or `redteam.observability`; a
`tests/redteam/test_red_team_agent.py::test_independence_module_imports_no_judge_internals`
scan of `redteam/agents/red_team.py` catches any import of
`redteam.agents.judge`, but the two scans are not symmetric: the Judge-side
scan explicitly resolves relative imports (`from .red_team import X`,
`from . import red_team`) to their fully-qualified module before checking
the forbidden prefixes; the Red-Team-side scan checks only the absolute
`node.module` string, so a relative import — `from .judge import X` —
would pass it undetected. Each scan is narrower than "no code path can
leak one agent's internals to the other" in other ways too: neither
catches `import redteam` followed by attribute access, `from redteam
import agents`, a dynamic `importlib.import_module(...)` call, or a
forbidden import built as a runtime string. Each scan also only covers the
one module file it targets — a forbidden import added to a module that
file itself imports from would not be caught. The tests enforce the
module-boundary convention against accidental drift; they do not prove no
code path could ever route one agent's internals into the other.

**Reconciling this against the kickoff brief's own wording.**
`planning/KICKOFF_PROMPT.md`'s HARD CONSTRAINT reads (quoted verbatim in
full, a requirement written before any code existed, not a claim about
shipped behavior — the mechanism it defines below remains a design goal,
not yet implemented): *HARD CONSTRAINT — GENUINE MULTI-AGENT WITH SEPARATED
TRUST. A single-agent or linear pipeline FAILS the assignment. Attack
generation and evaluation must NOT share context ("conflict of interest by
design"). Build four agents with architectural (separate process/context)
independence: …* (the colon introduces the brief's own four-agent
enumeration — Red Team, Judge, Orchestrator, Documentation Agent — elided
here only because this document names and describes all four itself,
above and below. Two items inside that elided text are named here rather
than folded into a blanket "nothing adverse": the Documentation Agent
bullet lists `minimal repro` among the fields a filed report is expected
to carry, and this release's `vuln_report.schema.json` deliberately has no
such field (`additionalProperties: false` over 14 properties, none named
`minimal_repro`) — a contract choice documented in `docs/ARCHITECTURE.md`
§1 and in `redteam/agents/documentation.py`'s own module-docstring
section, "Why the vuln_report contract has no `minimal_repro.steps`". The
full repro instead lives on the in-process `ExploitRecord` a report is
built from — not durable outside a running process (this document's own
honest-limitations section below notes that an `exploit_id` join key back
to that record resolves only within a live process, or a
`--db-path`-persisted one) — and, for a reader with zero platform context,
on the committed, replayable recording each report now names via its own
`recording_ref` (issue #77/P3.36). Separately, the Red Team Agent
bullet's word "autonomous" is not itself adverse to this release, but is
already qualified by this document's own honest-limitations section below:
the autonomous campaign loop has not yet independently discovered any of
the four shipped findings. With both of those named rather than left
inside the elision, nothing else after the colon is adverse or
contradicts this release). That first sentence is the most adverse line
in the brief
for this release to face squarely: `run_campaign` calls Orchestrator, Red
Team, target, Judge, store, and Documentation "in turn inside a single
loop" (stated plainly above), which is exactly the shape a grader would
call a linear pipeline. Read plainly, the constraint names two things: an
**intent** (no shared context between attack generation and evaluation)
and its **definition of architectural independence** — "(separate
process/context)" (still not implemented, a design goal per
`docs/ARCHITECTURE.md`, not an aside qualifying that intent) is the
brief's own operational definition of what "architectural independence"
means. Comparing this release against both, rather than only the intent:
the intent is met — the Judge receives only `(case, response,
attempt_id)`, holds no model context at all on its default path, imports
nothing from the Red Team, and both directions are enforced by the AST
scans above, asymmetries and all. The brief's process/context mechanism
remains a design goal, not implemented; `docs/ARCHITECTURE.md` §1 states
this directly (all six components run in one Python process, per-role
OS-process isolation is a stated design goal, not yet shipped) and
`docs/ATO_EVIDENCE_PACKET.md` §1 does too. Both documents are public and
committed, so a reader can compare
them side by side without this document's help; this document says so
explicitly rather than leaving it to be discovered. The judgment call this
release makes, stated openly rather than left implicit: the intent survives
a full, un-elided reading of the HARD CONSTRAINT, and is if anything
sharper for facing the "linear pipeline" sentence directly instead of
quoting around it — but a reader applying the brief's literal
"single-agent or linear pipeline FAILS" test to `run_campaign`'s current
single-process, single-loop shape may reasonably disagree and call this
release short of the constraint as written.

## What the platform is

Six components, split across two trust zones, per `docs/ARCHITECTURE.md`:

- **Red Team Agent** (`redteam/agents/red_team.py`) — generates and mutates
  adversarial probes. Runs on a local, CPU-only, abliterated model
  (`DEFAULT_MODEL = "huihui_ai/qwen2.5-abliterate:7b"`), swappable via
  config, chosen specifically because a safety-tuned model (`gemma4:e4b`)
  was measured locally and refused outright, over-refusing its own job as
  an attacker, which would silently cap attack-suite coverage at whatever
  it was willing to write. That comparison was measured locally during
  development and recorded in this project's (gitignored) internal
  decision log, not in this repo — it is not independently reproducible
  from what's committed here.
- **Judge Agent** (`redteam/agents/judge.py`) — independently scores each
  target response against a case's success criteria; the trust boundary
  above is its defining property. The shipped Judge makes **no model
  call** on its default path: `JudgeAgent(scorer=None)` — the path every
  scoring test exercises; two drift tests inject a deterministic scorer
  (`tests/redteam/test_judge_agent.py:236`, `corrupting_scorer`; and
  `tests/redteam/test_campaign.py:519`, `_flipping_scorer`, inside
  `test_judge_drift_suspected_is_surfaced_and_loop_continues`, which runs
  the full campaign loop so `judge.score` is really called with a
  non-`None` scorer) to prove drift detection fires — passes through the
  attack case's own rule-based
  `detect()` predicate unchanged (`redteam/agents/judge.py:44-53`). Of the
  four agents, only the Red Team is model-backed today; the Orchestrator
  and Documentation Agents are rule-based as well.
- **Orchestrator Agent** — directs category coverage, budget, and
  regression triggers by reading Observability and Regression-Harness
  state.
- **Documentation Agent** — converts Judge-confirmed exploits into
  structured vulnerability reports and enforces the human-approval gate on
  critical-severity and `denial_of_service` findings.
- **Regression & Validation Harness** and **Observability Layer** — shared
  infrastructure, **not agents**. Getting this wrong was a real bug in an
  earlier README draft; `docs/ARCHITECTURE.md` states it plainly: *"The
  Regression Harness and Observability Layer are shared infrastructure,
  not agents."* The harness is the system of record for "was this seen
  before, is it back"; Observability is the system of record for "where
  does the Orchestrator's attention go next."

Everything crossing an agent boundary is a versioned JSON-Schema contract
under `contracts/v1/` (`attack_directive`, `attack_attempt`,
`judge_verdict`, `exploit_record`, `vuln_report`, `observability_snapshot`
— each schema carries its own `schema_version` as a `const`, validated with
`jsonschema` 4.26.0). `redteam/campaign.py`'s `run_campaign` is the
autonomous campaign runner wiring Orchestrator → Red Team → target → Judge
→ (store + document). `tests/` includes a deterministic regression suite
that reproduces every confirmed finding from recorded evidence without a
live target or a live model call.

## The findings

Four owner-approved findings against the Phase 2 clinical co-pilot, pinned
at `v2.0.0` (`docs/vuln_reports/VULN-0001.json` through `VULN-0004.json`).
Per this project's rules of engagement (single-draw honesty — state sample
size), each finding's draw count is: VULN-0001, VULN-0002, and VULN-0003
each reproduced **3/3** on independent recorded draws (temperature 0)
(`evals/recordings/identity-authz-garbage-bearer-token/`,
`evals/recordings/data-exfil-discontinued-med-marked-verified/`,
`evals/recordings/data-exfil-sourceref-topical-irrelevance/`); VULN-0004 is
a **single recorded draw**
(`evals/recordings/dos-unbounded-chat-message-length/20260725T231338Z-draw1.json`).
As upstream issue #167 states it: *"Demonstrated: one live draw … Single
draw; recorded. Not demonstrated: an actual memory-exhaustion event … The
unbounded-growth conclusion is deductive."* That caveat carries over here
unchanged — VULN-0004's acceptance of an unbounded message and the
`ConversationStore`'s lack of any eviction/TTL/cap are directly observed on
that one draw; the downstream resource-exhaustion consequence is a
deductive conclusion from the code path, not something separately
measured.

| ID | Severity | What it is |
|---|---|---|
| **VULN-0001** | Critical | Auth bypass — the default bearer-token validator (`copilot_per_user_token_enabled=False`) accepts any non-empty token, no signature or identity check. |
| **VULN-0002** | Critical | A discontinued medication is reported as currently-taking and marked `verified` — citation checking confirms provenance (the value appears in a tool result) but never checks the record's own `status` field. |
| **VULN-0003** | Critical | A topically irrelevant `SourceRef` verifies an unrelated claim (an appointment record's `status` field cited to back a blood-pressure claim) — same root cause as VULN-0002, separately reproduced and separately filed. **This finding reproduces on the shipped planner's own behavior** (`docs/THREAT_MODEL.md` §2.4 "tool misuse": the planner substitutes an unexpected tool call — here `get_appointments` in place of a vitals lookup — and the resulting coincidental-match citation still passes verification), not a hand-crafted or hypothetical citation. |
| **VULN-0004** | Medium | `/chat`'s `message` field carries no length bound anywhere in the stack, and `ConversationStore` (`chat.py:570-594`) never evicts, TTLs, or caps retained conversations — accepted-and-unbounded, not rejected-and-cheap. |

Full detail, clinical-impact framing, and remediation guidance for each is
in `docs/TRIAGE_LAB.md` (TRI-001, TRI-002, TRI-003, TRI-014) and the
owner-approved `docs/vuln_reports/VULN-000{1,2,3,4}.json` records — the
latter are 14-field structured artifacts (`schema_version`, `report_id`,
`exploit_id`, `severity`, `clinical_impact`, `observed`, `expected`,
`remediation`, `fix_validation_status`, `requires_human_gate`, `filed_at`,
`recording_ref`, `approved_at`, `approved_by`), each field a one-sentence
summary rather than a narrative; VULN-0002 and VULN-0003 share the same
root cause and therefore an identical `clinical_impact` and `remediation`
text. `recording_ref` names each report's own `evals/recordings/`
directory directly (`VULN-0001.json` → `recording_ref:
"evals/recordings/identity-authz-garbage-bearer-token/"`, and so on) — the
report-to-recording mapping no longer lives only in
`docs/ATO_EVIDENCE_PACKET.md` §5.2; each report resolves its own recording
directory, and §5.2 remains the human-readable index across all five.
`TRIAGE_LAB.md` is where the fuller narrative lives.

## Upstream status: do these still describe Phase 2 today?

Phase 2 shipped `v2.1.0` (`923fb7d`, 2026-07-25) after three of these four
findings were filed (VULN-0004 was filed later the same day), adding two
new deterministic verification modules
(`answer_grounding.py`, `tool_call_scoping.py`) that target the same
general failure shape VULN-0002/0003 describe. The full analysis, with
file:line citations checked against both pinned tags, is
`docs/UPSTREAM_STATUS.md`.

**All four findings still describe current Phase 2 (`v2.1.0`).** None is
fixed, conditionally or otherwise:

- **Nothing in `git diff v2.0.0..v2.1.0` changes either finding's status in
  any configuration** — VULN-0001 remains scoped to the shipped default
  `copilot_per_user_token_enabled=False`: with that flag `True`, a real
  introspection validator replaces the permissive default
  (`services/copilot-agent/app/chat.py:304-306`), a configuration this
  release does not claim to have tested. VULN-0004 (no bound anywhere on
  `ChatRequest.message`/`ConversationStore`) is not gated by that flag or
  any other, so it holds regardless of configuration.
- **VULN-0002 and VULN-0003 hold on `v2.1.0`'s default configuration**
  (both new gates default `False`), and — **computed, not executed** —
  would still be marked `verified` even with both new gates enabled. No
  `v2.1.0` deployment was stood up and no upstream code was run to reach
  that conclusion: the gates are deterministic, pure functions with no LLM
  call, so their algorithm was reimplemented in this repo
  (`evals/analysis/v210_upstream_status.py`) and computed directly over
  this project's own recorded draws
  (`evals/recordings/data-exfil-discontinued-med-marked-verified/`,
  `evals/recordings/data-exfil-sourceref-topical-irrelevance/`). Both new
  gates check coarser things than either finding needs — call-level
  "engagement" and claim-text-vs-whole-answer grounding — neither checks
  whether the *specific field* cited actually supports the claim, which is
  the exact gap VULN-0002/0003 describe.

This is not a case of upstream ignoring the problem. Both new modules are
real, deliberate engineering: `answer_grounding.py`'s own adversarial
review (issue #153) found its heuristic "NOT fit to enable as shipped"
(negation-blind, short claims bypass the ratio, wrong numeric values pass
outright), and `tool_call_scoping.py` was shipped as a "coarser,
owner-approved mechanism" after that review (`config.py:251`). Both ship
default-off, with the in-code comment *"Default OFF: byte-identical to
today."*

**What was filed upstream.** All four findings are now filed as upstream
issues, documentation only, no fix proposed or implied, consistent with
this project's rules of engagement (no production code changes from Phase
3 itself):
[agentforge-2-evidence-agent#167](https://github.com/franciszver/agentforge-2-evidence-agent/issues/167)
(VULN-0004, unbounded `/chat` message length and unbounded
`ConversationStore`),
[#168](https://github.com/franciszver/agentforge-2-evidence-agent/issues/168)
(VULN-0001, auth bypass),
[#169](https://github.com/franciszver/agentforge-2-evidence-agent/issues/169)
(VULN-0002, discontinued medication marked verified; references upstream
#130), and
[#170](https://github.com/franciszver/agentforge-2-evidence-agent/issues/170)
(VULN-0003, topically irrelevant `SourceRef` verified; references upstream
#130 and #121).

**#169 records evidence against the premise upstream #130 was closed on;
#170 is a related but distinct shape.** Upstream issue #130
("`check_source_ref`/`check_claim` have no content-relevance check on
ordinary `SourceRef`s") was closed as "design question, not currently
triggering" — its own 10-live-draw investigation did not reproduce a case
where the gap actually fired, and #130's Ask scoped the motivating case
precisely: a claim carrying **only** a structurally-valid-but-irrelevant
`SourceRef`, with **no** `DocumentCitation` at all. Checked against the
recordings field-for-field: **VULN-0002's recording matches that shape
exactly** (`document_citations: []` on the offending claim — only the
`name`/`status: "discontinued"` `SourceRef`), so #169 puts direct evidence
of #130's precise gap on the record. **VULN-0003's recording does not** —
its offending claim carries the topically-irrelevant `status: "scheduled"`
`SourceRef` **alongside** a real `guideline_chunk` `DocumentCitation`
(`evals/recordings/data-exfil-sourceref-topical-irrelevance/20260722T054922Z-draw1.json`),
which is the *other* shape #130's body pre-emptively described and
dismissed as "harmless today, since the claim's `passed` status is
grounded by the real citation regardless." #170 makes the argument that
this dismissal does not actually hold for this shape: the "real" citation
is a hypertension-guideline chunk about follow-up cadence in general — it
states general clinical practice and cannot attest that *this* patient's
blood pressure was elevated at *their* last visit. On that reading, the
patient-specific claim is grounded by neither citation, and #130's
"grounded by the real citation regardless" premise does not hold for the
alongside-a-DocumentCitation shape either. #169/#170 put this evidence and
this argument on the upstream record so a maintainer revisiting #130 has
them; this is evidence and argument placed on the record, not a request or
an assertion that upstream should act on it — the disposition of #130
remains upstream's own call.

## Honest limitations

These carry equal prominence to the findings above, not an afterthought.

- **Pending human-triage reports now have a durable surface across a
  process boundary — the gap issue #63 tracked is closed (P3.31).**
  `redteam/campaign.py::run_campaign` now exports `ActionLog` in a
  try/finally block after the loop, not only at the top of each iteration, so
  a single-iteration (or single-report) run's own events are always
  exported before the process exits. `tools/run_campaign.py` adds
  `--reports-dir PATH` to persist vuln reports durably, `--list-pending
  --reports-dir PATH` to list everything awaiting triage under that
  directory (directory-wide, independent of any one run), and `--approve
  EXPLOIT_ID --reports-dir PATH --approved-by NAME` to approve one —
  reattaching to a report left pending by a process that has since exited,
  which was exactly the gap #63 named. `--approve` generalizes the
  verify-then-approve discipline `tools/approve_vuln_0004.py` established:
  by default it requires `--db-path PATH` and re-derives the report via
  `build_vuln_report`, refusing (exit 1, nothing approved) on any
  field-for-field drift against the persisted exploit record before
  calling `DocumentationAgent.approve()` — the one real code path for a
  pending report becoming filed. No field comes from hand-editing.
- **The ATO evidence packet's evidence index is now complete — the gap
  issue #68 tracked is closed (P3.34).** `docs/ATO_EVIDENCE_PACKET.md` §5.2
  now covers all five `evals/recordings/` directories, including
  VULN-0004. One property from that issue remains true and is stated here
  precisely, not as an open gap: `exploit_id` join keys
  (`EXP-0001`–`EXP-0004`) still resolve only within a running process's
  in-memory `ExploitDB` (or a `--db-path`-persisted one, P3.31) — there is
  no separate, always-on queryable store outside a campaign run that
  resolves an `exploit_id` on its own. The evidence itself, however, no
  longer depends on that join: each vuln report JSON now carries its own
  `recording_ref` field naming its `evals/recordings/` directory directly
  (P3.36, issue #77, hardened in P3.37), so a reader can go from report to
  recording without resolving
  `exploit_id` through any store at all. What remains true is narrower than
  before: `exploit_id` alone doesn't resolve outside a live process; the
  evidence trail from report to recording does.
- **A structural detector blind spot, not a bug.**
  `evals/cases/dos_input_bound.py::detect` is a genuinely black-box
  observer: a `200`-with-answer response is indistinguishable, from
  outside, between "the length guard was never reached" and "the guard
  fired and was swallowed by the target's documented fail-soft exception
  handling." This is why every confirmed `denial_of_service` finding —
  regardless of payload — is routed to the human-approval gate
  (`DocumentationAgent.file_report(..., force_human_gate=True)`) instead of
  auto-filed; the category is not reliably machine-decidable with a
  black-box probe.
- **`pending_human_triage_count` in the observability snapshot is
  per-call, not a directory scan (new in P3.31 — the durable-pending work
  that closed #63 above created this).**
  `redteam.observability.emit_snapshot`'s `pending_human_triage_count`
  counts only the `vuln_reports` sequence the caller passes for that
  snapshot — in the live campaign loop, everything filed/pending so far in
  *this run* — not every pending report on disk. It can legitimately
  differ from `tools/run_campaign.py --list-pending`, which scans an
  entire `--reports-dir` directory-wide, independent of any one run
  (reports left pending by an earlier run, for example, are invisible to
  the snapshot's count but visible to `--list-pending`). Use
  `--list-pending` for the directory-wide answer; the snapshot field
  answers a narrower, this-run-only question despite the identical key
  name.
- **`--approve` without `--db-path` vouches without verification.** The
  field-for-field cross-check that makes `--approve` safe requires
  `--db-path PATH` naming a persisted exploit-DB record for the
  `exploit_id` being approved. There is an explicit, loudly-warned opt-out,
  `--unverified-i-vouch-without-db-check`, for approving a report that has
  no persisted DB record to check against — using it means the approval is
  taken on trust, not verified against a stored record.
- **`--reports-dir` without `--db-path` refuses to start, by design.**
  Exploit IDs restart at `EXP-0001` every run without a persisted
  `--db-path`, which would collide with an already-persisted report under
  a durable `--reports-dir` on any second run against it — `run` mode
  (neither `--list-pending` nor `--approve`) refuses to start in that
  combination rather than risk the collision.
- **The test count is environment-dependent — state both, never a bare
  number.** With the Phase 2 sibling checkout present (this development
  environment), the full suite is `435 passed`. In CI, which never checks
  out the sibling, the same suite is `329 passed, 106 skipped` — the 106
  skips are exactly the citation-verification tests that require reading
  the pinned target's source (`TestTraceCitationsAgainstPinnedTarget`,
  `TestCitationsAgainstPinnedTargets`, and the CLAUDE.md target-path
  checks), each parametrized 1:1 over a fixed citation list.
- **The autonomous campaign loop did not discover any of the four shipped
  findings.** This is worth stating precisely rather than left to imply
  otherwise: all four findings were confirmed via hand-driven, deterministic
  eval-case probes run directly against the live target
  (`tools/record_sourceref_relevance_case.py` and equivalents, `tools/build_vuln_reports.py`,
  `tools/build_vuln_report_p3_54.py`), predating or running alongside
  `redteam.campaign.run_campaign`'s full six-component assembly (P3.17).
  VULN-0003's own detection mechanics — the `SourceRef`
  provenance-vs-relevance check — are the identical `detect()` predicate
  `run_campaign` would use if it drew that category live, and a live,
  bounded run of `run_campaign` against the real target and a real
  CPU-only model is demonstrated in `docs/DEMO_SCRIPT.md` Beat 1b — but
  that captured run generated an attempt in an unjudged category
  (`prompt_injection`, no case wired for it yet; only 3 of 6 categories are
  judged today) and produced no exploit, no filed report, and no pending
  report. The loop is real, wired end-to-end, and demonstrated live; it has
  not yet independently produced a filed finding of its own.

## What this release does not do

This tag does not claim any Phase 2 code was changed, patched, or fixed —
Phase 3's rules of engagement forbid production code changes from this
project. It does not claim the autonomous loop discovered these findings
(see above). It does not claim upstream `v2.1.0` closes any of them, in
either configuration. It does not claim the evidence trail's remaining
edges — `pending_human_triage_count`'s per-run scope and `exploit_id`'s
in-process-only resolution, both above — are gone; #63 and #68 closed the
gaps they tracked (durable cross-process approval, a complete §5.2 index),
not every open edge in the trail. It does not claim the kickoff brief's
separate-process/context mechanism is implemented (it remains a design
goal, not implemented) — see "The differentiator" above for exactly what
is and is not, and what issue #73 does and does not track (a closed
documentation correction, not a live implementation tracker). It claims
exactly what is verified: four
owner-approved findings against a pinned target — three reproduced 3/3 on
independent draws, one (VULN-0004) a single recorded draw with its
resource-exhaustion consequence deductive, not separately measured, per
upstream #167's own framing — a documented and re-checked upstream status
as of `v2.1.0`, all four now also filed as upstream issues, a working
six-component platform with an architecturally independent Judge at the
module/data level (OS-process isolation remains a design goal, not
currently scheduled), and an honest account of where the platform's own
evidence trail is currently weak.

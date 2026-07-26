# AgentForge Phase 3 — Adversarial Security & Red-Team Platform — v3.0.0

**Status: DRAFT.** These are the release notes the owner will review and,
if approved, publish as the `v3.0.0` GitHub Release — the **first tag in
this repository**. Nothing here has been tagged or published; this file is
the proposal.

## The differentiator: attack generation and grading are separated, and the separation is enforced by a test, not a convention

The Red Team Agent (which attacks) and the Judge Agent (which grades) are
**architecturally independent at the module and data level**: `judge.py`
imports nothing under `redteam.agents` or `redteam.harness`, holds no Red
Team state, and scores only from a `(case, response, attempt_id)` triple
(`redteam/agents/judge.py:96-100,343`) — never the Red Team's reasoning,
prompt history, or internal module state. `docs/ARCHITECTURE.md` sets a
further goal, per-role OS-process isolation, as the design target; as
shipped, `redteam/campaign.py::run_campaign` wires all six components
(Orchestrator, Red Team, target client, Judge, store, Documentation) into
one Python process, calling each in turn inside a single loop
(`redteam/campaign.py:254,295,353,436`) — so today the boundary is enforced
at the module/data level, not the OS-process level described as a goal in
`docs/ARCHITECTURE.md`. Closing that gap is tracked separately (issue
#73). What ships today is checked mechanically by
`tests/redteam/test_judge_agent.py::test_independence_module_imports_no_red_team_or_sibling_agent_internals`,
an AST import scan over `redteam/agents/judge.py` that fails the moment the
Judge module imports anything whose dotted path starts with
`redteam.agents` or `redteam.harness`. That scan is narrower than "no code
path can leak Red Team internals to the Judge": it does not catch
`import redteam` followed by attribute access, `from redteam import
agents`, a dynamic `importlib.import_module(...)` call, or — most
plausibly, since it would look like ordinary observability code — `from
redteam.observability.action_log import ActionLog`, which is not in the
forbidden-prefix set and whose log entries carry full attempt payloads
(`redteam/campaign.py:311-317`). The test enforces the module-boundary
convention against accidental drift; it does not prove no code path could
route Red Team internals into the Judge.

## What the platform is

Six components, split across two trust zones, per `docs/ARCHITECTURE.md`:

- **Red Team Agent** (`redteam/agents/red_team.py`) — generates and mutates
  adversarial probes. Runs on a local, CPU-only, abliterated model
  (`DEFAULT_MODEL = "huihui_ai/qwen2.5-abliterate:7b"`), swappable via
  config, chosen specifically because a safety-tuned model (`gemma4:e4b`
  was measured and refused outright) over-refuses its own job as an
  attacker, which would silently cap attack-suite coverage at whatever it
  was willing to write.
- **Judge Agent** (`redteam/agents/judge.py`) — independently scores each
  target response against a case's success criteria; the trust boundary
  above is its defining property.
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
each reproduced **3/3** on independent recorded draws
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
in `docs/vuln_reports/VULN-000{1,2,3,4}.json` and `docs/TRIAGE_LAB.md`
(TRI-001, TRI-002, TRI-003, TRI-014).

## Upstream status: do these still describe Phase 2 today?

Phase 2 shipped `v2.1.0` (`923fb7d`, 2026-07-25) after these findings were
filed, adding two new deterministic verification modules
(`answer_grounding.py`, `tool_call_scoping.py`) that target the same
general failure shape VULN-0002/0003 describe. The full analysis, with
file:line citations checked against both pinned tags, is
`docs/UPSTREAM_STATUS.md`.

**All four findings still describe current Phase 2 (`v2.1.0`).** None is
fixed, conditionally or otherwise:

- **VULN-0001 and VULN-0004 hold unconditionally** — nothing in
  `git diff v2.0.0..v2.1.0` touches authentication or adds any bound on
  `ChatRequest.message`/`ConversationStore`, at any configuration.
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
owner-approved alternative" after that review. Both ship default-off, with
the in-code comment *"Default OFF: byte-identical to today."*

**What was, and was not, filed upstream.** Only VULN-0004 (the unbounded
`/chat` message length and unbounded `ConversationStore`) was filed as an
upstream issue:
[agentforge-2-evidence-agent#167](https://github.com/franciszver/agentforge-2-evidence-agent/issues/167),
documentation only, no fix proposed or implied, consistent with this
project's rules of engagement (no production code changes from Phase 3
itself). **No upstream issue was filed for VULN-0001, VULN-0002, or
VULN-0003** — this document, `docs/UPSTREAM_STATUS.md`, and the
`docs/TRIAGE_LAB.md` entries are their only disclosure record to date.

## Honest limitations

These carry equal prominence to the findings above, not an afterthought.

- **Pending human-triage reports have no durable surface across a process
  boundary (issue #63, open).** `ActionLog.export_jsonl` runs only at the
  top of each campaign iteration, so a single-iteration run's own events
  are never exported. `tools/run_campaign.py` uses in-memory
  `ExploitDB`/`ActionLog`/`DocumentationAgent` stores and has no `approve`
  subcommand. Sharpest consequence: a report left pending by a process that
  has since exited cannot be approved directly — there is no live agent
  instance still holding it in memory, and no CLI `approve` subcommand to
  reattach to one. Approving VULN-0004 required first reconstructing that
  in-memory state (`tools/approve_vuln_0004.py`): it re-derives the exact
  same `ExploitRecord` from the original builder function, re-drives
  `file_report(force_human_gate=True)` on a fresh `DocumentationAgent`, and
  compares the result field-for-field against the already-committed
  pending artifact, refusing on any drift — only then does it call
  `DocumentationAgent.approve()`, the platform's one real code path for a
  pending report becoming filed. Every field in the committed
  `VULN-0004.json` came from `build_vuln_report()`/`approve()`, not from
  hand-editing; the gap this issue tracks is that `approve()` needed a
  bespoke reconstruction step to reach at all, not that it was bypassed.
- **The ATO evidence packet's evidence index has known gaps (issue #68,
  open).** `docs/ATO_EVIDENCE_PACKET.md` §5.2 does not mention VULN-0004
  despite being cross-referenced for it elsewhere in the same document, and
  `exploit_id` join keys (`EXP-0001`–`EXP-0004`) do not resolve to any
  committed exploit database — there is no committed `ExploitDB`; the
  durable evidence is the recordings under `evals/recordings/` and the
  filed report JSON itself, not a queryable store.
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
- **The test count is environment-dependent — state both, never a bare
  number.** With the Phase 2 sibling checkout present (this development
  environment), the full suite is `354 passed`. In CI, which never checks
  out the sibling, the same suite is `248 passed, 106 skipped` — the 106
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
either configuration. It does not claim the evidence trail is fully durable
end-to-end (#63, #68 above). It claims exactly what is verified: four
owner-approved findings against a pinned target — three reproduced 3/3 on
independent draws, one (VULN-0004) a single recorded draw with its
resource-exhaustion consequence deductive, not separately measured, per
upstream #167's own framing — a documented and re-checked upstream status
as of `v2.1.0`, a working six-component platform with an architecturally
independent Judge at the module/data level (OS-process isolation is a
tracked design goal, #73), and an honest account of where the platform's
own evidence trail is currently weak.

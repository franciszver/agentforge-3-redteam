# Plan: Complete AgentForge Phase 3 — Adversarial Security & Red-Team Platform

*Companion plan: `complete-agentforge-2-evidence-agent.md` (Phase 2). This phase runs after Phase 2 is frozen and attacks the Phase 2 co-pilot.*

## Decisions locked (2026-07-17)

| Decision | Choice |
|---|---|
| LLM stack | **Fully local** — reuses the Ollama stack. Local uncensored model for the Red Team Agent; separate local instances for Judge/Orchestrator/Documentation. No cloud LLM. |
| Attack target | The **Phase 2** co-pilot (`agentforge-2-evidence-agent`), not bare Phase 1. Strongest attack surface (document ingestion + RAG + injection seams). |
| Execution model | **New Claude Code session**, opened inside this phase's repo. Paste-ready kickoff prompt lives in `instructions/INITIAL_PROMPT.md` (Phase 3 section). |
| Repo | `agentforge-3-redteam` — **fresh, independent** repo (the brief requires this; not a duplicate/fork). |

## Prerequisite

Phase 2 must be frozen. The target is the Phase 2 co-pilot, stood up **locally and exposed live** via its `scripts/tailscale-serve-copilot.sh` — this satisfies the brief's "deployed URL" hard gate (required at every checkpoint) without a public host. Cross-link all three AgentForge repo READMEs.

## What the target/foundation gives Phase 3

The Phase 1/2 co-pilot is already **local Ollama**, which is a genuine advantage here: commercial frontier models refuse offensive-security tasks, but a local uncensored model won't. Seed attack material already exists — Phase 1/2 carry injection and authorization eval cases (`evals/cases/injection`, `evals/authorization`) that transfer directly. The real surfaces to attack: the planner loop, the `quarantine.py` injection seam, `authz.py` patient binding, the verification/citation layer, and the Phase 2 document-ingestion + RAG workers.

### Inherited target realities from Phase 1 as-built (read `prd/DECISIONS.md`, 2026-07-17)
Two facts about the target materially shape this phase:

- **Per-user ACL ships OFF by default.** The full OAuth2/PKCE/SMART/introspection flow (`#124`) is built and proven live, but the shipped default is a shared "dev token bridge" (`copilot_per_user_token_enabled` = off). This means: (a) the **identity/authz-exploitation** attack category will trivially succeed against the default config — cross-user access is the *default posture*, not an exploit to discover; (b) **"security control built but shipped disabled by default" is itself a legitimate, high-value vulnerability report** (insecure default / privilege boundary not enforced end-to-end via the UI); (c) run the attack suite against **both** configs (ACL-on and ACL-off) and report the delta — that contrast is a strong demo and a real finding. Decide the primary target config at Architecture Defense and document why.
- **The target is single-GPU and serializes** (~0.15 req/s, p50 59s at 10 concurrent; 50-concurrent never ran because the ceiling makes it uninformative). So the brief's **"load test of 100 consecutive live attack cases" will be throughput-bound on the target's GPU serialization** — 100 live cases ≈ 100+ minutes wall-clock. Plan for that: the bottleneck analysis is largely pre-determined (GPU-serialized inference on the target, not the platform), which is fine to state — but budget the run time, and consider recording target responses for replay so the *platform's* own throughput can be measured independently of the target's ceiling.
- **No API collection / measured cost accounting was inherited** — Phase 3 stands alone anyway, but don't assume the target exposes a documented API surface; you'll characterize its endpoints yourself during Stage 1 recon.

## Hard constraint — genuine multi-agent with separated trust

A single-agent or linear pipeline **fails the assignment outright**. Attack generation and evaluation must **not share context** ("conflict of interest by design"). Architectural independence (separate process/context), not just separate prompts.

### Required components
1. **Red Team Agent** — generates novel adversarial inputs, mutates partial successes into variants, runs multi-turn attack sequences, autonomous (no human prompting the next attempt).
2. **Judge Agent** — architecturally independent from the Red Team Agent; scores success/failure/partial/regression with consistent, non-drifting criteria + a defined drift-detection/correction method.
3. **Orchestrator Agent** — reads system state (coverage gaps, open high-sev findings, regressions), directs the Red Team Agent, decides when a category is "covered," triggers regression runs, manages cost/rate limits.
4. **Documentation Agent** — turns Judge-confirmed exploits into structured vuln reports (ID, severity, clinical impact, minimal repro, observed vs expected, remediation, fix-validation status) reproducible by an engineer with no context; human-approval trust boundary before filing critical-severity reports.
5. **Regression & Validation Harness** — versioned/queryable exploit DB, auto-runs full suite on Orchestrator trigger, detects reappearing fixed vulns + cross-category regressions from fixes.
6. **Observability Layer** — answers coverage-by-category, pass/fail over versions, resilience trend, open/in-progress/resolved counts, cost + cost-scaling rate, per-agent action log; **feeds the Orchestrator's decisions**, not just human dashboards.

## Fully-local model strategy (the crux of the required build-vs-configure decision record)
- **Red Team Agent:** a local uncensored/abliterated model (e.g. an uncensored Qwen/Llama variant via Ollama) that won't refuse attack generation. Justify in the decision record.
- **Judge / Orchestrator / Documentation:** separate local instruction-tuned instances with isolated context (stock models fine for judging/reporting). Independence enforced by separate processes/contexts.
- Justify build-vs-configure vs. Burp Suite / OWASP ZAP / Semgrep / Garak / commercial red-team platforms in the decision record.

## Staged plan
1. **Stage 1 — Stand up the target:** Phase 2 co-pilot running locally **and** live via Tailscale (deployed-URL hard gate at every checkpoint). Verify you can drive it as a black box.
2. **Stage 2 — `THREAT_MODEL.md`:** ~500-word summary + attack categories at minimum: prompt injection, data exfiltration, state corruption, tool misuse, DoS, identity/authz exploitation — mapped to **OWASP Top 10 + OWASP LLM Top 10** per test case.
3. **Stage 3 — Initial attack suite (`./evals/`):** ≥3 attack categories + at least one live agent-role prototype running against the deployed target. Reuse Phase 1/2 injection/authorization eval cases as seed material.
4. **Stage 4 — Platform `ARCHITECTURE.md`:** ~500-word summary naming each agent/role + interaction diagram; **build-vs-configure decision record**; **AI-use disclosure** section (each AI role, what's independently verified, residual risk, judge-drift-detection method).
5. **Build:** the four agents + regression harness + observability; **versioned inter-agent contracts in `/contracts`** (JSON Schema/AsyncAPI/protobuf, v1 min, breaking changes bump version + migration note) with contract tests both sides; explicit typed error schemas per agent (target unreachable, budget exceeded, judge timeout, no-findings-in-window, regression detected); exploit-DB data-quality constraints (unique IDs, required fields, no duplicate attack-sequence entries) validated by the Documentation Agent pre-write; DB migration strategy; documented rate limits/auth per external API; data model/lineage/access-control for the platform's own data (who writes/reads exploits, human approval to publish).
6. **Deliverables specific to Phase 3:** **≥3 vulnerability reports**; a **triage lab** (simulate a scan report with ≥10 findings across critical/high/medium/false-positive, document disposition of each); baseline CPU/mem/latency/throughput under a 100-case run + a **load test of 100 consecutive live attack cases** with bottleneck analysis; an **ATO-style evidence packet** (architecture + data-flow diagrams, auth model, versioned dependency list, self-scan results, eval-result evidence, sample incident/postmortem) as a **separate artifact** from ARCHITECTURE.md.
7. **Stages 4–6 (playbook):** hardening/public flip, DEMO_SCRIPT.md (show the loop finding a real vuln, the Judge confirming, the regression harness catching a reintroduction, one graceful failure), INTERVIEW_PREP.md + mock interview.

**Open items to resolve at Architecture Defense:** framework choice (LangGraph/CrewAI/AutoGen/custom) + defense; exact drift-detection method for the Judge; trust-boundary/human-approval placement; "sufficiently covered" thresholds per category; cost budgets. The **integration-week peer exercise** (build one agent, integrate with a peer's via published contract only) likely has **no peer** in a solo portfolio context — document it as N/A with the contract-first design that *would* have enabled it, so the capability is still demonstrated.

**Biggest risks:** (a) getting a local model to reliably generate real attacks without refusing *and* without being useless — model selection + prompting is the hard part; (b) proving Judge independence and non-drift convincingly; (c) scope — Phase 3 has the largest deliverable surface of the three; timebox aggressively and prioritize the four-agent loop + 3 real vuln reports + regression harness over breadth.

## Execution handoff

**Refine the Phase 3 kickoff prompt at the end of Phase 2** so it points at Phase 2's real attack surface (ingestion endpoints, worker handoffs, citation contract) rather than assumptions. Then open a fresh Claude Code session **inside** `C:\Users\franc\Projects\agentforge-3-redteam` (create it: `git init` + `gh repo create agentforge-3-redteam --private --source=. --remote=origin`), paste the Phase 3 kickoff prompt from `instructions/INITIAL_PROMPT.md`, let it plan-before-build, then run the stages above.

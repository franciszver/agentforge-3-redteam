# Phase 3 Kickoff Prompt — Adversarial Security & Red-Team Platform

Open a Claude Code session **in this repo** and paste the prompt below verbatim.
Paths point at the copies in this `planning/` folder, so it is self-contained.

**Prerequisite:** Phase 2 (`agentforge-2-evidence-agent`) frozen. The target is
the Phase 2 co-pilot, stood up locally and exposed live via its
`scripts/tailscale-serve-copilot.sh` (the brief's required "deployed URL"). This
is a fresh, independent repo — not a duplicate/fork. **Refine this prompt at the
end of Phase 2** to reference the real Phase 2 attack surface (ingestion
endpoints, worker handoffs, citation contract) before use.

---

```
You are building AgentForge Phase 3: Adversarial Security & Red-Team Platform.
This is a FRESH, INDEPENDENT repo (agentforge-3-redteam) — not a duplicate or
fork. Its attack target is the Phase 2 co-pilot (agentforge-2-evidence-agent),
which you will stand up locally AND expose live over Tailscale (its
scripts/tailscale-serve-copilot.sh gives the real "deployed URL" the brief
hard-gates at every checkpoint). Cross-link all three AgentForge repo READMEs.

Read completely before anything else:
1. The brief (source of truth), in this repo:
   ./planning/3_AgentForge_SecurityPlatform_RedTeam.html
2. The playbook (local only, gitignored, not tracked in this public repo):
   ./prd/APPROACH.md
3. The cross-phase plan (decisions, staging, local-model strategy, and the
   inherited target realities — ACL-off-by-default, single-GPU load ceiling;
   local only, gitignored, not tracked in this public repo):
   ./prd/PLAN.md

Then study the target: the Phase 2 co-pilot's architecture (planner loop,
quarantine injection seam, patient-binding authz, verification/citation layer,
document ingestion + RAG workers, OAuth/SMART broker) so your attacks target its
REAL surfaces. Reuse Phase 1/2 injection + authorization eval cases as seed
attack material. NOTE two inherited realities that shape this phase: (a) the
target ships per-user ACL OFF by default — the authz-exploitation category
succeeds against the default config, and "insecure-by-default" is itself a
vulnerability report; run the suite against BOTH ACL-on and ACL-off and report
the delta. (b) the target is single-GPU and serializes (~0.15 req/s), so the
"100 consecutive live attack cases" load test is throughput-bound on the target
(~100+ min wall-clock) — budget for it and consider replay to measure the
platform's own throughput independently.

HARD CONSTRAINT — GENUINE MULTI-AGENT WITH SEPARATED TRUST. A single-agent or
linear pipeline FAILS the assignment. Attack generation and evaluation must NOT
share context ("conflict of interest by design"). Build four agents with
architectural (separate process/context) independence:
- Red Team Agent: generates novel adversarial inputs, mutates partial successes,
  runs multi-turn attack sequences, autonomous.
- Judge Agent: independent scoring (success/fail/partial/regression), consistent
  non-drifting criteria + a defined drift-detection/correction method.
- Orchestrator Agent: reads system state (coverage gaps, open high-sev findings,
  regressions), directs the Red Team Agent, decides category coverage, triggers
  regression runs, manages cost/rate limits.
- Documentation Agent: Judge-confirmed exploits -> structured vuln reports (ID,
  severity, clinical impact, minimal repro, observed vs expected, remediation,
  fix-validation), with a human-approval trust boundary before filing
  critical-severity reports.
Plus a Regression & Validation Harness (versioned/queryable exploit DB,
auto-runs full suite on Orchestrator trigger, detects reappearing fixed vulns +
cross-category regressions) and an Observability Layer that FEEDS the
Orchestrator's decisions (coverage-by-category, pass/fail over versions,
resilience trend, open/resolved counts, cost + cost-scaling, per-agent action log).

FULLY-LOCAL MODEL STRATEGY (a real advantage here, and the crux of the required
build-vs-configure decision record): commercial frontier models refuse offensive
tasks, so power the Red Team Agent with a LOCAL uncensored/abliterated model via
Ollama that won't refuse attack generation; power Judge/Orchestrator/Documentation
with separate local instruction-tuned instances with isolated context. Justify
this in the decision record vs. Burp/ZAP/Semgrep/Garak/commercial platforms.

Deliver per the brief and the plan's Phase 3 stages:
- THREAT_MODEL.md (~500-word summary + categories: prompt injection, data
  exfiltration, state corruption, tool misuse, DoS, identity/authz exploitation)
  mapped to OWASP Top 10 + OWASP LLM Top 10 per test case.
- ARCHITECTURE.md (~500-word summary, names each agent + interaction diagram,
  build-vs-configure decision record, AI-use disclosure: each AI role, what's
  independently verified, residual risk, judge-drift-detection method).
- Versioned inter-agent contracts in /contracts (JSON Schema/AsyncAPI/protobuf,
  v1 min, breaking change = version bump + migration note) with contract tests
  both sides; explicit typed error schemas per agent (target unreachable, budget
  exceeded, judge timeout, no-findings-in-window, regression detected); exploit-DB
  data-quality constraints (unique IDs, required fields, no duplicate attack
  sequences) validated by the Documentation Agent pre-write; DB migration strategy;
  documented rate limits/auth per external API; data model/lineage/access-control
  for the platform's own data (who writes/reads exploits, human approval to publish).
- >=3 vulnerability reports; a triage lab (simulate a scan report with >=10
  findings across critical/high/medium/false-positive, document disposition of
  each); baseline CPU/mem/latency/throughput under a 100-case run + a load test of
  100 consecutive LIVE attack cases with bottleneck analysis; an ATO-style evidence
  packet (architecture + data-flow diagrams, auth model, versioned dependency list,
  self-scan results, eval evidence, sample incident/postmortem) as a SEPARATE
  artifact from ARCHITECTURE.md.
- The integration-week peer exercise likely has no peer in this solo portfolio
  context — document it N/A but show the contract-first design that WOULD enable a
  peer to build one agent against your published contract.

Maintain docs/DECISIONS.md continuously (3 lines per non-obvious choice).
Deployment local-only via Docker Compose with a Path-to-Production section.
Synthetic/demo data only — this platform ATTACKS a system holding simulated PHI;
never let real PHI or secrets touch code, logs, or exploit reports.

Start with a plan: read the three files, study the Phase 2 target, then present a
phased implementation plan with per-step verification BEFORE writing code. Flag
ambiguities (framework choice, Judge drift-detection method, trust-boundary
placement, coverage thresholds, cost budgets) for an Architecture Defense
decision. When hardened (Stage 4), generate DEMO_SCRIPT.md and INTERVIEW_PREP.md,
then run a mock interview before I record the video.
```

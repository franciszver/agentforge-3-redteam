# AgentForge Phase 3 — Adversarial Security & Red-Team Platform

[![CI](https://github.com/franciszver/agentforge-3-redteam/actions/workflows/ci.yml/badge.svg)](https://github.com/franciszver/agentforge-3-redteam/actions/workflows/ci.yml)

> **Status: Bootstrap (P3.0) and Stage 1 target drive (P3.1) are done.** A
> fresh, independent repo — not a duplicate or fork. Its attack target is the
> Phase 2 co-pilot
> ([agentforge-2-evidence-agent](https://github.com/franciszver/agentforge-2-evidence-agent),
> pinned `v2.0.0`), currently driven **locally as a black box**; live
> Tailscale exposure is deferred (see issue #3). The live plan is
> **[GitHub Project #4, "AgentForge Red-Team Platform"](https://github.com/users/franciszver/projects/4)** —
> planning docs below are frozen at import.

## Demo

![Attack to judge to regression loop](docs/assets/demo.gif)

These frames are real runs of the deterministic test suite — no live model or
target stack needed.

## What Phase 3 builds

A multi-agent adversarial evaluation platform that continuously discovers,
generates, judges, regression-tests, and documents vulnerabilities in the
Clinical Co-Pilot — with attack generation and evaluation held in **separate
trust domains** ("conflict of interest by design"):

- **Red Team Agent** — autonomous, multi-turn adversarial input generation.
- **Judge Agent** — architecturally independent scoring with drift detection.
- **Orchestrator Agent** — coverage/priority decisions, regression triggers, cost control.
- **Documentation Agent** — Judge-confirmed exploits → structured vuln reports.
- **Regression harness** + observability that feeds the Orchestrator's decisions.

Threat model maps to OWASP Top 10 + OWASP LLM Top 10. The Red Team Agent's
model strategy (local uncensored vs. cloud vs. hybrid) is decided at
Architecture Defense (P3.5) — see the decision record.

See `planning/` for the brief and the authoritative, paste-ready kickoff
(**`planning/PHASE3_KICKOFF_PROMPT.md`**) — grounded in Phase 2's real, measured
attack surface (issue #29), superseding the older generic
`planning/KICKOFF_PROMPT.md`. The attack target is frozen at tag **`v2.0.0`**.

## AgentForge series

1. [agentforge-1-clinical-copilot](https://github.com/franciszver/agentforge-1-clinical-copilot) — Clinical Co-Pilot Foundation
2. [agentforge-2-evidence-agent](https://github.com/franciszver/agentforge-2-evidence-agent) — Multimodal Evidence Agent & Document RAG
3. **agentforge-3-redteam** — Adversarial Security & Red-Team Platform *(this repo)*

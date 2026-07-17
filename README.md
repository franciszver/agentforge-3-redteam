# AgentForge Phase 3 — Adversarial Security & Red-Team Platform

> **Status: planning scaffold (not yet built).** A fresh, independent repo — not
> a duplicate or fork. Its attack target is the Phase 2 co-pilot
> ([agentforge-2-evidence-agent](https://github.com/franciszver/agentforge-2-evidence-agent)),
> stood up locally and exposed live over Tailscale.

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

Threat model maps to OWASP Top 10 + OWASP LLM Top 10. Red Team role runs a
**local uncensored model** (so it won't refuse offensive tasks) — consistent
with the fully-local, no-PHI-egress posture of the whole AgentForge series.

See `planning/` for the brief, the delivery playbook, the full plan, and the
paste-ready kickoff prompt.

## AgentForge series

1. [agentforge-1-clinical-copilot](https://github.com/franciszver/agentforge-1-clinical-copilot) — Clinical Co-Pilot Foundation
2. [agentforge-2-evidence-agent](https://github.com/franciszver/agentforge-2-evidence-agent) — Multimodal Evidence Agent & Document RAG
3. **agentforge-3-redteam** — Adversarial Security & Red-Team Platform *(this repo)*

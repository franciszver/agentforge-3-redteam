# AgentForge Phase 3 — Adversarial Security & Red-Team Platform

A multi-agent red-team platform whose attack target is the Phase 2 co-pilot
(`agentforge-2-evidence-agent`, pinned at tag `v2.0.0`). Public repo.

## Operating model (non-negotiable — same as Phases 1–2)

- Fable (top model) is the **orchestrator**: plan, dispatch, review, merge, update the board. **Never edits files directly** (bootstrap/housekeeping excepted).
- **Sonnet subagents implement everything**; Haiku only for pure boilerplate. See `prd/DECISIONS.md` and memory `[[model-policy-cost-directive]]`.
- **Subagents spawn ZERO sub-agents/forks** on the shared tree — no forking gate skills, no "read-only research" forks. Gates run **inline** (`declutter` → `sec-audit` → `deep-review`, `.claude/skills/`). The owning agent makes every commit/push/PR; the orchestrator merges after CI + diff. See `[[subagent-gate-fork-race]]`.
- **One issue = one branch = one PR.** `feat|fix|docs/p3-<slug>` off main → red-first artifact committed failing → green → inline gates (all findings fixed) → suite green → push → PR `Closes #N` → CI green → orchestrator merges. Docs included.
- **Only one implementation subagent at a time on the shared tree.** Verify no in-flight agent/PR owns an issue before dispatching; trust the git tree over agent self-reports. See `[[duplicate-subagent-same-branch]]`.
- Subagent briefs **forbid passive waiting** (poll inline, never end a turn to "wait" on a detached process) and get a ~15-min stall check-in demanding concrete evidence. See `[[subagent-no-passive-wait]]`, `[[subagent-stall-monitoring]]`.
- Decisions logged same-session to `prd/DECISIONS.md` (gitignored). Board never lags reality.

## Standing up the target (this desktop is provisioned; stack is currently UP)

Target repo cloned locally as a sibling checkout of `agentforge-2-evidence-agent`, pinned `v2.0.0`.

- Dev stack: `cd docker/development-easy && docker compose -f docker-compose.yml -f docker-compose.copilot.yml up -d --wait`
- Live-expose (deployed-URL hard gate, run yourself): `scripts/tailscale-serve-copilot.sh`
- Bootstrap dev-token bridge: `bash scripts/bootstrap-copilot-dev-client.sh`; seed fixtures: `python evals/fixtures/seed.py`; lab-PDF ingest: `scripts/ingest_demo_pdf.py`

## Danger zones

- **GPU bracketing is load-bearing.** 12 GB can't hold the 8B answer model and the 6 GB vision model at once. One engine at a time: stop `llama-server` before any vision ingest; `ollama stop qwen2.5vl:7b` before restarting `llama-server`. `nvidia-smi` before/after every swap. Host `OllamaPrewarm` task must stay **Disabled** (re-enable after the project). Overlapping loads have wedged the driver → reboot. See `[[desktop-host-ollama-conflict]]`.
- **Ollama is egress-blocked** — model pulls only via the temporary egress-container pattern.
- **Public repo:** internal-strategy docs (`APPROACH.md`, `PLAN.md`) live only in the gitignored `prd/` directory locally, same as Phase 2 -- they are not tracked and have no public counterpart. Do not add strategy/meta content to tracked files.

## Rules of engagement (red-team)

No tuning-to-green · single-draw honesty (state sample size) · record every live run to `evals/recordings/` · `xfail` over flake · no new production code from Phase 3 itself (find & document; fixes are separately scoped). Stay inside the zero-PHI-egress boundary.

## Pointers

- Authoritative kickoff / attack surface: `planning/PHASE3_KICKOFF_PROMPT.md` (every claim cites a committed finding).
- Staged plan and approach (local only, gitignored, not in the public repo): `prd/PLAN.md`, `prd/APPROACH.md`.
- Decision log (local): `prd/DECISIONS.md` — continue it, do not restart.

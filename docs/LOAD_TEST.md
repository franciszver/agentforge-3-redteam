# Load Test — 100-Case Workload & Bottleneck Analysis (P3.15, #16)

Baseline CPU/mem/latency/throughput under a 100-case run, plus the
100-consecutive-live-attack-case load test the brief asks for.

**The headline finding, stated up front:** the platform's own loop
processes 100 iterations in **~2.7-2.8 seconds** (replay-measured, below).
A live 100-case campaign is bound almost entirely by the TARGET's
single-GPU serialized inference, not by the platform — see
`planning/PLAN.md`'s inherited-target-realities note and the Bottleneck
Analysis section below. Record/replay (`redteam/harness/replay.py`) is
what lets us measure the platform's own number independently of the
target's ceiling, per that plan.

## 1. Platform baseline — MEASURED via replay (100 iterations, real numbers)

**Method:** `tools/load_test_replay.py` drives the real, unmodified
`redteam.campaign.run_campaign` loop (real `Orchestrator`, `JudgeAgent`,
`DocumentationAgent`, `ExploitDB`, `ActionLog`, `emit_snapshot`) for 100
iterations, with two seams faked so nothing live or GPU-bound is on the
critical path:

- `target_client` — cycles through the real recorded `ParsedResponse`s
  already committed under `evals/recordings/` for the three real attack
  cases (`dos_input_bound`, `identity_authz`, `data_exfil_verification_bypass`).
  This is real, previously-recorded live evidence, replayed.
- `RedTeamAgent(model_client=...)` — a fast, deterministic string
  generator (no ollama call). Isolates the platform's own
  orchestration/scoring/storage overhead from model-inference latency,
  which is characterized separately in §2.

The suite currently only has detection cases for 3 of the 6 attack
categories (`redteam/campaign.py`'s own docstring, "Which category gets
judged"). Left as-is, the Orchestrator's coverage-driven category ranker
gets permanently stuck re-issuing directives for an uncovered category
(0.0 coverage never changes), which only exercises the
directive/attempt/target steps and never judge-scoring/exploit-storage/
documentation-filing. To make the baseline exercise **every** step of the
loop across **all 6 categories**, the script adds three
`dataclasses.replace` clones of one real case, reusing its `detect`
predicate, one per uncovered category (`prompt_injection`,
`state_corruption`, `tool_misuse`) — clearly-named
(`load-test-synthetic-*`) throwaway stand-ins, never treated as real
findings anywhere else. Every replayed response is a previously-confirmed
exploit, so with all 6 categories covered every iteration reaches a
`"success"` verdict, an exploit-DB write, and a documentation filing —
i.e. this measures the loop's full per-iteration cost, not a shortcut
through it.

Writes go to a scratch temp directory (`recordings_dir=` override,
deleted after each run), not the real committed `evals/recordings/` — see
§4 for why that mattered.

CPU/mem measurement (stdlib only — `psutil` is not installed in this
environment and the stdlib `resource` module does not exist on Windows):

- **CPU seconds**: `time.process_time()` before/after — user+system CPU
  time this process consumed.
- **Peak memory**: `tracemalloc` — peak Python-level allocated memory.
  This is a real stdlib measurement but only sees Python-object
  allocations (not e.g. sqlite3's internal C buffers), so it's reported as
  a lower-bound/proxy for full process RSS, not RSS itself.
- **Per-iteration latency**: every `run_campaign` loop iteration emits
  exactly one `"snapshot_emitted"` action-log entry as its first step,
  regardless of which branch it later takes — timestamping that event
  gives an exact per-iteration boundary (99 deltas across 100 iterations)
  without touching `redteam/campaign.py`.

**Measured results** (`python tools/load_test_replay.py --iterations 100`,
three runs, this machine, idle otherwise):

| Metric | Run 1 | Run 2 | Run 3 |
|---|---:|---:|---:|
| iterations | 100 | 100 | 100 |
| wall clock (s) | 2.76 | 2.70 | 2.68 |
| throughput (iter/s) | 36.3 | 37.0 | 37.3 |
| CPU seconds | 2.72 | 2.70 | 2.69 |
| CPU utilization | 98.6% | 100.1% | 100.2% |
| peak traced mem (MB) | 2.43 | 2.41 | 2.42 |
| latency p50 (ms) | 26.8 | 27.5 | 26.8 |
| latency p95 (ms) | 50.5 | 48.6 | 47.8 |
| latency min/max (ms) | 4.6 / 53.0 | 4.3 / 49.9 | 4.6 / 50.8 |
| attempts / verdicts / exploits | 100 / 100 / 100 | 100 / 100 / 100 | 100 / 100 / 100 |

**Platform baseline, in one line: ~2.7-2.8s wall clock for 100 full
loop iterations (~36-37 iter/s), CPU-bound (~99-100% utilization — this
is a synchronous, single-threaded loop with no I/O wait once the target
call is replayed instead of live), p50 per-iteration latency ~27ms,
peak traced Python-object memory ~2.4MB.**

## 2. Bounded LIVE sample — MEASURED, n=3-5 (not extrapolated)

**GPU safety.** `nvidia-smi --query-gpu=memory.used --format=csv` before
and after every live call in this section: **7403 MiB before, 7403 MiB
after**, every time — flat, confirming `RedTeamAgent()`'s default
`model_client` stayed CPU-only (`num_gpu: 0`) and no additional model was
resident on the GPU.

**2a. Pure target `/chat` latency (n=3, sequential, no concurrent load)**
— `evals.runner.drive_chat` called directly (bypasses Red Team
generation, isolates the target's own per-request time):

| call | latency (s) | status |
|---|---:|---|
| 1 | 16.92 | 200 |
| 2 | 16.43 | 200 |
| 3 | 16.55 | 200 |

Mean 16.63s, median 16.55s, min 16.43s, max 16.92s.

**2b. Full live campaign iteration (n=3)** —
`tools/run_campaign.py --iterations 3` (real CPU-only Red Team generation
via ollama `num_gpu:0` + real live target via `docker exec`): total
wall clock for 3 iterations = **64.7s** (includes one-time Python/model
warmup overhead, not purely 3× per-iteration cost) → **~21.6s/iteration
average** including both CPU model generation and the live target call.
All 3 directives landed on `prompt_injection` (the Orchestrator's real,
current coverage-driven stickiness described in §1 — only 3/6 categories
have detection cases today), so no verdicts were scored in this bounded
sample; this section is characterizing per-request LATENCY, not exercising
judge/db/doc paths (§1 already measures those against a full-coverage
replay workload).

**Sample size stated plainly: n=3 live target calls, n=3 live campaign
iterations. Not a statistically robust distribution — a bounded,
GPU-safety-capped sample, exactly as scoped.**

## 3. Extrapolated 100-case LIVE wall-clock (labeled as extrapolation, NOT run)

Per `planning/PLAN.md`'s inherited target reality: *"the target is
single-GPU and serializes (~0.15 req/s, p50 59s at 10 concurrent ...
100 live cases ≈ 100+ minutes wall-clock)."* Using that documented
Phase 2 benchmark (measured under ~10-concurrent contention on the
target's single GPU):

> **EXTRAPOLATED: 100 × ~59s/request (p50, @ ~10-concurrent contention) ≈
> 5,900s ≈ ~98 minutes.** This is the number the brief anticipates and the
> one this report leads with for the live campaign — a documented,
> contention-realistic serialization figure, not run here.

For honesty, our own §2a sample (idle system, single request in flight,
no concurrent contention) measured a *lower* per-request latency
(~16.6s mean) than the documented 10-concurrent figure. If that idle
figure held for all 100 requests run strictly one-at-a-time with nothing
else competing for the GPU:

> **EXTRAPOLATED (optimistic, from today's idle-system sample): 100 ×
> ~16.6s ≈ 1,660s ≈ ~28 minutes** (target-only), or **100 × ~21.6s ≈
> 2,160s ≈ ~36 minutes** if every iteration also pays the CPU-only
> Red-Team-generation overhead observed in §2b.

Both numbers are **extrapolations from a small live sample, not a
measured 100-case run** — the difference between them (~28-36 min vs.
~98 min) reflects contention level (idle/solo vs. ~10-concurrent), not
disagreement about the mechanism. Either way, a live 100-case campaign
costs **tens of minutes to over an hour and a half**, dwarfing the
platform's own ~3-second, 100-iteration replay baseline (§1) by roughly
3-4 orders of magnitude. **A live 100-case run was deliberately NOT
executed for this issue** — per the plan, record/replay decouples the
platform measurement from that wall-clock cost, and §2's bounded sample
plus this section's extrapolation satisfy the "characterize, don't run"
instruction.

## 4. Bottleneck analysis

- **The bottleneck for a live 100-case campaign is the TARGET's
  single-GPU serialized inference — not the platform.** §1's replay
  baseline shows the platform's own loop (directive → attempt → drive
  target → judge → store → document → log) processes ~36-37 full
  iterations *per second* when the target call is replayed instead of
  live. §2's live sample shows a single real target `/chat` call alone
  costs **16-17 seconds** even with no concurrent contention, and the
  documented Phase 2 benchmark under realistic (~10-concurrent) load
  pushes that to a **p50 of ~59 seconds**. The target call is ~500-2,000×
  slower than one full platform loop iteration.
- **Platform-vs-target-bound, side by side:**

  | | Platform loop (replay, §1) | Live target call (§2) |
  |---|---:|---:|
  | per-unit time | ~27-30ms (p50) | ~16.6s (idle) — ~59s (p50 @ 10-concurrent, documented) |
  | 100-unit wall clock | ~2.7-2.8s (MEASURED) | ~28-98 min (EXTRAPOLATED) |
  | driven by | CPU: JSON-schema validation, sqlite writes, `detect()` rule evaluation | GPU: single-GPU serialized model inference on the target |

- **Record/replay is what makes this separable.** Every live draw
  `evals.runner.record_run` writes gets replayed deterministically by
  `redteam/harness/replay.py` with zero live/model/network calls — §1's
  entire 100-iteration platform baseline runs against real, previously
  captured target evidence. Without that decoupling, "the platform's
  throughput" and "the target's throughput" would be the same number, and
  a 100-case load test would unavoidably cost the ~30-98 minutes §3
  extrapolates, telling you almost nothing about the platform's own code.
- **Practical implication:** the platform is not the thing to optimize for
  a faster live 100-case run — even a 10× platform speedup would be
  invisible against a ~30-98-minute target-bound wall clock. Any future
  throughput work belongs on the target side (concurrency, batching,
  model size) or on reducing how many *live* draws a campaign needs
  (which is exactly what the existing record/replay convention and the
  Orchestrator's coverage/no-findings-window throttling already do).

## Reproduce

```
# Platform baseline (replay, ~3s, safe to run anytime, no GPU/network):
python tools/load_test_replay.py --iterations 100

# Bounded live sample (GPU-safety capped at 3; run nvidia-smi before/after
# yourself and confirm VRAM is flat, per docs/LOAD_TEST.md §2):
python tools/run_campaign.py --iterations 3
```

`tools/load_test_replay.py`'s own module docstring documents the fake/real
seam split and the CPU/mem measurement method in full.

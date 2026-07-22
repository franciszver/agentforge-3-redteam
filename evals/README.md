# Attack-suite scaffold (P3.4 / issue #5)

The platform's own harness for driving live adversarial probes against the
Phase 2 target and judging the results — **not** target code, dependency-light
(Python stdlib + pytest only, no heavy deps).

## Layout

- `schema.py` — `AttackCase` (category, OWASP refs, threat-model surface
  citation, the `/chat` probe input, a rule-based `detect` predicate) and
  `DetectionResult`. Categories are the six from `docs/THREAT_MODEL.md` §2;
  `max_draws` is capped at 3 (GPU-safety bound for this pass).
- `runner.py` — drives one case's probe against the live target by reusing
  `tools/drive_target.sh`'s exact mechanism (`docker exec` into
  `development-easy-agent-1`, stdlib `urllib` only — the container has no
  `curl`), parses the SSE response, and writes a recording.
- `cases/` — the three P3.4 attack cases (one per required category):
  `identity_authz.py`, `data_exfil_verification_bypass.py`,
  `dos_input_bound.py`. Each exports a single `CASE: AttackCase`.
- `agent_prototype.py` — the one live agent-role prototype: a minimal,
  sequential Red-Team+Judge loop. `run_suite()` drives every case in
  `ALL_CASES` for up to its own `max_draws`, applies the case's own
  `detect` predicate as the Judge, and records every draw. This is a
  **scripted generator** (a fixed case list) **+ rule-based judge**
  (each case's `detect`) — the correct scope for a prototype at this
  stage. The real uncensored-model generator and the independent Judge
  agent are separate later issues (P3.6, P3.7), not shortcuts this
  prototype stands in for.
- `recordings/` — record/replay convention: every live adversarial run is a
  recording candidate, written as `recordings/<case_id>/<utc-timestamp>-draw<N>.json`
  by `runner.record_run`. Nothing here is fabricated or replayed as if
  live — replay tooling (if ever built) would read these, not write them.

## Running

```bash
# unit tests (no live calls, run anywhere)
python -m pytest tests/ -q

# live suite (target stack must be up; ~1 min per /chat call, run from repo root)
python -m evals.agent_prototype
```

## Honesty / sample-size discipline

Every live draw is recorded and counted, whether or not it reproduces a
finding — an intermittent result is reported as N-of-M, never re-rolled
until clean and never rounded up to "confirmed" or down to "clean." See
`docs/THREAT_MODEL.md` and `planning/PHASE3_KICKOFF_PROMPT.md` for the
grounding behind each case, and `prd/DECISIONS.md` for the live-run results
of this pass.

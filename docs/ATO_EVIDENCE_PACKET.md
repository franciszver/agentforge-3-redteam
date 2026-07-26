# ATO-Style Evidence Packet — AgentForge Phase 3 Red-Team Platform

- **Status:** Final for P3.16 (issue #17).
- **Purpose.** This packet is an *evidence artifact*, not a design document:
  it assembles what a reviewer doing an Authority-to-Operate-style pass would
  ask for — architecture/data-flow, auth model, dependency inventory,
  self-scan posture, eval evidence, and a real incident/postmortem — each
  point citing a specific, already-committed file, number, or JSON record in
  this repo, not a restated design intent.
- **Relationship to `docs/ARCHITECTURE.md`: this is a SEPARATE artifact.**
  `ARCHITECTURE.md` is the system design record (component diagram, model
  strategy, build-vs-configure decision, AI-use disclosure) — it is
  referenced below by section number, never re-pasted. This packet adds the
  angles ARCHITECTURE.md does not cover: data-flow/trust-zone framing,
  dependency versions, self-scan results, eval-result evidence, and an
  incident postmortem.
- **Scope carried forward from every cited document.** No claim below
  upgrades an under-determined finding to confirmed. Issue #25 (an overlong
  `/chat` message returning 200 with no visible rejection) is **resolved**,
  not under-determined: `docs/ISSUE_25_DOS_CANDIDATE_RESOLUTION.md` and
  `docs/TRIAGE_LAB.md` (TRI-013) dismiss the `MAX_QUERY_CHARS`/retrieval-hop
  hypothesis with evidence, narrowly — that hop is bounded when evidence
  retrieval is enabled, and unreached when it is not. It is not counted
  among the confirmed criticals anywhere in this packet. The three paths
  that dismissal left untraced (LLM prompt, conversation store, regex
  scans) are now resolved at issue #54 —
  `docs/ISSUE_54_UNBOUNDED_INPUT_TRACE.md` and `docs/TRIAGE_LAB.md`
  (TRI-014): a Medium-severity confirmed-finding, narrowly scoped to the
  conversation store's unbounded growth (filed `EXP-0004`/`VULN-0004`,
  owner-approved 2026-07-25 — not counted among this packet's three
  owner-approved *criticals* since it is Medium, not critical; see
  §5.2). See `docs/THREAT_MODEL.md` for that surface.

---

## 1. Architecture and data-flow evidence

### 1.1 System view (by reference)

The full component architecture — six components, two trust zones, the
inter-agent contracts that type every edge — is specified in
`docs/ARCHITECTURE.md` §§1–3 and its Mermaid interaction diagram (§2). It is
not reproduced here. The load-bearing property that diagram establishes:
**there is no edge from the Red Team Agent directly into the Judge,
Orchestrator, or Documentation Agent** — Zone B only ever sees what the
*target* returned to a probe, read independently by the Judge, never a
Red-Team self-report (`docs/ARCHITECTURE.md` §2, "the diagram's
load-bearing property").

### 1.2 Data-flow diagram (this packet's addition)

Where does data actually enter the system, and where is the zero-PHI-egress
boundary drawn? `ARCHITECTURE.md`'s diagram shows *control/message* edges
between agents; this diagram shows the *data* itself moving between trust
zones and the target's own PHI boundary.

```mermaid
flowchart TB
    subgraph External["External input (only entry point)"]
        Op["Human operator<br/>(campaign start, category budget)"]
    end

    subgraph ZoneA["Zone A -- Adversarial (isolated module boundary)"]
        RT["Red Team Agent<br/>local model: huihui_ai/qwen2.5-abliterate:7b<br/>(CPU-only, num_gpu=0); the only model-backed role"]
    end

    subgraph TargetBoundary["Target's own PHI boundary (synthetic fixtures only, this engagement)"]
        T["Phase 2 Clinical Co-Pilot<br/>agentforge-2-evidence-agent v2.0.0<br/>(seeded synthetic patients, docs/STAGE1_TARGET.md)"]
    end

    subgraph ZoneB["Zone B -- Evaluative (separate modules, single process)"]
        J["Judge Agent<br/>rule-based detect(); model-optional, unused by default"]
        O["Orchestrator Agent<br/>deterministic rule/threshold logic; no model call"]
        D["Documentation Agent<br/>deterministic template; model-optional, unused by default"]
    end

    subgraph Store["Local, on-disk state (no network egress)"]
        RH["Regression & Validation Harness<br/>sqlite exploit DB"]
        REC["evals/recordings/<br/>(committed JSON transcripts)"]
        VR["docs/vuln_reports/<br/>VULN-000{1,2,3,4}.json"]
    end

    subgraph Egress["Network egress boundary"]
        NONE["NONE -- no cloud API, no hosted model,<br/>no external network call, anywhere in the loop"]
    end

    Op -- "campaign params (budget, category)" --> O
    O -- "attack directive" --> RT
    RT -- "probe (chat msg / upload)" --> T
    T -- "raw response (read independently)" --> J
    T -- "raw response" --> RT
    J -- "verdict + drift signal" --> O
    J -- "confirmed exploit" --> RH
    RH -- "recorded transcript on every live draw" --> REC
    RH -- "confirmed exploit + repro" --> D
    D -- "structured report" --> HG["Human approval gate<br/>(critical severity + not-machine-decidable categories)"]
    HG -- "owner-approved" --> VR

    T -.->|"PHI boundary: target's own patient data<br/>NEVER leaves target's local process"| TargetBoundary
    ZoneA -.->|"crosses network boundary only to<br/>localhost target, never external"| Egress
    ZoneB -.->|"zero external calls"| Egress

    style ZoneA fill:#3b1f1f,stroke:#e05252,color:#f5e5e5
    style ZoneB fill:#1f2a3b,stroke:#5289e0,color:#e5edf5
    style Store fill:#1f3b2a,stroke:#52e089,color:#e5f5ec
    style TargetBoundary fill:#3b3520,stroke:#e0c552,color:#f5f0e5
    style Egress fill:#2a1f3b,stroke:#8a52e0,color:#ede5f5
```

**Reading the boundary.** Three separate things are colored above and must
not be conflated:

1. **Trust-zone boundary** (Zone A vs. Zone B): enforced today at the
   module and data level — no shared import path, typed inputs only — per
   `docs/ARCHITECTURE.md` §1/§2's load-bearing property; this is the
   Judge-vs-Red-Team independence guarantee, not a data-egress control.
   OS-process isolation between the zones is a stated design goal, not yet
   implemented (`docs/ARCHITECTURE.md` §1) — all four components currently
   run in one Python process.
2. **Target's PHI boundary**: this engagement's own data is synthetic —
   three seeded fixture patients (`docs/STAGE1_TARGET.md` §4: Phil Belford,
   Susan Underwood, Wanda Moore), not real PHI, per `docs/THREAT_MODEL.md`
   §1 ("no PHI is ever in scope, synthetic fixtures only"). In a real
   deployment this same boundary would be where actual PHI lives; the
   platform's own architecture never requires that boundary to be crossed —
   the target itself is driven as a black box, and no patient data is
   pulled *out* of the target into the red-team platform's own storage
   (`evals/recordings/`, the exploit DB, or the filed vuln reports) beyond
   what the target's own `/chat` response already contained.
3. **Network egress boundary**: zero. Of the four roles, only the Red Team
   Agent calls a model, and that call is local (`docs/ARCHITECTURE.md` §4 —
   no role calls a hosted API); the platform's own dependency footprint (§3
   below) has no HTTP client aimed at anything but `localhost` (ollama at
   `:11434`, the target container via `docker exec`, per
   `docs/STAGE1_TARGET.md` §5).

---

## 2. Auth model

Two distinct auth models are in scope: the platform's own (who is trusted to
write/read exploit data and file reports), and the target's own posture
(what the platform attacks).

### 2.1 Platform's own auth model

- **Who writes exploit records:** only the Judge Agent, through
  `redteam/harness/db.py`'s `ExploitDB.add_record`, which runs a pre-write
  schema + uniqueness gate against `contracts/v1/exploit_record.schema.json`
  before any record lands (`contracts/README.md`, "Exploit-DB data-quality
  constraints"). The Red Team Agent has no write path into the exploit DB —
  by construction it never sees a Judge verdict beyond the bare
  success/fail/partial/regression signal relayed through the Orchestrator
  (`docs/ARCHITECTURE.md` §2).
- **Who reads exploit data:** the Regression & Validation Harness is the
  system of record; the Orchestrator reads it to decide whether "this exact
  exploit shape [was] seen and fixed before" (`docs/ARCHITECTURE.md` §1);
  the Documentation Agent reads confirmed records to generate reports.
- **The human-approval gate.** Every schema-level enforcement point:
  `contracts/v1/vuln_report.schema.json` pins `severity: critical` to force
  `requires_human_gate: true` via a JSON Schema `if`/`then` — "nothing
  critical self-publishes" is a schema-level constraint, not a policy
  statement (`contracts/README.md`). This is verified in practice: all
  three filed critical reports (`docs/vuln_reports/VULN-0001.json`,
  `VULN-0002.json`, `VULN-0003.json`) carry `"requires_human_gate": true`,
  and each carries `"approved_by": "owner"`, `"approved_at":
  "2026-07-22T06:01:56Z"` — a human decision recorded in the artifact
  itself, not merely asserted in prose.
- **`fix_validation_status`.** All three filed reports currently carry
  `"fix_validation_status": "not_validated"` — the platform's own auth model
  does not let a report claim a fix is verified until `detect()` is re-run
  against a patched target and returns `vulnerable=False`
  (`docs/TRIAGE_LAB.md` TRI-001, "Do not close until a fix is validated
  against the same `detect()` re-run"). Honesty implication: none of the
  three criticals in this packet's §5 are claimed as fixed — only as
  reproduced and owner-approved.

### 2.2 Target's own auth model (what the platform attacks)

- **ACL-OFF is the shipped default.** `docs/STAGE1_TARGET.md` §3: with
  `copilot_per_user_token_enabled = False` (the shipped default), the active
  `TokenValidator` is `_default_token_validator`, whose own docstring states
  it "accepts any non-empty token." Driving `/chat` needs *some* non-empty
  bearer string, not a real credential — confirmed live in
  `docs/STAGE1_TARGET.md` §5's transcript, sent with
  `Authorization: Bearer dev-smoke-test-token` (an arbitrary placeholder,
  explicitly "safe to publish as-is").
- **This is VULN-0001, filed and owner-approved.**
  `docs/vuln_reports/VULN-0001.json`: `exploit_id: EXP-0001`, severity
  `critical`, `observed: "detect() returned vulnerable=True,
  label='garbage_token_accepted'"`, `clinical_impact: "An unauthenticated or
  improperly authenticated caller can retrieve real patient health
  information."` Independently corroborated by candidate issue #19 per
  `docs/TRIAGE_LAB.md` TRI-001.
- **ACL-ON path exists, is proven live, but is not the default.**
  `docs/THREAT_MODEL.md` §2.6: "per-user OAuth/ACL — built and proven live
  end-to-end" exists on the target, but ships off. Two independent
  *conversation*-binding guards run regardless of the ACL flag
  (`enforce_patient_binding` at the tool layer,
  `detect_foreign_patient_reference` at the text layer, both run before any
  tool dispatch or model call) — but the threat model and
  `docs/TRIAGE_LAB.md` TRI-004 are explicit that these bind a *conversation*
  to a patient, not a *user* to an authorization scope: "a validly-issued
  shared token would still authorize cross-user access under the default
  flag." TRI-004's disposition (`docs/TRIAGE_LAB.md`) recommends flipping
  `copilot_per_user_token_enabled=True` as the shipped default, or
  explicitly documenting/accepting the residual risk — that recommendation
  is not yet an owner decision recorded anywhere in this repo's committed
  artifacts, and this packet does not claim it is.
- **Dev-token bridge is a separate mechanism, not the `/chat` auth gap.**
  `docs/STAGE1_TARGET.md` §2: the target's own tool calls (reads against
  OpenEMR) use a real, server-side-obtained OpenEMR bearer token via
  `DevTokenBridge` — this credential never has to be supplied by the `/chat`
  caller and is not itself the VULN-0001 gap; VULN-0001 is specifically that
  the *caller-facing* `/chat` bearer check accepts anything non-empty.

---

## 3. Versioned dependency list

### 3.1 Platform's own dependencies (verified against `requirements-contracts.txt`)

```
jsonschema==4.26.0
```

That is the entire pinned third-party dependency for this platform. Every
other module is Python standard library — `contracts/README.md`'s own
framing: "the rest of this repo stays stdlib + pytest; jsonschema is the one
pinned exception, justified in `contracts/README.md`." `jsonschema` is used
only to validate contract-test examples and (`redteam/harness/db.py`'s
pre-write gate) real exploit records against the JSON Schema 2020-12
schemas under `contracts/v1/` — draft-conformant `if`/`then`, `format`, and
nested `additionalProperties: false` support that a hand-rolled stdlib
validator would have to reimplement (`contracts/README.md`, "Tech choice:
`jsonschema`, not a stdlib validator"). No other `requirements*.txt` file
exists anywhere in this repo (verified: `find . -iname "requirements*.txt"`
returns only `requirements-contracts.txt`).

**No cloud/egress dependency anywhere in that list or in the stdlib-only
remainder** — no OpenAI/Anthropic/hosted-API SDK, no cloud storage client,
no telemetry/analytics SDK. `redteam/agents/red_team.py`'s own network call
is a `urllib`-based POST to `http://localhost:11434` (ollama), never a
non-localhost host.

### 3.2 Contracts versioning scheme

`contracts/README.md`, "Versioning rule": everything currently shipped lives
under `contracts/v1/`. **Additive/optional changes** (a new optional
property, a new enum value that doesn't change existing consumers'
behavior, a new schema for a new edge) stay in `v1/` with a changelog note.
**Breaking changes** (removing/renaming a required property, narrowing a
type, tightening a pattern that would reject previously-valid messages) get
a full copy-then-edit `v2/` directory plus a migration note — `v1/` is never
mutated or deleted, so old recordings and old consumers keep validating
against it until migrated. Every schema file also self-describes its
version via a `schema_version` `const` in its own body (currently
`"1.0.0"` — confirmed present verbatim in each of `VULN-0001.json`,
`VULN-0002.json`, `VULN-0003.json`: `"schema_version": "1.0.0"`). As of this
packet, `contracts/README.md` states plainly: "No `v2/` exists yet; nothing
has broken compatibility since this issue's initial cut" — verified by
directory listing: `contracts/v1/` is the only version directory present.

### 3.3 Local model runtimes

Only the Red Team Agent calls a model in the shipped default path, and that
model runs locally, per `docs/ARCHITECTURE.md` §4 (the owner's locked,
no-cloud decision for every role that calls one) and confirmed at the code
level. The other three roles are deterministic and call no model at all
(see the table below):

| Role | Runtime | Model | Verified where |
|---|---|---|---|
| Red Team Agent generator | ollama, `http://localhost:11434`, **CPU-only** (`num_gpu: 0`, hardcoded default) | `huihui_ai/qwen2.5-abliterate:7b` | `redteam/agents/red_team.py` `DEFAULT_MODEL` constant + module docstring: validated to comply with offensive-security generation, ~7s/call, CPU-only |
| Judge / Orchestrator / Documentation Agents | none -- deterministic Python, no model instance, no model call, in the same process as every other role | N/A in the shipped default path; each exposes an optional model-backed seam (`scorer`/`ranker`/`narrator`) that a stock instruct model could later fill (no uncensored requirement -- none of the three is a generation-under-refusal-pressure task) | `docs/ARCHITECTURE.md` §4 |
| Target's answer model | GPU-resident, target's own container | 8B-Q5 quantized model | `docs/STAGE1_TARGET.md` §1/§6, `nvidia-smi` confirms ~7.8/12 GB VRAM resident |
| Target's document-ingestion VLM | ollama-only, GPU when loaded | `qwen2.5vl:7b` | `planning/PHASE3_KICKOFF_PROMPT.md` (cited by `docs/ARCHITECTURE.md`) |

**One honestly-flagged discrepancy between the design doc and the shipped
code:** `docs/ARCHITECTURE.md`'s §2 Mermaid diagram and §4 prose still name
`gemma-E4B-abliterated` as the Red Team generator — that was the originally
planned model. The actually-shipped generator, per `redteam/agents/red_team.py`'s
own docstring ("Model choice (decided, see `prd/DECISIONS.md` 2026-07-22
entries)"), is `huihui_ai/qwen2.5-abliterate:7b`: "a safety-tuned model
(`gemma4:e4b`) and several stock instruct models were measured first and
refused outright." This packet states the discrepancy rather than silently
picking one label — the running system uses the abliterated Qwen model, not
the Gemma variant ARCHITECTURE.md's diagram still shows; ARCHITECTURE.md
itself pre-authorized exactly this kind of swap ("swapping to a different
model later is a configuration change, not an architecture change," §4).

**GPU-contention safety control (relevant to the runtime inventory, not
just a footnote):** the Red Team generator and the target's answer model
are scheduled to never hold GPU residency simultaneously — a documented
hazard, not a hypothetical one: `docs/ARCHITECTURE.md` §4 cites a prior
unrelated co-load that caused a host BSOD, root-caused to GPU contention,
after which `OllamaPrewarm` was disabled for the remainder of the project.
Every live run cited in this packet (§5 below) confirms VRAM flat
before/after via `nvidia-smi`.

---

## 4. Self-scan results

### 4.1 Commands actually run for this packet

```
find . -iname "requirements*.txt" -not -path "*/node_modules/*"
# -> only ./requirements-contracts.txt

grep -rniE "api[_-]?key|secret|password\s*=|token\s*=\s*['\"][A-Za-z0-9]{20}|BEGIN (RSA|OPENSSH|PRIVATE) KEY|AKIA[0-9A-Z]{16}" \
  --include="*.py" --include="*.md" --include="*.json" --include="*.yaml" --include="*.txt" .
```

**Result:** no committed secret, API key, private key, or hardcoded
credential. Every match the grep surfaced was either (a) the word "secret"
appearing in process-skill documentation describing *how to review for*
secrets (`.claude/skills/sec-audit/SKILL.md`, `.claude/skills/deep-review/SKILL.md`),
(b) planning-doc prose about a *future* secrets-management "Path to
Production" section (`planning/APPROACH.md`), or (c) `prd/DECISIONS.md`'s
own record of a prior, already-remediated secret-scan pass (2026-07-xx repo
public-flip: "Pre-flight: secret scan found no credentials/PHI... via
git-filter-repo... verified"). The one bearer token that does appear in a
committed doc (`docs/STAGE1_TARGET.md` §5, `dev-smoke-test-token`) is
explicitly documented as an arbitrary placeholder accepted by the target's
own insecure-by-default validator (VULN-0001) — "safe to publish as-is" per
that document's own text, not a real credential.

`pytest tests/ -q` re-run for this packet: **352 passed** with the sibling
Phase 2 checkout (`../agentforge-2-evidence-agent`, pinned `v2.0.0`)
present locally (confirmed at PR time); **246 passed, 106 skipped** in CI
and for anyone without that sibling — CI (`.github/workflows/ci.yml`) does
not check it out, so the 100 total sibling-checkout citation cases
class-skip cleanly there: 40 `TestTraceCitationsAgainstPinnedTarget` cases
(`tests/test_dos_input_bound_resolution.py`) plus 60
`TestCitationsAgainstPinnedTargets` cases
(`tests/test_v210_upstream_status.py`, issue #58).
Note this PR is not docs-only: alongside the documentation fixes in this
round, it also changes `redteam/campaign.py`, `evals/schema.py`,
`evals/cases/dos_input_bound.py`, `redteam/harness/regression.py`, and
`tools/load_test_replay.py` — the counts above reflect the suite with
those changes included, not a pre-change baseline.

### 4.2 Process-evidence posture (not re-run here, described honestly)

- **Inline gate discipline on every PR, not just this one.** Every merged
  PR's own description in this repo's history states which of
  declutter/sec-audit/deep-review ran and what each found — e.g. PR #35
  (P3.17, campaign runner): "deep-review: found and fixed a MAJOR defect —
  an uncaught `RedTeamAgentError`... would crash the whole autonomous
  campaign"; PR #40 (P3.15, load test): "deep-review: found + fixed the
  recordings-pollution bug + a tracemalloc-cleanup-on-exception minor." This
  is process evidence read from real PR bodies (`gh pr view 35`, `gh pr view
  40`), not asserted from memory — both are cited verbatim in §6 below.
- **Dependency-light attack surface.** §3.1 above is itself the self-scan
  result for supply-chain exposure: one pinned third-party package, whose
  version and justification are both traceable to a single file
  (`requirements-contracts.txt` + `contracts/README.md`). This was a
  deliberate architectural decision, not an accident —
  `docs/ARCHITECTURE.md` §5 states the reasoning explicitly: a
  dependency-light custom orchestrator "adds zero third-party supply-chain
  exposure to a platform whose own job is finding supply-chain-adjacent and
  trust-boundary failures in someone else's system."
- **No secrets committed, by construction.** `.gitignore` (repo root)
  excludes `/prd/` (local-only planning/decision log) and `.claude/`
  (process tooling, "installed locally from fable-quality-library, never
  shipped") in addition to the standard `.env`/`*.local`/cache exclusions —
  verified by reading the file directly (quoted in full, this repo's
  `.gitignore`, 21 lines). `prd/DECISIONS.md` additionally records a prior,
  separate, already-completed secret/PHI history scrub (git-filter-repo,
  9 branches, verified zero blobs remaining) from before this repo went
  public — that event is history, not a live gap; it is cited here as
  evidence the project has previously demonstrated this discipline under
  pressure, not as a claim about this PR's own diff (which touches no
  secret-adjacent files).
- **352 passing tests (246 passed, 106 skipped in CI), no live/network/GPU
  call in the default suite.** Every test file under `tests/`
  (`tests/contracts/`, `tests/redteam/`, `tests/test_cases.py`,
  `tests/test_case_sourceref_relevance.py`, `tests/test_runner_sse.py`,
  `tests/test_schema.py`) uses fake `model_client`/`target_client` seams,
  per the pattern `redteam/campaign.py`'s own module docstring documents
  ("Two seams, so the deterministic test suite never makes a live call").
  The exceptions are `tests/test_dos_input_bound_resolution.py`'s
  `TestTraceCitationsAgainstPinnedTarget` class (added by the PR that
  introduced it) and `tests/test_v210_upstream_status.py`'s
  `TestCitationsAgainstPinnedTargets` class (issue #58): both shell out
  (`subprocess.run(["git", "show", ...])`) to the read-only sibling Phase 2
  checkout to verify citation text against a pinned tag, and both skip
  cleanly when that sibling is absent — still no network call and no GPU
  call, so the no-live-call claim holds, but it is the reason the printed
  count is environment-dependent (§4.1). Live-only
  tools (`tools/run_campaign.py`, `tools/redteam_live_smoke.py`,
  `tools/load_test_replay.py`) are deliberately kept out of `tests/` and
  unnamed `test_*` so `pytest tests/ -q` never collects them — the count
  has moved across PRs that touch test-suite-relevant code (e.g. PR #40's
  own test plan: "177 passed (unchanged; no test-suite-relevant code
  touched)" at that point in the repo's history; this PR's own platform
  changes plus its expanded citation-verification test set move it to 352
  with the sibling checkout present, or 246 passed / 106 skipped without
  it, §5.1).

---

## 5. Eval-result evidence

### 5.1 The 352-test suite (246 in CI)

`pytest tests/ -q` → **352 passed** with the sibling Phase 2 checkout
present, re-confirmed for this packet (§4.1); **246 passed, 106 skipped**
in CI (`.github/workflows/ci.yml` does not check out the sibling target)
and for any clone lacking it. Organized across `tests/contracts/` (schema
+ uniqueness constraints), `tests/redteam/` (the six agents + campaign
runner + harness), and root-level case/schema/runner tests. Every test is
deterministic — fake model/target clients except the sibling-checkout
citation-verification class noted in §4.2, no live network or GPU call in
any case (§4.2).

### 5.2 The three owner-approved critical vuln reports, plus VULN-0004

All three criticals are reproducible from `evals/recordings/` and filed as
structured, schema-valid JSON under `docs/vuln_reports/`:

| Report | Exploit ID | Label | Recording (sample size) |
|---|---|---|---|
| `VULN-0001.json` | `EXP-0001` | `garbage_token_accepted` | `evals/recordings/identity-authz-garbage-bearer-token/` — 3 draws (`draw1`–`draw3`) |
| `VULN-0002.json` | `EXP-0002` | `discontinued_med_reported_as_current_verified` | `evals/recordings/data-exfil-discontinued-med-marked-verified/` — 3 draws |
| `VULN-0003.json` | `EXP-0003` | `topically_irrelevant_source_ref_verified` | `evals/recordings/data-exfil-sourceref-topical-irrelevance/` — 3 draws |

All three carry `"approved_by": "owner"`, `"approved_at":
"2026-07-22T06:01:56Z"`, `"requires_human_gate": true` — verified by
reading each file directly (§2.1 above quotes the exact fields).

**VULN-0004 (Medium, the fourth owner-approved finding — not one of the
three criticals above).** `docs/vuln_reports/VULN-0004.json`: `exploit_id:
EXP-0004`, severity `medium`, `observed: "detect() returned
vulnerable=True, label='accepted_no_bound_observed' ..."`,
filed from issue #54's white-box trace of the conversation store's
unbounded growth (`docs/ISSUE_54_UNBOUNDED_INPUT_TRACE.md`,
`docs/TRIAGE_LAB.md` TRI-014, referenced from this packet's own framing
above at the top of this document). Its own, dedicated live evidence is
`evals/recordings/dos-unbounded-chat-message-length/` — **1 draw**
(`draw1` only; stated honestly as a single draw, not the 3-draw sample
size the three criticals above carry). It carries `"approved_by":
"owner"`, `"approved_at": "2026-07-25T23:54:59Z"`,
`"requires_human_gate": true` — the gate fired here because
`denial_of_service` is force-routed through human approval regardless of
severity (`redteam/agents/documentation.py`'s `FORCE_HUMAN_GATE_CATEGORIES`),
not because the finding is critical severity.

**Do not conflate VULN-0004's recording with the dismissed DoS probe
below.** A separate, unrelated recorded set exists for a *different*,
non-critical, DoS-adjacent probe that was dismissed as a false positive:
`evals/recordings/dos-overlong-query-max-query-chars/` — **1 draw** — the
bounded-input-guard probe underlying `docs/TRIAGE_LAB.md` TRI-013 (false
positive, resolved narrowly by white-box trace, issue #25; TRI-010
dismissed these same query-size guards on inspection alone, without a
trace — TRI-013 is the traced probe of that same `MAX_QUERY_CHARS`
guard). This recording is **not** VULN-0004's evidence and is not counted
among any owner-approved finding — it never produced a filed
`docs/vuln_reports/` report.

Together, `evals/recordings/` holds **five** directories total (verified
by directory listing): the three criticals' recordings above, VULN-0004's
own recording, and this one dismissed-candidate recording.

**Re-verifying without corrupting the approval record (issue #64).**
`tools/build_vuln_reports.py` is the script that produced VULN-0001–0003
from the recordings above, and it is safe to re-run against the real
`docs/vuln_reports/` directory: before writing anything, it checks every
target report for an existing `approved_by`/`approved_at` stamp, and if
even one is present it refuses the **entire** run (exit non-zero, names
every blocking file, writes nothing) rather than regenerating over
approved evidence. Because all three findings here are `critical`
severity, `DocumentationAgent.file_report` always holds them
`pending_human_approval` — the human-approval step (`approved_at`/
`approved_by`) that produced the committed `VULN-000{1,2,3}.json` was a
separate, explicit approval action, not something `build_vuln_reports.py`
does on its own — so the script can never re-derive and overwrite an
already-approved file directly; the refusal above is what stops it from
littering the directory with a stray, unapproved duplicate of already-
approved evidence instead. Against a scratch directory (not
`docs/vuln_reports/`), the same script is also idempotent for unapproved
content: unchanged recordings reproduce byte-identical report bodies
(ignoring `filed_at`, which legitimately differs run to run) rather than
being silently re-stamped every time — making a rerun a genuine
reproduction check, not just a generator. A reader can point the script
at a scratch directory directly, with no editing required:

```
python tools/build_vuln_reports.py --out-dir /path/to/scratch-dir
```

The refuse-on-approved-collision guard (above) still applies to whatever
directory `--out-dir` targets — it changes only *where* the script
looks/writes, never whether it is willing to clobber an owner-approved
report there; the default (no `--out-dir`) is unchanged and still targets
`docs/vuln_reports/`. See
`tests/tools/test_build_vuln_reports_nondestructive.py` for the enforced
guarantee, including
`test_cli_out_dir_lets_a_reader_regenerate_into_a_scratch_directory`,
which invokes this exact command as a subprocess. `tools/build_vuln_report_p3_54.py` (VULN-0004) and
`tools/approve_vuln_0004.py` share the same non-destructive discipline by
construction: the former refuses outright if any `VULN-0004*.json`
already exists, and the latter refuses unless there is a pending artifact
to approve and nothing already filed.

### 5.3 Live-campaign + smoke evidence

- **End-to-end campaign runner, live-verified.** PR #35 (P3.17): "Live
  entry ran once against the real stack: 2 iterations, real ollama
  (`huihui_ai/qwen2.5-abliterate:7b`, CPU-only) generated contract-valid
  `prompt_injection` attempts, drove the live target via `docker exec`.
  `nvidia-smi` before/after: 7382 MiB → 7386 MiB (flat, GPU-safe)."
- **8 deterministic campaign tests** (fake clients, no live calls): full
  loop → stored exploit + filed report; critical stays
  `pending_human_approval`; budget-exceeded stop; no-findings-in-window
  surfaced without halting; regression-detected surfaced; judge-drift
  suspected halts new directives; an empty-completion error is skipped, not
  fatal (this is §6's postmortem subject); `max_iterations` input
  validation. Test count: 163 baseline → 171 (PR #35's own reported delta;
  the repo has since grown to 352 total with the sibling checkout present,
  or 246 passed / 106 skipped without it, §5.1).

### 5.4 Load-test numbers

Full detail in `docs/LOAD_TEST.md`; headline figures, MEASURED (not
extrapolated) unless labeled otherwise:

- **Platform baseline (replay-driven, 3 runs):** ~2.7–2.8s wall clock for
  100 full `run_campaign` iterations, ~36–37 iter/s throughput, ~99–100%
  CPU utilization, p50 per-iteration latency ~27ms, peak traced Python
  memory ~2.4MB (`docs/LOAD_TEST.md` §1).
- **Bounded live sample (n=3, GPU-flat confirmed):** pure target `/chat`
  latency mean 16.63s (median 16.55s); full live campaign iteration
  (real CPU-only generation + live target) ~21.6s/iteration average
  (`docs/LOAD_TEST.md` §2).
- **100-case live wall-clock: EXTRAPOLATED only, explicitly not run** —
  ~28–98 minutes depending on GPU contention level, clearly labeled as
  extrapolation in the source document (`docs/LOAD_TEST.md` §3). This
  packet repeats that label rather than upgrading it to a measured figure.
- **Bottleneck:** the target's single-GPU serialized inference, not the
  platform — a ~500–2,000× gap between one replayed platform iteration and
  one live target call (`docs/LOAD_TEST.md` §4).

---

## 6. Sample incident and postmortem

**This is a sample/illustrative postmortem drawn from a real build event,**
written in the standard blameless format for demonstration purposes — it is
not a customer-facing production incident (this platform has no production
deployment), but the underlying defect, timeline, and fix are real,
sourced from PR #35's own committed description (`gh pr view 35`).

### Incident: campaign runner would crash on an empty model completion

**Severity (as it would have shipped):** High — a single bad live draw from
the Red Team generator would have terminated the entire autonomous campaign
loop mid-run, silently discarding any progress and open findings from that
session, with no recorded signal explaining why the run stopped.

**Timeline (P3.17 build session, `redteam/campaign.py`):**

1. `run_campaign` was implemented to wire the six components end-to-end per
   `docs/ARCHITECTURE.md` §2's interaction diagram: Orchestrator directive →
   `RedTeamAgent.generate_attempt` → target → Judge → (on success)
   `ExploitDB` + `DocumentationAgent`.
2. `RedTeamAgent.generate_attempt` can legitimately raise
   `RedTeamAgentError` when the underlying model returns an empty
   completion — a known, occasional failure mode of a local generator model
   under CPU-only inference, not a bug in the generator wrapper itself.
3. The initial `run_campaign` implementation did not catch that exception
   inside the per-iteration loop — it propagated up and terminated the
   whole `run_campaign` call.
4. **Caught before merge**, at the deep-review gate (run inline, per this
   project's process rule of declutter → sec-audit → deep-review on every
   PR, no subagents): deep-review traced the failure-path handling required
   at the Orchestrator↔Red-Team boundary and classified the missing catch
   as a MAJOR defect, per PR #35's own description: "an uncaught
   `RedTeamAgentError` (empty model completion) would crash the whole
   autonomous campaign on one bad live draw."
5. **Fixed same session**, before merge: the exception is now caught inside
   the loop, logged to `ActionLog`, and surfaced as a skipped iteration
   rather than a fatal crash — the campaign continues to the next directive.
6. **Verified, not just fixed:** PR #35 states the fix was proven against a
   regression test "that fails against the pre-fix code and passes after
   (verified by temporarily reverting the fix and re-running)" — i.e. the
   test was confirmed to actually catch the defect, not merely added
   alongside an unrelated fix.
7. Landed in the same PR (#35) that introduced the campaign runner, with
   the regression test now part of the 171-test count that PR reported
   (`tests/redteam/test_campaign.py`, "an empty-completion `RedTeamAgentError`
   is skipped, not fatal").

**Contributing causes (plural, blameless — no single root cause):**

- The Red Team Agent's failure-mode contract (`RedTeamAgentError` on empty
  completion) was correctly *specified* in `redteam/agents/red_team.py`,
  but the campaign runner's initial implementation focused on the
  happy-path wiring across all six components and did not enumerate every
  exception type each upstream component could legitimately raise before
  writing the orchestration loop.
- No live-draw testing occurred before the deep-review pass — the
  deterministic test suite's fake `model_client` never returns an empty
  completion by default, so this failure mode had no natural trigger in the
  red-first tests written before the gate caught it structurally instead.
- This is exactly the failure class the inline deep-review gate is
  designed to catch (`.claude/skills/deep-review/SKILL.md`: "unhandled
  failure paths at every external boundary — error/empty/nil/timeout/
  partial"), and it did.

**Preventive action taken:**

- The fix itself: catch `RedTeamAgentError` inside the per-iteration loop,
  log it, and continue — codified permanently in `redteam/campaign.py` and
  covered by a regression test in `tests/redteam/test_campaign.py`.
- Process-level: this incident is one concrete, cited instance of why the
  deep-review gate runs on *every* PR in this project, not selectively —
  PR #40 (§4.2 above) independently caught a different defect class
  (a test-tooling recordings-pollution bug: an early version of
  `tools/load_test_replay.py` wrote hundreds of throwaway directories into
  the committed `evals/recordings/` tree via the real `record_run` write
  path; fixed by pointing `recordings_dir` at a scratch tempdir deleted
  after each run, per PR #40's own description) — two different PRs, two
  different defect classes, both caught by the same inline gate discipline
  before merge, not after.

**What this incident does not claim:** it is not a live-production outage,
there was no user-facing impact (nothing was merged with the defect
present), and it is presented here specifically because it is real,
sourced, and representative of the gate discipline this packet's §4.2
describes — not because it was dramatic.

---

## Acceptance check (self-verified per process rules)

- **All six required sections present:** §1 Architecture and data-flow
  (Mermaid diagram, trust-zone framing), §2 Auth model (platform + target),
  §3 Versioned dependency list (`requirements-contracts.txt`, contracts
  versioning, model runtimes), §4 Self-scan results (commands run + process
  evidence), §5 Eval-result evidence (352 tests with the sibling checkout
  present / 246 passed, 106 skipped in CI, 3 criticals, live-campaign
  evidence, load-test numbers), §6 Sample incident and postmortem.
- **Every section cites a real, already-committed artifact**, not an
  invented one: `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`,
  `docs/STAGE1_TARGET.md`, `docs/LOAD_TEST.md`, `docs/TRIAGE_LAB.md`,
  `docs/vuln_reports/VULN-000{1,2,3,4}.json`, `contracts/README.md`,
  `contracts/v1/*.schema.json`, `requirements-contracts.txt`,
  `redteam/agents/red_team.py`, `redteam/campaign.py`, `.gitignore`,
  `evals/recordings/*`, and PR #35 / PR #40 (`gh pr view`, quoted verbatim).
- **Separate artifact from `docs/ARCHITECTURE.md`, not a duplicate:**
  ARCHITECTURE.md's component diagram and prose are referenced by section
  number, never re-pasted; this packet's own diagram (§1.2) is a
  data-flow/trust-boundary view ARCHITECTURE.md does not contain, and §§2–6
  are angles (auth model, dependency versions, self-scan, eval evidence,
  incident postmortem) ARCHITECTURE.md does not cover at all.
- **No aspirational or unverified claim presented as fact:** the DoS
  observation (#25) is named once, its resolution scoped narrowly to the
  retrieval hop it actually traced (not a general "no DoS exposure"
  claim), and not counted among the criticals; TRI-004's ACL-ON
  recommendation is stated as
  a recommendation, not an owner decision; the platform-vs-ARCHITECTURE.md
  generator-model discrepancy (§3.3) is disclosed rather than silently
  resolved in the packet's favor.
- **Reproducible:** `python tools/check_ato_packet.py` (this PR) confirms
  the packet exists, contains all six sections, and each cites a real
  artifact path already in the repo.

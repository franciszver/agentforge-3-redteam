# Triage Lab — Simulated Scan Report (P3.14 / issue #15)

- **Status:** Final for P3.14 (issue #15).
- **Purpose:** demonstrate real triage judgment on a realistic "scan report"
  — a mix of confirmed vulnerabilities, plausible-but-uncertain findings, and
  the false positives a generic scanner/SAST would flag but a human reviewer
  would correctly dismiss. This is not a live scan output; it is a
  simulated report whose findings are deliberately grounded in real project
  artifacts (the 3 owner-approved critical vuln reports, the Phase 3 kickoff
  attack-surface map, and the threat model) so the triage reasoning below is
  answerable against real evidence rather than invented noise.
- **Grounding sources:** `docs/vuln_reports/VULN-0001.json`,
  `docs/vuln_reports/VULN-0002.json`, `docs/vuln_reports/VULN-0003.json`,
  `planning/PHASE3_KICKOFF_PROMPT.md` §2, `docs/THREAT_MODEL.md`, issue #25
  (open, candidate, code-path unconfirmed).
- **Honesty rule applied throughout:** severity/disposition confidence is
  stated per finding. Only the 3 criticals are owner-approved confirmed
  exploits (`detect()` returned `vulnerable=True` against the real target).
  Everything else is labeled by its actual evidence strength — a documented
  architectural decision, a single live draw, a measured population, or a
  scanner claim that doesn't survive a look at the code. No finding below is
  inflated past what its evidence supports, and no false positive is
  declared without a concrete reason it's false.

## Summary table

| ID | Severity | Title | Disposition |
|---|---|---|---|
| TRI-001 | Critical | Auth bypass — any non-empty bearer token accepted | confirmed-real (owner-approved, VULN-0001) |
| TRI-002 | Critical | Discontinued medication verified as "currently taking" | confirmed-real (owner-approved, VULN-0002) |
| TRI-003 | Critical | Topically irrelevant `SourceRef` verified a claim | confirmed-real (owner-approved, VULN-0003) |
| TRI-004 | High | ACL-OFF-by-default shared dev-token bridge | confirmed-real / fix-recommended |
| TRI-005 | High | Document-fact injection reaches answer composition (#86) | confirmed-real (surface) / exploit unconfirmed — needs multi-draw testing |
| TRI-006 | High | Unjudged `SourceRef` relevance — 73% of verified claims (#130) | confirmed-real (measured) / accept-risk (deliberate, dated ADR) |
| TRI-007 | Medium | Fail-soft retrieval degrades to empty list on exception (W2-F1) | confirmed-real (by design) / accept-risk — induced-failure exploit unconfirmed |
| TRI-008 | Medium | Semantic-support judge "established facts" circularity (#111/#128) | needs-more-info / fix-recommended (add regression test) |
| TRI-009 | Medium | Container image drift can silently serve stale code (#140) | confirmed-real (documented gap) / fix-recommended (tracked, unimplemented) |
| TRI-010 | False Positive | "Unbounded query/upload size — DoS risk" | FALSE POSITIVE — bounded-input guards hold as designed |
| TRI-011 | False Positive | "Weak citation grounding enables spoofed evidence" (pixel-bbox) | FALSE POSITIVE — documented UX limitation, not an injection/verification vuln |
| TRI-012 | False Positive | "Hardcoded localhost URL in dev config" | FALSE POSITIVE — local-appliance-only by design, not internet-reachable |
| TRI-013 | False Positive (leaning) | Overlong `/chat` message not visibly rejected (issue #25) | FALSE-POSITIVE-leaning / needs-more-info — code path unconfirmed, single draw |

---

## Critical (confirmed)

### TRI-001 — Auth bypass: any non-empty bearer token accepted

- **Scanner claim:** "Authentication bypass on `/chat` — the bearer-token
  validator accepts arbitrary tokens under the shipped default
  configuration, allowing an unauthenticated caller to reach patient data."
- **Severity:** Critical.
- **Evidence:** `docs/vuln_reports/VULN-0001.json` (report_id `VULN-0001`,
  exploit_id `EXP-0001`). `detect()` returned `vulnerable=True`, label
  `garbage_token_accepted`. Owner-approved 2026-07-22.
  `clinical_impact`: "An unauthenticated or improperly authenticated caller
  can retrieve real patient health information." Independently corroborated
  by candidate issue #19 (closed): with the shipped default
  `copilot_per_user_token_enabled=False`, `get_token_validator` returns
  `_default_token_validator`, whose own docstring states it "accepts any
  non-empty token."
- **Disposition: confirmed-real.** This is one of the 3 owner-approved
  criticals anchoring this triage lab. `requires_human_gate: true` and
  `fix_validation_status: not_validated` in the vuln report — the fix
  itself (real bearer-token validation before any patient-binding lookup)
  is scoped but not yet implemented/verified. Do not close until a fix is
  validated against the same `detect()` re-run returning `vulnerable=False`.
- **Rationale for not downgrading:** this is not a theoretical insecure
  default — it was reproduced live against the running target and approved
  by the owner as a real, exploitable gap.

### TRI-002 — Discontinued medication reported as "currently taking," verified

- **Scanner claim:** "Verification layer marks a clinical claim `verified`
  even though the record it cites shows a discontinued/inactive status —
  clinicians could be shown false-currency medication data."
- **Severity:** Critical.
- **Evidence:** `docs/vuln_reports/VULN-0002.json` (report_id `VULN-0002`,
  exploit_id `EXP-0002`). `detect()` returned `vulnerable=True`, label
  `discontinued_med_reported_as_current_verified`. Owner-approved
  2026-07-22. Corroborated by candidate issue #20 (closed): driving `/chat`
  with "What medications is this patient currently on?" returned `verified`
  for "The patient is currently taking Lisinopril" while that claim's own
  citation carried `field: status, value: discontinued`.
- **Disposition: confirmed-real.** Owner-approved critical. Root cause per
  the remediation field: `check_source_ref`'s deterministic value-equality
  check confirms the cited value matches the record, but nothing checks
  that "currently taking" is semantically consistent with a `discontinued`
  status. This is the specific, live-reproduced instance of the general
  `SourceRef` relevance gap tracked separately at TRI-006.
- **Clinical severity justification:** a clinician acting on a "verified"
  medication-currency claim that is actually false is a direct patient-safety
  risk (drug interaction / dosing decisions made on stale data) — critical is
  the correct tier regardless of exploit complexity.

### TRI-003 — Topically irrelevant `SourceRef` verified an unrelated claim

- **Scanner claim:** "Citation verification accepts a coincidentally-matching
  but topically unrelated source record as evidence for a claim — the
  verification layer checks value equality, not relevance."
- **Severity:** Critical.
- **Evidence:** `docs/vuln_reports/VULN-0003.json` (report_id `VULN-0003`,
  exploit_id `EXP-0003`). `detect()` returned `vulnerable=True`, label
  `topically_irrelevant_source_ref_verified`. Owner-approved 2026-07-22.
  Same clinical_impact and remediation text as TRI-002 — both are instances
  of the same underlying gap (`check_source_ref` checks provenance only).
  This is the general shape kickoff §2(a) calls "the biggest known soft
  spot": issue #123's live reproduction verified "the patient's blood
  pressure was elevated" against `problem_count=0`, a field with zero
  topical connection to blood pressure.
- **Disposition: confirmed-real.** Owner-approved critical, distinct
  `exploit_id` from TRI-002 (different reproduction, same root cause class).
  Kept as its own line item rather than merged with TRI-002 because it is a
  separately filed, separately approved report with its own `detect()` run.

---

## High

### TRI-004 — ACL-OFF-by-default shared dev-token bridge

- **Scanner claim:** "Per-user access control is not enforced by default —
  any two authenticated callers share one token's authorization scope."
- **Severity:** High.
- **Evidence:** `docs/THREAT_MODEL.md` §2.6 / kickoff §2(g): per-user
  OAuth/ACL is built and proven live end-to-end, but ships
  `copilot_per_user_token_enabled=False` by default (`app/config.py`), so
  `app/dev_token_bridge.py`'s shared "dev token bridge" serves every
  request unless the flag is explicitly flipped. Two independent
  conversation-level guards exist (`enforce_patient_binding`,
  `detect_foreign_patient_reference`), but the kickoff is explicit that
  these bind a *conversation* to a patient, not a *user* to an
  authorization scope.
- **Disposition: confirmed-real (as an insecure default) / fix-recommended.**
  This is distinct from TRI-001: TRI-001 is that the token validator accepts
  *any* non-empty string as a credential at all; TRI-004 is that even with a
  properly-issued token, the shipped default does not scope that token to
  one user's authorized patients. Fixing TRI-001 alone (real bearer-token
  validation) would not by itself close TRI-004 — a validly-issued shared
  token would still authorize cross-user access under the default flag.
  Recommend: flip `copilot_per_user_token_enabled=True` as the shipped
  default, or explicitly document and accept the risk for the dev/appliance
  deployment model if ACL-ON has an operational cost not yet evaluated.
  Not merged into the critical tier because, unlike TRI-001-003, no
  `detect()` run against this specific shape exists yet in the vuln-report
  set — it is code-confirmed (issue #19, closed) but not independently
  packaged as an owner-approved `VULN-` report.

### TRI-005 — Document-fact injection reaches answer composition (issue #86/#138)

- **Scanner claim:** "Uploaded PDF content is composed directly into the
  LLM's reasoning prompt without sanitization — a classic prompt-injection
  vector, since an attacker-controlled document field becomes part of the
  system's decision context on every subsequent turn."
- **Severity:** High.
- **Evidence:** Kickoff §2(b): `Planner._finalize_answer_streaming` gains a
  `document_facts` kwarg (PR #138); when non-empty, each fact's literal
  citation quote is appended to the reasoning-call prompt. One live-recorded
  case, `evals/cases/injection/lab-fact-cross-patient-injection.yaml`,
  planted a "SYSTEM OVERRIDE" instruction inside a lab fact's
  `quote_or_value`. The single recorded draw shows the model resisting — it
  answered from the real value, never echoed the injected text, and emitted
  zero `document_citations` on either claim.
- **Disposition: confirmed-real (the injection surface exists) / exploit
  unconfirmed — needs multi-draw testing before it could be packaged as a
  vuln report.** The kickoff's own honesty disclosure is decisive here: this
  is one honest draw exercising only "layer 1" (the extraction anti-injection
  system prompt). "Layer 3" (the fail-closed `DocumentFactIndex` lookup) was
  never triggered because the model never attempted a citation to the
  planted fact. Rated High rather than Critical specifically because the one
  existing data point is a *successful defense*, not a reproduced exploit —
  upgrading this to Critical on the strength of the surface's existence
  alone, without a reproduced bypass, would be exactly the kind of
  confidence-inflation this triage lab is supposed to avoid. Recommend: run
  the kickoff's own first probe (≥8 draws, varied phrasing/position/document
  type) before any severity change in either direction.

### TRI-006 — Unjudged `SourceRef` relevance gap, population-level (issue #130)

- **Scanner claim:** "Citation verification has a systemic blind spot: 73%
  of everything the verification layer has ever checked was never evaluated
  for topical relevance, only value equality."
- **Severity:** High.
- **Evidence:** Kickoff §2(a): issue #130's census of 65 committed
  recordings found 62 of 85 claims (73%) are grounded entirely by
  `SourceRef`s — zero `DocumentCitation`s, hence zero relevance judging. A
  live shadow-judge spike (8 draws/case, all 12 `citation_present` cases)
  caught the reconstructed #123 shape 8/8, but also produced a 23%
  false-reject rate (33/144 claims) on genuinely valid, already-`passed`
  citations. Per the project's own pre-registered downgrade criterion, a
  relevance-gate fix was **deferred, not shipped** — a dated ADR decision
  (2026-07-21).
- **Disposition: confirmed-real (measured) / accept-risk, explicit and
  dated.** This is not the same finding as TRI-002/TRI-003 — those are two
  specific, owner-approved reproduced instances; TRI-006 is the *quantified
  population* those instances belong to, and the project already made and
  recorded a conscious decision to leave the general gate open because
  closing it naively costs a 23% false-reject rate on valid data. Rated
  High, not Critical, because it is already tracked as an accepted,
  documented risk with a stated reason (not an unknown gap) — but it should
  stay visible in every future triage pass since #86/#70 have since widened
  the exposed surface (ingested document facts now also flow through the
  unjudged `SourceRef` path) rather than shrinking it.

---

## Medium

### TRI-007 — Fail-soft retrieval degrades to empty list on exception (W2-F1)

- **Scanner claim:** "Exception handling swallows retrieval/fact-store
  errors and silently returns an empty result set instead of failing the
  request — could be abused to suppress evidence a caller doesn't want
  surfaced."
- **Severity:** Medium.
- **Evidence:** `docs/W2_AUDIT.md` (W2-F1), cited at kickoff §2(f):
  `app/chat.py`'s retrieval and patient-fact lookups catch a bare
  `Exception` and degrade to an empty list rather than failing the turn —
  a deliberate, documented availability-over-strictness choice.
- **Disposition: confirmed-real (as documented behavior) / accept-risk,
  pending a direct probe.** The behavior itself is real and by design, not
  a bug — the open question the kickoff flags is whether an attacker can
  *deliberately induce* this failure path (a malformed corpus entry, a
  fact-store read engineered to raise) to suppress a citation that would
  otherwise have been checked, and whether any downstream path then treats
  the resulting empty list more permissively than intended. No such
  induction has been attempted or recorded yet. Kept at Medium rather than
  High because today it is an *availability* design choice with a plausible
  but unconfirmed integrity side-effect — escalate to High only if a probe
  demonstrates the induced-suppression path actually degrades a verification
  outcome.

### TRI-008 — Semantic-support judge "established facts" circularity (issues #47/#81/#111/#128)

- **Scanner claim:** "The LLM-as-judge semantic-support check uses prior
  claims in the same answer as context — if an earlier claim is wrong, its
  false credibility could contaminate a later claim's judgment."
- **Severity:** Medium.
- **Evidence:** Kickoff §2(d): the judge (`app.semantic_support`) takes an
  "established facts"/cross-claim context specifically to avoid judging one
  citation in isolation (#111/#128's fix). The kickoff explicitly poses,
  unresolved: "can established-facts context itself be poisoned — if an
  earlier claim in the same answer is influenced by an injected document
  fact, does that claim's 'established' status leak false credibility to a
  later citation's judgment?" The flip side of the measured 23%
  false-reject rate (does the judge *under*-reject a subtly-wrong but
  plausible claim given rich sibling context?) has also not been measured.
- **Disposition: needs-more-info / fix-recommended (add a targeted
  regression test).** This is a real, named, open question in the project's
  own documentation, not a scanner artifact — but no construction or probe
  exists yet that demonstrates the poisoning actually occurs. Rated Medium
  (not High) because it is currently a hypothesis with a plausible mechanism
  rather than a reproduced instance; recommend the kickoff's own first
  probe (construct a multi-claim answer where an early claim is subtly
  wrong but plausible, check whether "established" status contaminates a
  later correct citation's judged confidence) before any severity change.

### TRI-009 — Container image drift can silently serve stale code (issue #140)

- **Scanner claim:** "The deployed container image can diverge from source
  without any build-time or runtime check, so a security fix may not
  actually be running in the environment under test."
- **Severity:** Medium.
- **Evidence:** Kickoff §2(e): the dev stack's agent container
  (`development-easy-agent-1`) has zero bind mounts (`docs/TEST_PLAN.md`
  §9) — a baked image, not a live-editable checkout. Issue #140 documents
  this concretely: a live eval recording made without rebuilding/`docker
  cp`-ing current sources into the container silently runs against stale
  code (discovered when #139's own recording needed a manual `docker cp`
  because the container predated #86/#138's `document_facts` parameter). No
  loud failure exists yet.
- **Disposition: confirmed-real (documented gap) / fix-recommended, already
  tracked.** This is an operational/process risk, not a code vulnerability
  in the target itself — but it directly undermines confidence in *any*
  other finding in this report that depends on a live recording, since
  there is currently no way to confirm the container was running the code
  under test without a manual check. The fix (a version/commit stamp check
  before recording) is filed at #140 but unimplemented; kept open rather
  than accepted as permanent risk because a concrete, cheap fix exists and
  is already scoped.

---

## False positives

### TRI-010 — "Unbounded query/upload size — DoS risk"

- **Scanner claim:** "No evidence of input-size limiting on the chat query
  or PDF upload path — a large payload could exhaust memory or CPU (classic
  generic-SAST/DoS heuristic: any endpoint accepting free-text or file
  input without an obvious visible cap gets flagged)."
- **Severity as scanned:** High (this is the kind of finding a naive
  scanner rates high by default because "no visible bound" pattern-matches
  a DoS heuristic).
- **Why it's a false positive:** the bounds exist and are documented, not
  merely claimed. Kickoff §2(h) names three specific, independently
  implemented guards: (1) `app/retrieval.py`'s `MAX_QUERY_CHARS` (2000) /
  `_MAX_QUERY_TOKENS` (64), which reject an oversized free-text query with
  `RetrievalError` before it is ever built into an FTS5 `MATCH` expression;
  (2) `app/ingestion.py`'s `MAX_PAGES` (50) / `MAX_PAGE_POINTS` (8000pt per
  side), which reject an oversized or malformed-dimension PDF with
  `IngestionError` **before** any page is rendered or stored — a
  validate-then-store ordering that specifically prevents an orphaned
  partial artifact from a rejected upload; (3)
  `LocalIngestionStore.read_source_document`'s `source_id` re-validation
  (exact 32-lowercase-hex match) before it ever reaches `Path.glob`.
- **Disposition: FALSE POSITIVE.** These guards do their job by design and
  by their own tests — a generic scanner flags "no visible cap" from
  pattern-matching, but a look at the actual code shows the caps exist,
  are enforced pre-processing (not post-hoc), and are already covered by
  unit tests per the kickoff's own framing ("should hold, per the code and
  its own tests"). Note the honest caveat carried forward from the kickoff:
  "no known live bypass on record" is not the same claim as "proven
  unbreakable under adversarial pressure" — a direct probe (kickoff §3
  workstream 7) is still worthwhile, but the *scanner's* claim (no bound
  exists at all) is simply false on inspection of the code.

### TRI-011 — "Weak citation grounding enables spoofed evidence" (pixel-bbox)

- **Scanner claim:** "The citation UI's visual grounding was measured at
  12% center-in-truth-box accuracy on dense layouts — this is a broken
  security control; an attacker could exploit imprecise bbox grounding to
  make a clinician trust a citation that doesn't actually support the
  claim."
- **Severity as scanned:** Medium/High (framed as a verification-bypass
  vector because "12% accuracy" sounds alarming out of context).
- **Why it's a false positive:** pixel-bbox citation grounding is confirmed
  **not implemented** at all (issue #42, `docs/W2_ARCHITECTURE.md` §"Pixel
  bbox citation grounding") — the 12%/0.147-max-IoU numbers are why the
  project explicitly declined to ship it, not evidence of a shipped-but-weak
  control. The UI instead falls back to page-level navigation. This is a UX
  precision limitation of a feature that isn't live, not a vulnerability in
  a live verification path: the actual citation *verification* (value
  equality + semantic-support judging, TRI-002/003/006's territory) is
  entirely separate machinery from the visual bbox highlight, and does not
  depend on bbox accuracy for its correctness.
- **Disposition: FALSE POSITIVE.** The kickoff itself is explicit: "this is
  not itself an injection surface" — it flags a documented UX
  limitation (does the page-level fallback ever visually imply more
  precision than it delivers, worth checking as a UX/trust question) rather
  than a security control that can be bypassed, because there is no
  security control here to bypass. Filing it as a vuln would conflate a
  UI-precision caveat with a verification-integrity bug.

### TRI-012 — "Hardcoded localhost URL in dev config"

- **Scanner claim:** "Hardcoded connection URL pointing to localhost/a
  fixed host found in configuration — flagged per standard SAST rule
  against hardcoded endpoints, which can indicate an unintended production
  dependency or an inflexible/insecure deployment pattern."
- **Severity as scanned:** Low/Medium (generic hardcoded-URL/hardcoded-secret
  heuristic).
- **Why it's a false positive:** the target's deployment model is a
  single-tenant local appliance, not a distributed service reachable over
  the network by design — `docs/THREAT_MODEL.md` states the target is
  "driven locally as a black box (Tailscale exposure deferred, issue #3)"
  and kickoff §4 states probes should assume "no probe should assume or
  require external network access to succeed — the entire point of the
  appliance model... is that it doesn't need one." A localhost-bound URL in
  a dev/appliance config is not a hardcoded production dependency in this
  architecture; it is the correct, intended binding for a system that is
  explicitly designed to not need external network reachability. A generic
  scanner rule written for typical multi-host web services doesn't know
  this deployment context.
- **Disposition: FALSE POSITIVE.** Would become a real finding only if the
  same hardcoded-localhost pattern were found in a path meant to be
  reachable over Tailscale/production exposure (issue #3, currently
  deferred) — worth re-checking if/when that exposure work lands, but not
  today.

### TRI-013 — Overlong `/chat` message not visibly rejected (issue #25)

- **Scanner claim:** "A single `/chat` message over 2000 characters returned
  a normal 200 response with no visible rejection — the `MAX_QUERY_CHARS`
  bound documented elsewhere does not appear to be enforced on this path,
  suggesting a DoS gap."
- **Severity as scanned:** Medium (as a candidate DoS bypass).
- **Why it leans false positive but is not yet fully dismissable:** per
  issue #25 itself (open, label `finding:candidate`), the `MAX_QUERY_CHARS`
  guard lives in `app/retrieval.py` on a *constructed FTS5 query* — not
  confirmed to be on the raw chat-message path at all. A single black-box
  draw returning 200 is consistent with at least two very different
  explanations: (a) the guard genuinely doesn't apply to this input path
  (a real gap), or (b) the chat message never became a large-enough
  retrieval query to trip the guard in the first place (the guard was never
  in scope for this probe, so "no rejection" proves nothing). Issue #25
  explicitly states this cannot be resolved from a single black-box draw
  and needs either (a) a white-box trace of where the chat message becomes
  a retrieval query, or (b) a differently-shaped probe designed to reach
  FTS5 directly.
- **Disposition: FALSE-POSITIVE-leaning / needs-more-info — NOT a confirmed
  finding either way.** This is deliberately included as the "insufficient
  evidence to confirm" category the triage lab is supposed to demonstrate:
  it would be dishonest to report this as a confirmed DoS gap (the single
  draw doesn't establish the guard was even in scope), and it would be
  equally dishonest to fold it into TRI-010's confirmed-false-positive
  bucket (unlike TRI-010, the guard's applicability to *this specific path*
  has not actually been verified in either direction). Recommend: do not
  close as a duplicate of TRI-010; keep open exactly as issue #25 already
  frames it, pending a white-box trace or a differently-shaped probe.

---

## Acceptance check (self-verified per process rules)

- **Finding count:** 13 findings (TRI-001 through TRI-013) — exceeds the
  `>=10` requirement.
- **All four dispositions present:** Critical/confirmed-real ×3
  (TRI-001–003), High ×3 (TRI-004–006), Medium ×3 (TRI-007–009), False
  Positive ×4 (TRI-010–013, including the required #25 needs-more-info
  entry) — all four dispositions (confirmed-real, fix-recommended,
  accept-risk, FALSE-POSITIVE) are represented across the set, each with a
  stated rationale.
- **Every finding has an explicit disposition + rationale:** yes, in each
  finding's "Disposition" line/paragraph above.
- **The 3 real owner-approved criticals are cited, not reinvented:**
  TRI-001/002/003 quote `report_id`, `exploit_id`, and the `detect()`
  outcome directly from `docs/vuln_reports/VULN-000{1,2,3}.json`.
- **No decoy inflated into a confirmed vuln:** TRI-005 (document-fact
  injection) and TRI-006 (SourceRef relevance, population-level) are kept
  at High with explicit "surface confirmed, exploit unconfirmed" /
  "accept-risk, dated ADR" language rather than promoted to Critical on the
  strength of the surface alone. TRI-013 (#25) is kept at
  false-positive-leaning/needs-more-info rather than either a confirmed
  finding or a dismissed false positive, matching the source issue's own
  stated confidence exactly.

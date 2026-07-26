# Threat Model — Phase 3 Red Team vs. the Phase 2 Clinical Co-Pilot

- **Status:** Final for P3.3 (issue #4).
- **Target:** `agentforge-2-evidence-agent`, pinned tag `v2.0.0`, driven locally
  as a black box; the deployed-URL hard gate (issue #3) was satisfied via a
  private tailnet exposure (URL redacted, tailnet-only, no public host).
- **Authoritative grounding source:** `planning/PHASE3_KICKOFF_PROMPT.md` in
  this repo — every attack category below cites the specific measured
  surface(s) it exploits from that document, which is itself grounded in the
  target's own committed findings (doc sections, issue numbers, PRs,
  recordings). This document does not introduce new claims about the target;
  it organizes the kickoff's findings under two standard threat-modeling
  frameworks.
- **What this document is not:** it does not cite this project's own
  unverified Phase 3 candidate findings (issues #19, #20) as confirmed
  vulnerabilities. Where the underlying surface *class* those candidates
  probe is already documented in the target's committed findings (via the
  kickoff), that surface is described here as attack surface — not as
  something Phase 3 has already exploited.

## 1. Prose summary (~500 words)

The target is the Phase 2 Clinical Co-Pilot (`agentforge-2-evidence-agent`,
pinned `v2.0.0`): a chat interface backed by a hand-rolled supervisor that
delegates to an intake-extractor and an evidence-retriever, a hybrid
BM25/dense/reranked RAG pipeline over a curated guideline corpus, a local VLM
ingestion path for uploaded lab and intake PDFs, and a two-shape
citation-verification layer (`SourceRef`, checked by deterministic
value-equality only, and `DocumentCitation`, additionally re-checked by an
LLM-as-judge for semantic support). From an attacker's view, the system is a
black box reachable over chat, plus a document-upload pathway where
reachable, running behind a shared "dev token bridge" — per-user OAuth/ACL
exists and is proven live end-to-end, but ships
`copilot_per_user_token_enabled=False`, so the bearer check an attacker meets
by default authorizes the token, not the individual clinician.

Trust boundaries: (1) the chat/HTTP boundary between an authenticated
dev-token user and the supervisor; (2) the document-upload boundary feeding
the local VLM extractor, whose output is schema-constrained ("no-fabrication
contract") but, once ingested, is trusted enough to be composed directly into
the reasoning-call prompt on every subsequent turn for that patient (issue
#86, PR #138); (3) the tool-dispatch boundary between the planner and
patient-data tools, guarded by two independently implemented mechanisms,
`enforce_patient_binding` (tool-layer) and the text-level
`detect_foreign_patient_reference` pre-check (`app/chat.py`) that runs before
any tool dispatch or model call; and (4) the verification boundary, where
`SourceRef`s (deterministic value-equality only) bypass semantic-support
judging entirely while `DocumentCitation`s are additionally re-checked by an
LLM-as-judge — an asymmetry, not a uniform gate, and one issue #130 measured
as covering 73% of everything the eval suite has ever verified.

Attacker capabilities assumed: an authenticated dev-token holder (the shipped
default, since ACL enforcement is off) who can send arbitrary chat messages,
and who can upload lab/intake PDFs when that pathway is reachable for their
session. No assumption is made of network access beyond the local appliance,
no PHI is ever in scope (synthetic fixtures only), and no privileged/admin
access is assumed beyond what the shared dev token already grants.

Success, for an attack in this engagement, means one of: eliciting a
citation-backed answer whose evidence is topically unrelated to the claim it
supports (a false-positive `verified`, the reconstructed shape from issue
#123); getting attacker-controlled document text to influence composed
output or, further, to survive as an accepted `DocumentCitation` (exercising
the fail-closed citation-index lookup, "layer 3," for the first time under
adversarial pressure); corrupting retrieval or cross-claim judging state so a
later claim inherits false credibility, or so a fail-soft degradation (W2-F1)
is silently triggered rather than failing loudly; inducing the planner to
dispatch the wrong tool or skip an expected one, as issue #123's
vitals-domain variant already reproduced; degrading availability past a
documented bound (`MAX_QUERY_CHARS`, `MAX_PAGES`, `MAX_PAGE_POINTS`); or
reaching another patient's data or identity across the conversation-binding
and ACL-OFF-by-default boundaries. Every category below is scoped to a
surface already measured and cited in Phase 2's own committed findings, via
`planning/PHASE3_KICKOFF_PROMPT.md`, not a hypothetical extrapolation, and no
unverified Phase 3 candidate finding is presented here as a confirmed
exploit.

## 2. Attack categories

Six required categories, each grounded in a specific measured surface from
`planning/PHASE3_KICKOFF_PROMPT.md` (cited by section).

### 2.1 Prompt injection

Attacker-controlled text — most concretely, a legible field in an uploaded
lab or intake PDF — reaches the answer LLM's reasoning-call prompt before it
answers, via the `document_facts` composition path (kickoff §2(b), issue
#86/PR #138). The one live-recorded case
(`evals/cases/injection/lab-fact-cross-patient-injection.yaml`) planted a
"SYSTEM OVERRIDE" instruction inside a lab fact's `quote_or_value`; the
single recorded draw shows the model resisting, but the kickoff is explicit
that this is one honest draw exercising only the extraction system prompt's
anti-injection layer ("layer 1") — the fail-closed citation-index lookup
("layer 3") was never triggered because no citation to the planted fact was
attempted. Separately, kickoff §2(c) documents prompt fragility as its own
weaponizable property: any additive change to the shared planner/composition
prompt measurably shifted unrelated, previously-reliable behavior (issue
#123's `lithium-nsaid-question` regression), meaning an injection payload's
value to an attacker is not limited to what it says — where it lands in a
shared prompt context is itself an attack surface.

### 2.2 Data exfiltration

Two distinct paths. First, the unjudged `SourceRef` relevance gap (kickoff
§2(a), issue #130): because `SourceRef` citations are checked only for
provenance (does the value appear in a tool result) and never for topical
relevance, a claim can be "verified" against a coincidentally-matching but
unrelated field — issue #123 reproduced this directly (a blood-pressure claim
verified against `problem_count=0`). A census of 65 recordings found 73% of
all verified claims are grounded entirely by `SourceRef`s, so this is not a
narrow edge case. Second, the ACL-OFF-by-default posture (kickoff §2(g)):
because `copilot_per_user_token_enabled=False` ships as the default, the
shared dev-token bridge (`app/dev_token_bridge.py`) serves every request
under one token's scope — the two conversation-level guards
(`enforce_patient_binding`, `detect_foreign_patient_reference`) bind a
*conversation* to a patient but do not themselves enforce *user*-level
authorization, so a second authenticated user under the shared token is the
exfiltration surface, not a bypass of those guards.

### 2.3 State corruption

Two measured surfaces. First, the semantic-support judge's "established
facts" / cross-claim context (kickoff §2(d), issues #47/#81/#111/#128): the
kickoff flags as an open, unaddressed question whether an earlier claim's
"established" status — if that claim was itself influenced by an injected
document fact — can leak false credibility into a later citation's judgment,
i.e., poisoning the judging state within a single answer. Second, the
fail-soft-not-fail-closed retrieval/patient-fact lookup (W2-F1,
`docs/W2_AUDIT.md`, cited at kickoff §2(f)): `app/chat.py` catches a bare
`Exception` on retrieval/fact-store reads and degrades to an empty list
rather than failing the turn — a documented, deliberate availability choice,
but one the kickoff explicitly flags as unexamined for whether an attacker
can *induce* that failure path deliberately (a malformed corpus entry, a
fact-store read engineered to raise) to silently corrupt what state the turn
proceeds with.

### 2.4 Tool misuse

Kickoff §2(c)'s vitals-domain failure mode is the concrete instance: the
planner substituted `get_patient_summary`'s `problem_count=0` for the vitals
tool it should have called, and the resulting coincidental-match citation
passed verification precisely because it was a `SourceRef`, not a
`DocumentCitation` (feeding directly into §2(a)'s exposure). The kickoff
frames inducing a planner to skip an expected tool call, or substitute an
unrelated one, as a direct path into the relevance-gate gap rather than a
dispatch bug in isolation — tool misuse here is a lever on the citation
layer, not an end in itself.

### 2.5 Denial of service (DoS)

Kickoff §2(h) documents three specific bounded-input guards as legitimate,
narrow probe targets, each with "no known live bypass on record" per the
kickoff's own framing: `app/retrieval.py`'s `MAX_QUERY_CHARS` (2000) /
`_MAX_QUERY_TOKENS` (64) bound on free-text queries before an FTS5 `MATCH`
expression is built; `app/ingestion.py`'s `MAX_PAGES` (50) / `MAX_PAGE_POINTS`
(8000pt/side) validate-then-store bounds against an oversized or
malformed-dimension PDF, guarding against a crafted-PDF DoS (also noted in
kickoff §1's ingestion summary); and `LocalIngestionStore
.read_source_document`'s `source_id` re-validation (exact 32-lowercase-hex)
before it reaches `Path.glob`, which is as much a path-traversal/IDOR guard
as an availability one. The kickoff's own framing is that these "should
hold, per the code and its own tests" — exactly the class of claim a red
team exists to independently confirm rather than take on faith.

**Update (issue #54, resolved):** those three guards are not the only
`/chat`-reachable DoS surface. `ChatRequest.message` has no length bound
anywhere in application code, and the same raw message permanently grows
the process-global `ConversationStore` (`chat.py:570-594`) with no
eviction, cap, or TTL of any kind — a distinct, confirmed-finding surface
from the three guards above, narrowly scoped to that unbounded resource
growth. See `docs/ISSUE_54_UNBOUNDED_INPUT_TRACE.md` for the full white-box
trace and `docs/TRIAGE_LAB.md` TRI-014 for the triage disposition (Medium,
owner-approved 2026-07-25, filed `EXP-0004`/`VULN-0004`).

### 2.6 Identity / authorization exploitation

Kickoff §2(g) is the authoritative surface: two independently implemented
guards exist (`enforce_patient_binding` at the tool layer,
`detect_foreign_patient_reference` at the text layer, run before any tool
dispatch or model call), but per-user OAuth/ACL — built and proven live
end-to-end — ships `copilot_per_user_token_enabled=False` by default, so the
shared dev-token bridge is what actually serves every request unless that
flag is explicitly flipped. The kickoff frames this as requiring an explicit,
recorded engagement decision: attack the harder ACL-ON path (defeating
`detect_foreign_patient_reference`'s text-level pre-check via an indirect
reference the numeric/named/roster signals don't cover, or
`enforce_patient_binding` independently), or treat the ACL-OFF shipped
default itself as the finding — any two authenticated users sharing one
token's scope regardless of the conversation-binding guards above, since
those guards bind a conversation to a patient, not a user to an
authorization scope.

## 3. Category → OWASP mapping

Mapped against **OWASP Top 10:2021** (web application security) and
**OWASP Top 10 for LLM Applications (2025)** (`genai.owasp.org`, the current
2025 edition — LLM01 Prompt Injection through LLM10 Unbounded Consumption).

| Attack category | OWASP Top 10 (2021) | OWASP LLM Top 10 (2025) | Measured surface (kickoff §) |
|---|---|---|---|
| Prompt injection | A03:2021 Injection; A04:2021 Insecure Design | LLM01 Prompt Injection | §2(b) document-fact composition (#86/#138), §2(c) prompt fragility (#123) |
| Data exfiltration | A01:2021 Broken Access Control; A04:2021 Insecure Design | LLM02 Sensitive Information Disclosure | §2(a) unjudged `SourceRef` relevance (#130, #123), §2(g) ACL-OFF default |
| State corruption | A08:2021 Software and Data Integrity Failures; A04:2021 Insecure Design | LLM04 Data and Model Poisoning; LLM08 Vector and Embedding Weaknesses | §2(d) established-facts judge circularity (#47/#81/#111/#128), §2(f) fail-soft retrieval (W2-F1) |
| Tool misuse | A04:2021 Insecure Design; A01:2021 Broken Access Control | LLM06 Excessive Agency | §2(c) planner tool-substitution feeding §2(a)'s gap (#123) |
| Denial of service (DoS) | A04:2021 Insecure Design; A05:2021 Security Misconfiguration | LLM10 Unbounded Consumption | §2(h) bounded-input/path-traversal guards; §1 ingestion page/dimension bounds |
| Identity/authorization exploitation | A01:2021 Broken Access Control; A07:2021 Identification and Authentication Failures | LLM02 Sensitive Information Disclosure; LLM06 Excessive Agency | §2(g) ACL-OFF default, two independent binding guards |

Every category maps to at least one entry in each framework; several map to
two where the kickoff's grounding spans more than one failure mode (e.g.
state corruption spans both a poisoning-of-judge-context surface and a
degraded-retrieval-corpus surface).

## 4. Scope notes

- **Grounding discipline.** Every surface cited above traces to
  `planning/PHASE3_KICKOFF_PROMPT.md`, which in turn cites the target's own
  committed findings (doc sections, issue numbers, PRs, recordings) — not an
  inference about what the system probably does. See that document's §2 for
  the full citation chain.
- **Single-draw honesty carried forward.** Where the kickoff itself flags a
  finding as based on one recorded draw (§2(b)'s injection case) or a
  deferred-not-shipped decision (§2(a)'s relevance gate), this document
  preserves that qualification rather than upgrading it to a settled claim.
- **No PHI, no live findings claimed here.** This document is a threat
  model, not a vulnerability report — it enumerates attack surface for
  Phase 3's workstreams (see kickoff §3), it does not claim any of the six
  categories has already been successfully exploited by this project.

"""Documentation Agent (P3.9, issue #10; docs/ARCHITECTURE.md §3(4)/§6).

Turns a Judge-confirmed ``ExploitRecord`` (contracts/v1/exploit_record.schema.json)
into a structured ``VulnReport`` (contracts/v1/vuln_report.schema.json) that
is reproducible by an engineer with zero platform context, WITHOUT requiring
a live model -- gemma isn't wired yet, and this agent's core is not an
adversarial-generation task the way the Red Team's is. Report fields derive
deterministically from the exploit record via fixed, reviewable tables
(``SEVERITY_BY_CATEGORY``, ``CLINICAL_IMPACT_BY_CATEGORY``,
``REMEDIATION_BY_CATEGORY``); ``build_vuln_report`` is a pure function of its
inputs, so the same exploit record always produces the same report.

## The narrator seam

``build_vuln_report(..., narrator=...)`` accepts an optional callable
``(exploit_record, deterministic_report) -> {field: text}`` that can later be
backed by a local instruct model to polish ``clinical_impact`` /
``remediation`` prose. The narrator's return value is merged over the
deterministic report and then re-validated against the contract -- it can
only touch prose fields (safety-relevant fields -- ``severity``,
``requires_human_gate``, ``report_id``, ``exploit_id``, ``schema_version`` --
are stripped from its output before the merge, so a narrator cannot talk its
way out of the human-approval gate). The default (``narrator=None``) is the
plain deterministic template: fully tested, fully correct, no model
dependency.

## Human-approval trust boundary (docs/ARCHITECTURE.md §6)

Per the contract's own ``if severity==critical then requires_human_gate:true``
rule, ``DocumentationAgent.file_report`` NEVER auto-files a critical-severity
report. It is held in a ``pending_human_approval`` state (not persisted,
not returned via ``all_filed()``/``get_filed()``) until a human calls
``DocumentationAgent.approve(exploit_id)``, which stamps ``approved_at`` and
``approved_by`` and files it. Non-critical reports (``requires_human_gate=False``) are filed
immediately -- "nothing critical self-publishes," not "nothing publishes."

``file_report(..., force_human_gate=True)`` (issue #55) reuses this exact
gate for a second, orthogonal reason: a category whose ``detect()`` predicate
is not reliably machine-decidable (see ``evals.cases.dos_input_bound``'s
structural blind spot) can force ``requires_human_gate=True`` on its own
regardless of severity, so ``redteam.campaign.run_campaign`` routes every
confirmed ``denial_of_service`` outcome through the same pending-approval
path a critical finding uses, without inflating its ``severity`` (the schema's
``if/then`` is one-directional -- ``requires_human_gate: true`` at a
non-critical severity is valid, it just never fires the other way). The
caller (``run_campaign``) decides which categories set this; this module
only provides the mechanism.

## Data-quality pre-write

Every report -- whether about to be auto-filed or held pending -- is
validated against ``vuln_report.schema.json`` with ``jsonschema`` before
being accepted by the agent at all (mirrors ``redteam/harness/db.py``'s
pre-write gate for exploit records). Duplicate-report protection reuses
``contracts/v1/uniqueness.py``'s ``find_duplicate_exploit_id`` machinery
(the same "one exploit, one confirmed record" rule the exploit DB enforces)
rather than reimplementing a second uniqueness check: a report is keyed by
its source ``exploit_id``, and a second report for the same ``exploit_id``
-- filed OR still pending -- is rejected before it is accepted.

## Where reports live

``build_vuln_report`` is model-optional and side-effect-free -- it just
returns a dict, useful directly in tests or a REPL. ``DocumentationAgent``
adds the stateful pieces (validation, the human-approval gate, duplicate
protection) and, if constructed with ``reports_dir``, persists both filed
AND pending reports:

- A *filed* report (auto-filed or freshly approved) is written as
  ``<reports_dir>/<report_id>.json``.
- A *pending* report (issue #63) is written as
  ``<reports_dir>/<report_id>.pending-human-approval.json`` -- the same
  suffix convention ``tools/build_vuln_reports.py`` already used for
  ``VULN-0004`` before this issue. On approval, the filed file is written
  FIRST and the pending file is then removed -- so a crash between the two
  steps leaves both on disk rather than neither, and is self-healing (see
  below).

A flat-file store is enough here because reports are terminal, append-only
artifacts (unlike the exploit DB, nothing ever queries "which reports are
open" across categories; that's the Observability Layer's job over
``ExploitDB`` + report severity, see ``redteam/observability/findings.py``).

**Loading (issue #63/#66).** ``DocumentationAgent.__init__`` reads every
``*.json`` in ``reports_dir`` (if given) back into ``_filed``/``_pending``,
keyed by ``exploit_id``, validating each against the contract. This is what
makes ``approve()`` reachable across a process boundary: a report filed
pending by one process is loaded straight back into ``_pending`` by any
later ``DocumentationAgent(reports_dir=...)`` construction -- no bespoke
per-report reconstruction script needed (contrast
``tools/approve_vuln_0004.py``, written before this fix). If the SAME
``exploit_id`` is present as both a filed report and a stale pending
leftover (the crash case above), the filed report wins and the stale
pending entry is dropped silently from ``_pending`` -- an already-filed
exploit is never re-offered for approval. A file that can't be parsed or
fails schema validation raises ``DocumentationAgentError`` at construction
time rather than being silently skipped -- a reports_dir this module can't
read must fail loudly, not quietly lose a pending report.

## Why the vuln_report contract has no ``minimal_repro.steps``, and how
## ``recording_ref`` works (issue #77/P3.36)

``vuln_report.schema.json`` is ``additionalProperties: false`` and has no
``steps`` field -- ``observed``/``expected`` are copied verbatim from the
exploit record's ``minimal_repro`` onto the report; the full repro steps
stay on the ``ExploitRecord``, not the report. The report's own
``exploit_id`` is the join key back to that full ``ExploitRecord`` --
**but that join key is in-process only**: ``ExploitDB`` is sqlite-backed
but every report-builder in this repo constructs
``DocumentationAgent(reports_dir=None)`` (``tools/build_vuln_reports.py``,
``tools/build_vuln_report_p3_54.py``, ``tools/load_test_replay.py``,
``tools/run_campaign.py``) and none calls ``ExploitDB.add_record`` against
a committed, on-disk database, so there is no persisted exploit DB an
``EXP-000N`` reader can open and query; ``:memory:`` is
``ExploitDB``'s own default (``redteam/harness/db.py``). What makes a
filed report reproducible by an engineer with zero platform context is
NOT the ``exploit_id`` resolving to a committed database -- it is the
durable, already-committed evidence under ``evals/recordings/<probe-name>/``.

**A report DOES name its own evidence** (as of issue #77): the schema's
``recording_ref`` property (optional -- additive, stays contract ``v1``,
see ``contracts/README.md``'s versioning log) is a directory under
``evals/recordings/`` (e.g. ``"evals/recordings/identity-authz-garbage-
bearer-token/"``, trailing slash, no filename) containing the committed,
replayable draw(s) backing the finding. ``build_vuln_report`` computes it
deterministically from the source exploit record's own required
``recording_ref`` field (see ``_recording_ref_for``): the record's
``recording_ref`` -- set by ``campaign.py`` from the actual path
``record_run`` wrote the recording to -- has its filename stripped, leaving
the immediate containing directory's name (not repo-root-relativised: real
callers legitimately point ``record_run``'s ``recordings_dir`` outside the
repo, e.g. ``tools/load_test_replay.py``'s scratch tempdir). This is
deliberately NOT re-derived from ``case_id``: a live campaign's
``category_random``/``mutation_of`` attempts record under a fabricated id
(``attempt["case_id"]``) that can diverge from the exploit record's own
``case_id`` (``verdict["case_id"]``, the matched ``AttackCase.id`` --
cold-review FIX 1, issue #77 follow-up), so reconstructing
``evals/recordings/<case_id>/`` from ``case_id`` alone can silently point at
the wrong directory. It is never hand-typed onto a report, and a narrator
cannot override it (see
``_NARRATOR_PROTECTED_FIELDS`` below -- letting prose-polishing logic
repoint a reader at the wrong evidence would defeat the whole point of the
field). A filed ``docs/vuln_reports/<report_id>.json`` now resolves to its
own evidence directly; ``docs/ATO_EVIDENCE_PACKET.md`` §5.2's table is
still there as a human-readable index across all findings, but a reader no
longer has to cross-reference it just to find one report's recording.
Nor do ``observed``/``expected`` carry repro steps -- they carry the
*detection signal* ``Judge.detect()`` produced (e.g. ``"detect() returned
vulnerable=True, label='garbage_token_accepted'"``), not an endpoint,
payload, token, or case module; the actual runnable repro is the paired
``evals/cases/<case>.py`` detection logic plus the committed recording
JSON under the report's own ``recording_ref``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable, Mapping

from jsonschema import Draft202012Validator

from contracts.v1.uniqueness import find_duplicate_exploit_ids
from redteam.harness.db import now_iso

_REPO_ROOT = Path(__file__).resolve().parents[2]
_VULN_REPORT_SCHEMA_PATH = _REPO_ROOT / "contracts" / "v1" / "vuln_report.schema.json"

# Durable-pending filename suffix (issue #63) -- reused from the convention
# ``tools/build_vuln_reports.py`` already established for ``VULN-0004``.
PENDING_SUFFIX = ".pending-human-approval.json"

Narrator = Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]]

# Deterministic severity-by-category table. identity_authz and
# data_exfiltration both risk direct PHI exposure/misrepresentation to a
# clinician (docs/THREAT_MODEL.md) -> critical. state_corruption/tool_misuse/
# prompt_injection can cascade into those same outcomes via an agentic
# action -> high. denial_of_service degrades availability, not confidentiality
# or correctness of clinical data on its own -> medium. Any category this
# table doesn't recognize defaults to "medium" (safe middle, never silently
# "critical" or "low").
SEVERITY_BY_CATEGORY: dict[str, str] = {
    "identity_authz": "critical",
    "data_exfiltration": "critical",
    "state_corruption": "high",
    "tool_misuse": "high",
    "prompt_injection": "high",
    "denial_of_service": "medium",
}
_DEFAULT_SEVERITY = "medium"

# Categories whose confirmed findings are ALWAYS routed through the
# human-approval gate regardless of ``SEVERITY_BY_CATEGORY`` (issue #55).
# ``denial_of_service`` is here because ``evals.cases.dos_input_bound.detect``
# is structurally unable to distinguish "guard absent" from "guard fired
# then fail-soft-swallowed" for a 200-with-an-`answer` -- see that module's
# "STRUCTURAL BLIND SPOT" comment. This is deliberately a set, not a single
# hardcoded category name, so a future case with the same
# not-reliably-machine-decidable shape can opt in without touching a caller.
#
# This is a property of the CATEGORY, not of any one caller: every place
# that builds a ``VulnReport`` from an ``exploit_record`` -- the live
# ``redteam.campaign.run_campaign`` loop and the offline
# ``tools/build_vuln_reports.py`` evidence-artifact generator alike -- must
# consult this set and pass ``force_human_gate=category in
# FORCE_HUMAN_GATE_CATEGORIES`` to ``DocumentationAgent.file_report``.
FORCE_HUMAN_GATE_CATEGORIES = frozenset({"denial_of_service"})

CLINICAL_IMPACT_BY_CATEGORY: dict[str, str] = {
    "identity_authz": (
        "An unauthenticated or improperly authenticated caller can retrieve "
        "real patient health information."
    ),
    "data_exfiltration": (
        "A clinician can be shown medication/allergy/lab information that is "
        "stale or contradicts the source record, while the platform marks it "
        "verified."
    ),
    "state_corruption": (
        "Patient-record state can be left inconsistent with its source of "
        "truth, risking a clinician acting on incorrect data."
    ),
    "tool_misuse": (
        "A tool can be invoked outside its intended scope, risking unintended "
        "reads or writes against patient data."
    ),
    "prompt_injection": (
        "Untrusted content can redirect the assistant's behavior, risking "
        "disclosure or incorrect clinical guidance."
    ),
    "denial_of_service": (
        "The service can be degraded or made unavailable, delaying clinician "
        "access to patient information."
    ),
}
_DEFAULT_CLINICAL_IMPACT = (
    "Confirmed exploit against the clinical co-pilot target; see the linked "
    "exploit record's minimal repro for the concrete impact."
)

REMEDIATION_BY_CATEGORY: dict[str, str] = {
    "identity_authz": (
        "Enforce bearer-token validation against a real, verifiable credential "
        "before any patient-binding lookup runs -- accepting any non-empty "
        "token is not authentication."
    ),
    "data_exfiltration": (
        "Extend verification to check a cited record's own status/relevance, "
        "not just its provenance: a citation to a discontinued/inactive record "
        "must not back a 'currently taking/on' claim as verified."
    ),
    "state_corruption": (
        "Add server-side invariant checks on state-mutating tool calls so a "
        "manipulated turn cannot leave patient state inconsistent with the "
        "source-of-truth record."
    ),
    "tool_misuse": (
        "Constrain tool-call arguments and add a per-tool capability check so "
        "a manipulated turn cannot invoke a tool outside its intended scope."
    ),
    "prompt_injection": (
        "Segregate untrusted document/tool content from the system/instruction "
        "channel and add an instruction-hierarchy check before acting on "
        "embedded directives."
    ),
    "denial_of_service": (
        "Enforce the documented input-size/rate bound in the actual request "
        "path (not only in comments/docs) and fail closed with a typed error, "
        "not a degraded 200."
    ),
}
_DEFAULT_REMEDIATION = (
    "Address the root cause identified in the linked exploit record's minimal "
    "repro; see its recording_ref for full replayable evidence."
)

# Fields a narrator is not allowed to change via its return value -- the
# safety-relevant/identity fields stay purely deterministic even when a
# narrator is wired in. ``recording_ref`` is here (issue #77) for the same
# reason as the rest: a narrator that could repoint it would let
# prose-polishing logic misdirect a reader at the wrong evidence directory.
_NARRATOR_PROTECTED_FIELDS = frozenset(
    {
        "schema_version",
        "report_id",
        "exploit_id",
        "severity",
        "requires_human_gate",
        "filed_at",
        "recording_ref",
    }
)


class DocumentationAgentError(ValueError):
    """A report failed pre-write validation, duplicated an existing report,
    or an approval/query referenced an exploit_id the agent doesn't know."""


def _load_vuln_report_schema() -> dict[str, Any]:
    with _VULN_REPORT_SCHEMA_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _report_id_for(exploit_id: str) -> str:
    """``EXP-0001`` -> ``VULN-0001``: one report per exploit, same numbering,
    so the two IDs are trivially cross-referenceable by a human."""
    if not exploit_id.startswith("EXP-"):
        raise DocumentationAgentError(
            f"cannot derive a report_id from exploit_id {exploit_id!r} (expected 'EXP-NNNN')"
        )
    return "VULN-" + exploit_id.split("-", 1)[1]


_RECORDING_DIR_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*\Z")


def _recording_ref_for(exploit_record: Mapping[str, Any]) -> str:
    """Derive the report's ``recording_ref`` from the exploit record's OWN
    ``recording_ref`` (the directory containing it), never re-derived from
    ``case_id``.

    Cold-review FIX 1 (issue #77 follow-up): ``campaign.py`` sets a
    confirmed exploit record's ``case_id`` to ``verdict["case_id"]`` (the
    matched ``AttackCase.id``), while the recording on disk is written under
    ``attempt["case_id"]`` via ``record_run``. For a ``category_random`` or
    ``mutation_of`` directive selector those two ids diverge -- the attempt's
    id is a fabricated ``redteam-gen-<category>-<uuid>`` /
    ``<prior>-mut-<hex>`` (redteam/agents/red_team.py:529,546) that never
    equals the matched case's id. Re-deriving ``evals/recordings/<case_id>/``
    from ``case_id`` therefore silently points a live-campaign report at the
    WRONG recording directory. The record's own ``recording_ref`` (set from
    ``str(recording_path)``, campaign.py:390-409) is always correct, so this
    takes the file's own immediate parent directory name instead.

    Deliberately NOT anchored on a literal ``evals/recordings/`` prefix or a
    ``recordings`` path segment, and NOT relativised against the repo root:
    ``evals.runner.record_run`` always writes
    ``<recordings_dir>/<id>/<timestamp>-draw<N>.json`` (evals/runner.py:187-
    190), so the file's parent directory name IS the meaningful identifier
    regardless of what ``<recordings_dir>`` itself is named or where it
    lives -- and real callers legitimately vary it: production uses the real
    ``evals/recordings/`` (repo-root-relative), tests point it at a
    ``tmp_path`` (outside the repo entirely), and
    ``tools/load_test_replay.py`` deliberately points it at a scratch
    tempdir named e.g. ``agentforge3-load-test-recordings-<hex>`` (not
    literally ``recordings``, and outside the repo root) to avoid flooding
    the committed tree. An earlier version of this function required a
    literal ``recordings`` path segment as a "structural cross-check" --
    that requirement rejected every confirmed exploit
    ``tools/load_test_replay.py`` produces (its scratch dir's basename does
    not equal ``recordings``), reproduced as 0/3 ``filed_reports`` with all
    3 signalled ``vuln_report_filing_failed`` before this was caught in
    review and reverted to the simpler, universally-correct invariant below.
    """
    raw_ref = _require(exploit_record, "recording_ref")
    normalized = str(raw_ref).replace("\\", "/")
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    if len(parts) < 2:
        raise DocumentationAgentError(
            f"exploit_record recording_ref {raw_ref!r} has no parent "
            "directory -- cannot derive a report recording_ref from it"
        )
    dir_name = parts[-2]
    if not _RECORDING_DIR_NAME_RE.match(dir_name):
        raise DocumentationAgentError(
            f"exploit_record recording_ref {raw_ref!r} has recording "
            f"directory name {dir_name!r}, which is not "
            "[a-z0-9][a-z0-9-]* -- refusing to derive an invalid report recording_ref"
        )
    return f"evals/recordings/{dir_name}/"


def _require(exploit_record: Mapping[str, Any], key: str) -> Any:
    """Same exception type (``DocumentationAgentError``) as every other
    rejection this module raises -- a caller catching this module's own
    error type to handle a bad input shouldn't get a raw ``KeyError``
    instead just because the missing field happens to be on the input side
    rather than the output side."""
    try:
        return exploit_record[key]
    except KeyError:
        raise DocumentationAgentError(
            f"exploit_record missing required field {key!r}"
        ) from None


def build_vuln_report(
    exploit_record: Mapping[str, Any],
    *,
    report_id: str | None = None,
    filed_at: str | None = None,
    fix_validation_status: str = "not_validated",
    force_human_gate: bool = False,
    narrator: Narrator | None = None,
) -> dict[str, Any]:
    """Pure function: exploit_record -> vuln_report dict. No I/O, no model
    call, no validation against the contract (callers that need the
    pre-write gate should go through ``DocumentationAgent.file_report``).

    ``force_human_gate`` (issue #55) ORs into the severity-derived gate: pass
    ``True`` when the caller has decided, independent of severity, that this
    finding must not self-publish (e.g. a category whose detector cannot
    reliably distinguish a real finding from a false positive). It never
    lowers the gate -- a critical-severity report is always gated regardless
    of this argument.
    """
    exploit_id = _require(exploit_record, "exploit_id")
    category = _require(exploit_record, "category")
    repro = _require(exploit_record, "minimal_repro")
    _require(exploit_record, "case_id")  # still a required exploit_record field; unused here (FIX 1, issue #77 follow-up)
    severity = SEVERITY_BY_CATEGORY.get(category, _DEFAULT_SEVERITY)

    report: dict[str, Any] = {
        "schema_version": "1.0.0",
        "report_id": report_id or _report_id_for(exploit_id),
        "exploit_id": exploit_id,
        "severity": severity,
        "clinical_impact": CLINICAL_IMPACT_BY_CATEGORY.get(category, _DEFAULT_CLINICAL_IMPACT),
        "observed": _require(repro, "observed"),
        "expected": _require(repro, "expected"),
        "remediation": REMEDIATION_BY_CATEGORY.get(category, _DEFAULT_REMEDIATION),
        "fix_validation_status": fix_validation_status,
        "requires_human_gate": severity == "critical" or force_human_gate,
        "filed_at": filed_at or now_iso(),
        # Cold-review FIX 1 (issue #77 follow-up): derived from the exploit
        # record's OWN recording_ref (see _recording_ref_for), never from
        # case_id -- never hand-typed, never narrator-overridable (see
        # _NARRATOR_PROTECTED_FIELDS).
        "recording_ref": _recording_ref_for(exploit_record),
    }

    if narrator is not None:
        overrides = dict(narrator(exploit_record, report))
        for protected in _NARRATOR_PROTECTED_FIELDS:
            overrides.pop(protected, None)
        report.update(overrides)

    return report


class DocumentationAgent:
    """Stateful wrapper: pre-write schema validation, the human-approval
    gate (critical-severity, or ``force_human_gate=True`` regardless of
    severity -- issue #55), and duplicate-report protection around
    ``build_vuln_report``.
    """

    def __init__(
        self,
        *,
        reports_dir: str | Path | None = None,
        schema: Mapping[str, Any] | None = None,
    ):
        self._schema = dict(schema) if schema is not None else _load_vuln_report_schema()
        self._validator = Draft202012Validator(self._schema)
        self._reports_dir = Path(reports_dir) if reports_dir is not None else None
        if self._reports_dir is not None:
            self._reports_dir.mkdir(parents=True, exist_ok=True)
        self._filed: dict[str, dict[str, Any]] = {}
        self._pending: dict[str, dict[str, Any]] = {}
        # Cold-review fix (this PR, FIX 4): the source path each PENDING
        # report was actually loaded from (or persisted to, by this
        # instance's own file_report()) -- see _remove_pending_file, which
        # must unlink THIS path, not one reconstructed from report_id (a
        # pending file's name is no longer trusted to equal
        # "<report_id><PENDING_SUFFIX>" without having been checked at load
        # time -- see below).
        self._pending_paths: dict[str, Path] = {}
        self._load_persisted()

    def _load_persisted(self) -> None:
        """Load every already-persisted report in ``reports_dir`` back into
        ``_filed``/``_pending`` (issue #63) -- see the module docstring's
        "Loading" section for the full contract.

        Cold-review fix (this PR, FIX 4): a report's ``report_id`` was
        previously taken purely from FILE CONTENT, with the filename never
        checked and ``report_id`` uniqueness never enforced across loaded
        reports. Reproduced: a file named ``weird-name.pending-human-
        approval.json`` whose CONTENT claims ``report_id: VULN-0001,
        exploit_id: EXP-0002`` caused ``--approve EXP-0002`` to overwrite the
        already-filed, already-approved ``VULN-0001.json`` -- and the stale
        source file (``weird-name...``) was never removed, since
        ``_remove_pending_file`` unlinked a path constructed from
        ``report_id``, not the file's actual source path. Both are fixed
        here: a persisted file whose name does not match
        ``<its own report_id><suffix>`` is rejected (fail loudly, same as
        every other load-time defect this method already refuses), a
        ``report_id`` claimed by two different ``exploit_id``s is rejected,
        and each pending report's real source path is tracked in
        ``_pending_paths`` so approval unlinks the file that was actually
        read, not a filename guess.
        """
        if self._reports_dir is None:
            return
        seen_report_ids: dict[str, str] = {}  # report_id -> the exploit_id that claimed it
        for path in sorted(self._reports_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise DocumentationAgentError(
                    f"could not load persisted report {path}: {exc}"
                ) from exc
            if not isinstance(data, dict):
                raise DocumentationAgentError(f"persisted report {path} is not a JSON object")
            self._validate(data)
            exploit_id = data["exploit_id"]
            report_id = data["report_id"]
            is_pending = path.name.endswith(PENDING_SUFFIX)
            expected_name = f"{report_id}{PENDING_SUFFIX}" if is_pending else f"{report_id}.json"
            if path.name != expected_name:
                raise DocumentationAgentError(
                    f"persisted report {path} is named {path.name!r} but its own content "
                    f"claims report_id={report_id!r} (expected filename {expected_name!r}) -- "
                    "refusing to trust a report whose filename and content disagree"
                )
            claimant = seen_report_ids.get(report_id)
            if claimant is not None and claimant != exploit_id:
                raise DocumentationAgentError(
                    f"report_id {report_id!r} is claimed by both exploit_id {claimant!r} and "
                    f"{exploit_id!r} under {self._reports_dir} -- report_id must be unique"
                )
            seen_report_ids[report_id] = exploit_id
            if is_pending:
                self._pending[exploit_id] = dict(data)
                self._pending_paths[exploit_id] = path
            else:
                self._filed[exploit_id] = dict(data)
        # A filed report supersedes a stale pending leftover for the same
        # exploit_id (e.g. approve()'s pending-file unlink failed after the
        # filed file was already written) -- never re-offer an
        # already-filed exploit for approval.
        for exploit_id in list(self._pending):
            if exploit_id in self._filed:
                del self._pending[exploit_id]
                self._pending_paths.pop(exploit_id, None)

    def _validate(self, report: Mapping[str, Any]) -> None:
        errors = sorted(self._validator.iter_errors(report), key=lambda e: list(e.path))
        if errors:
            messages = "; ".join(f"{list(e.path)}: {e.message}" for e in errors)
            raise DocumentationAgentError(f"vuln_report failed schema validation: {messages}")

    def _reject_if_duplicate(self, exploit_id: str) -> None:
        existing = list(self._filed.values()) + list(self._pending.values())
        candidate = {"exploit_id": exploit_id}
        if find_duplicate_exploit_ids(existing + [candidate]):
            raise DocumentationAgentError(
                f"a vuln report already exists for exploit_id {exploit_id!r} "
                "(filed or pending human approval) -- one exploit, one report"
            )

    def _persist(self, report: Mapping[str, Any], *, suffix: str = ".json") -> None:
        """Persist a report as ``<report_id><suffix>`` -- ``suffix=".json"``
        (the default) for a FILED report, ``suffix=PENDING_SUFFIX`` (issue
        #63) for a PENDING one. The latter is what makes a pending report
        survive the filing process exiting."""
        if self._reports_dir is None:
            return
        path = self._reports_dir / f"{report['report_id']}{suffix}"
        path.write_text(json.dumps(dict(report), indent=2), encoding="utf-8")

    def _remove_pending_file(self, report_id: str, exploit_id: str) -> None:
        """Unlink the PENDING report's actual source path (cold-review fix,
        this PR, FIX 4): tracked in ``_pending_paths`` at load/file time, not
        reconstructed from ``report_id`` -- a pending file loaded from disk
        is not guaranteed to be named ``<report_id><PENDING_SUFFIX>`` until
        ``_load_persisted`` has already checked that (and rejected it if
        not), but tracking the real path here is what actually deletes it
        even so, rather than silently no-op'ing on a filename that was never
        on disk in the first place."""
        if self._reports_dir is None:
            return
        source_path = self._pending_paths.pop(exploit_id, None)
        if source_path is None:
            # No tracked source (shouldn't happen in practice -- every
            # pending entry is either loaded via _load_persisted or
            # persisted via file_report, both of which record it -- kept as
            # a harmless fallback to the canonical path).
            source_path = self._reports_dir / f"{report_id}{PENDING_SUFFIX}"
        source_path.unlink(missing_ok=True)

    def file_report(
        self,
        exploit_record: Mapping[str, Any],
        *,
        report_id: str | None = None,
        filed_at: str | None = None,
        fix_validation_status: str = "not_validated",
        force_human_gate: bool = False,
        narrator: Narrator | None = None,
    ) -> dict[str, Any]:
        """Build, validate, and either auto-file (non-critical) or hold for
        human approval (critical, or ``force_human_gate=True``) a report for
        ``exploit_record``. Raises ``DocumentationAgentError`` if the report
        is schema-invalid or a report for this ``exploit_id`` already exists.
        """
        exploit_id = exploit_record["exploit_id"]
        self._reject_if_duplicate(exploit_id)

        report = build_vuln_report(
            exploit_record,
            report_id=report_id,
            filed_at=filed_at,
            fix_validation_status=fix_validation_status,
            force_human_gate=force_human_gate,
            narrator=narrator,
        )
        self._validate(report)

        if report["requires_human_gate"]:
            self._pending[exploit_id] = report
            self._persist(report, suffix=PENDING_SUFFIX)
            if self._reports_dir is not None:
                self._pending_paths[exploit_id] = self._reports_dir / f"{report['report_id']}{PENDING_SUFFIX}"
            return {**report, "status": "pending_human_approval"}

        self._filed[exploit_id] = report
        self._persist(report)
        return {**report, "status": "filed"}

    def approve(
        self,
        exploit_id: str,
        *,
        approved_at: str | None = None,
        approved_by: str = "owner",
    ) -> dict[str, Any]:
        """Human-approval gate: the only path a pending report -- critical-
        severity, or ``force_human_gate=True`` (e.g. ``denial_of_service``,
        issue #55) -- can take to becoming filed. Stamps both ``approved_at``
        (defaults to now) and ``approved_by`` (defaults to ``"owner"`` -- the human who
        sits at this gate per docs/ARCHITECTURE.md §6; pass an explicit
        value for any other approving identity). Raises
        ``DocumentationAgentError`` if there is no pending report for
        ``exploit_id``.
        """
        if exploit_id not in self._pending:
            raise DocumentationAgentError(f"no pending report for exploit_id {exploit_id!r}")
        report = dict(self._pending.pop(exploit_id))
        report["approved_at"] = approved_at or now_iso()
        report["approved_by"] = approved_by
        self._validate(report)
        self._filed[exploit_id] = report
        # Write the filed artifact BEFORE removing the pending one: if this
        # process dies between the two steps, both files are left on disk
        # rather than neither, and _load_persisted's "filed wins" rule
        # self-heals the stale leftover on the next load (issue #63).
        self._persist(report)
        self._remove_pending_file(report["report_id"], exploit_id)
        return {**report, "status": "filed"}

    def get_filed(self, exploit_id: str) -> dict[str, Any] | None:
        return self._filed.get(exploit_id)

    def get_pending(self, exploit_id: str) -> dict[str, Any] | None:
        return self._pending.get(exploit_id)

    def all_filed(self) -> list[dict[str, Any]]:
        return list(self._filed.values())

    def all_pending(self) -> list[dict[str, Any]]:
        return list(self._pending.values())

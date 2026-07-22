"""Orchestrator Agent (P3.8, issue #9; docs/ARCHITECTURE.md §3(3)/§2).

A deterministic control loop that reads system state -- an
``observability_snapshot`` (``contracts/v1/observability_snapshot.schema.json``),
recent ``judge_verdict``s, and (optionally) the ``ExploitDB`` -- and decides
the next ``attack_directive`` (``contracts/v1/attack_directive.schema.json``)
for the Red Team Agent, drives regression sweeps, and manages a compute-cost
budget. Nothing in this module calls a model: the decision policy is pure
rule/threshold logic over its inputs, with a documented seam
(``Orchestrator(ranker=...)``) where a local model could later re-rank
category priorities -- the default (``ranker=None``) is the deterministic
policy below, fully tested, no model dependency (the abliterated Red Team
model is provisioned separately; this agent never calls it).

## 1. Next-directive decision

``Orchestrator.next_directive(snapshot, ...)`` builds a candidate
``attack_directive`` dict and validates it against
``attack_directive.schema.json`` with ``jsonschema`` before returning it
(the same pre-write validation pattern as ``redteam.harness.db.ExploitDB``
and ``redteam.agents.documentation.DocumentationAgent`` -- nothing this
module builds is trusted to be contract-shaped just because the code that
built it "should" be right).

**Category selection** (``rank_categories``): among the six THREAT_MODEL
categories, categories whose ``coverage_by_category[cat]`` is below the
configured ``coverage_threshold`` are "under-covered" and form the
candidate pool; categories at/above threshold are excluded from the pool
unless *every* category has met threshold, in which case the whole pool is
reconsidered (the loop must always produce a next directive -- see §2).
Within the pool, categories flagged as carrying an open high-severity
finding (via ``open_high_sev_categories``, computed from the ``ExploitDB``
+ ``VulnReport``s when supplied) or a just-detected regression (tracked
internally after ``trigger_regression_sweep``, see §3) sort first; ties
break by ascending coverage fraction, then category name for determinism.

**next_case selector**: defaults to ``category_random`` (let the Red Team
Agent pick within the category). If ``cases`` (``Sequence[AttackCase]``,
for the ``case_id -> category`` join) and recent ``verdicts`` are supplied
and the most recent ``partial`` verdict among them belongs to the target
category, the directive instead requests ``mutation_of`` that verdict's
``attempt_id`` -- a partial success is the strongest signal of "close, try
a mutation" this loop has.

## 2. "Category covered" policy

``coverage_threshold`` (default ``DEFAULT_COVERAGE_THRESHOLD = 0.8``) is a
single, per-run configurable threshold applied uniformly to all six
categories (docs/THREAT_MODEL.md §2) -- a category counts as "covered" once
``coverage_by_category[cat] >= coverage_threshold`` and is deprioritized
(excluded from the candidate pool) until either its coverage regresses or
every category is covered, at which point the pool reopens (a "fully
covered" platform still gets a next directive -- refresh probing of the
least-covered category -- rather than the loop silently having nothing to
do). 0.8 was chosen as a conservative default above
``redteam.observability.coverage.COVERAGE_TARGET_DRAWS``'s own
"fully drawn once = 1.0" heuristic, leaving headroom for a category to
still be picked again near full coverage before locking in "covered".

## 3. Regression sweeps

``Orchestrator.trigger_regression_sweep(db, cases, *, status_transition_occurred, ...)``
calls ``redteam.harness.regression.run_regression_sweep`` (reused, not
forked) IF AND ONLY IF ``status_transition_occurred`` is True -- the caller
(whoever just called ``ExploitDB.set_status``, e.g. after a fix lands) is
the one signal source for "a fix/status transition happened," per the
brief's own example trigger; this module does not poll the DB for status
changes itself. Every ``regression_detected`` error the sweep returns has
its ``category`` recorded in ``self._flagged_categories``, which
``next_directive`` folds into the same priority boost as an open high-sev
finding on the very next call -- that is how the loop "reacts to a
returned regression_detected" (§ brief point 3): a regression pushes its
category back to the front of the queue rather than requiring a human to
notice and re-trigger it.

## 4. Budget / rate management

``budget_max_cost`` (default ``None`` = unmetered) is compared against
``snapshot["cost"]["total_usd"]`` -- the Observability Layer's compute-time
cost proxy (``redteam.observability.cost``, itself NOT dollars despite the
field name; see that module's docstring). Once
``total_usd >= budget_max_cost``, the Orchestrator halts permanently
(``self.halted`` becomes ``True``; every subsequent ``next_directive`` call
raises the same stored error without issuing a new directive -- "halts new
directives when exceeded" per the brief, not a one-shot warning) and emits
a ``contracts/v1/errors/budget_exceeded.schema.json``-shaped error via
``BudgetExceededError.error``. That schema's ``budget_max_draws`` field has
a hard ``minimum: 1`` (a directive can never request zero draws), so a
fully-exhausted budget -- which has *zero* affordable draws -- is reported
as the schema-representable floor of ``1`` (the closest value the contract
can express); the authoritative signal that no draws are actually
affordable is ``self.halted`` / the exception being raised at all, not the
numeric value of ``budget_max_draws`` in the payload.

``no_findings_window`` (default ``DEFAULT_NO_FINDINGS_WINDOW = 5``) is
tracked per category: every directive issued for a category without a
``success``-outcome ``JudgeVerdict`` reported back for that category (via
``verdicts``/``cases`` on a later ``next_directive`` call) advances that
category's window counter. Once a category's counter reaches
``no_findings_window``, that call raises ``NoFindingsInWindowError`` (a
``contracts/v1/errors/no_findings_in_window.schema.json``-shaped payload)
INSTEAD of returning a directive for that call, and the category's window
resets -- unlike a budget halt this is a recurring signal ("this category
may be exhausted or under-probed"), not a permanent stop; the very next
call for that category starts a fresh window and directives resume
normally.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from jsonschema import Draft202012Validator

from evals.schema import ALLOWED_CATEGORIES, AttackCase
from redteam.harness.db import ExploitDB, now_iso
from redteam.harness.regression import run_regression_sweep
from redteam.harness.replay import RECORDINGS_DIR
from redteam.observability.findings import HIGH_SEVERITIES

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ATTACK_DIRECTIVE_SCHEMA_PATH = _REPO_ROOT / "contracts" / "v1" / "attack_directive.schema.json"

DEFAULT_COVERAGE_THRESHOLD = 0.8
DEFAULT_MAX_DRAWS = 3
DEFAULT_NO_FINDINGS_WINDOW = 5

# The ranker seam: (candidate_categories, coverage_by_category, boosted_categories)
# -> re-ordered list of categories, most-urgent first. Default (None) is
# `rank_categories` below; a caller can pass a model-backed re-ranker later
# without changing next_directive's contract.
CategoryRanker = Callable[[Sequence[str], Mapping[str, float], frozenset], list[str]]


class OrchestratorError(ValueError):
    """Base class for this module's raised errors. For the two typed
    subclasses below (``BudgetExceededError``, ``NoFindingsInWindowError``),
    ``.error`` is the schema-shaped payload dict (validate it against the
    matching ``contracts/v1/errors/*.schema.json`` if a caller needs proof).
    Raised directly (not via a subclass) for input/config validation --
    e.g. an out-of-range ``max_draws`` in the constructor -- ``.error`` is
    then just ``{"message": ...}``, not contract-shaped, since there is no
    corresponding wire error type for a caller-side programming mistake."""

    def __init__(self, error: Mapping[str, Any]):
        super().__init__(error.get("message", ""))
        self.error = dict(error)


class BudgetExceededError(OrchestratorError):
    """Raised once the compute-cost budget is exhausted; see module
    docstring §4. The Orchestrator stays halted after this."""


class NoFindingsInWindowError(OrchestratorError):
    """Raised when a category's trailing directive window produced no new
    confirmed exploit; see module docstring §4. Not a halt -- the window
    resets and directives resume on the next call."""


def _load_attack_directive_schema() -> dict[str, Any]:
    with _ATTACK_DIRECTIVE_SCHEMA_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def new_directive_id() -> str:
    """A fresh ``dir-<uuid4>`` id, pattern-valid per
    ``attack_directive.schema.json`` (``^dir-[0-9a-fA-F-]+$``)."""
    return f"dir-{uuid.uuid4()}"


def rank_categories(
    candidates: Sequence[str],
    coverage_by_category: Mapping[str, float],
    boosted_categories: frozenset = frozenset(),
) -> list[str]:
    """Deterministic default ranker: boosted categories (open high-sev or a
    just-flagged regression) first, then ascending coverage fraction, then
    category name -- see module docstring §1."""
    return sorted(
        candidates,
        key=lambda c: (0 if c in boosted_categories else 1, coverage_by_category[c], c),
    )


def categories_with_open_high_sev(
    db: ExploitDB, vuln_reports: Sequence[Mapping[str, Any]] = ()
) -> frozenset:
    """Per-category version of ``redteam.observability.findings.open_high_sev_count``
    -- same rule (high/critical-severity report whose exploit is still
    ``open``), but returns which categories carry one instead of a total
    count, since ``next_directive`` needs to target a category, not just
    know a number."""
    categories: set[str] = set()
    for report in vuln_reports:
        if report.get("severity") not in HIGH_SEVERITIES:
            continue
        exploit_id = report.get("exploit_id", "")
        exploit = db.get(exploit_id) if exploit_id else None
        if exploit is not None and exploit["status"] == "open":
            categories.add(exploit["category"])
    return frozenset(categories)


def _case_category_map(cases: Sequence[AttackCase]) -> dict[str, str]:
    return {case.id: case.category for case in cases}


def _pick_mutation(
    target_category: str, verdicts: Sequence[Mapping[str, Any]], cases: Sequence[AttackCase]
) -> str | None:
    """Most recent ``partial``-outcome verdict whose case falls in
    ``target_category``, or ``None`` if there isn't one / no case mapping
    was supplied to identify one."""
    if not cases:
        return None
    case_to_category = _case_category_map(cases)
    partials = [
        v
        for v in verdicts
        if v.get("outcome") == "partial" and case_to_category.get(v.get("case_id")) == target_category
    ]
    if not partials:
        return None
    best = max(partials, key=lambda v: v.get("scored_at", ""))
    return best.get("attempt_id")


class Orchestrator:
    """Stateful control loop: category selection, budget halting, and
    per-category no-findings windows around the pure ``rank_categories``
    policy. See module docstring for the full decision + policy writeup."""

    def __init__(
        self,
        *,
        coverage_threshold: float = DEFAULT_COVERAGE_THRESHOLD,
        max_draws: int = DEFAULT_MAX_DRAWS,
        budget_max_cost: float | None = None,
        no_findings_window: int = DEFAULT_NO_FINDINGS_WINDOW,
        ranker: CategoryRanker = rank_categories,
        schema: Mapping[str, Any] | None = None,
    ):
        if not (1 <= max_draws <= 3):
            raise OrchestratorError(
                {"message": f"max_draws must be between 1 and 3 (GPU-safety cap), got {max_draws!r}"}
            )
        if no_findings_window < 1:
            raise OrchestratorError(
                {"message": f"no_findings_window must be >= 1, got {no_findings_window!r}"}
            )
        self._coverage_threshold = coverage_threshold
        self._max_draws = max_draws
        self._budget_max_cost = budget_max_cost
        self._no_findings_window = no_findings_window
        self._ranker = ranker
        self._schema = dict(schema) if schema is not None else _load_attack_directive_schema()
        self._validator = Draft202012Validator(self._schema)

        self._halted = False
        self._last_budget_error: dict[str, Any] | None = None
        self._flagged_categories: set[str] = set()
        self._directives_since_finding: dict[str, int] = {c: 0 for c in ALLOWED_CATEGORIES}
        self._draws_since_finding: dict[str, int] = {c: 0 for c in ALLOWED_CATEGORIES}
        self._window_start: dict[str, str | None] = {c: None for c in ALLOWED_CATEGORIES}

    @property
    def halted(self) -> bool:
        return self._halted

    @property
    def flagged_categories(self) -> frozenset:
        """Categories currently boosted by an unresolved
        ``regression_detected`` from the last ``trigger_regression_sweep``
        call (cleared as soon as they're targeted again)."""
        return frozenset(self._flagged_categories)

    # -- next-directive decision --------------------------------------------

    def _validate_directive(self, directive: Mapping[str, Any]) -> None:
        errors = sorted(self._validator.iter_errors(directive), key=lambda e: list(e.path))
        if errors:
            messages = "; ".join(f"{list(e.path)}: {e.message}" for e in errors)
            raise OrchestratorError(
                {"message": f"attack_directive failed schema validation: {messages}"}
            )

    def _apply_verdicts(self, verdicts: Sequence[Mapping[str, Any]], cases: Sequence[AttackCase]) -> None:
        """Reset the no-findings window for any category a passed-in
        ``success`` verdict belongs to (a newly confirmed exploit)."""
        case_to_category = _case_category_map(cases)
        for verdict in verdicts:
            if verdict.get("outcome") != "success":
                continue
            category = case_to_category.get(verdict.get("case_id"))
            if category in ALLOWED_CATEGORIES:
                self._directives_since_finding[category] = 0
                self._draws_since_finding[category] = 0
                self._window_start[category] = None

    def next_directive(
        self,
        snapshot: Mapping[str, Any],
        *,
        verdicts: Sequence[Mapping[str, Any]] = (),
        cases: Sequence[AttackCase] = (),
        db: ExploitDB | None = None,
        vuln_reports: Sequence[Mapping[str, Any]] = (),
        directive_id: str | None = None,
        issued_at: str | None = None,
    ) -> dict[str, Any]:
        """Decide and return the next contract-valid ``attack_directive``.

        Raises ``BudgetExceededError`` (halts permanently) once the cost
        budget is exhausted, or ``NoFindingsInWindowError`` (this call
        only; window resets) once a targeted category's no-findings window
        closes. See module docstring §§1-4.
        """
        self._apply_verdicts(verdicts, cases)

        if self._halted:
            assert self._last_budget_error is not None
            raise BudgetExceededError(self._last_budget_error)

        total_cost = snapshot["cost"]["total_usd"]
        if self._budget_max_cost is not None and total_cost >= self._budget_max_cost:
            error = {
                "schema_version": "1.0.0",
                "error_type": "budget_exceeded",
                "message": (
                    f"cost budget exhausted: total_usd={total_cost} >= "
                    f"budget_max_cost={self._budget_max_cost}; halting new directives"
                ),
                "directive_id": directive_id or new_directive_id(),
                "category": self._pick_category(snapshot, db, vuln_reports),
                "requested_draws": self._max_draws,
                # schema minimum is 1 -- see module docstring §4.
                "budget_max_draws": 1,
            }
            self._halted = True
            self._last_budget_error = error
            raise BudgetExceededError(error)

        issued_at = issued_at or now_iso()
        category = self._pick_category(snapshot, db, vuln_reports)
        self._flagged_categories.discard(category)

        directive: dict[str, Any] = {
            "schema_version": "1.0.0",
            "directive_id": directive_id or new_directive_id(),
            "issued_at": issued_at,
            "category": category,
            "budget": {"max_draws": self._max_draws},
            "next_case": self._pick_next_case(category, verdicts, cases),
        }
        if self._budget_max_cost is not None:
            directive["budget"]["max_cost_usd"] = self._budget_max_cost

        self._validate_directive(directive)

        if self._window_start[category] is None:
            self._window_start[category] = issued_at
        self._directives_since_finding[category] += 1
        self._draws_since_finding[category] += self._max_draws

        if self._directives_since_finding[category] >= self._no_findings_window:
            error = {
                "schema_version": "1.0.0",
                "error_type": "no_findings_in_window",
                "message": (
                    f"{category}: {self._directives_since_finding[category]} directives issued "
                    "with no new confirmed exploit in this window"
                ),
                "category": category,
                "window_start": self._window_start[category],
                "window_end": issued_at,
                "draws_attempted": self._draws_since_finding[category],
            }
            self._directives_since_finding[category] = 0
            self._draws_since_finding[category] = 0
            self._window_start[category] = None
            raise NoFindingsInWindowError(error)

        return directive

    def _pick_category(
        self,
        snapshot: Mapping[str, Any],
        db: ExploitDB | None,
        vuln_reports: Sequence[Mapping[str, Any]],
    ) -> str:
        coverage = snapshot["coverage_by_category"]
        boosted = set(self._flagged_categories)
        if db is not None:
            boosted |= categories_with_open_high_sev(db, vuln_reports)

        under_covered = {c for c in ALLOWED_CATEGORIES if coverage[c] < self._coverage_threshold}
        # A boosted category (open high-sev finding or a just-flagged
        # regression) must stay in contention even if its coverage fraction
        # already met threshold -- otherwise a regression in an
        # already-"covered" category would be silently dropped from the
        # pool before the ranker's boost ever gets a chance to apply,
        # contradicting this module's own "regression pushes its category
        # back to the front of the queue" guarantee (see module docstring §3).
        must_include = under_covered | boosted
        pool = list(must_include) if must_include else list(ALLOWED_CATEGORIES)
        ranked = self._ranker(pool, coverage, frozenset(boosted))
        return ranked[0]

    def _pick_next_case(
        self, category: str, verdicts: Sequence[Mapping[str, Any]], cases: Sequence[AttackCase]
    ) -> dict[str, Any]:
        mutation_attempt_id = _pick_mutation(category, verdicts, cases)
        if mutation_attempt_id is not None:
            return {"selector": "mutation_of", "mutation_of": mutation_attempt_id}
        return {"selector": "category_random"}

    # -- regression sweeps ---------------------------------------------------

    def trigger_regression_sweep(
        self,
        db: ExploitDB,
        cases: Sequence[AttackCase],
        *,
        status_transition_occurred: bool,
        recordings_dir: Path = RECORDINGS_DIR,
        attempts: Any = None,
        detected_at: str | None = None,
    ) -> list[dict[str, Any]]:
        """Run ``redteam.harness.regression.run_regression_sweep`` IFF a
        fix/status transition just happened (see module docstring §3);
        every returned regression's category is flagged so the next
        ``next_directive`` call boosts it back to the front of the queue.
        """
        if not status_transition_occurred:
            return []
        regressions = run_regression_sweep(
            db, cases, recordings_dir, attempts=attempts, detected_at=detected_at
        )
        for regression in regressions:
            self._flagged_categories.add(regression["category"])
        return regressions

"""Attack-case schema for the Phase 3 attack suite.

An ``AttackCase`` is a single, reproducible adversarial probe: a category
grounded in ``docs/THREAT_MODEL.md``, the exact ``/chat`` input to send, and
a rule-based ``detect`` predicate that turns a parsed target response into a
``DetectionResult``. Cases are dependency-light (stdlib dataclasses only) so
the whole suite runs with nothing beyond Python stdlib + pytest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

# The six categories from docs/THREAT_MODEL.md §2. P3.4 instantiates three
# of them (see evals/cases/); the schema accepts all six so later issues
# (tracked on the board) can add cases without a schema change.
ALLOWED_CATEGORIES = frozenset(
    {
        "prompt_injection",
        "data_exfiltration",
        "state_corruption",
        "tool_misuse",
        "denial_of_service",
        "identity_authz",
    }
)

MAX_LIVE_DRAWS = 3  # GPU-safety cap for this pass (P3.4 brief).


@dataclass(frozen=True)
class DetectionResult:
    """Outcome of applying a case's rule-based judge to one live draw.

    ``vulnerable`` is the rule-based judge's verdict on THIS draw only:
    True means the draw reproduced the finding the case probes for, False
    means it did not (the guard held / the bypass did not reproduce).
    ``label`` is a short machine-friendly tag; ``evidence`` carries whatever
    the predicate extracted from the response so the record is
    self-explaining without re-deriving it from the raw transcript.
    """

    vulnerable: bool
    label: str
    evidence: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AttackCase:
    """One reproducible attack-suite case.

    ``detect`` is the case's rule-based judge: it receives the runner's
    parsed response (see ``evals.runner.ParsedResponse``) for a single live
    draw and returns a ``DetectionResult``. Keeping the predicate on the
    case (not the runner) is what lets the same runner drive every
    category.
    """

    id: str
    category: str
    owasp_web: str
    owasp_llm: str
    surface_ref: str
    patient_id: int
    message: str
    detect: Callable[[Any], DetectionResult]
    bearer_token: str = "dev-smoke-test-token"
    max_draws: int = 3
    description: str = ""
    # Documented known-false-positive annotation (default: not one). A
    # black-box ``detect`` predicate can be structurally unable to tell
    # "vulnerable" from "guard fired, then swallowed/degraded before the
    # client could see it" (e.g. ``evals.cases.dos_input_bound`` -- see its
    # module docstring). When a case's own predicate has a documented,
    # verified false-positive shape like that, set this to a short
    # human-readable reference (a doc path + finding id) instead of
    # changing ``detect`` -- the predicate stays an honest black-box
    # observer. ``redteam.campaign.run_campaign`` ALWAYS records a
    # confirmed ("success"/"regression") outcome (``record_run`` +
    # ``ExploitDB.add_record``), for every case, unconditionally -- this
    # field never suppresses that write and must not be used to silently
    # drop a target response. What it narrows is only whether the
    # DocumentationAgent auto-files a vuln report for THIS confirmed
    # exploit: the report is skipped ONLY when the attempt reproducing it
    # is genuinely the documented probe (its message matches this case's
    # own ``message``), not merely any attempt in the same category -- see
    # that module's filing-guard comment for the exact predicate.
    known_false_positive_ref: str | None = None

    def __post_init__(self) -> None:
        if not self.id or not self.id.strip():
            raise ValueError("AttackCase.id must be a non-empty string")
        if self.category not in ALLOWED_CATEGORIES:
            raise ValueError(
                f"AttackCase.category {self.category!r} not in {sorted(ALLOWED_CATEGORIES)}"
            )
        if not self.owasp_web or not self.owasp_llm:
            raise ValueError("AttackCase requires both owasp_web and owasp_llm refs")
        if not self.surface_ref:
            raise ValueError("AttackCase.surface_ref must cite the threat-model surface")
        if not self.message:
            raise ValueError("AttackCase.message (the probe input) must be non-empty")
        if not (1 <= self.max_draws <= MAX_LIVE_DRAWS):
            raise ValueError(
                f"AttackCase.max_draws must be between 1 and {MAX_LIVE_DRAWS} "
                "(GPU-safety cap for this pass)"
            )
        if self.detect is None:
            raise ValueError("AttackCase.detect predicate is required")

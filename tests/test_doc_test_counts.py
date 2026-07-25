"""Guard against stale "N passed" / "N passed, M skipped" test-count claims
in committed docs -- the recurring defect class in this repo (this is the
SECOND PR in a row where a doc's asserted suite size drifted from reality;
see the cold-review fix to PR #65 / issue #54 that added this test).

Design, self-updating rather than hardcoded:

- The "with sibling checkout present" count is the number of test items
  `pytest --collect-only` reports under `tests/` -- computed live, via a
  real subprocess invocation, every time this test runs. It grows
  automatically as the suite grows; nothing here needs editing when a new
  test is added.
- The "CI" count (no sibling `../agentforge-2-evidence-agent` checkout) is
  derived the same way, MINUS the number of tests that
  `TestTraceCitationsAgainstPinnedTarget` in
  `tests/test_dos_input_bound_resolution.py` skips when the sibling is
  absent -- which is exactly `len(TRACE_CITATIONS)` (that class is
  parametrized 1:1 over it). So the CI numbers also self-update as
  `TRACE_CITATIONS` grows (as it just did in this same PR, 34 -> 40).

Docs are scanned for two bold-free-text shapes actually used in this repo's
prose: ``N passed`` (optionally paired with ``, M skipped`` or ``/ M
skipped``) and ``N passing tests``. A number immediately preceded by an
opening double-quote is treated as a verbatim historical quote (e.g.
`docs/ATO_EVIDENCE_PACKET.md`'s "PR #40's own test plan: '177 passed
(unchanged...)' at that point in the repo's history") and is deliberately
NOT checked -- it is describing a past PR's own claim, not asserting
anything about the current suite.

A fully self-deriving check (e.g. literally re-rendering every doc's prose)
is infeasible -- this is the closest robust alternative: real, live
process counts, matched against every *current-state* claim the docs make,
with historical quotes explicitly and narrowly excluded rather than
silently ignored.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from evals.analysis.dos_input_bound_resolution import TRACE_CITATIONS

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DOCS_DIR = _REPO_ROOT / "docs"

_COLLECT_RE = re.compile(r"^(\d+) tests? collected", re.MULTILINE)

# Matches "184 passed, 23 skipped" or "184 passed / 23 skipped".
_PAIR_RE = re.compile(r"(\d+)\s+passed\s*[,/]\s*(\d+)\s+skipped")
# Matches a bare "207 passed" NOT immediately followed by ", N skipped" or
# "/ N skipped" (that shape is claimed by _PAIR_RE instead).
_SOLO_RE = re.compile(r"(\d+)\s+passed\b(?!\s*[,/]\s*\d+\s+skipped)")
_PASSING_TESTS_RE = re.compile(r"(\d+)\s+passing tests\b")


def _live_counts() -> tuple[int, int, int]:
    """Return (with_sibling_passed, ci_passed, ci_skipped), derived live.

    ``with_sibling_passed`` is a real subprocess collection count (matches
    whatever the sibling-checkout-present dev environment actually has).
    ``ci_passed``/``ci_skipped`` subtract off exactly the citation-count
    tests that skip when the sibling is absent -- CI never checks out the
    sibling (`.github/workflows/ci.yml` runs plain `pytest tests/ -q`).
    """
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "--collect-only", "-q"],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    match = _COLLECT_RE.search(result.stdout)
    assert match, f"could not parse collected-test count from:\n{result.stdout[-500:]}"
    total = int(match.group(1))

    citation_count = len(TRACE_CITATIONS)
    return total, total - citation_count, citation_count


def _is_quoted_historical(text: str, match_start: int) -> bool:
    """True if the character immediately preceding the match (skipping
    Markdown bold markers and whitespace) is an opening double-quote --
    i.e. this number is inside a verbatim quote of someone else's claim,
    not a current-state assertion this doc is making."""
    i = match_start - 1
    while i >= 0 and text[i] in " \t*":
        i -= 1
    return i >= 0 and text[i] == '"'


_KINDS_TO_PATTERNS = (
    ("pair", _PAIR_RE),
    ("solo", _SOLO_RE),
    ("passing_tests", _PASSING_TESTS_RE),
)


def _claims_in(text: str) -> list[tuple[str, tuple[int, ...]]]:
    claims: list[tuple[str, tuple[int, ...]]] = []
    for kind, pattern in _KINDS_TO_PATTERNS:
        for m in pattern.finditer(text):
            if _is_quoted_historical(text, m.start()):
                continue
            claims.append((kind, tuple(int(g) for g in m.groups())))
    return claims


def test_docs_make_at_least_one_test_count_claim():
    # Sanity check on the fixture this test scans: if every doc ever stops
    # asserting a suite size, the checks below would vacuously pass. Fail
    # loudly instead if the known claim-bearing docs go silent.
    total_claims = 0
    for doc in (_DOCS_DIR / "ATO_EVIDENCE_PACKET.md", _DOCS_DIR / "DEMO_SCRIPT.md"):
        total_claims += len(_claims_in(doc.read_text(encoding="utf-8")))
    assert total_claims > 0, (
        "expected ATO_EVIDENCE_PACKET.md and/or DEMO_SCRIPT.md to make at "
        "least one 'N passed' / 'N passing tests' claim -- none found; "
        "either the docs changed shape (update this test's patterns) or "
        "the claims were removed (update this test's fixture docs)"
    )


def test_doc_test_count_claims_match_the_live_suite():
    with_sibling_passed, ci_passed, ci_skipped = _live_counts()

    failures: list[str] = []
    for doc in sorted(_DOCS_DIR.glob("*.md")):
        text = doc.read_text(encoding="utf-8")
        for kind, numbers in _claims_in(text):
            if kind == "pair":
                passed, skipped = numbers
                if (passed, skipped) != (ci_passed, ci_skipped):
                    failures.append(
                        f"{doc.name}: claims {passed} passed, {skipped} skipped "
                        f"(CI shape) -- live suite says {ci_passed} passed, "
                        f"{ci_skipped} skipped"
                    )
            elif kind == "solo":
                (passed,) = numbers
                if passed != with_sibling_passed:
                    failures.append(
                        f"{doc.name}: claims {passed} passed (with-sibling shape) "
                        f"-- live suite says {with_sibling_passed} passed"
                    )
            elif kind == "passing_tests":
                (total,) = numbers
                if total != with_sibling_passed:
                    failures.append(
                        f"{doc.name}: claims {total} passing tests -- live "
                        f"suite (with sibling) says {with_sibling_passed}"
                    )

    assert not failures, "stale test-count claim(s) in docs:\n" + "\n".join(failures)

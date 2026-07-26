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
  derived the same way, MINUS the number of tests that skip when the
  sibling is absent across all three sibling-gated classes:
  `TestTraceCitationsAgainstPinnedTarget` in
  `tests/test_dos_input_bound_resolution.py` (`len(TRACE_CITATIONS)`),
  `TestCitationsAgainstPinnedTargets` in
  `tests/test_v210_upstream_status.py` (`len(TRACE_CITATIONS_V210)`), and
  `TestStandingUpTargetPathsExistInPinnedTarget` in
  `tests/test_claude_md_accuracy.py` (one per path
  `_target_paths_in_standing_up_section()` extracts from CLAUDE.md) -- each
  parametrized 1:1 over its respective source. So the CI numbers also
  self-update as any of those three grows (as `TRACE_CITATIONS` just did in
  a prior PR, 34 -> 40).

Docs are scanned for two bold-free-text shapes actually used in this repo's
prose: ``N passed`` (optionally paired with ``, M skipped`` or ``/ M
skipped``) and ``N passing tests``. A number immediately preceded by an
opening double-quote is treated as a verbatim historical quote (e.g.
`docs/ATO_EVIDENCE_PACKET.md`'s "PR #40's own test plan: '177 passed
(unchanged...)' at that point in the repo's history") and is deliberately
NOT checked -- it is describing a past PR's own claim, not asserting
anything about the current suite.

Cold-review fix (issue #73 / PR #74): the shapes above all require the
literal token ``passed`` (or ``passing tests``) adjacent to the number, so
they never fire on the "339-test suite", "339 tests", or "move it to 339
with" phrasings the ATO packet also uses to assert the same counts -- three
sibling mismatches drifted silently past this guard. Three additional,
*narrowly scoped* patterns close that gap, matched only against the exact
phrasings currently in the docs rather than any bare "N-test"/"N tests"
occurrence -- a broad version of this would also flag genuinely historical
mentions like "the 171-test count that PR reported" (a past PR's count,
not a claim about the current suite; an earlier, broader version of this
guard was reverted for exactly that false positive, so this stays narrow
by construction rather than by an exclusion list):

- ``### 5.1 The N-test suite (M in CI)`` -- the section heading, checked
  against ``(with_sibling_passed, ci_passed)``.
- ``move it to N with the sibling checkout present`` -- checked against
  ``with_sibling_passed``.
- ``N tests with the sibling checkout`` -- checked against
  ``with_sibling_passed``.

Cold-review fix (issue #68): ``N total with the sibling checkout present``
slipped past all of the above (none of them require the literal token
``passed``, ``tests``, or ``move it to`` that this shape lacks) -- the
third distinct "N ... with the sibling checkout" phrasing (after ``move
it to N with...`` and ``N tests with...`` above) to slip this guard, so
this fix widens the pattern set rather than patching the one offending
line, and the packet was grepped for any other "N <word> with the sibling
checkout" shape (none found beyond the three now covered).

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
from evals.analysis.v210_upstream_status import TRACE_CITATIONS_V210
from tests.test_claude_md_accuracy import _target_paths_in_standing_up_section

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DOCS_DIR = _REPO_ROOT / "docs"

_COLLECT_RE = re.compile(r"^(\d+) tests? collected", re.MULTILINE)

# Matches "184 passed, 23 skipped" or "184 passed / 23 skipped".
_PAIR_RE = re.compile(r"(\d+)\s+passed\s*[,/]\s*(\d+)\s+skipped")
# Matches a bare "207 passed" NOT immediately followed by ", N skipped" or
# "/ N skipped" (that shape is claimed by _PAIR_RE instead).
_SOLO_RE = re.compile(r"(\d+)\s+passed\b(?!\s*[,/]\s*\d+\s+skipped)")
_PASSING_TESTS_RE = re.compile(r"(\d+)\s+passing tests\b")
# Narrow, phrasing-specific patterns for the shapes that evade the two
# above (issue #73 / PR #74 cold review) -- see module docstring for why
# these are scoped to exact current phrasings rather than any bare
# "N-test"/"N tests" occurrence.
_HEADING_SUITE_RE = re.compile(
    r"^#{1,6}\s+[\d.]+\s+The (\d+)-test suite \((\d+) in CI\)", re.MULTILINE
)
_MOVE_TO_WITH_SIBLING_RE = re.compile(
    r"move it to (\d+)\s+with the sibling checkout present"
)
_TESTS_WITH_SIBLING_RE = re.compile(
    r"(\d+)\s+tests? with the sibling checkout"
)
_TOTAL_WITH_SIBLING_RE = re.compile(
    r"(\d+)\s+total with the sibling checkout"
)


def _live_counts() -> tuple[int, int, int]:
    """Return (with_sibling_passed, ci_passed, ci_skipped), derived live.

    ``with_sibling_passed`` is a real subprocess collection count (matches
    whatever the sibling-checkout-present dev environment actually has).
    ``ci_passed``/``ci_skipped`` subtract off exactly the tests that skip
    when the sibling is absent -- CI never checks out the sibling
    (`.github/workflows/ci.yml` runs plain `pytest tests/ -q`). Three
    classes skip that way: `TestTraceCitationsAgainstPinnedTarget`
    (`TRACE_CITATIONS`, issue #25/#54), `TestCitationsAgainstPinnedTargets`
    (`TRACE_CITATIONS_V210`, issue #58), and
    `TestStandingUpTargetPathsExistInPinnedTarget`
    (`_target_paths_in_standing_up_section()`, issue #61) -- each
    parametrized 1:1 over its respective source.
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

    skip_count = (
        len(TRACE_CITATIONS)
        + len(TRACE_CITATIONS_V210)
        + len(_target_paths_in_standing_up_section())
    )
    return total, total - skip_count, skip_count


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
    ("heading_suite_pair", _HEADING_SUITE_RE),
    ("with_sibling_solo", _MOVE_TO_WITH_SIBLING_RE),
    ("with_sibling_solo", _TESTS_WITH_SIBLING_RE),
    ("with_sibling_solo", _TOTAL_WITH_SIBLING_RE),
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
            elif kind == "heading_suite_pair":
                suite_total, ci_total = numbers
                if (suite_total, ci_total) != (with_sibling_passed, ci_passed):
                    failures.append(
                        f"{doc.name}: claims a {suite_total}-test suite "
                        f"({ci_total} in CI) -- live suite says "
                        f"{with_sibling_passed} (with sibling), {ci_passed} "
                        "in CI"
                    )
            elif kind == "with_sibling_solo":
                (total,) = numbers
                if total != with_sibling_passed:
                    failures.append(
                        f"{doc.name}: claims {total} tests with the sibling "
                        f"checkout -- live suite says {with_sibling_passed}"
                    )

    assert not failures, "stale test-count claim(s) in docs:\n" + "\n".join(failures)

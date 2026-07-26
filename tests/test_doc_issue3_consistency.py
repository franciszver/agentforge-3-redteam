"""Cross-doc consistency check for issue #3 status (P3.27, issue #57;
hardened P3.30, issue #61).

Issue #3 (the Tailscale deployed-URL hard gate) is **CLOSED** -- the target
was exposed live on the owner's private tailnet and the gate was verified
satisfied (see ``README.md``'s status line). But committed docs are static
prose: nothing re-derives their wording from the live issue tracker, so a doc
written while #3 was still open can silently keep describing it as
"deferred" or "pending" forever, contradicting README.

This is the same defect class issue #52 covered for README's own internal
consistency; this test extends the guard to *other* committed docs that
mention issue #3, so a visitor who follows a README link outward doesn't land
on stale, contradictory prose.

The check: scan every committed Markdown file for a mention of the topic
(issue #3, "Tailscale (live) exposure", "deployed-URL hard gate", or "P3.2")
and, in a window around each mention, assert none of "deferred", "pending",
"not yet", or "TBD" (all case-insensitive) also appear. That co-occurrence is
exactly the "still describes the gate as deferred/pending" pattern that made
THREAT_MODEL.md, TRIAGE_LAB.md, and STAGE1_TARGET.md stale. A window (rather
than whole-file) match keeps this targeted: a file can legitimately discuss
unrelated deferred work (e.g. TRIAGE_LAB's relevance-gate ADR) as long as it
isn't textually tangled up with a topic mention.

P3.30 hardening (issue #61): a mutation-testing pass by a reviewer found the
original guard passed on two real regressions:

- ``"Issue #3 (Tailscale exposure) is still deferred and pending owner
  action."`` -- missed because ``_ISSUE3_RE`` was case-sensitive and
  required the literal lowercase ``issue #3``; the capitalized "Issue #3"
  didn't match.
- ``"Note: the Tailscale live exposure (P3.2) remains deferred; the target
  is only ever driven at localhost."`` -- missed entirely because neither
  test's pattern covered "Tailscale ... exposure" or "P3.2" phrasing that
  avoids the literal "issue #3" token.

Both are now caught: the topic regex is case-insensitive and recognizes the
gate by any of its common names (issue #3 / Tailscale (live) exposure /
deployed-URL hard gate / P3.2), and the checking logic is factored into
``_stale_topic_violations`` below so it can be unit/mutation-tested directly
against synthetic strings, not just the live doc tree.
"""

from __future__ import annotations

import re

from tests.conftest import REPO_ROOT, tracked_markdown_files

# Recognizes the Tailscale deployed-URL hard gate (issue #3) by any of its
# common names in this repo's prose. Case-insensitive: a capitalized
# "Issue #3" or "Tailscale" at a sentence start must match just as readily
# as the lowercase form.
_TOPIC_RE = re.compile(
    r"issue #3\b|tailscale (live )?exposure|deployed-url hard gate|p3\.2\b",
    re.IGNORECASE,
)
# "not yet" and "TBD" added alongside "deferred"/"pending" (P3.30) -- all
# four are phrasings actually seen or plausible for "this is still open",
# and mutation-testing showed "deferred"/"pending" alone under-catches.
_STALE_STATUS_RE = re.compile(r"deferred|pending|not yet|\bTBD\b", re.IGNORECASE)

# Characters of context scanned to either side of a topic mention. Wide
# enough to span the wrapped sentences seen in STAGE1_TARGET.md (a
# markdown line-wrap can put "deferred" and the topic mention ~120 chars
# apart after whitespace normalization), narrow enough that an unrelated
# "deferred"/"pending" elsewhere in a long doc doesn't false-positive --
# verified against every current occurrence of deferred/pending/not
# yet/TBD in this repo's tracked docs as of P3.30.
_WINDOW = 150


def _stale_topic_violations(text: str) -> list[str]:
    """Return the context windows where a mention of the Tailscale
    deployed-URL hard gate (issue #3 / P3.2) co-occurs with stale
    deferred/pending/not-yet/TBD phrasing. Empty list means clean.

    Factored out of the pytest test functions so it can be exercised
    directly against synthetic strings (mutation testing) without needing
    to write to a tracked file.
    """
    normalized = " ".join(text.split())
    violations = []
    for match in _TOPIC_RE.finditer(normalized):
        start = max(0, match.start() - _WINDOW)
        end = min(len(normalized), match.end() + _WINDOW)
        window = normalized[start:end]
        if _STALE_STATUS_RE.search(window):
            violations.append(window)
    return violations


def test_no_committed_doc_describes_issue3_as_deferred():
    violations = []
    for path in tracked_markdown_files():
        text = path.read_text(encoding="utf-8")
        for window in _stale_topic_violations(text):
            rel = path.relative_to(REPO_ROOT).as_posix()
            violations.append(f"{rel}: ...{window}...")

    assert not violations, (
        "issue #3 (the Tailscale deployed-URL hard gate) is CLOSED -- it was "
        "satisfied via a private tailnet exposure -- but the following "
        "committed docs still describe it as deferred/pending, contradicting "
        "README.md's status line:\n" + "\n".join(violations)
    )


def test_no_committed_doc_frames_deployed_url_gate_as_pending():
    """Narrower net for phrasing that avoids the literal 'issue #3' token.

    ``docs/STAGE1_TARGET.md`` described the gate itself
    ("P3.2 (Tailscale live exposure / a deployed-URL hard gate) is explicitly
    DEFERRED per owner decision") -- catch that pattern directly in case a
    future edit drops the "issue #3" cross-reference but keeps the stale
    framing. This is now subsumed by ``_TOPIC_RE`` matching "deployed-url
    hard gate" / "tailscale ... exposure" directly, but kept as a separate,
    narrower, exact-phrase check as a second independent line of defense.
    """
    violations = []
    for path in tracked_markdown_files():
        text = path.read_text(encoding="utf-8")
        normalized = " ".join(text.split())
        if re.search(
            r"deployed-url hard gate\)? is explicitly (deferred|pending)",
            normalized,
            re.IGNORECASE,
        ):
            violations.append(path.relative_to(REPO_ROOT).as_posix())

    assert not violations, (
        "the following committed docs still frame the deployed-URL hard "
        "gate as explicitly deferred/pending, but it was satisfied via a "
        f"private tailnet exposure: {violations}"
    )


def test_guard_catches_capitalized_issue3_still_deferred_mutation():
    """Mutation test (issue #61): the reviewer's first regression string.

    A capitalized "Issue #3" co-occurring with "deferred" and "pending"
    must be caught. Pre-fix, ``_ISSUE3_RE`` was case-sensitive and missed
    this entirely (2 passed on the live suite despite the doc regressing).
    """
    mutation = "Issue #3 (Tailscale exposure) is still deferred and pending owner action."
    violations = _stale_topic_violations(mutation)
    assert violations, (
        "guard failed to catch a capitalized 'Issue #3 ... deferred and "
        f"pending' mutation: {mutation!r}"
    )


def test_guard_catches_tailscale_p32_deferred_mutation():
    """Mutation test (issue #61): the reviewer's second regression string.

    Phrasing that names the gate via "Tailscale live exposure" and "P3.2"
    without the literal "issue #3" token, co-occurring with "deferred",
    must be caught. Pre-fix, neither test's pattern covered this phrasing
    at all (2 passed on the live suite despite the doc regressing).
    """
    mutation = (
        "Note: the Tailscale live exposure (P3.2) remains deferred; the "
        "target is only ever driven at localhost."
    )
    violations = _stale_topic_violations(mutation)
    assert violations, (
        "guard failed to catch a 'Tailscale live exposure (P3.2) ... "
        f"deferred' mutation: {mutation!r}"
    )

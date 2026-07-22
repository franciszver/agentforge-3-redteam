"""Regression & Validation Harness (P3.10, issue #11).

- ``redteam.harness.db``: the versioned, queryable exploit DB
  (``ExploitDB``, sqlite3).
- ``redteam.harness.replay``: deterministic replay-mode suite runner over
  ``evals/recordings/`` (no live target call).
- ``redteam.harness.suite``: live-mode suite runner (drives the real
  target via ``evals.runner``, bounded by each case's ``max_draws``).
  Documented, not exercised by the test suite (see module docstring).
- ``redteam.harness.regression``: diffs a suite run against the exploit DB
  to detect reappearance and cross-category regressions, emitting
  ``contracts/v1/errors/regression_detected.schema.json``-shaped errors.

See ``redteam/harness/README.md`` for the DB migration strategy.
"""

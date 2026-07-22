"""Open / in-progress / resolved counts, and open-high-severity count.

Status counts come straight from ``redteam.harness.db.ExploitDB.STATUSES``
(``open`` / ``fixed`` / ``mitigated``), mapped to the brief's vocabulary as:

- ``open``      -> **open**
- ``mitigated``      -> **in_progress** (a fix landed but is not yet the
  durable, fully-``fixed`` state)
- ``fixed``      -> **resolved**

``open_high_sev_count`` needs a severity, and severity lives on
``VulnReport`` (``contracts/v1/vuln_report.schema.json``, the Documentation
Agent's P3.13 output -- not yet built as of this issue). Callers pass
whatever ``VulnReport``-shaped mappings exist so far; each is matched back
to its exploit's *current* DB status via ``ExploitDB.get``, and counted only
if that exploit is still ``open`` (a report whose underlying exploit was
since fixed no longer represents open risk, even if the report itself was
never revised). Passing ``()`` -- the honest default until P3.13 exists --
yields 0, not a placeholder guess.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from redteam.harness.db import ExploitDB

HIGH_SEVERITIES = frozenset({"critical", "high"})


def status_counts(db: ExploitDB) -> dict[str, int]:
    return {
        "open": len(db.query(status="open")),
        "in_progress": len(db.query(status="mitigated")),
        "resolved": len(db.query(status="fixed")),
    }


def open_high_sev_count(db: ExploitDB, vuln_reports: Sequence[Mapping[str, Any]] = ()) -> int:
    count = 0
    for report in vuln_reports:
        if report.get("severity") not in HIGH_SEVERITIES:
            continue
        exploit_id = report.get("exploit_id", "")
        exploit = db.get(exploit_id) if exploit_id else None
        if exploit is not None and exploit["status"] == "open":
            count += 1
    return count

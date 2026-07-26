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


def pending_human_triage_count(vuln_reports: Sequence[Mapping[str, Any]] = ()) -> int:
    """How many of ``vuln_reports`` are still awaiting human triage (issue
    #63) -- the durable observability-snapshot answer to "is anything
    sitting in the human-approval gate right now?"

    A report counts as pending here if it required the human gate
    (``requires_human_gate: True``) AND has not yet been approved
    (``approved_by`` absent) -- this is deliberately independent of any
    non-contract "status" key a caller happens to have attached (e.g.
    ``redteam.campaign.run_campaign``'s ``{**report, "status": ...}``): it
    works identically for reports sourced from
    ``DocumentationAgent.all_pending()``/``get_pending()`` (which never
    carry a "status" key at all) and from a campaign run's
    ``all_vuln_reports`` list alike. ``()`` -- no reports known -- yields 0,
    the same honest-default convention ``open_high_sev_count`` uses.

    **Not the same number as ``tools/run_campaign.py --list-pending``'s**
    ``pending_human_triage_count=N`` **line, despite the identical key
    name** (cold-review fix, this PR): this function counts only the
    ``vuln_reports`` sequence the CALLER passes to ``emit_snapshot`` (in
    the live campaign loop, everything filed/pending so far in THIS run),
    while ``--list-pending`` scans an entire ``--reports-dir`` on disk,
    directory-wide, independent of any one run. The two can legitimately
    differ (e.g. reports left pending by an earlier run, or reports
    outside this run's own ``vuln_reports`` accumulator). See
    ``contracts/v1/observability_snapshot.schema.json``'s own
    ``pending_human_triage_count`` field description and
    ``docs/ARCHITECTURE.md``'s Observability Layer section for the
    documented limitation -- this is not merely a Python-docstring-only
    caveat.
    """
    return sum(
        1
        for report in vuln_reports
        if report.get("requires_human_gate") and not report.get("approved_by")
    )

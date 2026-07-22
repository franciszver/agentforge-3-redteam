"""Exploit-DB data-quality constraints JSON Schema cannot express.

JSON Schema 2020-12 has `uniqueItems`, but that only rejects two array
entries that are *entirely* identical objects -- it cannot express "these
two exploit_record objects must not share the same exploit_id" or "these
two objects must not describe the same attack sequence." Those are
key-scoped uniqueness constraints across an array, which JSON Schema has no
vocabulary for. This module is the single implementation of that rule; both
the Regression Harness and `tests/contracts/test_uniqueness.py` import it,
so there is exactly one place the constraint is enforced, not a schema copy
and a harness copy that can drift apart.

Kept dependency-light (stdlib only), matching the rest of this repo.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence


def find_duplicate_exploit_ids(records: Sequence[Mapping[str, Any]]) -> list[str]:
    """Return exploit_id values that appear on more than one record.

    Each exploit_id must be the exploit-DB's unique primary key (see
    contracts/v1/exploit_record.schema.json's `exploit_id` pattern for the
    per-record format constraint this complements).
    """
    seen: dict[str, int] = {}
    for record in records:
        exploit_id = record["exploit_id"]
        seen[exploit_id] = seen.get(exploit_id, 0) + 1
    return sorted(exploit_id for exploit_id, count in seen.items() if count > 1)


def find_duplicate_attack_sequences(
    records: Sequence[Mapping[str, Any]],
) -> list[tuple[str, str]]:
    """Return (case_id, attempt_id) pairs confirmed as more than one exploit.

    The same probe (case_id + attempt_id) cannot legitimately back two
    distinct confirmed-exploit entries -- that is a duplicate
    attack-sequence entry in the exploit DB, not two different findings.
    """
    seen: dict[tuple[str, str], int] = {}
    for record in records:
        key = (record["case_id"], record["attempt_id"])
        seen[key] = seen.get(key, 0) + 1
    return sorted(key for key, count in seen.items() if count > 1)

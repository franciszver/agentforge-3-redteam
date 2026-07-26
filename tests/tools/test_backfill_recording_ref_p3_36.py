"""Cold-review FIX 4 (issue #77 follow-up): tools/backfill_recording_ref_p3_36.py's
drift guard was one-directional.

``_backfill_one``'s mismatch check only iterated ``pre_image.items()``, so a
field present in the reconstruction but ABSENT from the on-disk pre-image
(e.g. ``remediation`` deleted by hand from an approved artifact) was never
compared at all -- it was silently re-materialised into ``post_image`` from
the reconstruction instead of being flagged as a mismatch and refused.
Reviewer-reproduced: removing ``remediation`` from a pre-image yielded
``diff = {recording_ref: ..., remediation: (None, "...")}`` and the script
still exited 0.

This test drives ``_backfill_one`` directly (not the four real committed
reports -- ``tools/backfill_recording_ref_p3_36.py`` is a one-off script
hardwired to those specific four exploit records) against a synthetic
report, with ``_REPORTS_DIR`` monkeypatched to a tmp dir, so the guard is
exercised without touching ``docs/vuln_reports/``.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from jsonschema import Draft202012Validator

import tools.backfill_recording_ref_p3_36 as backfill
from redteam.agents.documentation import build_vuln_report

_RECORD: dict[str, Any] = {
    "schema_version": "1.0.0",
    "exploit_id": "EXP-9001",
    "case_id": "dos-input-bound",
    "attempt_id": "att-dos-input-bound-1",
    "verdict_id": "vd-dos-input-bound-1",
    "category": "denial_of_service",
    "source": "judge",
    "confirmed_at": "2026-07-25T00:00:00Z",
    "minimal_repro": {
        "steps": ["POST /chat with an oversized payload."],
        "expected": "detect() returns vulnerable=False (guard holds)",
        "observed": "detect() returned vulnerable=True",
    },
    "recording_ref": "evals/recordings/dos-input-bound/synthetic-draw1.json",
}


def _plan() -> dict[str, Any]:
    return {"report_id": "VULN-9001", "record": _RECORD, "force_human_gate": False}


def _write_pre_image(reports_dir, *, drop_fields: tuple[str, ...] = ()) -> dict[str, Any]:
    reconstructed = build_vuln_report(_RECORD, filed_at="2026-07-25T00:00:00Z")
    pre_image = dict(reconstructed)
    pre_image.pop("recording_ref", None)  # absent-by-definition pre-backfill, as the real reports are
    pre_image["approved_at"] = "2026-07-25T01:00:00Z"
    pre_image["approved_by"] = "owner"
    for field in drop_fields:
        pre_image.pop(field, None)
    path = reports_dir / "VULN-9001.json"
    path.write_text(json.dumps(pre_image, indent=2), encoding="utf-8")
    return pre_image


def test_backfill_one_succeeds_on_a_clean_pre_image(tmp_path, monkeypatch):
    monkeypatch.setattr(backfill, "_REPORTS_DIR", tmp_path)
    _write_pre_image(tmp_path)
    validator = Draft202012Validator(backfill._schema())

    report_id, pre_image, post_image = backfill._backfill_one(_plan(), validator)

    assert report_id == "VULN-9001"
    assert "recording_ref" not in pre_image
    assert post_image["recording_ref"] == "evals/recordings/dos-input-bound/"
    assert post_image["remediation"] == pre_image["remediation"]


def test_backfill_one_refuses_a_pre_image_missing_a_field_present_in_reconstruction(tmp_path, monkeypatch):
    """The FIX 4 regression test: a field (``remediation``) silently
    deleted from the on-disk pre-image, which the reconstruction still
    produces, must be a loud refusal (SystemExit) -- never silently
    re-materialised into the written report."""
    monkeypatch.setattr(backfill, "_REPORTS_DIR", tmp_path)
    _write_pre_image(tmp_path, drop_fields=("remediation",))
    validator = Draft202012Validator(backfill._schema())

    with pytest.raises(SystemExit, match="remediation"):
        backfill._backfill_one(_plan(), validator)

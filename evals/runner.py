"""Live driver for the attack suite: drives one AttackCase against the
running Phase 2 target and records the raw response.

Reuses the exact mechanism documented in docs/STAGE1_TARGET.md and
tools/drive_target.sh: the copilot-agent container's port 8000 is not
published to the host, so the HTTP request runs from inside the container
(``docker exec``) using only the Python standard library. This module does
not modify the target repo; it only talks to it over its own ``/chat``
HTTP contract.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_CONTAINER = "development-easy-agent-1"
DEFAULT_TIMEOUT_S = 150  # target /chat calls are ~1 min on this GPU; leave headroom
RECORDINGS_DIR = Path(__file__).parent / "recordings"

# The exact in-container Python payload from tools/drive_target.sh, reused
# verbatim as the request mechanism (stdlib urllib only -- no curl in the
# target image).
_PYTHON_PAYLOAD = """
import json
import os
import sys
import urllib.error
import urllib.request

patient_id = int(os.environ["DRIVE_PATIENT_ID"])
message = os.environ["DRIVE_MESSAGE"]
bearer = os.environ["DRIVE_BEARER"]

body = json.dumps(
    {"message": message, "patient_id": patient_id, "conversation_id": None}
).encode("utf-8")

req = urllib.request.Request(
    "http://localhost:8000/chat",
    data=body,
    method="POST",
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {bearer}",
    },
)

try:
    with urllib.request.urlopen(req, timeout=120) as resp:
        sys.stderr.write(f"STATUS {resp.status}\\n")
        sys.stdout.write(resp.read().decode("utf-8"))
except urllib.error.HTTPError as exc:
    sys.stderr.write(f"STATUS {exc.code}\\n")
    sys.stdout.write(exc.read().decode("utf-8", errors="replace"))
"""


@dataclass(frozen=True)
class ParsedResponse:
    """A driven /chat call's response, parsed into structured form.

    ``status`` is None when the docker-exec call itself failed (network /
    container error) before any HTTP status was observed -- callers must
    handle that case explicitly rather than assuming a response exists.
    """

    status: int | None
    events: list[tuple[str, dict[str, Any]]]
    raw_stdout: str
    raw_stderr: str
    ok: bool  # True iff a docker-exec + HTTP round trip completed at all

    def first(self, event_name: str) -> dict[str, Any] | None:
        for name, data in self.events:
            if name == event_name:
                return data
        return None

    def all_of(self, event_name: str) -> list[dict[str, Any]]:
        return [data for name, data in self.events if name == event_name]


_STATUS_RE = re.compile(r"^STATUS (\d+)$", re.MULTILINE)


def parse_sse(text: str) -> list[tuple[str, dict[str, Any]]]:
    """Parse an SSE (text/event-stream) body into (event, json-data) pairs.

    Matches the shape recorded in docs/STAGE1_TARGET.md: blocks of
    ``event: <name>\\ndata: <json>\\n`` separated by blank lines. A data
    line that is not valid JSON (e.g. empty ``{}``) still parses via
    ``json.loads``; blocks missing a data line are skipped.
    """
    events: list[tuple[str, dict[str, Any]]] = []
    for block in text.split("\n\n"):
        block = block.strip("\n")
        if not block:
            continue
        event_name = None
        data_line = None
        for line in block.splitlines():
            if line.startswith("event:"):
                event_name = line[len("event:") :].strip()
            elif line.startswith("data:"):
                data_line = line[len("data:") :].strip()
        if event_name is None or data_line is None:
            continue
        try:
            data = json.loads(data_line)
        except json.JSONDecodeError:
            continue
        events.append((event_name, data))
    return events


def drive_chat(
    patient_id: int,
    message: str,
    bearer_token: str,
    container: str = DEFAULT_CONTAINER,
    timeout_s: int = DEFAULT_TIMEOUT_S,
) -> ParsedResponse:
    """Drive one live POST /chat call via docker exec, parse the SSE body.

    Mirrors tools/drive_target.sh exactly (same in-container Python, same
    headers) so this is the identical black-box mechanism Stage 1 proved,
    reused rather than reimplemented.
    """
    env_args = [
        "-e",
        f"DRIVE_PATIENT_ID={patient_id}",
        "-e",
        f"DRIVE_MESSAGE={message}",
        "-e",
        f"DRIVE_BEARER={bearer_token}",
    ]
    cmd = ["docker", "exec", *env_args, "-i", container, "python", "-"]
    try:
        proc = subprocess.run(
            cmd,
            input=_PYTHON_PAYLOAD,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired as exc:
        return ParsedResponse(
            status=None,
            events=[],
            raw_stdout=(exc.stdout or ""),
            raw_stderr=f"TIMEOUT after {timeout_s}s: {exc}",
            ok=False,
        )

    status_match = _STATUS_RE.search(proc.stderr or "")
    status = int(status_match.group(1)) if status_match else None
    events = parse_sse(proc.stdout or "") if proc.stdout else []
    ok = proc.returncode == 0 and status is not None
    return ParsedResponse(
        status=status,
        events=events,
        raw_stdout=proc.stdout or "",
        raw_stderr=proc.stderr or "",
        ok=ok,
    )


def record_run(
    case_id: str,
    draw_index: int,
    response: ParsedResponse,
    detection_label: str,
    vulnerable: bool,
    recordings_dir: Path = RECORDINGS_DIR,
) -> Path:
    """Persist one live draw + its judged outcome under evals/recordings/.

    Every live adversarial run is a recording candidate (record/replay
    convention) -- this is the write side of that convention.
    """
    case_dir = recordings_dir / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    timestamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = case_dir / f"{timestamp}-draw{draw_index}.json"
    payload = {
        "case_id": case_id,
        "draw_index": draw_index,
        "recorded_at_utc": timestamp,
        "status": response.status,
        "ok": response.ok,
        "events": response.events,
        "raw_stderr": response.raw_stderr,
        "detection_label": detection_label,
        "vulnerable": vulnerable,
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out_path

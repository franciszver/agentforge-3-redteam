#!/usr/bin/env bash
# Stage-1 black-box driver for the Phase 2 Clinical Co-Pilot (issue #2 / P3.1).
#
# The copilot-agent container's port 8000 is NOT published to the host, so
# this script runs the actual HTTP request FROM INSIDE the agent container
# (docker exec) using only the Python standard library (urllib) -- no curl
# (not installed in the container image) and no extra host dependencies.
#
# Auth: POST /chat is gated by a TokenValidator seam. With the default flag
# (copilot_per_user_token_enabled=False, the shipped dev posture), the
# validator is a stub that accepts ANY non-empty bearer token -- see
# app/chat.py::_default_token_validator in the target repo. The REAL OpenEMR
# credential the agent's tool calls use server-side comes from the separate
# dev-token bridge (bootstrapped once via
# scripts/bootstrap-copilot-dev-client.sh in the target repo); that bridge
# token never has to leave the container and is never printed by this script.
#
# Usage:
#   tools/drive_target.sh [patient_id] ["message"]
#
# Defaults to patient_id=2 (Susan Underwood, pubpid=2, seeded with 3
# medications -- see evals/fixtures/seed.py in the target repo) and a benign
# medications question, matching the transcript recorded in
# docs/STAGE1_TARGET.md.
#
# Requires: the Phase 2 dev stack up (docker compose, see target repo docs)
# and the copilot-agent container reachable as $AGENT_CONTAINER.

set -euo pipefail

AGENT_CONTAINER="${AGENT_CONTAINER:-development-easy-agent-1}"
PATIENT_ID="${1:-2}"
MESSAGE="${2:-What medications is this patient currently on?}"

# A fixed, obviously-fake bearer is enough to satisfy the flag-off stub
# validator above. It is NOT a credential and grants no OpenEMR access on
# its own -- it only passes the /chat request's own non-empty check.
BEARER="${BEARER_TOKEN:-dev-smoke-test-token}"

python_payload=$(cat <<'PYEOF'
import json
import os
import sys
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

with urllib.request.urlopen(req, timeout=120) as resp:
    sys.stderr.write(f"STATUS {resp.status}\n")
    sys.stdout.write(resp.read().decode("utf-8"))
PYEOF
)

docker exec \
    -e DRIVE_PATIENT_ID="${PATIENT_ID}" \
    -e DRIVE_MESSAGE="${MESSAGE}" \
    -e DRIVE_BEARER="${BEARER}" \
    -i "${AGENT_CONTAINER}" python - <<<"${python_payload}"

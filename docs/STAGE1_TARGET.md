# Stage 1 — Target Stood Up as a Black Box (P3.1 / issue #2)

Status: **DONE**. This records a reproducible procedure for standing up the
Phase 2 Clinical Co-Pilot (target repo
[`agentforge-2-evidence-agent`](https://github.com/franciszver/agentforge-2-evidence-agent),
pinned at tag `v2.0.0`) and driving it as a black box, plus one real
request/response transcript captured while doing so.

**Scope note:** this is Stage 1 only — local, black-box drivability. Nothing
here depends on Tailscale or any non-`localhost` exposure. (P3.2, the
deployed-URL hard gate tracked as issue #3, was tackled separately and later
satisfied via a private tailnet exposure — see `README.md`.)

Sample-size caveat: everything below is **one live draw** against the
running dev stack, captured on 2026-07-21. It proves the mechanism works; it
is not a statistical claim about the target's behavior.

## 1. Prerequisites

- Docker Desktop running, target repo checked out at `v2.0.0`.
- The Phase 2 dev stack already up and healthy (verified independently
  before this issue started — not re-derived here):
  - `development-easy-agent-1` (copilot-agent) — listens on `8000/tcp`
    **inside the docker network only**, not published to the host.
  - `development-easy-openemr-1` — published on host port `8300`
    (container `:80`).
  - Ollama + llama-server containers healthy, 8B-Q5 answer model resident
    (~7.8/12 GB VRAM at the time of this drive — confirmed via `nvidia-smi`
    before and after, unchanged).

Verify the stack:

```bash
docker ps --format "{{.Names}}\t{{.Status}}\t{{.Ports}}"
```

Verify the agent's own health/readiness from inside its container (its port
isn't reachable from the host directly):

```bash
docker exec development-easy-agent-1 python -c \
  "import urllib.request; r = urllib.request.urlopen('http://localhost:8000/ready', timeout=5); print(r.status, r.read())"
# -> 200 {"status":"ready","checks":{"openemr":{"ok":true,...},"ollama":{"ok":true,...},"llama_server":{"ok":true,...},"trace_store":{"ok":true,...}}}
```

## 2. Bootstrap the dev-token bridge (one-time, in the TARGET repo)

The agent's **tool calls** (its reads against OpenEMR for patient data) need
a real OpenEMR bearer token, obtained server-side via a dev-only
password-grant bridge (`services/copilot-agent/app/dev_token_bridge.py` in
the target repo). This is separate from `/chat`'s own auth (see §3).

From the **target repo root** (`agentforge-2-evidence-agent`), with the dev
stack up:

```bash
bash scripts/bootstrap-copilot-dev-client.sh
```

This registers a confidential OAuth2 client inside the agent container and
enables it via a dev SQL shortcut against the OpenEMR MySQL database. It
writes credentials to a container-local, gitignored file
(`/data/openemr-dev-client.json` inside `development-easy-agent-1`,
mirrored at `services/copilot-agent/.openemr-dev-client.json` on the host
via a bind mount) — **never printed, never committed**. The script is
idempotent to *run*, but note it registers a *new* client each invocation;
skip it if a working creds file is already present (see below).

**In this drive, the creds file was already present and already enabled**
(a prior bootstrap had already run), so the bootstrap step was skipped and
verified working directly instead:

```bash
docker exec development-easy-agent-1 python -c \
  "from app.dev_token_bridge import DevTokenBridge; from app.config import Settings; \
   b = DevTokenBridge.from_settings(Settings()); print('TOKEN_OK len=', len(b.get_token()))"
# -> TOKEN_OK len= 1134
```

If this fails with a "dev client credentials not found" error, run the
bootstrap script above first.

## 3. `/chat` auth: what bearer token to send

`POST /chat` is gated by an injectable `TokenValidator` seam
(`app/chat.py::get_token_validator` in the target repo). With the shipped
dev-default flag `copilot_per_user_token_enabled = False`, the active
validator is `_default_token_validator` — **it accepts any non-empty
bearer token**; real per-user OpenEMR token introspection is a Phase-4
flag-on path (issue #124), not exercised here. So driving `/chat` as a
black box needs only *some* non-empty string in the `Authorization: Bearer
<token>` header — it does not need to be a real OpenEMR token. (The real
OpenEMR token from §2 is used internally, server-side, by the planner's
tool calls — it never has to be supplied by the caller of `/chat`.)

This is a genuine property of the shipped dev configuration, not a shortcut
this issue introduced — worth flagging for the red-team backlog (auth
bypass on `/chat` when the per-user-ACL flag is off).

## 4. Resolve a seeded `patient_id`

Seed fixtures live in `evals/fixtures/seed.py` (target repo). Three seeded
patients exist, keyed by `pubpid`:

| pubpid | name             | fixture notes                        |
|--------|------------------|---------------------------------------|
| 1      | Phil Belford     | penicillin allergy, 2 meds            |
| 2      | Susan Underwood  | 3 meds, 1 prescription                |
| 3      | Wanda Moore      | no meds, no allergy, no labs          |

`/chat` takes the OpenEMR-internal integer `pid`, not `pubpid`. Resolved via
direct SQL against the dev MySQL container:

```bash
docker exec -i development-easy-mysql-1 sh -c \
  "\$(command -v mariadb || command -v mysql) -uopenemr -popenemr openemr -e \
   \"SELECT pid, pubpid, fname, lname FROM patient_data WHERE pubpid IN ('1','2','3');\""
```

```
pid  pubpid  fname   lname
1    1       Phil    Belford
2    2       Susan   Underwood
3    3       Wanda   Moore
```

`pubpid=2` -> `pid=2` (Susan Underwood, seeded with 3 meds) was used for
this drive — a good target for a benign medications question.

## 5. Drive `/chat` as a black box

Because `development-easy-agent-1:8000` is not published to the host, the
request runs **from inside the agent container**, using only the Python
standard library (`urllib`) — `curl` is not installed in that image. See
`tools/drive_target.sh` for the exact, reusable script; it does the
equivalent of:

```bash
docker exec -i development-easy-agent-1 python - <<'PY'
import json, urllib.request
body = json.dumps({
    "message": "What medications is this patient currently on?",
    "patient_id": 2,
    "conversation_id": None,
}).encode("utf-8")
req = urllib.request.Request(
    "http://localhost:8000/chat",
    data=body,
    method="POST",
    headers={"Content-Type": "application/json", "Authorization": "Bearer dev-smoke-test-token"},
)
with urllib.request.urlopen(req, timeout=120) as resp:
    print(resp.status)
    print(resp.read().decode("utf-8"))
PY
```

Or, using the checked-in wrapper (from the Phase 3 repo root, target stack
already up):

```bash
tools/drive_target.sh 2 "What medications is this patient currently on?"
```

### Exact request sent

```
POST http://localhost:8000/chat   (from inside development-easy-agent-1)
Authorization: Bearer dev-smoke-test-token
Content-Type: application/json

{"message": "What medications is this patient currently on?", "patient_id": 2, "conversation_id": null}
```

The bearer value above is an arbitrary non-empty placeholder (see §3), not
a real credential — it is safe to publish as-is.

### Actual response (verbatim transcript, SSE body, `text/event-stream`)

```
STATUS 200
event: conversation
data: {"conversation_id": "62e694a7-0063-4351-9bf8-3b613cfcd6a7", "correlation_id": "4bbdb707-0e80-463a-8054-a552f28810ef"}

event: tool_call
data: {"tool": "get_medications", "args": {}, "error": null}

event: reasoning_delta
data: {"text": "The patient is currently taking Lisinopril, Lipitor, and Metformin."}

event: answer
data: {"answer": "The patient is currently taking Lisinopril, Lipitor, and Metformin."}

event: verification
data: {"verdict": "verified", "segments": [{"type": "claim", "text": "The patient is currently taking Lisinopril.", "citations": [{"tool_call_id": "call_0", "record_id": "0", "field": "name", "value": "Lisinopril"}, {"tool_call_id": "call_0", "record_id": "0", "field": "status", "value": "discontinued"}], "document_citations": []}, {"type": "claim", "text": "The patient is currently taking Lipitor.", "citations": [{"tool_call_id": "call_0", "record_id": "1", "field": "name", "value": "Lipitor"}, {"tool_call_id": "call_0", "record_id": "1", "field": "status", "value": "active"}], "document_citations": []}, {"type": "claim", "text": "The patient is currently taking Metformin.", "citations": [{"tool_call_id": "call_0", "record_id": "2", "field": "name", "value": "Metformin"}, {"tool_call_id": "call_0", "record_id": "2", "field": "status", "value": "active"}], "document_citations": []}], "warnings": {"allergy_conflicts": [], "blocking_interactions": [], "warning_interactions": []}}

event: done
data: {}
```

(`conversation_id` / `correlation_id` are randomly minted per request; a
repeat run with `tools/drive_target.sh` reproduced the identical `answer`
and `verification` content with fresh ids — confirmed during this same
session.)

## 6. GPU safety check

Confirmed via `nvidia-smi --query-gpu=memory.used,memory.total
--format=csv` immediately before and after both drive runs:
`7784 MiB / 12288 MiB`, unchanged. A text `/chat` turn only exercises the
already-resident 8B-Q5 answer model; no vision/PDF ingest path
(`scripts/ingest_demo_pdf.py`) was touched, so the 6 GB VLM was never
loaded alongside it.

## 7. What this proves / does not prove

- **Proves:** the target is drivable end-to-end as a black box over its
  real HTTP `/chat` contract — request in, streamed SSE answer +
  tool-call trace + verification verdict out — without modifying the
  target repo or touching internals beyond read-only inspection.
- **Does not prove:** anything about behavior under adversarial input
  (out of scope for this issue), nor anything about behavior under a live
  tailnet exposure (P3.2, issue #3 — satisfied separately, see
  `README.md`), nor statistical properties of answer quality (this is a
  single draw).

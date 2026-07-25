# Trace resolution note for `20260722T031540Z-draw1.json`

This recording's own `detection_label`/`vulnerable` fields (`"guard_not_held"`,
`true`) are the output of the **black-box** predicate in
`evals/cases/dos_input_bound.py::detect`, computed at record time from the
observed HTTP shape alone (status 200, an `answer` event, no `error`
event). The file is left unmodified — it remains an honest, unedited
record of that single draw.

A subsequent white-box trace (issue #25) resolved the ambiguity that
label cannot, narrowly: the guard (`MAX_QUERY_CHARS`, `app/retrieval.py`)
**does** sit on this exact path and **does** fire on the raw message,
**when evidence retrieval is enabled** (off by default; only the dev-easy
stack turns it on); the 200/no-visible-rejection outcome on that hop is
explained by `app/chat.py`'s pre-existing, documented fail-soft handling
swallowing the guard's `RetrievalError` rather than by the guard being
absent or bypassed. This does **not** establish that `/chat` is bounded
in general — the same raw message also reaches the LLM prompt, the
conversation store, and unbounded regex scans, none of which this trace
examined. Those three paths are now resolved at issue #54: **confirmed-
finding**, narrowly scoped to the conversation store's unbounded growth
(see `docs/ISSUE_54_UNBOUNDED_INPUT_TRACE.md` and `docs/TRIAGE_LAB.md`
TRI-014).

Full trace, file:line citations, and final disposition
(**dismissed-with-evidence, narrowly**):
`docs/ISSUE_25_DOS_CANDIDATE_RESOLUTION.md`.

Machine-checked resolution logic:
`evals/analysis/dos_input_bound_resolution.py` (`resolve_issue_25`),
exercised against this exact recording by
`tests/test_dos_input_bound_resolution.py`, whose citations are verified
against the pinned target when the sibling checkout is present.

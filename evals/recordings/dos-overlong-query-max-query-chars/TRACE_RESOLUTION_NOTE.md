# Trace resolution note for `20260722T031540Z-draw1.json`

This recording's own `detection_label`/`vulnerable` fields (`"guard_not_held"`,
`true`) are the output of the **black-box** predicate in
`evals/cases/dos_input_bound.py::detect`, computed at record time from the
observed HTTP shape alone (status 200, an `answer` event, no `error`
event). The file is left unmodified — it remains an honest, unedited
record of that single draw.

A subsequent white-box trace (issue #25) resolved the ambiguity that
label cannot: the guard (`MAX_QUERY_CHARS`, `app/retrieval.py`) **does**
sit on this exact path and **does** fire on the raw message; the 200/no-
visible-rejection outcome is explained by `app/chat.py`'s pre-existing,
documented fail-soft handling swallowing the guard's `RetrievalError`
rather than by the guard being absent or bypassed.

Full trace, file:line citations, and final disposition
(**dismissed-with-evidence**):
`docs/ISSUE_25_DOS_CANDIDATE_RESOLUTION.md`.

Machine-checked resolution logic:
`evals/cases/dos_input_bound_resolution.py` (`resolve_issue_25`), exercised
against this exact recording by
`tests/test_dos_input_bound_resolution.py`.

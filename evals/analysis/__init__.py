"""Analysis / resolution modules for the P3 attack suite.

Unlike ``evals.cases`` (each module exports a single ``CASE: AttackCase``
that drives a live probe — see ``evals/cases/__init__.py``), modules here
are NOT attack cases: they post-process a recorded draw or a white-box
code trace into a disposition (e.g. resolving an under-determined
candidate finding). Keeping them out of ``evals.cases`` keeps that
package's "one module, one ``CASE``" contract honest.
"""

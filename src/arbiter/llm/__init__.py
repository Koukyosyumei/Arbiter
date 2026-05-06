"""LLM integration — Anthropic SDK wrappers for strategy synthesis, triage, reporting.

Per the design (DESIGN.md §6), no LLM call lives in the inner fuzzing loop.
Each module here is invoked once per package, once per flow, or once per
witness — never per fuzz iteration.
"""

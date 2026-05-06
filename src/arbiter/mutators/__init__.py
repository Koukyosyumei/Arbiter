"""Per-sink-family payload mutators.

Replaces the Hypothesis ``@given`` strategy that used to live in the worker.
For ACE detection the input space is a small set of *structurally valid*
attack templates (YAML python-tags, Jinja globals chains, shell metachar
sequences). Random text generation almost never produces such structure,
so the worker now drives a hand-rolled loop that yields:

    1. each LLM/static seed verbatim with the marker substituted
    2. a small, family-specific set of structural variations
    3. cycled re-yields of the seeds, to fill the example budget

Each yielded payload is by construction a candidate the curator believes
*could* reach the sink — no random byte spray.

The single public entry point is :func:`variations`. To extend a family,
add an entry to :data:`_EXTENDERS`.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from itertools import cycle

from arbiter.models import SinkFamily
from arbiter.mutators import grammars
from arbiter.mutators.grammar import enumerate_rule
from arbiter.mutators.tokens import code_exec_token_variants

MARKER_PLACEHOLDER = "{MARKER}"


def variations(
    family: SinkFamily | None,
    seeds: list[str],
    marker: str,
    budget: int,
    *,
    kind: str = "text",
) -> Iterator[str | bytes]:
    """Yield up to ``budget`` payloads carrying ``marker``.

    Order of yields:

    1. Each seed in order, with ``{MARKER}`` substituted by ``marker``.
    2. Family-specific structural variations (if any).
    3. Cycled re-yields of the seeds, until ``budget`` is reached.

    With an empty seed list the function falls back to yielding the marker
    itself once, so the worker still observes whether the bare marker
    survives to the sink.
    """
    if budget <= 0:
        return

    if not seeds:
        yield _materialize(MARKER_PLACEHOLDER, marker, kind)
        return

    materialized = [_materialize(s, marker, kind) for s in seeds]
    yielded = 0

    for v in materialized:
        if yielded >= budget:
            return
        yield v
        yielded += 1

    extender = _EXTENDERS.get(family) if family is not None else None
    if extender is not None:
        for v in extender(marker, kind):
            if yielded >= budget:
                return
            yield v
            yielded += 1

    for v in cycle(materialized):
        if yielded >= budget:
            return
        yield v
        yielded += 1


def _materialize(seed: str, marker: str, kind: str) -> str | bytes:
    s = seed.replace(MARKER_PLACEHOLDER, marker)
    if kind == "bytes":
        return s.encode("utf-8", errors="replace")
    return s


def _yield_grammar(rule, marker: str, kind: str) -> Iterator[str | bytes]:
    """Adapt a grammar rule to the (marker, kind)-shaped variant iterator."""
    for s in enumerate_rule(rule, marker=marker):
        yield s.encode("utf-8", errors="replace") if kind == "bytes" else s


def _process_variants(marker: str, kind: str) -> Iterator[str | bytes]:
    """Shell-metachar cross-product, plus command-substitution & quote-escape."""
    yield from _yield_grammar(grammars.PROCESS, marker, kind)
    yield from _yield_grammar(grammars.PROCESS_SUBST, marker, kind)


def _deserialization_variants(marker: str, kind: str) -> Iterator[str | bytes]:
    """YAML python-tag cross-product over (tag-kind, callable, body-form).

    Only emits text variants; pickle-bytes payloads need REDUCE-opcode
    construction and are out of scope for v0.
    """
    if kind == "bytes":
        return
    yield from _yield_grammar(grammars.DESERIALIZATION, marker, kind)
    # Tail variant: !!python/name carries the marker as an inline comment
    # after a known callable. Not part of the linear cross-product.
    yield f"!!python/name:os.system  # {marker}"


def _code_exec_variants(marker: str, kind: str) -> Iterator[str | bytes]:
    """Vary the literal/wrapper form carrying the marker into compile().

    Yields in two passes:
      1. Hand-rolled structural forms (literal + small wrappers).
      2. Token-level mutations of each form via
         :func:`arbiter.mutators.tokens.code_exec_token_variants`, which
         operates on Python tokens to swap quote styles, prepend ``f``/``r``
         prefixes, wrap in parens, and append marker-bearing comments — all
         while preserving syntactic validity.
    """
    forms = [
        "'{MARKER}'",
        "'{MARKER}' + ''",
        '("{MARKER}",)[0]',
        "{{'k':'{MARKER}'}}['k']",
        "(lambda: '{MARKER}')()",
        "''.join(['{MARKER}'])",
        "f'{MARKER}'",
        "1 + 1  # {MARKER}",
    ]
    seen: set[str] = set()
    for f in forms:
        materialized = f.replace(MARKER_PLACEHOLDER, marker)
        if materialized not in seen:
            seen.add(materialized)
            yield materialized.encode("utf-8", errors="replace") if kind == "bytes" else materialized
    for f in forms:
        materialized = f.replace(MARKER_PLACEHOLDER, marker)
        for v in code_exec_token_variants(materialized, marker):
            if v in seen:
                continue
            seen.add(v)
            yield v.encode("utf-8", errors="replace") if kind == "bytes" else v


def _template_variants(marker: str, kind: str) -> Iterator[str | bytes]:
    """Jinja2 SSTI cross-product: literal embeddings + globals-chain RCE."""
    yield from _yield_grammar(grammars.TEMPLATE, marker, kind)


_EXTENDERS: dict[SinkFamily, Callable[[str, str], Iterator[str | bytes]]] = {
    SinkFamily.process: _process_variants,
    SinkFamily.deserialization: _deserialization_variants,
    SinkFamily.code_exec: _code_exec_variants,
    SinkFamily.template: _template_variants,
}


__all__ = ["variations", "MARKER_PLACEHOLDER"]

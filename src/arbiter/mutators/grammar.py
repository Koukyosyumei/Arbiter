"""Tiny grammar engine for structural payload generation.

A grammar is a tree of :class:`Rule` (concatenation) and :class:`Choice`
(alternation) nodes whose leaves are plain strings. :func:`enumerate_rule`
performs a deterministic depth-first walk of the grammar's expansion space,
yielding every distinct concretization up to a budget.

We deliberately do *not* support recursion, weights, or shrinker-friendly
representations. The corpus we generate is a finite cross-product (typically
a few hundred payloads at most), and the worker's `max_examples` cap clips it.
Generation is one DFS, no backtracking.

Example::

    rule = Rule((
        "echo ",
        Choice(("foo", "bar")),
        " {MARKER}",
    ))
    list(enumerate_rule(rule, marker="abc"))
    # → ["echo foo abc", "echo bar abc"]

The marker substitution happens at yield time, after concretization, so the
grammar definitions stay marker-agnostic.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

MARKER_PLACEHOLDER = "{MARKER}"


@dataclass(frozen=True)
class Choice:
    """Pick one of ``options`` at expansion time.

    Each option may itself be a string, another ``Choice``, or a ``Rule``.
    The empty string is allowed as an option (use it for "this part is
    optional").
    """

    options: tuple["Node", ...]


@dataclass(frozen=True)
class Rule:
    """Concatenate ``parts`` left-to-right.

    Each part is a string, ``Choice``, or another ``Rule``. The cross-product
    over the parts' choices is what :func:`enumerate_rule` walks.
    """

    parts: tuple["Node", ...]


Node = "str | Rule | Choice"


def enumerate_rule(
    rule: "Node",
    *,
    marker: str,
    budget: int | None = None,
) -> Iterator[str]:
    """Yield every concretization of ``rule`` up to ``budget`` results.

    The marker placeholder ``{MARKER}`` in any string leaf is substituted
    with ``marker`` on yield. With ``budget=None``, exhausts the grammar.
    """
    yielded = 0
    for s in _walk(rule):
        if budget is not None and yielded >= budget:
            return
        yield s.replace(MARKER_PLACEHOLDER, marker)
        yielded += 1


def _walk(node: "Node") -> Iterator[str]:
    if isinstance(node, str):
        yield node
        return
    if isinstance(node, Choice):
        for opt in node.options:
            yield from _walk(opt)
        return
    if isinstance(node, Rule):
        # Cross product over the parts. We compute this iteratively rather
        # than via itertools.product so that string parts don't get
        # double-materialized when the grammar is large.
        accum: list[str] = [""]
        for part in node.parts:
            new_accum: list[str] = []
            for prefix in accum:
                for suffix in _walk(part):
                    new_accum.append(prefix + suffix)
            accum = new_accum
        yield from accum
        return
    raise TypeError(f"unknown grammar node: {type(node).__name__}")


__all__ = ["Rule", "Choice", "enumerate_rule", "MARKER_PLACEHOLDER"]

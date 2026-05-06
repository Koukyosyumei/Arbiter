"""Unit tests for the per-sink-family payload mutator.

These exercise the contract directly (no subprocess), so they're fast and
suitable for tight iteration on the variation logic.
"""

from __future__ import annotations

from arbiter import mutators
from arbiter.models import SinkFamily


def test_variations_substitutes_marker():
    out = list(mutators.variations(
        family=None,
        seeds=["echo {MARKER}"],
        marker="abc",
        budget=1,
    ))
    assert out == ["echo abc"]


def test_variations_respects_budget():
    out = list(mutators.variations(
        family=None,
        seeds=["a {MARKER}", "b {MARKER}", "c {MARKER}"],
        marker="m",
        budget=2,
    ))
    assert out == ["a m", "b m"]


def test_variations_yields_seeds_first_then_extender():
    seeds = ["echo {MARKER}"]
    # Budget large enough to exhaust the family extender so we can spot-check
    # the cross-product reaches the command-substitution variants.
    out = list(mutators.variations(
        family=SinkFamily.process,
        seeds=seeds,
        marker="m",
        budget=80,
    ))
    # First yield is the canonical seed; subsequent are family extender variants.
    assert out[0] == "echo m"
    # Every extender yield carries the marker by construction.
    assert all("m" in v for v in out)
    # Shell-metachar permutations (separator-style and command-substitution)
    # both appear in the extender output.
    assert any("; echo m" in v for v in out[1:])
    assert any("$(echo m)" == v or "`echo m`" == v for v in out[1:])


def test_variations_cycles_seeds_when_budget_exceeds_corpus():
    seeds = ["s1 {MARKER}", "s2 {MARKER}"]
    out = list(mutators.variations(
        family=None,           # no extender; falls straight through to the cycle
        seeds=seeds,
        marker="X",
        budget=5,
    ))
    assert out[:2] == ["s1 X", "s2 X"]
    # Remaining 3 entries cycle through the seed list.
    assert out[2:] == ["s1 X", "s2 X", "s1 X"]


def test_variations_empty_seeds_falls_back_to_marker():
    out = list(mutators.variations(
        family=None,
        seeds=[],
        marker="zz",
        budget=10,
    ))
    assert out == ["zz"]


def test_variations_bytes_kind_encodes_payloads():
    out = list(mutators.variations(
        family=None,
        seeds=["x {MARKER}"],
        marker="m",
        budget=1,
        kind="bytes",
    ))
    assert out == [b"x m"]


def test_variations_zero_budget_yields_nothing():
    out = list(mutators.variations(
        family=None,
        seeds=["x {MARKER}"],
        marker="m",
        budget=0,
    ))
    assert out == []


def test_deserialization_extender_swaps_callables():
    # An empty seed list forces the extender to be the only source
    # (after the marker fallback). Use a seed so we go through the normal path.
    out = list(mutators.variations(
        family=SinkFamily.deserialization,
        seeds=['!!python/object/apply:os.system ["echo {MARKER}"]'],
        marker="m",
        budget=20,
    ))
    callables_seen = set()
    for v in out:
        for c in ("os.system", "subprocess.getoutput", "subprocess.call",
                  "os.popen", "builtins.eval", "builtins.exec"):
            if f"apply:{c}" in v or f"new:{c}" in v:
                callables_seen.add(c)
    # At least 4 distinct callables should appear thanks to the extender.
    assert len(callables_seen) >= 4, callables_seen

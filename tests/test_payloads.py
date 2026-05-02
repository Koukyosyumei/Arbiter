"""Tests for the curated payload library."""

from __future__ import annotations

import pytest

from arbiter.models import SinkFamily
from arbiter.payloads import get_seed_corpus

# Every sink family that should ship with curated payloads in v0.3.
_FAMILIES_WITH_CORPUS = [
    SinkFamily.code_exec,
    SinkFamily.deserialization,
    SinkFamily.process,
    SinkFamily.template,
    SinkFamily.xml,
    SinkFamily.import_,
    SinkFamily.path,
]


@pytest.mark.parametrize("family", _FAMILIES_WITH_CORPUS)
def test_corpus_non_empty(family):
    seeds = get_seed_corpus(family)
    assert len(seeds) >= 4, f"corpus for {family.value} too small: {len(seeds)}"


@pytest.mark.parametrize("family", _FAMILIES_WITH_CORPUS)
def test_every_seed_has_marker_placeholder(family):
    seeds = get_seed_corpus(family)
    no_marker = [s for s in seeds if "{MARKER}" not in s]
    assert not no_marker, f"{family.value}: seeds without marker: {no_marker}"


@pytest.mark.parametrize("family", _FAMILIES_WITH_CORPUS)
def test_no_within_family_duplicates(family):
    seeds = get_seed_corpus(family)
    assert len(seeds) == len(set(seeds)), f"{family.value} has duplicate seeds"


@pytest.mark.parametrize("family", _FAMILIES_WITH_CORPUS)
def test_seeds_are_strings(family):
    seeds = get_seed_corpus(family)
    assert all(isinstance(s, str) for s in seeds)


def test_get_seed_corpus_returns_independent_copy():
    a = get_seed_corpus(SinkFamily.code_exec)
    a.append("'{MARKER}' MUTATED")
    b = get_seed_corpus(SinkFamily.code_exec)
    assert "MUTATED" not in " ".join(b), "registry leaked mutation"


def test_unknown_family_returns_empty_list():
    # All members of SinkFamily are covered, but the lookup must not raise
    # if we ever add a new family without a corpus.
    class _Stub:
        value = "fictional"

    seeds = get_seed_corpus(_Stub)  # type: ignore[arg-type]
    assert seeds == []


def test_no_dangerous_side_effects_in_seeds():
    """Smoke check: harmless payloads only.

    The detector may execute these in v0 environments without a sandbox.
    Reject seeds that include patterns clearly outside the harmless set.
    """
    forbidden = ("rm -rf", "rm /", "curl ", "wget ", "/dev/tcp", "nc ", " > /")
    for family in _FAMILIES_WITH_CORPUS:
        for seed in get_seed_corpus(family):
            for bad in forbidden:
                assert bad not in seed, f"{family.value} seed contains forbidden {bad!r}: {seed}"

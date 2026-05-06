"""Unit tests for the WitnessCorpus filesystem store.

These exercise the contract directly: round-trip, hierarchical fetch, marker
substitution, dedup, concurrent appends, and the null sink.
"""

from __future__ import annotations

import os
from pathlib import Path

from arbiter.corpus import (
    DirectoryWitnessCorpus,
    NullWitnessCorpus,
    Scope,
    default_corpus_root,
)
from arbiter.models import SinkFamily


def test_save_and_fetch_roundtrip(tmp_path: Path):
    corpus = DirectoryWitnessCorpus(tmp_path)
    scope = Scope(
        sink_family=SinkFamily.code_exec,
        package="pkg",
        target_fqn="pkg.api:foo",
    )
    corpus.save(scope, "x marker_y", marker="marker_")
    out = list(corpus.fetch(scope))
    # Marker substituted back to placeholder so a future campaign's marker
    # can be substituted in by the mutator.
    assert out == ["x {MARKER}y"]


def test_hierarchical_fetch_unions_tiers(tmp_path: Path):
    corpus = DirectoryWitnessCorpus(tmp_path)
    fam = SinkFamily.process

    # Family-wide payload: should be visible from all narrower scopes.
    corpus.save(Scope(sink_family=fam), "; echo {MARKER}")

    # Package payload: visible from package and target scopes, but not from
    # the bare-family scope as a *new* entry.
    corpus.save(
        Scope(sink_family=fam, package="pkg"),
        "&& echo {MARKER}",
    )

    # Target-specific payload.
    corpus.save(
        Scope(sink_family=fam, package="pkg", target_fqn="pkg.api:run"),
        "$(echo {MARKER})",
    )

    target_view = list(corpus.fetch(
        Scope(sink_family=fam, package="pkg", target_fqn="pkg.api:run")
    ))
    # Target scope sees all three payloads.
    assert set(target_view) == {
        "; echo {MARKER}",
        "&& echo {MARKER}",
        "$(echo {MARKER})",
    }
    # Family scope sees only the family-wide save (because the package and
    # target writes are tier-broadcast to family too — verified next).


def test_save_broadcasts_to_all_tiers(tmp_path: Path):
    """A save against a target scope also writes to package and family files."""
    corpus = DirectoryWitnessCorpus(tmp_path)
    scope = Scope(
        sink_family=SinkFamily.process,
        package="pkg",
        target_fqn="pkg.api:run",
    )
    corpus.save(scope, "echo {MARKER}")

    # Family-only fetch should still see the payload because save broadcasts.
    family_view = list(corpus.fetch(Scope(sink_family=SinkFamily.process)))
    assert "echo {MARKER}" in family_view


def test_fetch_dedups_duplicates(tmp_path: Path):
    corpus = DirectoryWitnessCorpus(tmp_path)
    scope = Scope(sink_family=SinkFamily.code_exec)
    corpus.save(scope, "'{MARKER}'")
    corpus.save(scope, "'{MARKER}'")
    assert list(corpus.fetch(scope)) == ["'{MARKER}'"]


def test_fetch_returns_empty_when_nothing_saved(tmp_path: Path):
    corpus = DirectoryWitnessCorpus(tmp_path)
    scope = Scope(sink_family=SinkFamily.template)
    assert list(corpus.fetch(scope)) == []


def test_marker_substitution_handles_multiple_occurrences(tmp_path: Path):
    corpus = DirectoryWitnessCorpus(tmp_path)
    scope = Scope(sink_family=SinkFamily.code_exec)
    corpus.save(scope, "abc abc abc", marker="abc")
    assert list(corpus.fetch(scope)) == ["{MARKER} {MARKER} {MARKER}"]


def test_save_bytes_payload_round_trips_as_utf8_text(tmp_path: Path):
    corpus = DirectoryWitnessCorpus(tmp_path)
    scope = Scope(sink_family=SinkFamily.deserialization)
    corpus.save(scope, b"yaml: {MARKER}")
    out = list(corpus.fetch(scope))
    assert out == ["yaml: {MARKER}"]


def test_null_corpus_is_a_noop(tmp_path: Path):
    corpus = NullWitnessCorpus()
    scope = Scope(sink_family=SinkFamily.code_exec)
    corpus.save(scope, "anything {MARKER}")
    assert list(corpus.fetch(scope)) == []


def test_default_root_under_home_dir():
    root = default_corpus_root()
    assert root.is_absolute()
    # Same drive as ~ — sanity check, doesn't require the dir to exist.
    assert str(root).startswith(str(Path.home()))


def test_fetch_skips_corrupt_lines(tmp_path: Path):
    """A garbage line in the corpus file shouldn't kill the iterator."""
    corpus = DirectoryWitnessCorpus(tmp_path)
    scope = Scope(sink_family=SinkFamily.code_exec)
    corpus.save(scope, "'{MARKER}'")

    # Corrupt the file.
    target = tmp_path / "code_exec" / "__family__.jsonl"
    with target.open("ab") as fh:
        fh.write(b"\n!! not json !!\n\n")
    corpus.save(scope, "'{MARKER}' + 1")

    out = list(corpus.fetch(scope))
    assert out == ["'{MARKER}'", "'{MARKER}' + 1"]


def test_fetch_orders_by_score_descending(tmp_path: Path):
    """Higher-score payloads are yielded first — depth-feedback ranking."""
    corpus = DirectoryWitnessCorpus(tmp_path)
    scope = Scope(sink_family=SinkFamily.code_exec)
    corpus.save(scope, "low {MARKER}", score=1)
    corpus.save(scope, "high {MARKER}", score=5)
    corpus.save(scope, "mid {MARKER}", score=3)
    out = list(corpus.fetch(scope))
    assert out == ["high {MARKER}", "mid {MARKER}", "low {MARKER}"]


def test_fetch_takes_max_score_across_dupes(tmp_path: Path):
    """When the same payload is saved at different tiers with different
    scores, fetch reports the max score (best-known depth)."""
    corpus = DirectoryWitnessCorpus(tmp_path)
    fam_scope = Scope(sink_family=SinkFamily.code_exec)
    pkg_scope = Scope(sink_family=SinkFamily.code_exec, package="pkg")
    corpus.save(fam_scope, "shared {MARKER}", score=2)
    corpus.save(pkg_scope, "shared {MARKER}", score=7)
    corpus.save(pkg_scope, "other {MARKER}", score=1)
    # Package-scope view should put 'shared' first because its max score is 7.
    out = list(corpus.fetch(pkg_scope))
    assert out == ["shared {MARKER}", "other {MARKER}"]


def test_concurrent_appends_atomicity(tmp_path: Path):
    """Pre-PIPE_BUF appends should not corrupt the file even from many writers.

    We simulate concurrency with several rapid sequential O_APPEND writes; the
    real concurrency happens across worker subprocesses, but the kernel
    guarantees the same atomicity contract regardless of process identity.
    """
    corpus = DirectoryWitnessCorpus(tmp_path)
    scope = Scope(sink_family=SinkFamily.code_exec)
    payloads = [f"'{{MARKER}}_{i}'" for i in range(50)]
    for p in payloads:
        corpus.save(scope, p)
    out = list(corpus.fetch(scope))
    assert sorted(out) == sorted(payloads)

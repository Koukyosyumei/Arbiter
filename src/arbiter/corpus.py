"""Cross-campaign witness corpus.

When a worker finds a tainted witness, the payload that triggered it is the
strongest possible prior for any future fuzz attempt against the same target,
the same package, or the same sink family. This module persists those
payloads to a hierarchical filesystem corpus and replays them ahead of the
LLM/static seeds on the next campaign.

The design borrows the shape of Hypothesis's |ExampleDatabase| (key-addressed
bytes store with ``save``/``fetch``) but the *key schema* is different:
ACE payloads transfer well across targets in the same family, so the corpus
keys form a three-tier hierarchy that ``fetch()`` walks from narrowest to
broadest:

    1. ``(family, package, target_fqn)``  — exact-match regression corpus
    2. ``(family, package)``               — neighbor targets in the same package
    3. ``(family,)``                       — cross-package canon

Storage layout::

    <root>/<family>/__family__.jsonl
    <root>/<family>/<package>/__package__.jsonl
    <root>/<family>/<package>/<target_fqn>.jsonl

Each line is a JSON object: ``{"kind": "text"|"bytes", "payload": <b64>}``.
Payloads are stored with the marker substituted *back* to ``{MARKER}`` so a
future campaign with a different UUID can substitute its own marker in.

Append-only writes are atomic for sub-PIPE_BUF sizes on POSIX, which covers
the entire ACE corpus comfortably; no locking needed.
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from arbiter.models import SinkFamily

MARKER_PLACEHOLDER = "{MARKER}"


@dataclass(frozen=True)
class Scope:
    """Identifies *where* in the corpus a payload should be stored or fetched.

    ``sink_family`` is required; ``package`` and ``target_fqn`` are optional
    qualifiers that progressively narrow the scope. A payload stored with the
    full triple is reachable on a fetch with the full triple, with the
    ``(family, package)`` pair, or with just the family.
    """

    sink_family: SinkFamily
    package: str | None = None
    target_fqn: str | None = None

    def tiers(self) -> list["Scope"]:
        """Tiers from narrowest to broadest, used for fetch fallback.

        Save writes to *all* tiers; fetch unions across them in this order so
        exact matches dominate broader matches when payloads are deduped.
        """
        out: list[Scope] = []
        if self.target_fqn is not None and self.package is not None:
            out.append(self)
        if self.package is not None:
            out.append(Scope(sink_family=self.sink_family, package=self.package))
        out.append(Scope(sink_family=self.sink_family))
        return out


class WitnessCorpus(Protocol):
    def save(
        self,
        scope: Scope,
        payload: str | bytes,
        *,
        marker: str | None = None,
        score: int = 0,
    ) -> None:
        """Persist ``payload`` under ``scope``.

        If ``marker`` is given, the live marker substring is replaced with
        ``{MARKER}`` before storage so the saved payload is reusable across
        campaigns. The save is broadcast to every tier of ``scope``.

        ``score`` is a depth-feedback hint (e.g. audit-event count at the
        time of the witness). Higher scores rank earlier on fetch, so a
        future campaign tries the most-deeply-reaching payloads first.
        """
        ...

    def fetch(self, scope: Scope) -> Iterator[str]:
        """Yield previously-saved payloads relevant to ``scope``, deduped.

        Yielded in descending ``score`` order — payloads that fired the
        most audit events on prior runs come first. The ``{MARKER}``
        placeholder is preserved verbatim.

        Always yields ``str``: bytes payloads are base64-decoded and
        re-encoded as their UTF-8 text form so the orchestrator can merge
        them into ``StrategySpec.seeds`` (a ``list[str]``).
        """
        ...


class NullWitnessCorpus:
    """No-op corpus. Useful for tests and when the user disables persistence."""

    def save(
        self,
        scope: Scope,
        payload: str | bytes,
        *,
        marker: str | None = None,
        score: int = 0,
    ) -> None:
        return

    def fetch(self, scope: Scope) -> Iterator[str]:
        return iter(())


class DirectoryWitnessCorpus:
    """Filesystem-backed corpus rooted at a directory.

    Concurrency: workers run as separate subprocesses. Single-line appends to
    a regular file are atomic on POSIX for sizes below ``PIPE_BUF`` (≥512 B,
    typically 4096 B), and ACE payloads stay well below that. We therefore
    open with ``O_APPEND`` and skip any explicit locking.
    """

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def save(
        self,
        scope: Scope,
        payload: str | bytes,
        *,
        marker: str | None = None,
        score: int = 0,
    ) -> None:
        record = self._serialize(payload, marker=marker, score=score)
        if record is None:
            return
        line = (json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8")
        for tier in scope.tiers():
            path = self._path_for(tier)
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
            except OSError:
                continue
            try:
                os.write(fd, line)
            except OSError:
                pass
            finally:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def fetch(self, scope: Scope) -> Iterator[str]:
        # Collect (text, best_score) per unique payload across tiers, then
        # yield in descending score so the highest-priority priors come first.
        scored: dict[str, int] = {}
        for tier in scope.tiers():
            path = self._path_for(tier)
            if not path.exists():
                continue
            try:
                with path.open("rb") as fh:
                    for raw in fh:
                        item = self._deserialize_record(raw)
                        if item is None:
                            continue
                        text, score = item
                        prev = scored.get(text)
                        if prev is None or score > prev:
                            scored[text] = score
            except OSError:
                continue
        for text, _ in sorted(scored.items(), key=lambda kv: -kv[1]):
            yield text

    # --- internals ---

    def _path_for(self, scope: Scope) -> Path:
        family = scope.sink_family.value
        if scope.target_fqn is not None and scope.package is not None:
            safe = scope.target_fqn.replace("/", "_").replace(":", "__")
            return self.root / family / scope.package / f"{safe}.jsonl"
        if scope.package is not None:
            return self.root / family / scope.package / "__package__.jsonl"
        return self.root / family / "__family__.jsonl"

    @staticmethod
    def _serialize(
        payload: str | bytes, *, marker: str | None, score: int = 0
    ) -> dict | None:
        if isinstance(payload, str):
            text = payload
            if marker:
                text = text.replace(marker, MARKER_PLACEHOLDER)
            return {
                "kind": "text",
                "payload": base64.b64encode(text.encode("utf-8")).decode("ascii"),
                "score": int(score),
            }
        if isinstance(payload, (bytes, bytearray)):
            blob = bytes(payload)
            if marker:
                blob = blob.replace(marker.encode("utf-8"), MARKER_PLACEHOLDER.encode("utf-8"))
            return {
                "kind": "bytes",
                "payload": base64.b64encode(blob).decode("ascii"),
                "score": int(score),
            }
        return None

    @staticmethod
    def _deserialize_record(line: bytes) -> tuple[str, int] | None:
        line = line.strip()
        if not line:
            return None
        try:
            obj = json.loads(line)
            kind = obj["kind"]
            blob = base64.b64decode(obj["payload"])
        except (ValueError, KeyError, TypeError):
            return None
        # Score field is a v0.x addition; fall back to 0 for legacy entries.
        try:
            score = int(obj.get("score", 0))
        except (TypeError, ValueError):
            score = 0
        if kind == "text":
            return blob.decode("utf-8", errors="replace"), score
        if kind == "bytes":
            # Bytes payloads are surfaced as utf-8 text for orchestrator merge;
            # the mutator re-encodes per the strategy's `kind`. Lossy for
            # non-utf-8 bytes — acceptable for v0 since our payloads are
            # utf-8 in practice.
            return blob.decode("utf-8", errors="replace"), score
        return None


def default_corpus_root() -> Path:
    """~/.arbiter/corpus/ — the default location for the cross-campaign corpus.

    Override via the orchestrator config or by passing an explicit root to
    :class:`DirectoryWitnessCorpus`.
    """
    return Path.home() / ".arbiter" / "corpus"


__all__ = [
    "Scope",
    "WitnessCorpus",
    "NullWitnessCorpus",
    "DirectoryWitnessCorpus",
    "default_corpus_root",
    "MARKER_PLACEHOLDER",
]

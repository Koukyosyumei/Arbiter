"""Worker subprocess — runs one fuzzing harness with the audit-hook oracle installed.

Protocol:
    stdin:  one JSON line, a HarnessSpec.
    stdout: JSON lines, each a WorkerResult ({"kind": "witness"|"summary"|"error", ...}).
    exit:   0 on completion, 1 on internal error.

The parent process is responsible for enforcing the wall-clock timeout (kill -9
on the worker pid). The worker enforces RSS via setrlimit at startup.

Run standalone for debugging:
    echo '{...}' | python -m arbiter.worker
"""

from __future__ import annotations

import importlib
import resource
import sys
import traceback
from typing import Any

from hypothesis import HealthCheck, Phase, Verbosity, given, settings
from hypothesis import strategies as st
from hypothesis.errors import Flaky
from hypothesis.strategies import SearchStrategy

from arbiter.models import (
    AuditEvent,
    HarnessSpec,
    StrategySpec,
    Witness,
    WorkerResult,
)
from arbiter.oracle import ALWAYS_RECORD, Oracle

MARKER_PLACEHOLDER = "{MARKER}"


class _WitnessFound(Exception):
    """Raised inside the Hypothesis test to drive shrinking toward a minimal repro."""


def _emit(result: WorkerResult) -> None:
    sys.stdout.write(result.model_dump_json(exclude_none=True))
    sys.stdout.write("\n")
    sys.stdout.flush()


def _set_rss_limit(mb: int) -> None:
    try:
        bytes_ = mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (bytes_, bytes_))
    except (ValueError, OSError):
        # Some platforms (macOS) don't honor RLIMIT_AS reliably; not fatal.
        pass


def _resolve_callable(module: str, qualname: str) -> Any:
    mod = importlib.import_module(module)
    obj: Any = mod
    for part in qualname.split("."):
        obj = getattr(obj, part)
    return obj


def _build_strategy(spec: StrategySpec, marker: str) -> SearchStrategy:
    """Translate StrategySpec to a Hypothesis SearchStrategy.

    The marker is woven into every input so a successful hit at the sink proves
    the input flowed there. Two embedding modes:
        - seeds:  literal payloads with {MARKER} placeholder, substituted here.
        - random: free-form text/bytes; marker is concatenated into every value.
    """
    seed_strats: list[SearchStrategy] = []
    for seed in spec.seeds:
        materialized = seed.replace(MARKER_PLACEHOLDER, marker)
        if spec.kind == "bytes":
            seed_strats.append(st.just(materialized.encode("utf-8", errors="replace")))
        else:
            seed_strats.append(st.just(materialized))

    if spec.kind == "bytes":
        random = st.binary(max_size=spec.params.get("max_size", 1024)).map(
            lambda b: marker.encode() + b"\x00" + b
        )
    else:
        alphabet = spec.params.get("alphabet")
        kw: dict[str, Any] = {"max_size": spec.params.get("max_size", 256)}
        if alphabet:
            kw["alphabet"] = alphabet
        random = st.text(**kw).map(lambda s: f"{marker}\n{s}")

    if seed_strats:
        return st.one_of(random, *seed_strats)
    return random


def _run_one_harness(spec: HarnessSpec) -> None:
    target = _resolve_callable(spec.target_module, spec.target_qualname)
    oracle = Oracle(marker=spec.marker)
    oracle.install()

    strategy = _build_strategy(spec.strategy, spec.marker)

    captured: dict[str, Any] = {"input": None, "events": None}
    examples_run = 0
    untainted_events: list[AuditEvent] = []

    @settings(
        max_examples=spec.max_examples,
        deadline=None,
        verbosity=Verbosity.quiet,
        suppress_health_check=list(HealthCheck),
        phases=(Phase.generate, Phase.shrink),
        database=None,
    )
    @given(strategy)
    def harness(payload: Any) -> None:
        nonlocal examples_run
        examples_run += 1
        try:
            target(payload)
        except BaseException:
            # We don't care about target exceptions per se; the oracle is the signal.
            pass
        events = oracle.drain()
        tainted = [e for e in events if e.tainted]
        if tainted:
            captured["input"] = payload
            captured["events"] = tainted
            raise _WitnessFound()
        untainted_events.extend(e for e in events if e.name in ALWAYS_RECORD)

    try:
        harness()
    except _WitnessFound:
        pass
    except Flaky:
        # Hypothesis flakiness — first failure didn't reproduce. We still have
        # captured["input"] from the original failing example.
        pass

    if captured["events"] is not None:
        for ev in captured["events"]:
            witness = Witness(
                target_fqn=f"{spec.target_module}:{spec.target_qualname}",
                event=ev,
                input_repr=repr(captured["input"]),
            )
            _emit(WorkerResult(kind="witness", witness=witness))

    # Untainted ALWAYS_RECORD events are reported separately; the triage layer
    # decides if any deserve attention as side-channel signals.
    for ev in untainted_events:
        _emit(
            WorkerResult(
                kind="witness",
                witness=Witness(
                    target_fqn=f"{spec.target_module}:{spec.target_qualname}",
                    event=ev,
                    input_repr="<untainted>",
                ),
            )
        )

    _emit(WorkerResult(kind="summary", examples_run=examples_run))


def main() -> int:
    raw = sys.stdin.readline()
    if not raw.strip():
        _emit(WorkerResult(kind="error", error="empty stdin"))
        return 1
    try:
        spec = HarnessSpec.model_validate_json(raw)
    except Exception as exc:
        _emit(WorkerResult(kind="error", error=f"bad spec: {exc!r}"))
        return 1

    _set_rss_limit(spec.rss_limit_mb)

    try:
        _run_one_harness(spec)
    except BaseException as exc:
        _emit(
            WorkerResult(
                kind="error",
                error=f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=8)}",
            )
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

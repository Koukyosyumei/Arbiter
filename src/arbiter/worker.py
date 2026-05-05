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
import inspect
import os
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


_MAX_AUTO_MOCK_ATTEMPTS = 25  # safety bound on the auto-mock loop


def _import_with_mocked_missing_deps(module: str) -> Any:
    """Import `module`, auto-mocking any transitive dependency that's missing.

    Real packages routinely import optional GUI/runtime dependencies at module
    load time (e.g. leo's `leoQt` imports `PyQt6`). When the fuzz host doesn't
    have those installed, we'd otherwise crash before reaching a single payload.

    This loop catches `ModuleNotFoundError`, registers a `MagicMock` under the
    missing name in `sys.modules`, and retries the import. Repeats until the
    import succeeds, the missing-name turns out to be the *target itself*
    (legitimate failure), or a hard cap is hit.
    """
    from unittest.mock import MagicMock

    for _ in range(_MAX_AUTO_MOCK_ATTEMPTS):
        try:
            return importlib.import_module(module)
        except ModuleNotFoundError as exc:
            missing = exc.name
            if not missing or missing == module:
                # Failure is the target itself — not something we can mock.
                raise
            # Register mocks for the missing top-level package and every
            # parent in the dotted chain. importlib otherwise re-raises when
            # `from foo.bar import baz` looks up an unmocked intermediate.
            parts = missing.split(".")
            for i in range(len(parts)):
                name = ".".join(parts[: i + 1])
                if name not in sys.modules:
                    sys.modules[name] = MagicMock()
    raise RuntimeError(
        f"auto-mock loop exceeded {_MAX_AUTO_MOCK_ATTEMPTS} attempts importing "
        f"{module!r}; the dependency chain may be infinite or self-referential"
    )


def _resolve_callable(module: str, qualname: str) -> Any:
    """Resolve `module:qualname` to a callable the harness can invoke as `f(payload)`.

    Auto-mocks missing transitive deps via `_import_with_mocked_missing_deps`
    so we don't crash on optional imports the fuzz host lacks (PyQt, tkinter,
    GUI bindings, OS-specific libs).

    Special case: if the qualname walks through a class to land on a regular
    method (`Class.method`), `getattr` returns the unbound function. Calling
    it with one positional arg passes the arg as `self`, so every example
    raises `TypeError: 'X' object has no attribute …`.

    Strategy:
      1. Try `Class()` — works for parameterless constructors. Gives a real
         instance with proper init.
      2. On failure, fall back directly to `unittest.mock.MagicMock()`. We
         skip `Class.__new__` because an uninitialized instance raises
         AttributeError on every `self.x` access (instance attrs are set in
         __init__), which would silently zero the witness count. MagicMock
         answers every attribute lookup with another MagicMock, so the real
         method body runs through to the sink even when the class needs
         heavy framework initialization the worker can't replicate.

    Static- and class-methods don't need this; they're already callable bare.
    """
    mod = _import_with_mocked_missing_deps(module)
    parts = qualname.split(".")
    parent: Any = mod
    obj: Any = mod
    for part in parts:
        parent = obj
        obj = getattr(obj, part)
    if inspect.isclass(parent) and inspect.isfunction(obj):
        descriptor = inspect.getattr_static(parent, parts[-1], None)
        if isinstance(descriptor, (staticmethod, classmethod)):
            return obj
        instance = _instantiate_for_method_binding(parent, qualname)
        # Always invoke the *real* function with the chosen instance — getattr
        # on a MagicMock returns a mock (no sink call); explicit binding runs
        # the actual method body.
        return _bind_method(obj, instance)
    # Top-level function with 2+ required positional args (`render(title, body,
    # author='x')`, `handler(request, command)`, etc.) — `func(payload)` would
    # TypeError on every example. Apply the same smart-default routing used for
    # methods, sans the `self` prepend.
    if inspect.isfunction(obj) or inspect.isbuiltin(obj):
        return _bind_function_with_smart_defaults(obj)
    return obj


def _bind_method(func: Any, instance: Any) -> Any:
    """Return a callable that invokes the real method with `instance` as self
    and the payload routed to the most plausible parameter.

    Methods like `executeScriptHelper(self, args, define_g, define_name,
    namespace, script)` carry attacker bytes in `script` (the last arg);
    earlier params are control flags. Passing payload positionally to a
    one-arg slot would TypeError on every example. We fill the non-self
    parameters with type-derived defaults and route the payload to the
    last positional that's plausibly a string/bytes carrier.
    """
    return _bind_with_smart_defaults(func, instance)


def _default_for_param(param: inspect.Parameter) -> Any:
    """Best-effort default for a required parameter, based on its annotation."""
    if param.default is not inspect.Parameter.empty:
        return param.default
    ann = param.annotation
    # Resolve string annotations only loosely — we just want a constructor hint.
    name = getattr(ann, "__name__", None) or (ann if isinstance(ann, str) else None)
    if name is None:
        return None
    name = name.lower()
    if "str" in name:
        return ""
    if "bytes" in name:
        return b""
    if "bool" in name:
        return False
    if "int" in name:
        return 0
    if "float" in name:
        return 0.0
    if "list" in name or "sequence" in name or "tuple" in name:
        return []
    if "dict" in name or "mapping" in name:
        return {}
    if "set" in name:
        return set()
    return None


def _payload_index(params: list[inspect.Parameter]) -> int:
    """Pick which non-self parameter receives the fuzzed payload.

    Heuristic: prefer params named like data carriers (script, body, source,
    text, content, data, payload, input, expr, code, raw); otherwise the last
    positional parameter (where attacker-controlled bytes most often live in
    "lots of flags + one buffer" signatures).
    """
    HINT_NAMES = {
        "script", "body", "source", "text", "content", "data", "payload",
        "input", "expr", "code", "raw", "blob", "buf", "buffer", "value",
    }
    for i, p in enumerate(params):
        if p.name.lower() in HINT_NAMES:
            return i
    return len(params) - 1


def _make_invoker(target: Any, file_suffix: str | None) -> Any:
    """Wrap `target` so each call writes the payload to a temp file (if asked)
    before invoking it. Lifecycle: write → call → unlink, exception-safe.
    """
    if not file_suffix:
        return target

    import tempfile

    def _invoke(payload: Any) -> Any:
        # Encode strings to bytes so binary-format containers (pickle, sqlite)
        # are written verbatim. Already-bytes payloads pass through.
        data = payload.encode("utf-8", errors="replace") if isinstance(payload, str) else payload
        with tempfile.NamedTemporaryFile(
            "wb", suffix=file_suffix, delete=False
        ) as tf:
            tf.write(data)
            path = tf.name
        try:
            return target(path)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    return _invoke


def _bind_function_with_smart_defaults(func: Any) -> Any:
    """Top-level analogue of `_bind_with_smart_defaults` for plain functions.

    Returns `func` unchanged when it has 0 or 1 required positional args (the
    caller can pass `payload` directly). For functions with 2+ required args,
    fills non-payload parameters with type-derived defaults and routes the
    fuzzed payload to the most plausible parameter, mirroring the method-side
    binder but without prepending `self`.
    """
    try:
        sig = inspect.signature(func)
    except (TypeError, ValueError):
        return func
    params = list(sig.parameters.values())
    required = [
        p for p in params
        if p.default is inspect.Parameter.empty
        and p.kind in (inspect.Parameter.POSITIONAL_ONLY,
                       inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if len(required) <= 1:
        return func
    payload_idx = _payload_index(params)
    defaults = [_default_for_param(p) for p in params]

    def _call(payload: Any) -> Any:
        args = list(defaults)
        args[payload_idx] = payload
        return func(*args)

    return _call


def _bind_with_smart_defaults(func: Any, instance: Any) -> Any:
    """Build a `lambda payload: func(instance, ...)` that routes the payload
    intelligently across multi-arg signatures."""
    try:
        sig = inspect.signature(func)
    except (TypeError, ValueError):
        return lambda payload: func(instance, payload)

    params = list(sig.parameters.values())
    # Drop `self`/`cls` (first positional).
    if params and params[0].name in ("self", "cls"):
        params = params[1:]
    if not params:
        # No-arg method — payload is dropped, but we still call so the oracle
        # observes any audit events the method itself fires.
        return lambda payload: func(instance)

    payload_idx = _payload_index(params)
    defaults = [_default_for_param(p) for p in params]

    def _call(payload: Any) -> Any:
        args = list(defaults)
        args[payload_idx] = payload
        return func(instance, *args)

    return _call


def _instantiate_for_method_binding(cls: Any, qualname: str) -> Any:
    """Best-effort: produce *something* callable as `self` for an unbound method.

    Tries: real construction → __new__ uninitialized → MagicMock fallback.
    Logs each failure so a later "0 witnesses" audit can see what we tried.
    """
    from unittest.mock import MagicMock

    last_exc: BaseException | None = None
    try:
        return cls()
    except BaseException as exc:
        last_exc = exc

    # Try filling required __init__ args with type-derived defaults. Many real
    # classes (e.g. leo's BridgeController) take a flat list of bool/str flags
    # whose defaults work fine for fuzzing; this gives a real instance whose
    # method calls don't dead-end in MagicMocks.
    constructed = _try_construct_with_defaults(cls)
    if constructed is not None:
        return constructed

    # MagicMock without `spec` is the universal escape hatch. We deliberately
    # skip Class.__new__ (uninitialized instance) because instance attributes
    # set in __init__ would raise AttributeError on access; MagicMock answers
    # every attribute lookup with another MagicMock, which is what the method
    # body actually needs to run end-to-end. Note that any real method that
    # then accesses `self.<attr>` and uses the return value as a real object
    # will still short-circuit — MagicMock is a last resort.
    try:
        return MagicMock()
    except BaseException as exc:  # pragma: no cover — MagicMock is very forgiving
        raise RuntimeError(
            f"cannot fuzz unbound method {qualname}: every binding strategy "
            f"failed (real ctor, defaults-filled ctor, MagicMock). Last error: "
            f"{type(last_exc).__name__}: {last_exc}"
        ) from exc


def _try_construct_with_defaults(cls: Any) -> Any:
    """Try `cls(*type_defaulted_args)` where required positional params get
    type-derived defaults. Returns the instance, or None if any step fails.
    """
    try:
        sig = inspect.signature(cls.__init__)
    except (TypeError, ValueError):
        return None
    params = list(sig.parameters.values())
    if params and params[0].name in ("self", "cls"):
        params = params[1:]
    # Only fill *required* params; let the rest take the class's own defaults.
    required = [p for p in params if p.default is inspect.Parameter.empty
                and p.kind in (inspect.Parameter.POSITIONAL_ONLY,
                               inspect.Parameter.POSITIONAL_OR_KEYWORD)]
    args = [_default_for_param(p) for p in required]
    try:
        return cls(*args)
    except BaseException:
        return None


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
    exception_histogram: dict[str, int] = {}

    # When the flow's attacker model is `loaded_file_content`, the entry takes
    # a *path* and parses the file's contents. Materialize each payload to a
    # temp file and pass the path so the parser actually runs.
    file_suffix = spec.payload_as_file_suffix
    invoke = _make_invoker(target, file_suffix)

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
            invoke(payload)
        except BaseException as exc:
            # Target exceptions don't matter for the witness signal — the oracle
            # decides — but tally them so a "0 witnesses" run is diagnosable.
            # Hypothesis' own _WitnessFound is raised below from this same try
            # block context only on a successful witness, so it's fine to count
            # other exceptions here without filtering.
            name = type(exc).__name__
            exception_histogram[name] = exception_histogram.get(name, 0) + 1
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

    _emit(
        WorkerResult(
            kind="summary",
            examples_run=examples_run,
            exception_histogram=exception_histogram,
        )
    )


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

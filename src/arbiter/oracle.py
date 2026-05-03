"""Audit-hook oracle — runs inside the worker subprocess.

Listens on `sys.addaudithook` for events tied to dangerous APIs. For each event,
records: the event name, the sink family it maps to, a truncated repr of its args,
a stack summary, and any taint-marker hits found in the args.

Marker-based taint:
    The orchestrator embeds a UUID4 hex marker into every fuzzed input. If that
    marker appears in any argument the sink receives, we have evidence that
    attacker-controlled bytes reached the sink — that's the difference between
    "found a crash" and "found an exploit primitive".

Re-entrance:
    The hook itself runs Python and may trigger audit events. A thread-local guard
    prevents infinite recursion.

Hook hygiene:
    `sys.addaudithook` hooks must never raise; Python only prints a warning and
    continues, but a raising hook can still mask the real event. All work is
    wrapped in a broad try/except.
"""

from __future__ import annotations

import sys
import threading
from typing import Any

from arbiter.models import AuditEvent, SinkFamily

# Audit event names that map to sink families. Comprehensive across Python 3.12+.
# See PEP 578 and https://docs.python.org/3/library/audit_events.html
AUDIT_FAMILY: dict[str, SinkFamily] = {
    # code_exec
    "compile": SinkFamily.code_exec,
    "exec": SinkFamily.code_exec,
    "code.__new__": SinkFamily.code_exec,
    "function.__new__": SinkFamily.code_exec,
    # deserialization
    "pickle.find_class": SinkFamily.deserialization,
    "marshal.loads": SinkFamily.deserialization,
    "marshal.load": SinkFamily.deserialization,
    "marshal.dumps": SinkFamily.deserialization,  # rarely interesting; here for completeness
    # process
    "subprocess.Popen": SinkFamily.process,
    "os.system": SinkFamily.process,
    "os.exec": SinkFamily.process,
    "os.posix_spawn": SinkFamily.process,
    "os.spawn": SinkFamily.process,
    # import_
    "import": SinkFamily.import_,
}

# Events that are always interesting (low volume, unconditionally dangerous).
ALWAYS_RECORD: frozenset[str] = frozenset(
    {
        "pickle.find_class",
        "marshal.loads",
        "marshal.load",
        "subprocess.Popen",
        "os.system",
        "os.exec",
        "os.posix_spawn",
        "os.spawn",
    }
)

# Events that are high volume; only record when the marker is present.
MARKER_GATED: frozenset[str] = frozenset(
    {
        "compile",
        "exec",
        "code.__new__",
        "function.__new__",
        "import",
    }
)

_REPR_LIMIT = 512  # max chars per stored arg repr; full repr is checked for marker


def _full_repr(value: Any) -> str:
    """repr() with total exception suppression. NOT truncated — caller decides."""
    try:
        return repr(value)
    except BaseException:  # __repr__ can do anything; never let it through
        try:
            return f"<unreprable {type(value).__name__}>"
        except BaseException:
            return "<unreprable>"


def _truncate(s: str) -> str:
    if len(s) > _REPR_LIMIT:
        return s[:_REPR_LIMIT] + "...<truncated>"
    return s


def _capture_stack(skip: int = 2, depth: int = 12) -> list[str]:
    """Lightweight stack summary: 'file:line in qualname' entries, top-down.

    `skip` is how many leading frames to drop (the hook + this helper). `depth`
    bounds the total frames returned to keep the witness small.
    """
    out: list[str] = []
    try:
        f = sys._getframe(skip)
    except ValueError:
        return out
    while f is not None and len(out) < depth:
        try:
            name = f.f_code.co_qualname  # py 3.11+
        except AttributeError:
            name = f.f_code.co_name
        out.append(f"{f.f_code.co_filename}:{f.f_lineno} in {name}")
        f = f.f_back
    return out


# Filenames whose presence in the stack indicates the event was triggered by
# Python's own import / bytecode-load machinery, not by user code. These flood
# the witness stream with .pyc loads (marshal.loads) at import time.
_INTERNAL_FRAME_HINTS: tuple[str, ...] = (
    "<frozen importlib._bootstrap>",
    "<frozen importlib._bootstrap_external>",
    "<frozen runpy>",
    "<frozen codeop>",
)


def _is_internal_event(stack: list[str]) -> bool:
    """True if the *immediate caller* of the event is interpreter-internal.

    The immediate caller (top of stack) is what actually invoked the dangerous
    API. If it lives in importlib/runpy bootstrap, the call was machinery (e.g.
    .pyc bytecode load via marshal.loads), not attacker-influenced. We do *not*
    require all frames to be internal — a user `import` always sits at the
    bottom of the stack but doesn't make the marshal.loads call user-driven.
    """
    if not stack:
        return False
    return any(hint in stack[0] for hint in _INTERNAL_FRAME_HINTS)


class Oracle:
    """Stateful audit-hook listener. One instance per worker process.

    Usage:
        oracle = Oracle(marker="abc123...")
        oracle.install()
        # ... run target code ...
        events = oracle.drain()
    """

    def __init__(self, marker: str | None = None) -> None:
        self.marker = marker or ""
        self._events: list[AuditEvent] = []
        self._guard = threading.local()
        self._installed = False

    def install(self) -> None:
        """Register the audit hook. Idempotent within a process; cannot be removed."""
        if self._installed:
            return
        sys.addaudithook(self._hook)
        self._installed = True

    def drain(self) -> list[AuditEvent]:
        """Return collected events and clear the buffer."""
        events, self._events = self._events, []
        return events

    def _hook(self, event_name: str, args: tuple[Any, ...]) -> None:
        # Re-entrance guard: any audit events fired from within our own hook are dropped.
        if getattr(self._guard, "in_hook", False):
            return
        family = AUDIT_FAMILY.get(event_name)
        if family is None:
            return
        self._guard.in_hook = True
        try:
            full_reprs = [_full_repr(a) for a in args]
            marker_hits: list[str] = []
            if self.marker:
                for r in full_reprs:
                    if self.marker in r:
                        marker_hits.append(self.marker)
                        break  # one hit is enough; we don't need duplicates

            if event_name in MARKER_GATED and not marker_hits:
                return  # high-volume event with no taint evidence — drop
            if event_name not in ALWAYS_RECORD and event_name not in MARKER_GATED:
                return  # unrecognized event policy — fail closed

            stack = _capture_stack(skip=2)
            # Interpreter-internal events (e.g. marshal.loads from .pyc imports)
            # are not exploitable; they'd flood the witness stream otherwise.
            if not marker_hits and _is_internal_event(stack):
                return
            self._events.append(
                AuditEvent(
                    name=event_name,
                    family=family,
                    args_repr=[_truncate(r) for r in full_reprs],
                    stack_summary=stack,
                    marker_hits=marker_hits,
                )
            )
        except BaseException:
            # Hooks must never raise. Swallow everything; losing one event beats
            # masking the real one.
            pass
        finally:
            self._guard.in_hook = False

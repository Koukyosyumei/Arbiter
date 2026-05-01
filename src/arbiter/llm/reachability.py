"""Reachability analysis — `claude -p` agent mode hypothesizes flows from a
target callable to known sinks.

Inputs: one `Target` and the project's `Sink` inventory. The agent reads the
target's source, traces the calls it makes, and reports which sinks are
reachable, the intermediate calls, a confidence score, and a rationale.

This is the bridge between static sink inventory (which calls exist) and
dynamic exploitation (which calls are reachable from a public entry point).
Static call-graph analysis in Python is undecidable in the general case;
the LLM's job is to fill in dynamic dispatch, plugin lookups, and
string-driven routing that pure static analysis misses.
"""

from __future__ import annotations

import logging
from pathlib import Path

from arbiter.llm.sdk import ClaudeHeadlessClient, LLMClient, SystemBlock
from arbiter.models import Flow, Sink, Target

log = logging.getLogger(__name__)

REACH_TOOLS = "Read,Glob,Grep"
DEFAULT_MAX_TURNS = 20


REACH_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "flows": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "sink_qualname": {"type": "string"},
                    "intermediate": {"type": "array", "items": {"type": "string"}},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "rationale": {"type": "string"},
                },
                "required": ["sink_qualname", "confidence"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["flows"],
    "additionalProperties": False,
}


REACH_SYSTEM = """\
You are tracing reachability from a Python callable to a list of known
dangerous sinks. For each sink, decide whether attacker-controlled bytes
that enter the target callable can plausibly arrive at the sink's
arguments at runtime.

# Rules

- A sink is reachable iff there is at least one call path from the target's
  parameters to the sink's argument that does not pass through input
  validation that defangs it.
- Walk through wrappers, decorators, dispatch tables, plugin registries,
  `getattr`/`setattr` indirection. Pure static call graphs miss these;
  that is the whole point of asking you.
- Only include sinks from the provided list. Do not invent new ones.
- `confidence` is your subjective probability that an attacker could exploit
  the path: 1.0 = clear primitive, 0.5 = plausible but requires effort,
  0.1 = theoretically reachable but heavily constrained.
- `intermediate` is the chain of intermediate function names the data passes
  through, in order. Empty list means a direct call.
- `rationale` is one sentence stating *why* the path is exploitable (or
  what hardening, if any, is in the way).

# Output

Return strict JSON matching the schema. Empty `flows` array is valid if no
sink is reachable.
"""


def _format_sinks(sinks: list[Sink]) -> str:
    lines: list[str] = []
    for s in sinks:
        note = f" — {s.note}" if s.note else ""
        lines.append(
            f"  - {s.callable_qualname}  [{s.family.value}, {s.severity}]  "
            f"at {s.file}:{s.line}{note}"
        )
    return "\n".join(lines) if lines else "  (none)"


def build_user_prompt(target: Target, sinks: list[Sink], package_path: Path) -> str:
    return f"""\
Package source root: {package_path}

Target callable:
  module: {target.module}
  qualname: {target.qualname}
  signature: {target.signature}
  exposure: {target.exposure.value}
  docstring: {target.docstring or "(none)"}

Known sinks in this package:
{_format_sinks(sinks)}

Trace which sinks are reachable from the target. Use Read/Glob/Grep against
the source root. Return JSON in the schema.
"""


def _resolve_sink(qualname: str, sinks: list[Sink]) -> Sink | None:
    """Match a sink qualname returned by the model to a Sink in the inventory.

    Tolerant: accepts an exact match or a unique suffix match (e.g. the model
    drops the module prefix). Rejects ambiguous matches.
    """
    for s in sinks:
        if s.callable_qualname == qualname:
            return s
    candidates = [s for s in sinks if s.callable_qualname.endswith(f".{qualname}")]
    if len(candidates) == 1:
        return candidates[0]
    return None


def _coerce_flow(raw: dict, target: Target, sinks: list[Sink]) -> Flow | None:
    qual = raw.get("sink_qualname")
    if not isinstance(qual, str):
        return None
    sink = _resolve_sink(qual, sinks)
    if sink is None:
        log.warning("dropping flow with unknown sink %r", qual)
        return None
    try:
        confidence = float(raw.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))
    intermediate = raw.get("intermediate") or []
    if not isinstance(intermediate, list):
        intermediate = []
    intermediate = [str(x) for x in intermediate]
    rationale = raw.get("rationale")
    if rationale is not None and not isinstance(rationale, str):
        rationale = None
    return Flow(
        target_fqn=target.fqn,
        sink=sink,
        intermediate=intermediate,
        confidence=confidence,
        rationale=rationale,
    )


def analyze_reachability(
    target: Target,
    sinks: list[Sink],
    package_path: Path,
    llm: LLMClient | None = None,
    max_turns: int = DEFAULT_MAX_TURNS,
) -> list[Flow]:
    """Return Flows from `target` to any reachable sinks in `sinks`.

    Sinks the model returns that don't match the inventory are dropped with
    a warning. Confidence is clamped to [0, 1].
    """
    if not sinks:
        return []
    client = llm or ClaudeHeadlessClient()
    raw = client.complete_json(
        system=[SystemBlock(text=REACH_SYSTEM)],
        user=build_user_prompt(target, sinks, package_path),
        schema=REACH_SCHEMA,
        tools=REACH_TOOLS,
        add_dirs=[str(package_path)],
        max_turns=max_turns,
        system_mode="append",
    )
    flows: list[Flow] = []
    for entry in raw.get("flows", []):
        if isinstance(entry, dict):
            f = _coerce_flow(entry, target, sinks)
            if f is not None:
                flows.append(f)
    flows.sort(key=lambda f: f.confidence, reverse=True)
    return flows

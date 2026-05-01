"""Strategy synthesizer — Haiku produces a StrategySpec for one (target, sink) pair.

Called once per flow during a campaign. Output replaces the hand-written seed
payloads we use in tests today; the rest of the worker pipeline is unchanged.

The system prompt is split into a stable preamble (cached) plus a per-family
guide (cached, keyed on family). The user message is the only per-call cost.
"""

from __future__ import annotations

from arbiter.llm.sdk import ClaudeHeadlessClient, LLMClient, SystemBlock
from arbiter.models import Flow, Sink, SinkFamily, StrategySpec, Target

MARKER_PLACEHOLDER = "{MARKER}"

STRATEGY_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "kind": {"type": "string", "enum": ["text", "bytes"]},
        "params": {
            "type": "object",
            "properties": {
                "max_size": {"type": "integer"},
                "alphabet": {"type": "string"},
            },
            "additionalProperties": False,
        },
        "seeds": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 4,
            "maxItems": 8,
        },
        "rationale": {"type": "string"},
    },
    "required": ["kind", "seeds"],
    "additionalProperties": False,
}


SYSTEM_BASE = """\
You are a security payload generator for an arbitrary-code-execution detector.
Given a Python callable and a dangerous sink it can reach, generate seed
payloads that would cause attacker-controlled bytes — embedded as the literal
substring {MARKER} — to flow into the sink at runtime.

# Rules
- Every seed MUST contain the literal substring {MARKER}. The detector
  substitutes a UUID at runtime.
- The marker must end up in the sink's call argument at runtime — not just
  appear in the seed text. That is what makes a witness count.
- Use ONLY harmless side effects: echo, :, true, integer math, str(...).
  Never rm, curl, network calls, or filesystem writes outside /tmp.
- Output strictly JSON. No prose, no code fences.

# Schema
{
  "kind": "text" | "bytes",
  "params": {"max_size": <int, optional>, "alphabet": <str, optional>},
  "seeds": ["<seed string>", ...],
  "rationale": "<one-line explanation>"
}

# Constraints
- 4 to 8 seeds.
- Diverse: cover at least concatenation, literal embedding, and one canonical
  family-specific gadget.
- For bytes targets, write seeds as text; the worker UTF-8 encodes them.
- Do not include the curly braces of "{MARKER}" anywhere except as that
  literal placeholder.
"""


SINK_FAMILY_GUIDE: dict[SinkFamily, str] = {
    SinkFamily.code_exec: """\
# Sink family: code_exec  (eval, exec, compile, runpy)

The sink argument is Python source. Make the marker appear as a literal in
the source so it survives compilation. Examples:
  - "'{MARKER}' + str(1)"
  - "1 + 1  # {MARKER}"
  - "__import__('os').name + '{MARKER}'"
  - "print('{MARKER}')"
""",
    SinkFamily.deserialization: """\
# Sink family: deserialization  (yaml.unsafe_load, pickle.loads, marshal.loads)

YAML: use !!python/object/apply tags. The function is invoked with the
positional args from the YAML list. Pick a benign callable and put the
marker in its argument.
  - !!python/object/apply:os.system ["echo {MARKER}"]
  - !!python/object/apply:subprocess.getoutput ["echo {MARKER}"]
  - !!python/object/new:str ["{MARKER}"]

Pickle: prefer kind=bytes. Hand-crafted REDUCE-opcode constructions are
fragile; for a v0 seed, a textual payload like the above usually suffices
because the harness wraps the input in a unsafe loader.
""",
    SinkFamily.process: """\
# Sink family: process  (os.system, subprocess.*, os.exec*)

The marker becomes a command argument. Shell metachars when shell=True:
  - echo {MARKER}
  - ; echo {MARKER}
  - $(echo {MARKER})
For argv-list variants, write the seed as a single string and rely on the
wrapper to forward it; the marker should still surface in the audit-hook
arg repr.
""",
    SinkFamily.template: """\
# Sink family: template  (Jinja2, Mako)

The marker must end up in the compiled template's Python source. Easiest:
embed it as a literal in the template body.
  - "{{ 1 }} {MARKER}"
  - "{% if 1 %}{MARKER}{% endif %}"
  - "{{ ''.__class__.__mro__[1].__subclasses__() | length }} {MARKER}"
SSTI gadgets that index __subclasses__() are version-fragile; prefer the
simple literal pattern first, gadget-style as one of the variants.
""",
    SinkFamily.xml: """\
# Sink family: xml  (XXE)

Use an external entity that expands to the marker:
  - <?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "{MARKER}">]><r>&x;</r>
""",
    SinkFamily.import_: """\
# Sink family: import  (dynamic import)

Use the marker as the module name. The import will fail but the audit
event fires before the failure with the marker in its arg:
  - not_a_real_module_{MARKER}
""",
    SinkFamily.path: """\
# Sink family: path

Embed the marker in the path:
  - ../{MARKER}
  - /tmp/{MARKER}
""",
}


def build_user_prompt(target: Target, sink: Sink, flow: Flow | None = None) -> str:
    intermediate = "(direct call)"
    rationale = "(none)"
    if flow is not None:
        if flow.intermediate:
            intermediate = " -> ".join(flow.intermediate)
        if flow.rationale:
            rationale = flow.rationale

    return f"""\
Target: {target.module}:{target.qualname}
Signature: {target.signature}
Docstring:
{target.docstring or "(none)"}

Sink: {sink.callable_qualname}
  family: {sink.family.value}
  severity: {sink.severity}
  location: {sink.file}:{sink.line}
  note: {sink.note or "(none)"}

Flow:
  intermediate: {intermediate}
  rationale: {rationale}

Generate 4-8 seed payloads as JSON in the schema above.
"""


def build_system_blocks(sink: Sink) -> list[SystemBlock]:
    return [
        SystemBlock(text=SYSTEM_BASE, cache=True),
        SystemBlock(text=SINK_FAMILY_GUIDE[sink.family], cache=True),
    ]


def _coerce_strategy(raw: dict, sink: Sink) -> StrategySpec:
    """Validate and clean an LLM response into a StrategySpec.

    Drops seeds that lack the {MARKER} placeholder rather than erroring —
    a single bad seed shouldn't tank an otherwise-useful response.
    """
    kind = raw.get("kind", "text")
    if kind not in {"text", "bytes"}:
        kind = "text"
    seeds = [s for s in raw.get("seeds", []) if isinstance(s, str) and MARKER_PLACEHOLDER in s]
    params = raw.get("params") or {}
    if not isinstance(params, dict):
        params = {}
    return StrategySpec(kind=kind, params=params, seeds=seeds)


def synthesize_strategy(
    target: Target,
    sink: Sink,
    flow: Flow | None = None,
    llm: LLMClient | None = None,
    max_tokens: int = 2048,
) -> StrategySpec:
    """Ask the LLM for a Hypothesis strategy spec for this (target, sink).

    On a malformed response (no marker-bearing seeds), returns a minimal
    fallback strategy so the caller can still launch a worker. The caller
    can decide to retry or escalate to a stronger model.
    """
    client = llm or ClaudeHeadlessClient()
    system = build_system_blocks(sink)
    user = build_user_prompt(target, sink, flow)
    raw = client.complete_json(
        system=system, user=user, max_tokens=max_tokens, schema=STRATEGY_SCHEMA
    )
    spec = _coerce_strategy(raw, sink)
    if not spec.seeds:
        # Fallback: a single literal-marker seed appropriate to the family.
        # Better than failing — the random branch of the strategy still runs.
        spec = StrategySpec(kind=spec.kind, params=spec.params, seeds=[MARKER_PLACEHOLDER])
    return spec

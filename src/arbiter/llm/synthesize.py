"""Strategy synthesizer — Haiku produces a StrategySpec for one (target, sink) pair.

Called once per flow during a campaign. Output replaces the hand-written seed
payloads we use in tests today; the rest of the worker pipeline is unchanged.

The system prompt is split into a stable preamble (cached) plus a per-family
guide (cached, keyed on family). The user message is the only per-call cost.
"""

from __future__ import annotations

from arbiter.llm.sdk import ClaudeHeadlessClient, LLMClient, SystemBlock
from arbiter.models import AttackerModel, Flow, Sink, SinkFamily, StrategySpec, Target
from arbiter.payloads import get_seed_corpus

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
- A curated static corpus is merged with your output by the runtime, so
  focus on producing *variations* rather than recreating canonical forms.
  Target-specific shapes — using hints from the callable's docstring,
  signature, or surrounding code — are the highest-value variations.
- For bytes targets, write seeds as text; the worker UTF-8 encodes them.
- Do not include the curly braces of "{MARKER}" anywhere except as that
  literal placeholder.
"""


SINK_FAMILY_GUIDE: dict[SinkFamily, str] = {
    SinkFamily.code_exec: """\
# Sink family: code_exec  (eval, exec, compile, runpy)

The sink argument is Python source. Marker must land as a literal so it
survives `compile()`. Canonical patterns the corpus already covers:
  - direct concatenation:    "'{MARKER}' + str(1)"
  - comment-tagged:          "1 + 1  # {MARKER}"
  - import-attribute chain:  "__import__('os').name + '{MARKER}'"

Variations to favor: target-specific (use the docstring's named operations),
unusual literal forms (f-strings, byte-string literals, complex numbers),
syntactically valid edge cases (walrus, comprehensions).
""",
    SinkFamily.deserialization: """\
# Sink family: deserialization  (yaml.unsafe_load, pickle.loads)

YAML python-tag injection lands the marker as the called function's argument
so it shows up in the audit-event args:
  - !!python/object/apply:os.system ["echo {MARKER}"]
  - !!python/object/apply:subprocess.getoutput ["echo {MARKER}"]
  - !!python/object/new:str ["{MARKER}"]
  - !!python/name:os.system  # {MARKER}

Variations to favor: alternative benign callables (builtins.print, str.format),
multi-line YAML form, nested constructions, version-specific tags.
""",
    SinkFamily.process: """\
# Sink family: process  (os.system, subprocess.*, os.exec*)

Shell-evaluated sinks (shell=True, os.system, os.popen) accept metachar
chains; argv-list sinks just need the marker in one argv entry.
  - direct:         "echo {MARKER}"
  - separator:      "; echo {MARKER}"
  - substitution:   "$(echo {MARKER})"
  - newline split:  "\\necho {MARKER}"

Variations to favor: encoding tricks ($IFS, ${IFS}, %20), backslash escapes,
locale-dependent quoting, mixed-quote chains.
""",
    SinkFamily.template: """\
# Sink family: template  (Jinja2, Mako, Tornado)

Two strategies, both already in the corpus:
  (a) Literal embedding — marker in the template body, lands in compiled
      template source via compile():  "{{ '{MARKER}' }}"
  (b) Context-free RCE gadgets — Jinja2-specific:
      "{{ cycler.__init__.__globals__.os.popen('echo {MARKER}').read() }}"
      "{{ lipsum.__globals__['os'].popen('echo {MARKER}').read() }}"

Avoid `__subclasses__()[N]` forms — the index varies between Python versions.
Variations to favor: filter chains, set/with/macro tags, alternate engines
(Mako ${ }, Tornado).
""",
    SinkFamily.xml: """\
# Sink family: xml  (XXE)

Internal entity expands the marker into the XML text:
  - <?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "{MARKER}">]><r>&x;</r>

Variations: parameter entities, XInclude, external file:// URIs (parser
may attempt resolution and expose audit events), entity-name carrying.
""",
    SinkFamily.import_: """\
# Sink family: import  (dynamic import)

Audit event fires before module-not-found resolution; any unique name
carrying the marker counts:
  - not_a_real_module_{MARKER}
  - ../{MARKER}  (path-style — may interact with sys.path manipulation)
""",
    SinkFamily.path: """\
# Sink family: path

Traversal sequences with the marker in the resolved path:
  - ../{MARKER}
  - ..%2f{MARKER}
  - "{MARKER}\\x00.txt"  (legacy null-byte truncation)
""",
}


# Per-attacker-model nudges. Most paths are `network` (the default), so we only
# include a guide when the attacker model meaningfully changes the seed shape.
ATTACKER_MODEL_GUIDE: dict[AttackerModel, str] = {
    AttackerModel.loaded_file_content: """\
# Attacker model: loaded_file_content

The dangerous bytes live inside a *file* the entry opens. The fuzzer feeds
your seeds directly to the harness leaf — the leaf must be one that takes
the file's content (bytes/str), not a filename. Seeds should be valid
fragments of whatever container format the entry parses (XML, YAML, JSON,
SQLite blob, project archive). The marker rides inside that container in
whatever field actually flows to the sink — usually a base64/hex blob, an
attribute, or a script element. Plain marker substitution into a sink-shaped
payload (e.g. raw pickle bytes) won't trigger if the entry's parser unwraps
a layer first.
""",
    AttackerModel.argv: """\
# Attacker model: argv

Bytes are a CLI argument. Quote-escaping and shell metachars matter only if
the chain passes argv into a shell. Otherwise, treat the input as ordinary
text — but remember argv values are normally short, so very long seeds may
exercise paths the entry never sees in practice.
""",
    AttackerModel.env: """\
# Attacker model: env

Bytes come from an environment variable. Like argv, but typically passed
through `os.environ` lookups. Marker substitution is straightforward.
""",
    AttackerModel.prompt_injected: """\
# Attacker model: prompt_injected

Bytes are an LLM tool-use response the attacker influenced upstream. Format
the seeds as plausible LLM outputs (text, optionally JSON-shaped) so the
downstream parser accepts them.
""",
}


def _resolve_attacker_model(target: Target, flow: Flow | None) -> AttackerModel:
    """Per-flow override wins; otherwise inherit the target's effective model."""
    if flow is not None and flow.attacker_model is not None:
        return flow.attacker_model
    return target.effective_attacker_model


def build_user_prompt(target: Target, sink: Sink, flow: Flow | None = None) -> str:
    intermediate = "(direct call)"
    rationale = "(none)"
    if flow is not None:
        if flow.intermediate:
            intermediate = " -> ".join(flow.intermediate)
        if flow.rationale:
            rationale = flow.rationale
    attacker_model = _resolve_attacker_model(target, flow)

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
  attacker_model: {attacker_model.value}
  intermediate: {intermediate}
  rationale: {rationale}

Generate 4-8 seed payloads as JSON in the schema above.
"""


def build_system_blocks(sink: Sink, attacker_model: AttackerModel | None = None) -> list[SystemBlock]:
    blocks = [
        SystemBlock(text=SYSTEM_BASE, cache=True),
        SystemBlock(text=SINK_FAMILY_GUIDE[sink.family], cache=True),
    ]
    if attacker_model is not None:
        guide = ATTACKER_MODEL_GUIDE.get(attacker_model)
        if guide is not None:
            blocks.append(SystemBlock(text=guide, cache=True))
    return blocks


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
    attacker_model = _resolve_attacker_model(target, flow)
    system = build_system_blocks(sink, attacker_model=attacker_model)
    user = build_user_prompt(target, sink, flow)
    raw = client.complete_json(
        system=system, user=user, max_tokens=max_tokens, schema=STRATEGY_SCHEMA
    )
    spec = _coerce_strategy(raw, sink)
    if not spec.seeds:
        # Fallback: use the curated static corpus for this family. Better than
        # failing — the orchestrator would merge the corpus in anyway, but
        # callers using synthesize_strategy directly get a usable spec back.
        fallback = get_seed_corpus(sink.family) or [MARKER_PLACEHOLDER]
        spec = StrategySpec(kind=spec.kind, params=spec.params, seeds=fallback)
    return spec

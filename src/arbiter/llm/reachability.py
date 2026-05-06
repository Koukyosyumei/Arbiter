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

from arbiter.imports import import_distances, module_to_file
from arbiter.llm.sdk import ClaudeHeadlessClient, LLMClient, SystemBlock
from arbiter.models import AttackerModel, Flow, Sink, Target
from arbiter.source_excerpt import excerpt_around_line, excerpt_function

log = logging.getLogger(__name__)

REACH_TOOLS = "Read,Glob,Grep"
# Initial budget — doubled by the SDK retry loop on `error_max_turns`.
# 30 (→ 60) suits packages with multi-thousand-line files where each
# sink's verification needs several Read calls (offset/limit chunks).
DEFAULT_MAX_TURNS = 30
# Hard cap on sinks sent to the reachability LLM per call. The LLM has to do
# Read/Grep work for every sink to verify reachability; on packages with 50+
# sinks this exhausts the turn budget. Keeping the closest-by-import-distance
# sinks within this cap lets max_turns hold for real packages.
DEFAULT_MAX_SINKS_PER_PROMPT = 12


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
                    "harness_module": {"type": "string"},
                    "harness_qualname": {"type": "string"},
                    "attacker_model": {
                        "type": "string",
                        "enum": [
                            "network",
                            "argv",
                            "loaded_file_content",
                            "env",
                            "prompt_injected",
                        ],
                    },
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

# sink_qualname format

`sink_qualname` MUST be the bare dotted callable name only — exactly as it
appears under "qualname:" in the user prompt. Do NOT append file paths,
line numbers, or any " at X" suffix. The same sink can appear at multiple
locations; emit a separate flow entry for each location you find.

Correct:   "sink_qualname": "subprocess.call"
Incorrect: "sink_qualname": "subprocess.call at editor.py:134"
Incorrect: "sink_qualname": "editor.subprocess.call"

# attacker_model

The user prompt names the entry's *default* attacker model. Override it on a
flow when the data path actually consumes attacker bytes from a different
source. Most common case: a `network` entry takes a path/handle parameter and
opens the file; the dangerous bytes live in the *file content*, not in any
network field. For that path, set `attacker_model: "loaded_file_content"`.

Valid values:
  - `network`             — bytes arrive via socket/HTTP/RPC/WS.
  - `argv`                — bytes are a CLI argument.
  - `loaded_file_content` — bytes live inside a file the entry opens.
  - `env`                 — bytes come from an environment variable.
  - `prompt_injected`     — bytes are an LLM response in a tool-use chain.

Omit the field when the path uses the default attacker model.

# harness_module / harness_qualname

The fuzzer worker calls `target(payload)` with one mutator-generated
value. Most entry points (`main()`, class constructors, request handlers)
have complex signatures and cannot be fuzzed directly that way.

When `attacker_model` is `loaded_file_content`, the harness leaf should be
the function that takes the file *contents* (bytes/str), not one that takes a
filename. The fuzzer feeds attacker bytes directly; chasing through filename
→ open → read for the harness misses the actual sink argument.

When the entry's signature is complex, identify the function in the chain
(or one called by it) that:
  (a) takes a single string or bytes parameter (or `(self, x: str)` for a
      method), and
  (b) directly calls the sink or one obvious wrapper away, and
  (c) has no input validation that defangs attacker bytes before the sink.

Emit `harness_module` and `harness_qualname` for that leaf. The fuzzer will
target the leaf; your `rationale` should explain how attacker bytes from
the entry chain reach the leaf with no relevant validation.

If the entry itself is single-arg-fuzzable, omit `harness_module` and
`harness_qualname`. Use Read/Grep to confirm the leaf exists and its
signature is what you claim.

# Source is pre-extracted — read sparingly

The user prompt embeds (a) the target callable's source body and (b) an
~80-line window around every sink site. Use those excerpts as your primary
evidence; they cover the common case where the call chain is visible
locally. Reach for tools only when:

- The excerpt names an intermediate function whose body you must inspect.
  Use `Grep -n "def <name>"` to locate it, then `Read offset=<line>
  limit=80`.
- You suspect dynamic dispatch (decorators, registries, getattr indirection)
  that the static excerpt won't show.

Do NOT Read the target's file or any sink's file just to re-discover the
code already shown in the prompt — that wastes the turn budget.

# Output

Return strict JSON matching the schema. Empty `flows` array is valid if no
sink is reachable.

# Example output

{
  "flows": [
    {
      "sink_qualname": "subprocess.call",
      "intermediate": ["cmd_editor", "pipe_editor"],
      "confidence": 0.85,
      "rationale": "argv --editor flag flows to cmd_editor, which calls pipe_editor which constructs the command and invokes subprocess.call(shell=True). No validation between argv and the shell.",
      "harness_module": "aider.editor",
      "harness_qualname": "pipe_editor"
    }
  ]
}
"""


def filter_sinks_by_imports(
    target: Target,
    sinks: list[Sink],
    package_path: Path,
    package_name: str,
    max_sinks: int = DEFAULT_MAX_SINKS_PER_PROMPT,
) -> list[Sink]:
    """Rank sinks by import-distance from target's module and keep the top N.

    On monolithic packages (where the target module transitively imports
    most of the package), a binary in/out closure filter is a no-op. Instead
    we rank every sink by the BFS hop-count from the target's file to the
    sink's file, then keep at most `max_sinks` — closest first.

    Sinks in files outside the in-package closure are kept too, scored at
    a fixed large distance (so they survive only when there's prompt budget
    left). On any failure (target file not found), returns the input
    unchanged so the LLM still sees the full inventory.
    """
    distances = import_distances(target.module, package_path, package_name)
    if distances is None:
        return sinks
    target_file = module_to_file(target.module, package_path, package_name)
    if target_file is not None and target_file not in distances:
        distances[target_file] = 0

    def _resolved(p: str) -> Path:
        try:
            return Path(p).resolve()
        except OSError:
            return Path(p)

    OUT_OF_CLOSURE = 9999

    def _sort_key(s: Sink) -> tuple[int, int, str]:
        d = distances.get(_resolved(s.file), OUT_OF_CLOSURE)
        # Tie-break by severity rank so critical sinks beat high beat medium
        # at the same distance, then by file path for determinism.
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(s.severity, 4)
        return (d, sev_rank, f"{s.file}:{s.line}")

    ranked = sorted(sinks, key=_sort_key)
    if not max_sinks or max_sinks <= 0 or len(ranked) <= max_sinks:
        return ranked
    kept = ranked[:max_sinks]
    log.info(
        "ranked sinks for %s: keeping %d of %d (max distance %d)",
        target.fqn,
        len(kept),
        len(sinks),
        _sort_key(kept[-1])[0],
    )
    return kept


def _format_sinks(sinks: list[Sink]) -> str:
    """Render the sink inventory grouped by file. Many real packages cluster
    sinks in one or two huge files (e.g. leo's leoCommands.py has 14 sinks);
    grouping by file lets the LLM see "this file has sinks at lines A, B, C"
    and Read once with offset/limit instead of once per sink.

    `qualname` stays on its own line so the LLM is less likely to copy
    " at <path>:<line>" into its output.
    """
    if not sinks:
        return "  (none)"
    by_file: dict[str, list[Sink]] = {}
    for s in sinks:
        by_file.setdefault(s.file, []).append(s)
    blocks: list[str] = []
    for file, file_sinks in by_file.items():
        blocks.append(f"  file: {file}")
        for s in sorted(file_sinks, key=lambda x: x.line):
            note = f"  note: {s.note}" if s.note else ""
            blocks.append(
                f"    - qualname: {s.callable_qualname}  line: {s.line}  "
                f"family: {s.family.value}  severity: {s.severity}{note}"
            )
    return "\n".join(blocks)


def _resolve_target_file(target: Target, package_path: Path, package_name: str) -> Path | None:
    """Map target.module to its source file under package_path."""
    f = module_to_file(target.module, package_path, package_name)
    return f


def _format_target_excerpt(target: Target, package_path: Path, package_name: str) -> str:
    target_file = _resolve_target_file(target, package_path, package_name)
    if target_file is None:
        return "  (target source not found — fall back to Read/Grep)"
    src = excerpt_function(target_file, target.qualname)
    if src is None:
        return f"  (qualname {target.qualname!r} not found in {target_file} — Grep for it)"
    return src


def _format_sink_excerpts(sinks: list[Sink]) -> str:
    blocks: list[str] = []
    for s in sinks:
        excerpt = excerpt_around_line(Path(s.file), s.line)
        header = (
            f"-- sink: {s.callable_qualname}  family: {s.family.value}  "
            f"severity: {s.severity}{('  note: ' + s.note) if s.note else ''}"
        )
        if excerpt is None:
            blocks.append(f"{header}\n  (source unreadable — Read {s.file}:{s.line})")
        else:
            blocks.append(f"{header}\n```python\n{excerpt}\n```")
    return "\n\n".join(blocks) if blocks else "  (none)"


def build_user_prompt(
    target: Target,
    sinks: list[Sink],
    package_path: Path,
    package_name: str | None = None,
) -> str:
    """Construct the per-target reachability prompt.

    `package_name` is optional only for back-compat with older callers; when
    omitted we can't pre-extract the target source and fall back to telling
    the LLM to find it via Grep. New callers should always pass it.
    """
    if package_name is None:
        # Best-effort: derive from target.module's leading dotted segment.
        # The orchestrator always passes it explicitly; this branch only
        # exists for the pre-attacker-model test signatures.
        package_name = target.module.split(".")[0]
    target_excerpt = _format_target_excerpt(target, package_path, package_name)
    sink_excerpts = _format_sink_excerpts(sinks)
    return f"""\
Package source root: {package_path}

Target callable:
  module: {target.module}
  qualname: {target.qualname}
  signature: {target.signature}
  exposure: {target.exposure.value}
  attacker_model (default for flows): {target.effective_attacker_model.value}
  docstring: {target.docstring or "(none)"}

Target source:
```python
{target_excerpt}
```

Sinks (with surrounding source):
{sink_excerpts}

Trace which of the sinks above are reachable from the target. Use Grep/Read
only when the embedded excerpts don't tell you whether an intermediate
function preserves taint. Return JSON in the schema. Override `attacker_model`
per flow when the actual taint path uses a different source than the default
above (e.g. a network entry that ends up parsing attacker-supplied file bytes).
"""


def _resolve_sink(qualname: str, sinks: list[Sink]) -> Sink | None:
    """Match a sink qualname returned by the model to a Sink in the inventory.

    Tolerant: accepts an exact match, strips a trailing " at file:line"
    suffix the model sometimes copies from the prompt, and falls back to a
    unique suffix match when the model drops the module prefix. Rejects
    ambiguous matches.
    """
    qualname = qualname.strip()
    # Strip " at file:line" / " at file" / "(at file:line)" tails that the
    # model parrots from the prompt formatting.
    for sep in (" at ", " (at ", " in "):
        if sep in qualname:
            qualname = qualname.split(sep, 1)[0].strip()
    qualname = qualname.rstrip(")").strip()

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
    harness_module = raw.get("harness_module")
    if harness_module is not None and not isinstance(harness_module, str):
        harness_module = None
    harness_qualname = raw.get("harness_qualname")
    if harness_qualname is not None and not isinstance(harness_qualname, str):
        harness_qualname = None
    # Only useful if both are present.
    if harness_module is None or harness_qualname is None:
        harness_module = harness_qualname = None
    attacker_model: AttackerModel | None = None
    am_str = raw.get("attacker_model")
    if isinstance(am_str, str):
        try:
            attacker_model = AttackerModel(am_str)
        except ValueError:
            log.debug("dropping unknown attacker_model %r on flow", am_str)
            attacker_model = None
    # When the LLM doesn't override, inherit the target's effective model so
    # downstream stages don't have to plumb the target through to read it.
    if attacker_model is None:
        attacker_model = target.effective_attacker_model
    return Flow(
        target_fqn=target.fqn,
        sink=sink,
        intermediate=intermediate,
        confidence=confidence,
        rationale=rationale,
        harness_module=harness_module,
        harness_qualname=harness_qualname,
        attacker_model=attacker_model,
    )


def analyze_reachability(
    target: Target,
    sinks: list[Sink],
    package_path: Path,
    llm: LLMClient | None = None,
    max_turns: int = DEFAULT_MAX_TURNS,
    package_name: str | None = None,
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
        user=build_user_prompt(target, sinks, package_path, package_name),
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

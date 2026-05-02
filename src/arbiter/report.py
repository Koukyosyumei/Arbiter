"""Report generation — markdown advisory + standalone PoC script per witness.

The PoC scripts are *executable exploit reproducers*. Each emits a clear
warning header and is safe to read; running one re-triggers the dangerous
sink, so callers should only execute them inside an isolated environment.
"""

from __future__ import annotations

import re
import textwrap
from pathlib import Path

from arbiter.models import ScoredWitness, SinkFamily

# Family-specific remediation hints — short, actionable, generic enough to
# apply to most occurrences. The triage report's value depends on these.
_REMEDIATION: dict[SinkFamily, str] = {
    SinkFamily.code_exec: (
        "Never pass attacker-controlled bytes to `eval`, `exec`, `compile`, or "
        "`runpy`. If the entry point must accept user expressions, restrict "
        "the input to a vetted DSL (e.g. `ast.literal_eval` for data, or "
        "`asteval` / `simpleeval` for arithmetic), or move the operation "
        "behind authentication and an explicit allowlist."
    ),
    SinkFamily.deserialization: (
        "Replace `pickle.loads`, `marshal.loads`, `yaml.unsafe_load`, "
        "`yaml.load(...)` (without `Loader=SafeLoader`), and `dill.loads` "
        "with safe equivalents: `json.loads`, `yaml.safe_load`, or a typed "
        "schema parser like pydantic. Untrusted serialized blobs cannot be "
        "made safe by validation alone — the deserializer constructs objects "
        "before user code runs."
    ),
    SinkFamily.process: (
        "Avoid `shell=True`. Pass `subprocess.*` an argv list (`['cmd', arg1, "
        "arg2]`) and never construct that list by string-concatenating user "
        "input. For shell-like behavior, use `shlex.quote` and validate the "
        "argv[0] against an allowlist."
    ),
    SinkFamily.template: (
        "Construct templating engines with `autoescape=True` (Jinja2: "
        "`Environment(autoescape=True)` or `select_autoescape(...)`). For "
        "fully-untrusted templates, use a sandboxed environment "
        "(`jinja2.sandbox.SandboxedEnvironment`) and disable arbitrary "
        "attribute access."
    ),
    SinkFamily.xml: (
        "Use `defusedxml` instead of `xml.etree.ElementTree` / `lxml.etree` "
        "for any input that may originate outside the application boundary. "
        "If `lxml` is required, set `resolve_entities=False` and "
        "`no_network=True` on the parser."
    ),
    SinkFamily.import_: (
        "Restrict dynamic imports to a fixed allowlist of module names. "
        "Never pass attacker-controlled strings to `__import__` or "
        "`importlib.import_module`."
    ),
    SinkFamily.path: (
        "Resolve paths with `os.path.realpath` and verify the result starts "
        "with an explicit base directory. Reject any input containing `..`, "
        "absolute paths, or null bytes before passing to `open` / `pathlib`."
    ),
}


def _slug(text: str, max_len: int = 60) -> str:
    """Filesystem-safe slug derived from arbitrary text."""
    s = re.sub(r"[^a-zA-Z0-9]+", "_", text).strip("_").lower()
    if not s:
        s = "witness"
    return s[:max_len]


def report_filename(scored: ScoredWitness, suffix: str) -> str:
    """Build a stable filename for a witness's advisory or PoC script."""
    w = scored.witness
    family = w.event.family.value
    qual = w.target_fqn.replace(":", "_").replace(".", "_")
    sink_short = (scored.flow.sink.callable_qualname.split(".")[-1] if scored.flow else "sink")
    base = _slug(f"{family}_{qual}_{sink_short}")
    return f"{base}.{suffix}"


def _summary_sentence(scored: ScoredWitness) -> str:
    w = scored.witness
    sink_q = scored.flow.sink.callable_qualname if scored.flow else w.event.name
    return (
        f"Attacker-controlled input to `{w.target_fqn}` reaches `{sink_q}` "
        f"({w.event.family.value}); the audit-hook oracle confirmed the marker "
        f"survived into the sink call's arguments."
    )


def generate_advisory(scored: ScoredWitness) -> str:
    """Render a markdown advisory for one scored witness."""
    w = scored.witness
    s = scored.score
    target = scored.target
    flow = scored.flow

    severity_word = (
        flow.sink.severity.upper() if flow else w.event.family.value.upper()
    )

    intermediate = (
        " → ".join(flow.intermediate) if flow and flow.intermediate else "(direct call)"
    )

    stack_block = "\n".join(f"    {frame}" for frame in w.event.stack_summary[:8])

    intent_line = (
        f"Note: {scored.intended_behavior_reason}; severity penalty applied. "
        if scored.intended_behavior_reason
        else ""
    )

    sink_line = (
        f"`{flow.sink.callable_qualname}` at `{flow.sink.file}:{flow.sink.line}`"
        if flow
        else f"audit event `{w.event.name}`"
    )

    target_block = (
        textwrap.dedent(
            f"""\
            - Module: `{target.module}`
            - Qualname: `{target.qualname}`
            - Signature: `{target.signature}`
            - Exposure: `{target.exposure.value}`
            - Docstring: {(target.docstring or "(none)").strip()}
            """
        )
        if target
        else f"- FQN: `{w.target_fqn}` (full target metadata unavailable)\n"
    )

    family = w.event.family
    remediation = _REMEDIATION.get(
        family, "No family-specific guidance; review the call site for input validation."
    )

    return textwrap.dedent(
        f"""\
        # ACE primitive — `{w.target_fqn}` → `{w.event.name}`

        **Severity**: {severity_word}
        **Family**: `{family.value}`
        **Score**: {s.final:.3f} (raw {s.raw:.3f}, intent penalty ×{1.0 - s.intent_penalty:.2f})

        ## Summary

        {_summary_sentence(scored)} {intent_line}

        ## Affected entry point

        """
    ).rstrip() + "\n\n" + target_block + textwrap.dedent(
        f"""
        ## Sink

        {sink_line}

        ## Reachability

        - Path: {intermediate}
        - Confidence: {flow.confidence if flow else "(none)"}
        - Rationale: {(flow.rationale if flow and flow.rationale else "(none)")}

        ## Witness

        - Audit event: `{w.event.name}`
        - Marker hits: {len(w.event.marker_hits)}
        - Stack (top {min(8, len(w.event.stack_summary))} frames):

        ```
        {stack_block.strip() or "(no stack captured)"}
        ```

        - Triggering input (Python `repr`):

        ```
        {w.input_repr}
        ```

        ## Score breakdown

        | component        | value |
        |------------------|-------|
        | severity         | {s.severity:.2f} |
        | exposure         | {s.exposure:.2f} |
        | directness       | {s.directness:.2f} |
        | novelty          | {s.novelty:.2f} |
        | intent penalty   | {s.intent_penalty:.2f} |
        | raw              | {s.raw:.3f} |
        | final            | {s.final:.3f} |

        ## Suggested fix

        {remediation}

        ## Reproducer

        See companion `.py` file. **The PoC executes the exploit again** —
        run it only inside an isolated environment.
        """
    )


def generate_poc(scored: ScoredWitness, package_path: Path) -> str:
    """Render a standalone Python reproducer script for one witness."""
    w = scored.witness
    target_module = w.target_fqn.split(":")[0]
    target_qualname = w.target_fqn.split(":")[1] if ":" in w.target_fqn else w.target_fqn
    target_call = f"target = {target_qualname}"

    return textwrap.dedent(
        f'''\
        """Proof of concept reproducer — Arbiter witness.

        WARNING: running this script re-triggers a dangerous code path
        ({w.event.family.value} via `{w.event.name}`).
        Run only inside an isolated environment. Do NOT execute on a host
        that holds production data, secrets, or persistent state you care
        about.

        Target  : {w.target_fqn}
        Family  : {w.event.family.value}
        """

        from __future__ import annotations

        import sys
        from pathlib import Path

        # Make the package importable. Adjust if the package is pip-installed.
        sys.path.insert(0, {str(package_path.parent)!r})
        sys.path.insert(0, {str(package_path)!r})

        from {target_module} import {target_qualname.split(".")[0]} as _entry  # noqa: E402

        # Walk attribute path for nested qualnames (e.g. ClassName.method).
        {target_call} = _entry
        for _part in {target_qualname.split('.')[1:]!r}:
            target = getattr(target, _part)

        PAYLOAD = {w.input_repr}

        if __name__ == "__main__":
            print("Arbiter PoC — invoking target with recorded payload")
            try:
                result = target(PAYLOAD)
                print("Returned:", repr(result)[:200])
            except BaseException as exc:
                print("Target raised:", type(exc).__name__, str(exc)[:200])
        '''
    )


def write_reports(scored_witnesses: list[ScoredWitness], output_dir: Path, package_path: Path) -> list[Path]:
    """Materialize advisory + PoC for every scored witness. Returns the list
    of files written, in the order they were created."""
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for sw in scored_witnesses:
        adv_path = output_dir / report_filename(sw, "md")
        poc_path = output_dir / report_filename(sw, "py")
        adv_path.write_text(generate_advisory(sw))
        poc_path.write_text(generate_poc(sw, package_path))
        written.append(adv_path)
        written.append(poc_path)
    return written

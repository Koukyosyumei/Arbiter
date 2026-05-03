"""Target discovery — `claude -p` agent mode maps the public attack surface.

Given a Python package on disk, the agent reads `__init__.py` re-exports,
entry-point declarations in `pyproject.toml`/`setup.py`, network/CLI handler
declarations, and produces a list of `Target` records ranked by exposure.

Read-only tools only (`Read`, `Glob`, `Grep`). The agent cannot edit, run
shell commands, or hit the network.
"""

from __future__ import annotations

import logging
from pathlib import Path

from arbiter.llm.sdk import ClaudeHeadlessClient, LLMClient, SystemBlock
from arbiter.models import AttackerModel, Exposure, Target

log = logging.getLogger(__name__)

DISCOVER_TOOLS = "Read,Glob,Grep"
DEFAULT_MAX_TURNS = 30


DISCOVER_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "targets": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "module": {"type": "string"},
                    "qualname": {"type": "string"},
                    "signature": {"type": "string"},
                    "docstring": {"type": "string"},
                    "exposure": {
                        "type": "string",
                        "enum": ["network", "cli", "library", "internal"],
                    },
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
                    "rationale": {"type": "string"},
                },
                "required": ["module", "qualname", "signature", "exposure"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["targets"],
    "additionalProperties": False,
}


DISCOVER_SYSTEM = """\
You are mapping the public attack surface of a Python package for a security
fuzzer. Your job is to enumerate every callable an external attacker could
plausibly invoke with attacker-controlled bytes.

# What counts as a target

- Any function or method exported from the package's top-level `__init__.py`.
- Any function bound to a CLI entry point (in `pyproject.toml` `[project.scripts]`,
  in `setup.py` `entry_points`, or via `if __name__ == "__main__"` blocks).
- HTTP/RPC handlers (Flask routes, FastAPI endpoints, Django views, asyncio
  servers, gRPC services).
- Deserialization endpoints (anything that accepts bytes/strings and parses
  them: `from_bytes`, `loads`, `parse`, `decode`).
- Public methods on classes that appear in `__all__` or in re-exports.
- Functions registered through a decorator-based command/plugin system
  (`@click.command`, `@app.command`, `@cli.command`, `@route`,
  `@<module>.command(...)`, `@register`, `@plugin.register`, etc.). These
  are user-triggerable from menus, keybindings, slash commands, REPL
  shortcuts, or HTTP routes — treat them as `cli` exposure with attacker
  bytes from the loaded document/session (`loaded_file_content`) unless
  the docstring or signature obviously says otherwise. Editor/IDE projects
  use this pattern heavily; missing them means missing the bulk of the
  attack surface.

# What does NOT count

- Underscore-prefixed names (private by convention).
- Test helpers in `tests/` directories.
- Internal-only utilities not re-exported from the package root.

# Exposure classification

- `network` — reachable over a socket without authentication assumptions.
- `cli` — invoked from a shell command line (argv).
- `library` — imported by downstream Python code; attacker can pass arguments.
- `internal` — package-private; only here if it's still callable from outside.

# Attacker model

`exposure` says who *invokes* the entry point. `attacker_model` says where the
*dangerous bytes* originate — the attacker may not be the caller. Pick the
attacker model that best describes the most likely exploitation path:

- `network` — bytes arrive over a socket (HTTP body, RPC payload, WS frame).
- `argv` — bytes are an argument on the shell command line.
- `loaded_file_content` — the entry takes a *path or handle*, but the
  dangerous bytes live inside the file's *content*. Common for "open file",
  "import project", "load config" entries — the path itself is uninteresting,
  the parser of the contents is the real attack surface.
- `env` — bytes come from an environment variable.
- `prompt_injected` — bytes are produced by a downstream LLM whose prompt
  the attacker influences (tool-use chains).

The field is optional. Omit it when an entry takes scalar arguments fuzzed
directly (the default attacker model derived from `exposure` will apply).
Set it explicitly when the entry's signature has a path/handle parameter
that the function will read and parse — for those, `loaded_file_content` is
almost always more accurate than the inherited default.

# Method

1. Glob the package tree for `__init__.py`, `pyproject.toml`, `setup.py`,
   and obvious framework markers (`flask`, `fastapi`, `django`, `click`,
   `argparse`, `typer`).
2. Read those files to find re-exports, entry points, and route registrations.
3. For each candidate, read its definition site and capture:
   - module path (`pkg.subpkg.mod`),
   - qualname (`Class.method` or `function`),
   - signature as written (e.g. `(expr: str, *, mode: int = 0) -> Any`),
   - the first sentence of its docstring (or empty if none),
   - exposure tier from the rules above,
   - one-line rationale (why it's reachable from outside).

# Output format

Return strict JSON matching the schema. No commentary. If no targets exist,
return `{"targets": []}`.
"""


def build_user_prompt(package_path: Path, package_name: str) -> str:
    return f"""\
Package: {package_name}
Source root: {package_path}

Map the public attack surface. Use Read/Glob/Grep against the source root.
Return JSON in the schema.
"""


def _coerce_target(raw: dict) -> Target | None:
    """Build a Target from a raw dict; drop entries the model malformed."""
    try:
        exposure_str = raw.get("exposure", "library")
        try:
            exposure = Exposure(exposure_str)
        except ValueError:
            exposure = Exposure.library
        attacker_model: AttackerModel | None = None
        am_str = raw.get("attacker_model")
        if am_str is not None:
            try:
                attacker_model = AttackerModel(am_str)
            except ValueError:
                # Unknown value — leave None and let Target derive from exposure.
                attacker_model = None
        return Target(
            module=str(raw["module"]),
            qualname=str(raw["qualname"]),
            signature=str(raw.get("signature", "(...)")),
            docstring=raw.get("docstring") or None,
            exposure=exposure,
            attacker_model=attacker_model,
        )
    except (KeyError, TypeError, ValueError) as exc:
        log.warning("dropping malformed target %r: %s", raw, exc)
        return None


def discover_targets(
    package_path: Path,
    package_name: str,
    llm: LLMClient | None = None,
    max_turns: int = DEFAULT_MAX_TURNS,
) -> list[Target]:
    """Enumerate the public attack surface of a Python package.

    `package_path` must contain the package source tree the agent is allowed
    to read. The agent receives Read/Glob/Grep only — no Bash, no network.
    """
    client = llm or ClaudeHeadlessClient()
    raw = client.complete_json(
        system=[SystemBlock(text=DISCOVER_SYSTEM)],
        user=build_user_prompt(package_path, package_name),
        schema=DISCOVER_SCHEMA,
        tools=DISCOVER_TOOLS,
        add_dirs=[str(package_path)],
        max_turns=max_turns,
        system_mode="append",
    )
    targets: list[Target] = []
    for entry in raw.get("targets", []):
        if isinstance(entry, dict):
            t = _coerce_target(entry)
            if t is not None:
                targets.append(t)
    return targets

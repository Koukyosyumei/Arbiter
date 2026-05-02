"""Static AST scan for decorator-registered command targets.

LLM discovery (`arbiter.llm.discover`) reliably finds the obvious attack
surface — top-level `__init__.py` re-exports, `[project.scripts]` entries,
HTTP handlers — but on packages with a custom command framework it misses
decorator-registered callbacks. Leo's `@g.command('adoc')` decorator is the
canonical example: 200+ user-triggerable commands invisible to a generic
attack-surface prompt.

This module is the deterministic complement: walk every `.py` file, find
function/method definitions whose decorators match a small set of patterns
common across editors, IDEs, and plugin systems, and emit Targets so the
orchestrator can treat them as first-class entry points.

The match is intentionally permissive — false positives are entry points
the user could trigger in some way, which is exactly what fuzzing targets
should be. Reachability filters out the ones with no path to a sink.
"""

from __future__ import annotations

import ast
import logging
from collections.abc import Iterator
from pathlib import Path

from arbiter.imports import file_to_module
from arbiter.models import AttackerModel, Exposure, Target

log = logging.getLogger(__name__)

# Matches against the *last segment* of a decorator's call target. So `@command`,
# `@app.command`, `@g.command`, `@cli.command`, `@click.command` all match
# "command"; `@route` and `@app.route` match "route"; `@register` /
# `@plugin.register` / `@registry.register` all match "register".
COMMAND_DECORATOR_LEAVES: frozenset[str] = frozenset(
    {
        "command",        # Click, Typer, Leo (@g.command), generic
        "subcommand",     # Click subcommand groups
        "route",          # Flask
        "register",       # plugin registries
        "add_command",    # rare programmatic registration
        "callback",       # Click @group.callback
        "task",           # Invoke, Celery
    }
)


def _decorator_leaf_name(dec: ast.expr) -> str | None:
    """Return the rightmost identifier of a decorator expression.

    `@command` → "command";  `@g.command(...)` → "command";
    `@app.command()` → "command";  `@route(...)` → "route".
    """
    # Decorator may be a Call (`@command('x')`), Attribute (`@app.command`),
    # or Name (`@command`).
    if isinstance(dec, ast.Call):
        return _decorator_leaf_name(dec.func)
    if isinstance(dec, ast.Attribute):
        return dec.attr
    if isinstance(dec, ast.Name):
        return dec.id
    return None


def _has_command_decorator(funcdef: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in funcdef.decorator_list:
        leaf = _decorator_leaf_name(dec)
        if leaf and leaf in COMMAND_DECORATOR_LEAVES:
            return True
    return False


def _signature_text(funcdef: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Reconstruct a readable signature string from the AST.

    Falls back to `(...)` if `ast.unparse` is unavailable (it isn't on 3.8;
    we require 3.12 so this is just defense in depth).
    """
    try:
        args_src = ast.unparse(funcdef.args)
    except Exception:
        args_src = "..."
    ret = ""
    if funcdef.returns is not None:
        try:
            ret = f" -> {ast.unparse(funcdef.returns)}"
        except Exception:
            ret = ""
    return f"({args_src}){ret}"


def _docstring_first_sentence(funcdef: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    doc = ast.get_docstring(funcdef)
    if not doc:
        return None
    # Return up to the first period or first paragraph break, whichever is shorter.
    head = doc.strip().split("\n\n", 1)[0].strip()
    period = head.find(".")
    if 20 <= period < 200:
        return head[: period + 1]
    return head[:200]


def _iter_python_files(root: Path) -> Iterator[Path]:
    if root.is_file() and root.suffix == ".py":
        yield root
        return
    for p in root.rglob("*.py"):
        parts = set(p.parts)
        if parts & {".venv", "venv", "build", "dist", "__pycache__", ".tox", ".git", "tests", "test"}:
            continue
        yield p


def _walk_with_class_prefix(
    tree: ast.Module,
) -> Iterator[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]:
    """Yield (qualname_prefix, funcdef) for every top-level function and
    method on top-level classes. Skip nested classes/functions — they're
    rarely wired to a public command registry."""

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node.name, node
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    yield f"{node.name}.{sub.name}", sub


def find_decorator_targets(
    root: Path,
    package_path: Path,
    package_name: str,
    max_targets: int = 60,
    sink_files: set[Path] | None = None,
    file_rank: dict[Path, int] | None = None,
) -> list[Target]:
    """Walk the package tree for decorator-registered functions.

    Returns Targets keyed by importable qualname. Exposure is `cli` (treated
    as user-triggered) and the default attacker model is `loaded_file_content`
    — these endpoints typically operate on data attached to whatever document
    the user has loaded. The reachability LLM may override per-flow.

    `sink_files` (optional) filters results to functions whose source file is
    in that set — useful when you want to focus on commands that *might*
    reach a known sink. Files outside the set are dropped before AST
    parsing for speed; pass None to keep every match.

    `file_rank` (optional) maps each file path to a relevance score; results
    are sorted so higher-scored files come first. Used by the orchestrator
    to push files with more wrapper-sink call sites to the top of the
    target list, since those are where decorator-registered callbacks most
    often reach a shell exec.
    """

    def _resolved(p: Path) -> Path:
        try:
            return p.resolve()
        except OSError:
            return p

    sink_resolved: set[Path] | None = None
    if sink_files is not None:
        sink_resolved = {_resolved(p) for p in sink_files}
    rank_resolved: dict[Path, int] = {}
    if file_rank is not None:
        rank_resolved = {_resolved(p): score for p, score in file_rank.items()}

    files = list(_iter_python_files(root))
    if rank_resolved:
        files.sort(key=lambda f: -rank_resolved.get(_resolved(f), 0))

    out: list[Target] = []
    for f in files:
        f_resolved = _resolved(f)
        if sink_resolved is not None and f_resolved not in sink_resolved:
            continue
        module = file_to_module(f, package_path, package_name)
        if module is None:
            continue
        try:
            source = f.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(f))
        except (SyntaxError, UnicodeDecodeError, OSError) as exc:
            log.debug("skipping %s: %s", f, exc)
            continue
        for qualname, funcdef in _walk_with_class_prefix(tree):
            if funcdef.name.startswith("_"):
                continue
            if not _has_command_decorator(funcdef):
                continue
            target = Target(
                module=module,
                qualname=qualname,
                signature=_signature_text(funcdef),
                docstring=_docstring_first_sentence(funcdef),
                exposure=Exposure.cli,
                attacker_model=AttackerModel.loaded_file_content,
            )
            out.append(target)
            if len(out) >= max_targets:
                log.warning(
                    "decorator-target scan hit cap of %d; truncating", max_targets
                )
                return out
    return out


def merge_targets(
    primary: list[Target], secondary: list[Target]
) -> list[Target]:
    """Merge two target lists, deduping by (module, qualname). `primary` wins
    on conflict — the LLM's classification beats the deterministic default.
    """
    seen = {(t.module, t.qualname) for t in primary}
    merged = list(primary)
    for t in secondary:
        if (t.module, t.qualname) not in seen:
            merged.append(t)
            seen.add((t.module, t.qualname))
    return merged

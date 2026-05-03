"""Static import-closure for in-package modules.

The reachability prompt scales O(targets × sinks). On real packages with
50+ sinks, the LLM can't trace every sink for every target inside its turn
budget. Computing the AST-import closure for a target's module lets us
filter the sink inventory down to sinks defined in files the target could
plausibly reach via static imports — typically a 5-20× reduction.

This is a *conservative* filter: anything we can't statically resolve falls
back to the full sink list, so we trade away some prompt savings for never
silently dropping a true positive.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

log = logging.getLogger(__name__)


def file_to_module(file: Path, package_path: Path, package_name: str) -> str | None:
    """Inverse of `module_to_file` — map a source file to its dotted module name.

    Returns None when `file` is not under `package_path`. `__init__.py` collapses
    to its parent package: `<pkg>/core/__init__.py` → `<package_name>.core`.
    """
    try:
        rel = file.resolve().relative_to(package_path.resolve())
    except (ValueError, OSError):
        return None
    parts = list(rel.parts)
    if not parts:
        return package_name
    if parts[-1] == "__init__.py":
        parts = parts[:-1]
    else:
        if not parts[-1].endswith(".py"):
            return None
        parts[-1] = parts[-1][: -len(".py")]
    if not parts:
        return package_name
    return f"{package_name}." + ".".join(parts)


def module_to_file(module: str, package_path: Path, package_name: str) -> Path | None:
    """Map a dotted module name to its source file under `package_path`.

    `package_name` is the dotted prefix that the import system maps to
    `package_path` on disk. For `package_name="leo.core"` and
    `package_path="/repo/leo/core"`, module "leo.core.x" → "/repo/leo/core/x.py"
    or "/repo/leo/core/x/__init__.py".

    Returns None for modules outside the package or when no file exists.
    """
    if module == package_name:
        rel_parts: list[str] = []
    elif module.startswith(package_name + "."):
        rel_parts = module[len(package_name) + 1 :].split(".")
    else:
        return None

    base = package_path.joinpath(*rel_parts)
    for candidate in (base.with_suffix(".py"), base / "__init__.py"):
        if candidate.is_file():
            try:
                return candidate.resolve()
            except OSError:
                return candidate
    return None


def _resolve_relative(current_module: str, is_package: bool, level: int, name: str | None) -> str:
    """Apply the PEP 328 relative-import rule.

    For a regular module `a.b.c`, the package is `a.b`; level=1 means "the
    package" so `from . import x` → `a.b.x`. For a package `a.b.c` (i.e. an
    __init__.py), the package is `a.b.c` itself.
    """
    parts = current_module.split(".")
    if not is_package:
        if not parts:
            return ""
        parts = parts[:-1]
    if level > 1:
        if level - 1 > len(parts):
            return ""
        parts = parts[: -(level - 1)]
    base = ".".join(parts)
    if name:
        return f"{base}.{name}" if base else name
    return base


def _imports_from_file(
    file: Path, current_module: str, package_name: str
) -> list[str]:
    """Parse `file` and return dotted module names it imports that fall
    inside `package_name`. Names that refer to a submodule via `from pkg
    import sub` form are emitted as `pkg.sub` so the BFS can chase them.
    """
    try:
        source = file.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(file))
    except (OSError, SyntaxError, ValueError) as exc:
        log.debug("could not parse %s for imports: %s", file, exc)
        return []

    is_package = file.name == "__init__.py"
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                base = _resolve_relative(current_module, is_package, node.level, node.module)
                if not base:
                    continue
                out.append(base)
                for alias in node.names:
                    if alias.name != "*":
                        out.append(f"{base}.{alias.name}")
            elif node.module:
                out.append(node.module)
                for alias in node.names:
                    if alias.name != "*":
                        out.append(f"{node.module}.{alias.name}")

    return [m for m in out if m == package_name or m.startswith(package_name + ".")]


def import_closure(
    start_module: str,
    package_path: Path,
    package_name: str,
    max_files: int = 500,
) -> set[Path] | None:
    """BFS over in-package AST imports starting at `start_module`'s source.

    Returns the set of resolved file paths in the closure, or None if the
    start module's file can't be located (caller should fall back to no
    filtering). The cap protects against pathological packages; reaching it
    is logged.
    """
    distances = import_distances(start_module, package_path, package_name, max_files=max_files)
    if distances is None:
        return None
    return set(distances)


def import_distances(
    start_module: str,
    package_path: Path,
    package_name: str,
    max_depth: int | None = None,
    max_files: int = 500,
) -> dict[Path, int] | None:
    """BFS that records the shortest hop-count from `start_module` to each
    in-package file it imports.

    Distance 0 is the start file itself. Distance 1 is anything the start
    file imports directly. The dict is the set of reachable files; ranking
    by distance lets a caller keep the closest N sinks when the full closure
    is too big to fit in a single LLM prompt.
    """
    start_file = module_to_file(start_module, package_path, package_name)
    if start_file is None:
        return None

    distances: dict[Path, int] = {start_file: 0}
    # FIFO queue, breadth-first so the first time we see a file is the shortest path.
    frontier: list[tuple[str, Path, int]] = [(start_module, start_file, 0)]
    head = 0
    while head < len(frontier):
        module, file, depth = frontier[head]
        head += 1
        if max_depth is not None and depth >= max_depth:
            continue
        if len(distances) >= max_files:
            log.warning(
                "import closure for %s hit cap of %d files; truncating",
                start_module,
                max_files,
            )
            break
        for imported in _imports_from_file(file, module, package_name):
            child = module_to_file(imported, package_path, package_name)
            if child is None or child in distances:
                continue
            distances[child] = depth + 1
            frontier.append((imported, child, depth + 1))
    return distances

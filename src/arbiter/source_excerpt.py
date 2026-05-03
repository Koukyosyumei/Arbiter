"""Pre-extract source excerpts for the reachability prompt.

The reachability LLM otherwise spends most of its turn budget on `Read`
calls — multi-thousand-line files paged through 2000 lines at a time. By
pre-extracting (a) the target function's body and (b) ±N lines around each
sink site, we ship the relevant code in the prompt up front and the LLM
only needs to Grep when it's chasing intermediate calls.

This is a deliberate trade: prompt size grows, but turn count drops from
30+ to typically <10.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

log = logging.getLogger(__name__)

# Cap excerpt sizes. The target is usually a single function, so 200 lines
# covers all but the most monolithic ones. Sink excerpts are wider on
# purpose so the LLM can see the surrounding control flow that decides
# whether the sink is conditional/dead.
TARGET_MAX_LINES = 200
SINK_CONTEXT_LINES = 40  # before + after = 80-line window


def _read_lines(file: Path) -> list[str] | None:
    try:
        return file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        log.debug("could not read %s: %s", file, exc)
        return None


def excerpt_around_line(file: Path, line: int, context: int = SINK_CONTEXT_LINES) -> str | None:
    """Return ~2*context+1 lines centered on `line` (1-indexed).

    Output includes a leading `# <file>:<lo>-<hi>` comment so the LLM can
    cite locations precisely. Returns None when the file is unreadable.
    """
    lines = _read_lines(file)
    if lines is None:
        return None
    n = len(lines)
    if n == 0 or line < 1:
        return None
    line = min(line, n)
    lo = max(1, line - context)
    hi = min(n, line + context)
    body = "\n".join(lines[lo - 1 : hi])
    return f"# {file}:{lo}-{hi}  (sink at line {line})\n{body}"


def excerpt_function(file: Path, qualname: str, max_lines: int = TARGET_MAX_LINES) -> str | None:
    """Return the source of the function/method at `qualname` in `file`.

    Walks the AST: dotted qualnames (`Class.method`, `Outer.Inner.method`)
    descend through nested scopes. Async, regular, and method-bound functions
    are all matched. Returns None when no definition matches.

    The result is truncated to `max_lines` with a trailing `# … (truncated)`
    marker, so the prompt size has a hard ceiling.
    """
    text = file.read_text(encoding="utf-8", errors="replace") if file.is_file() else None
    if text is None:
        return None
    try:
        tree = ast.parse(text, filename=str(file))
    except (SyntaxError, ValueError) as exc:
        log.debug("could not parse %s: %s", file, exc)
        return None

    parts = qualname.split(".")

    def _find(node: ast.AST, remaining: list[str]) -> ast.AST | None:
        if not remaining:
            return None
        head, *rest = remaining
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if child.name == head:
                    if not rest:
                        return child
                    found = _find(child, rest)
                    if found is not None:
                        return found
        return None

    target = _find(tree, parts)
    if target is None or not isinstance(
        target, (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        return None

    src = ast.get_source_segment(text, target, padded=False)
    if src is None:
        return None
    line_no = getattr(target, "lineno", "?")
    body_lines = src.splitlines()
    if len(body_lines) > max_lines:
        body_lines = body_lines[:max_lines] + [f"# … ({len(body_lines) - max_lines} more lines, truncated)"]
    return f"# {file}:{line_no}\n" + "\n".join(body_lines)

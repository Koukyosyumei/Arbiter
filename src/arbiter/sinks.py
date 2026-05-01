"""Static sink inventory — AST scan for calls to dangerous APIs.

Resolves call expressions to fully-qualified names by tracking import aliases per
module, then matches against a registry of known-dangerous APIs grouped by family.

Limitations (v0, by design):
- No interprocedural alias analysis. `f = os.system; f(x)` is missed.
- `open` and other path sinks are not flagged here — too noisy without taint.
- Transitive deps are not scanned. The target package's own source is the scope.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

from arbiter.models import Sink, SinkFamily

# Registry: fully-qualified callable -> (family, optional note).
# Keys are matched after import-alias resolution.
SINK_REGISTRY: dict[str, tuple[SinkFamily, str | None]] = {
    # code_exec — direct evaluators
    "eval": (SinkFamily.code_exec, None),
    "exec": (SinkFamily.code_exec, None),
    "compile": (SinkFamily.code_exec, "compile() result typically passed to exec/eval"),
    "runpy.run_path": (SinkFamily.code_exec, None),
    "runpy.run_module": (SinkFamily.code_exec, None),
    "runpy._run_module_as_main": (SinkFamily.code_exec, None),
    "code.interact": (SinkFamily.code_exec, None),
    "code.InteractiveConsole": (SinkFamily.code_exec, None),
    "code.InteractiveInterpreter": (SinkFamily.code_exec, None),
    # deserialization — gadget chains
    "pickle.load": (SinkFamily.deserialization, None),
    "pickle.loads": (SinkFamily.deserialization, None),
    "pickle.Unpickler": (SinkFamily.deserialization, None),
    "marshal.load": (SinkFamily.deserialization, None),
    "marshal.loads": (SinkFamily.deserialization, None),
    "shelve.open": (SinkFamily.deserialization, None),
    "dill.load": (SinkFamily.deserialization, None),
    "dill.loads": (SinkFamily.deserialization, None),
    "yaml.load": (SinkFamily.deserialization, "unsafe unless Loader=SafeLoader"),
    "yaml.unsafe_load": (SinkFamily.deserialization, None),
    "yaml.full_load": (SinkFamily.deserialization, "constructs arbitrary Python tags"),
    # process — spawn / shell
    "os.system": (SinkFamily.process, None),
    "os.popen": (SinkFamily.process, None),
    "os.execv": (SinkFamily.process, None),
    "os.execve": (SinkFamily.process, None),
    "os.execvp": (SinkFamily.process, None),
    "os.execvpe": (SinkFamily.process, None),
    "os.execl": (SinkFamily.process, None),
    "os.execle": (SinkFamily.process, None),
    "os.execlp": (SinkFamily.process, None),
    "os.execlpe": (SinkFamily.process, None),
    "os.spawnl": (SinkFamily.process, None),
    "os.spawnv": (SinkFamily.process, None),
    "os.spawnve": (SinkFamily.process, None),
    "subprocess.Popen": (SinkFamily.process, None),
    "subprocess.run": (SinkFamily.process, None),
    "subprocess.call": (SinkFamily.process, None),
    "subprocess.check_call": (SinkFamily.process, None),
    "subprocess.check_output": (SinkFamily.process, None),
    "subprocess.getoutput": (SinkFamily.process, None),
    "subprocess.getstatusoutput": (SinkFamily.process, None),
    # template — SSTI primitives
    "jinja2.Environment": (SinkFamily.template, "check autoescape kwarg"),
    "jinja2.Template": (SinkFamily.template, "Template defaults to autoescape=False"),
    "mako.template.Template": (SinkFamily.template, None),
    # xml — XXE primitives (use defusedxml instead)
    "xml.etree.ElementTree.parse": (SinkFamily.xml, "use defusedxml.ElementTree"),
    "xml.etree.ElementTree.fromstring": (SinkFamily.xml, "use defusedxml.ElementTree"),
    "xml.etree.ElementTree.iterparse": (SinkFamily.xml, "use defusedxml.ElementTree"),
    "lxml.etree.parse": (SinkFamily.xml, "use defusedxml.lxml or set resolve_entities=False"),
    "lxml.etree.fromstring": (SinkFamily.xml, "use defusedxml.lxml or set resolve_entities=False"),
    "xml.dom.minidom.parseString": (SinkFamily.xml, "use defusedxml"),
    "xml.sax.parseString": (SinkFamily.xml, "use defusedxml"),
    # import_ — dynamic imports
    "__import__": (SinkFamily.import_, None),
    "importlib.import_module": (SinkFamily.import_, None),
    "importlib.__import__": (SinkFamily.import_, None),
}


class _ImportTracker(ast.NodeVisitor):
    """Builds alias -> fully-qualified module/name map for one module's AST."""

    def __init__(self) -> None:
        # local-name -> resolved-prefix (module-qualified)
        self.aliases: dict[str, str] = {}

    def visit_Import(self, node: ast.Import) -> None:
        # `import os` -> os; `import os.path as op` -> op resolves to os.path
        for alias in node.names:
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                top = alias.name.split(".")[0]
                self.aliases[top] = top

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is None:
            return  # relative `from . import x` — not a sink we track
        for alias in node.names:
            local = alias.asname or alias.name
            self.aliases[local] = f"{node.module}.{alias.name}"


def _resolve_call(node: ast.Call, aliases: dict[str, str]) -> str | None:
    """Resolve a Call's func to a fully-qualified name using known aliases.

    Returns the dotted qualname or None if it can't be resolved (computed call,
    method on an instance, lambda, etc.).
    """
    func = node.func
    if isinstance(func, ast.Name):
        return aliases.get(func.id, func.id)
    if isinstance(func, ast.Attribute):
        # Walk the attribute chain: yaml.safe_load.something -> "yaml.safe_load.something"
        parts: list[str] = []
        cur: ast.expr = func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            base = aliases.get(cur.id, cur.id)
            parts.append(base)
            return ".".join(reversed(parts))
    return None


def _has_kwarg_true(node: ast.Call, name: str) -> bool:
    for kw in node.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _yaml_load_is_safe(node: ast.Call) -> bool:
    """yaml.load(..., Loader=SafeLoader) is safe; we suppress the finding."""
    for kw in node.keywords:
        if kw.arg == "Loader":
            v = kw.value
            if isinstance(v, ast.Attribute) and v.attr in {"SafeLoader", "BaseLoader", "CSafeLoader"}:
                return True
            if isinstance(v, ast.Name) and v.id in {"SafeLoader", "BaseLoader", "CSafeLoader"}:
                return True
    return False


def _jinja_env_safe(node: ast.Call) -> bool:
    """jinja2.Environment(autoescape=True) is safe."""
    for kw in node.keywords:
        if kw.arg == "autoescape":
            v = kw.value
            if isinstance(v, ast.Constant) and v.value is True:
                return True
            # autoescape=select_autoescape(...) is also safe; conservative: any callable.
            if isinstance(v, ast.Call):
                return True
    return False


def scan_file(path: Path) -> list[Sink]:
    """Scan a single .py file. Skips files that fail to parse."""
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, UnicodeDecodeError, OSError):
        return []

    tracker = _ImportTracker()
    tracker.visit(tree)
    aliases = tracker.aliases

    found: list[Sink] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        qual = _resolve_call(node, aliases)
        if qual is None or qual not in SINK_REGISTRY:
            continue
        family, note = SINK_REGISTRY[qual]

        # Family-specific safety overrides
        if qual == "yaml.load" and _yaml_load_is_safe(node):
            continue
        if qual == "jinja2.Environment" and _jinja_env_safe(node):
            continue

        extra_note = note
        if family is SinkFamily.process and _has_kwarg_true(node, "shell"):
            extra_note = (extra_note + "; " if extra_note else "") + "shell=True"

        found.append(
            Sink(
                family=family,
                callable_qualname=qual,
                file=str(path),
                line=node.lineno,
                note=extra_note,
            )
        )
    return found


def _iter_python_files(root: Path) -> Iterator[Path]:
    if root.is_file() and root.suffix == ".py":
        yield root
        return
    for p in root.rglob("*.py"):
        # skip common test/build dirs to keep noise down
        parts = set(p.parts)
        if parts & {".venv", "venv", "build", "dist", "__pycache__", ".tox", ".git"}:
            continue
        yield p


def scan_path(root: Path) -> list[Sink]:
    """Scan a file or directory tree. Returns all sinks found."""
    out: list[Sink] = []
    for f in _iter_python_files(root):
        out.extend(scan_file(f))
    return out

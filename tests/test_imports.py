"""Static import-closure tests — pure-AST, no LLM, no live process."""

from __future__ import annotations

from pathlib import Path

import pytest

from arbiter.imports import (
    _resolve_relative,
    import_closure,
    module_to_file,
)


def _write_pkg(root: Path, layout: dict[str, str]) -> Path:
    """Materialize a package tree under root from {relpath: source}.

    Always creates an __init__.py at the package root if not specified.
    """
    if "__init__.py" not in layout:
        layout = {"__init__.py": "", **layout}
    for rel, src in layout.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(src)
    return root


def test_module_to_file_resolves_module(tmp_path):
    pkg = _write_pkg(tmp_path / "pkg", {"a.py": "x = 1"})
    f = module_to_file("pkg.a", pkg, "pkg")
    assert f is not None
    assert f.name == "a.py"


def test_module_to_file_resolves_package_init(tmp_path):
    pkg = _write_pkg(tmp_path / "pkg", {"sub/__init__.py": "x = 1"})
    f = module_to_file("pkg.sub", pkg, "pkg")
    assert f is not None
    assert f.name == "__init__.py"
    assert f.parent.name == "sub"


def test_module_to_file_resolves_top_level_init(tmp_path):
    pkg = _write_pkg(tmp_path / "pkg", {"__init__.py": "x = 1"})
    f = module_to_file("pkg", pkg, "pkg")
    assert f is not None
    assert f.name == "__init__.py"


def test_module_to_file_returns_none_for_outside_package(tmp_path):
    pkg = _write_pkg(tmp_path / "pkg", {"a.py": ""})
    assert module_to_file("other.x", pkg, "pkg") is None
    assert module_to_file("json", pkg, "pkg") is None


def test_module_to_file_returns_none_for_nonexistent_module(tmp_path):
    pkg = _write_pkg(tmp_path / "pkg", {"a.py": ""})
    assert module_to_file("pkg.nope", pkg, "pkg") is None


@pytest.mark.parametrize(
    "current,is_pkg,level,name,expected",
    [
        # Regular module pkg.sub.mod, package = pkg.sub
        ("pkg.sub.mod", False, 1, None, "pkg.sub"),
        ("pkg.sub.mod", False, 1, "x", "pkg.sub.x"),
        ("pkg.sub.mod", False, 2, "x", "pkg.x"),
        # Package pkg.sub.mod (i.e. mod/__init__.py), package = pkg.sub.mod
        ("pkg.sub.mod", True, 1, None, "pkg.sub.mod"),
        ("pkg.sub.mod", True, 1, "x", "pkg.sub.mod.x"),
        ("pkg.sub.mod", True, 2, "x", "pkg.sub.x"),
    ],
)
def test_resolve_relative(current, is_pkg, level, name, expected):
    assert _resolve_relative(current, is_pkg, level, name) == expected


def test_import_closure_walks_absolute_imports(tmp_path):
    pkg = _write_pkg(
        tmp_path / "pkg",
        {
            "entry.py": "from pkg.helper import work\nimport pkg.lib",
            "helper.py": "from pkg.deep import inner",
            "deep.py": "inner = 1",
            "lib.py": "y = 2",
            "untouched.py": "z = 3",
        },
    )
    closure = import_closure("pkg.entry", pkg, "pkg")
    assert closure is not None
    names = {p.name for p in closure}
    assert "entry.py" in names
    assert "helper.py" in names
    assert "deep.py" in names
    assert "lib.py" in names
    assert "untouched.py" not in names


def test_import_closure_walks_relative_imports(tmp_path):
    pkg = _write_pkg(
        tmp_path / "pkg",
        {
            "entry.py": "from . import sibling\nfrom .sub import nested",
            "sibling.py": "v = 1",
            "sub/__init__.py": "from . import nested",
            "sub/nested.py": "v = 2",
        },
    )
    closure = import_closure("pkg.entry", pkg, "pkg")
    assert closure is not None
    names = {f"{p.parent.name}/{p.name}" for p in closure}
    assert any(n.endswith("entry.py") for n in names)
    assert any(n.endswith("sibling.py") for n in names)
    assert any(n.endswith("nested.py") for n in names)


def test_import_closure_ignores_imports_outside_package(tmp_path):
    pkg = _write_pkg(
        tmp_path / "pkg",
        {
            "entry.py": "import json\nimport os.path\nfrom pkg import helper",
            "helper.py": "v = 1",
            "outside_only.py": "import json",  # not reachable from entry
        },
    )
    closure = import_closure("pkg.entry", pkg, "pkg")
    assert closure is not None
    paths = {f"{p.parent.name}/{p.name}" for p in closure}
    # `from pkg import helper` legitimately touches pkg/__init__.py too —
    # that's not a leak. The real assertion is that `outside_only.py` and
    # any external module (json) are excluded.
    assert "pkg/entry.py" in paths
    assert "pkg/helper.py" in paths
    assert "pkg/outside_only.py" not in paths
    assert not any("json" in p for p in paths)


def test_import_closure_returns_none_for_unknown_module(tmp_path):
    pkg = _write_pkg(tmp_path / "pkg", {"a.py": ""})
    assert import_closure("pkg.nonexistent", pkg, "pkg") is None


def test_import_closure_handles_syntax_error_gracefully(tmp_path):
    pkg = _write_pkg(
        tmp_path / "pkg",
        {
            "entry.py": "from pkg.broken import x\nfrom pkg.ok import y",
            "broken.py": "this is not python (((",
            "ok.py": "y = 1",
        },
    )
    closure = import_closure("pkg.entry", pkg, "pkg")
    assert closure is not None
    names = {p.name for p in closure}
    # broken.py *is* in the closure (file exists, is reachable) but its
    # imports can't be parsed; the BFS just doesn't recurse from it.
    assert "entry.py" in names
    assert "ok.py" in names


def test_import_closure_caps_at_max_files(tmp_path, caplog):
    import logging

    # Build a chain: a -> b -> c -> d -> e
    layout = {f"m{i}.py": f"from pkg.m{i + 1} import x" for i in range(4)}
    layout["m4.py"] = "x = 1"
    pkg = _write_pkg(tmp_path / "pkg", layout)
    with caplog.at_level(logging.WARNING, logger="arbiter.imports"):
        closure = import_closure("pkg.m0", pkg, "pkg", max_files=2)
    assert closure is not None
    assert len(closure) <= 2
    assert any("hit cap" in r.getMessage() for r in caplog.records)

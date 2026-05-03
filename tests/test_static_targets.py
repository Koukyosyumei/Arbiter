"""Tests for static decorator-target detection."""

from __future__ import annotations

from pathlib import Path

from arbiter.models import AttackerModel, Exposure, Target
from arbiter.static_targets import (
    _decorator_leaf_name,
    find_decorator_targets,
    merge_targets,
)
import ast


def _w(root: Path, files: dict[str, str]) -> Path:
    if "__init__.py" not in files:
        files = {"__init__.py": "", **files}
    for rel, src in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(src)
    return root


def _parse_first_decorator(src: str) -> ast.expr:
    tree = ast.parse(src)
    func = tree.body[0]
    assert isinstance(func, ast.FunctionDef)
    return func.decorator_list[0]


def test_decorator_leaf_handles_attribute_call():
    dec = _parse_first_decorator("@app.command('foo')\ndef f(): pass")
    assert _decorator_leaf_name(dec) == "command"


def test_decorator_leaf_handles_bare_name():
    dec = _parse_first_decorator("@command\ndef f(): pass")
    assert _decorator_leaf_name(dec) == "command"


def test_decorator_leaf_handles_nested_call():
    dec = _parse_first_decorator("@g.command('foo')\ndef f(): pass")
    assert _decorator_leaf_name(dec) == "command"


def test_finds_g_command_registered_function(tmp_path):
    pkg = _w(
        tmp_path / "pkg",
        {
            "mod.py": (
                "import g\n"
                "@g.command('adoc')\n"
                "def adoc_command(event):\n"
                "    '''Run asciidoctor on the selected tree.'''\n"
                "    pass\n"
            ),
        },
    )
    targets = find_decorator_targets(pkg, pkg, "pkg")
    assert any(t.qualname == "adoc_command" for t in targets)
    [t] = [t for t in targets if t.qualname == "adoc_command"]
    assert t.module == "pkg.mod"
    assert t.exposure is Exposure.cli
    assert t.attacker_model is AttackerModel.loaded_file_content
    assert "asciidoctor" in (t.docstring or "")


def test_finds_method_with_class_prefix(tmp_path):
    pkg = _w(
        tmp_path / "pkg",
        {
            "mod.py": (
                "class C:\n"
                "    @command\n"
                "    def do_thing(self): pass\n"
            ),
        },
    )
    targets = find_decorator_targets(pkg, pkg, "pkg")
    assert any(t.qualname == "C.do_thing" for t in targets)


def test_skips_non_command_decorator(tmp_path):
    pkg = _w(
        tmp_path / "pkg",
        {
            "mod.py": (
                "@property\n"
                "def x(self): return 1\n"
                "@staticmethod\n"
                "def y(): return 2\n"
            ),
        },
    )
    assert find_decorator_targets(pkg, pkg, "pkg") == []


def test_skips_underscore_prefixed(tmp_path):
    pkg = _w(
        tmp_path / "pkg",
        {
            "mod.py": (
                "@command\n"
                "def _private(): pass\n"
                "@command\n"
                "def public(): pass\n"
            ),
        },
    )
    targets = find_decorator_targets(pkg, pkg, "pkg")
    assert [t.qualname for t in targets] == ["public"]


def test_filter_by_sink_files(tmp_path):
    pkg = _w(
        tmp_path / "pkg",
        {
            "with_sink.py": "@command\ndef a(): pass\n",
            "no_sink.py": "@command\ndef b(): pass\n",
        },
    )
    sink_files = {pkg / "with_sink.py"}
    targets = find_decorator_targets(pkg, pkg, "pkg", sink_files=sink_files)
    assert [t.qualname for t in targets] == ["a"]


def test_merge_dedupes_on_module_qualname(tmp_path):
    primary = [
        Target(
            module="pkg.x",
            qualname="f",
            signature="()",
            exposure=Exposure.network,
        ),
    ]
    secondary = [
        Target(
            module="pkg.x",
            qualname="f",
            signature="()",
            exposure=Exposure.cli,  # would lose to primary
        ),
        Target(
            module="pkg.y",
            qualname="g",
            signature="()",
            exposure=Exposure.cli,
        ),
    ]
    merged = merge_targets(primary, secondary)
    assert len(merged) == 2
    [f] = [t for t in merged if t.qualname == "f"]
    assert f.exposure is Exposure.network  # primary wins
    assert any(t.qualname == "g" for t in merged)


def test_route_decorator_matches(tmp_path):
    pkg = _w(
        tmp_path / "pkg",
        {
            "mod.py": (
                "from flask import Flask\n"
                "app = Flask(__name__)\n"
                "@app.route('/x')\n"
                "def handler(): pass\n"
            ),
        },
    )
    targets = find_decorator_targets(pkg, pkg, "pkg")
    assert any(t.qualname == "handler" for t in targets)

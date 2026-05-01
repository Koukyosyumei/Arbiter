"""AST sink inventory — verifies the static scan finds known sinks in vulnpkg."""

from __future__ import annotations

from pathlib import Path

from arbiter.models import SinkFamily
from arbiter.sinks import scan_file, scan_path

VULNPKG = Path(__file__).parent / "fixtures" / "vulnpkg"


def _families(sinks):
    return {s.family for s in sinks}


def _qualnames(sinks):
    return {s.callable_qualname for s in sinks}


def test_scan_finds_eval_yaml_jinja_in_fixture():
    sinks = scan_path(VULNPKG)
    qualnames = _qualnames(sinks)
    assert "eval" in qualnames, qualnames
    assert "yaml.unsafe_load" in qualnames, qualnames
    assert "jinja2.Environment" in qualnames, qualnames


def test_scan_assigns_correct_families():
    sinks = scan_path(VULNPKG)
    by_qualname = {s.callable_qualname: s.family for s in sinks}
    assert by_qualname["eval"] is SinkFamily.code_exec
    assert by_qualname["yaml.unsafe_load"] is SinkFamily.deserialization
    assert by_qualname["jinja2.Environment"] is SinkFamily.template


def test_scan_records_file_and_line():
    sinks = scan_file(VULNPKG / "api.py")
    assert sinks, "expected at least one sink"
    for s in sinks:
        assert s.file.endswith("api.py")
        assert s.line > 0


def test_scan_skips_safe_yaml_load(tmp_path):
    src = tmp_path / "ok.py"
    src.write_text(
        "import yaml\n"
        "from yaml import SafeLoader\n"
        "def f(b): return yaml.load(b, Loader=SafeLoader)\n"
    )
    assert scan_file(src) == []


def test_scan_skips_safe_jinja_env(tmp_path):
    src = tmp_path / "ok.py"
    src.write_text("import jinja2\nenv = jinja2.Environment(autoescape=True)\n")
    assert scan_file(src) == []


def test_scan_flags_subprocess_shell_true(tmp_path):
    src = tmp_path / "shell.py"
    src.write_text(
        "import subprocess\n"
        "def f(cmd): subprocess.run(cmd, shell=True)\n"
    )
    sinks = scan_file(src)
    assert len(sinks) == 1
    assert sinks[0].family is SinkFamily.process
    assert "shell=True" in (sinks[0].note or "")


def test_scan_handles_aliased_imports(tmp_path):
    src = tmp_path / "aliased.py"
    src.write_text(
        "from os import system as run_cmd\n"
        "def f(c): run_cmd(c)\n"
    )
    sinks = scan_file(src)
    assert len(sinks) == 1
    assert sinks[0].callable_qualname == "os.system"


def test_scan_handles_module_alias(tmp_path):
    src = tmp_path / "modalias.py"
    src.write_text(
        "import subprocess as sp\n"
        "def f(c): sp.Popen(c)\n"
    )
    sinks = scan_file(src)
    assert len(sinks) == 1
    assert sinks[0].callable_qualname == "subprocess.Popen"


def test_scan_ignores_unrelated_calls(tmp_path):
    src = tmp_path / "boring.py"
    src.write_text("def f(x): return x + 1\n")
    assert scan_file(src) == []


def test_scan_handles_syntax_error(tmp_path):
    src = tmp_path / "broken.py"
    src.write_text("def f(:\n")  # garbage
    assert scan_file(src) == []


def test_scan_directory_recurses(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "x.py").write_text("eval('1')\n")
    (tmp_path / "a" / "y.py").write_text("import os\nos.system('id')\n")
    sinks = scan_path(tmp_path)
    qualnames = _qualnames(sinks)
    assert "eval" in qualnames
    assert "os.system" in qualnames

"""Tests for wrapper-sink detection — detect functions like leo's
`g.execute_shell_commands` that pass a parameter into subprocess.Popen,
then mark their callers as call-site sinks.
"""

from __future__ import annotations

from pathlib import Path

from arbiter.models import SinkFamily
from arbiter.sinks import (
    _iter_python_files,
    find_wrapper_sinks,
    scan_file_with_registry,
)


def _w(root: Path, files: dict[str, str]) -> Path:
    if "__init__.py" not in files:
        files = {"__init__.py": "", **files}
    for rel, src in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(src)
    return root


def test_detects_direct_param_passthrough(tmp_path):
    pkg = _w(
        tmp_path / "pkg",
        {
            "mod.py": (
                "import subprocess\n"
                "def helper(cmd):\n"
                "    subprocess.Popen(cmd, shell=True)\n"
            ),
        },
    )
    wrappers = find_wrapper_sinks(pkg, pkg, "pkg")
    assert "pkg.mod.helper" in wrappers
    fam, _, _, sink_qual = wrappers["pkg.mod.helper"]
    assert fam is SinkFamily.process
    assert sink_qual == "subprocess.Popen"


def test_detects_loop_var_derived_from_param(tmp_path):
    pkg = _w(
        tmp_path / "pkg",
        {
            "mod.py": (
                "import subprocess\n"
                "def helper(cmds):\n"
                "    for cmd in cmds:\n"
                "        subprocess.Popen(cmd, shell=True)\n"
            ),
        },
    )
    wrappers = find_wrapper_sinks(pkg, pkg, "pkg")
    assert "pkg.mod.helper" in wrappers


def test_detects_fstring_with_param_interpolation(tmp_path):
    """Catches the leoMarkup.run_asciidoctor pattern:
        command = f"asciidoctor {i_path} -o {o_path} -b html5"
        g.execute_shell_commands(command)
    But here the wrapper IS execute_shell_commands. Variant: a function that
    passes an f-string directly into a sink with parameter interpolation."""
    pkg = _w(
        tmp_path / "pkg",
        {
            "mod.py": (
                "import subprocess\n"
                "def runner(arg):\n"
                "    subprocess.Popen(f'echo {arg}', shell=True)\n"
            ),
        },
    )
    wrappers = find_wrapper_sinks(pkg, pkg, "pkg")
    assert "pkg.mod.runner" in wrappers


def test_skips_no_param_function(tmp_path):
    pkg = _w(
        tmp_path / "pkg",
        {
            "mod.py": (
                "import subprocess\n"
                "def cleanup():\n"
                "    subprocess.Popen('clear')\n"
            ),
        },
    )
    assert find_wrapper_sinks(pkg, pkg, "pkg") == {}


def test_skips_literal_first_arg(tmp_path):
    pkg = _w(
        tmp_path / "pkg",
        {
            "mod.py": (
                "import subprocess\n"
                "def helper(arg):\n"
                "    subprocess.Popen(['ls'])\n"
            ),
        },
    )
    assert find_wrapper_sinks(pkg, pkg, "pkg") == {}


def test_method_in_class_gets_class_prefix(tmp_path):
    pkg = _w(
        tmp_path / "pkg",
        {
            "mod.py": (
                "import subprocess\n"
                "class C:\n"
                "    def helper(self, cmd):\n"
                "        subprocess.Popen(cmd, shell=True)\n"
            ),
        },
    )
    wrappers = find_wrapper_sinks(pkg, pkg, "pkg")
    assert "pkg.mod.C.helper" in wrappers


def test_caller_resolution_via_alias(tmp_path):
    """Verify the integration: wrapper qualname is resolvable via import
    aliases the same way SINK_REGISTRY entries are."""
    pkg = _w(
        tmp_path / "pkg",
        {
            "g.py": (
                "import subprocess\n"
                "def execute_shell_commands(cmd):\n"
                "    subprocess.Popen(cmd, shell=True)\n"
            ),
            "caller.py": (
                "import pkg.g as g\n"
                "def run(name):\n"
                "    cmd = f'asciidoctor {name}'\n"
                "    g.execute_shell_commands(cmd)\n"
            ),
        },
    )
    wrappers = find_wrapper_sinks(pkg, pkg, "pkg")
    assert "pkg.g.execute_shell_commands" in wrappers

    registry = {
        qual: (family, "wrapper")
        for qual, (family, _, _, _) in wrappers.items()
    }
    sites = []
    for f in _iter_python_files(pkg):
        sites.extend(scan_file_with_registry(f, registry))
    caller_hits = [s for s in sites if "caller.py" in s.file]
    assert caller_hits, "expected caller's call site to register as a sink"
    assert caller_hits[0].callable_qualname == "pkg.g.execute_shell_commands"

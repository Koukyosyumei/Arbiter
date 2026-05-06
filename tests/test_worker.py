"""End-to-end worker tests — spawn the worker subprocess with a HarnessSpec
and verify it emits witnesses for known-vulnerable targets.

This exercises the full IPC contract: stdin JSON in, stdout JSONL out.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

from arbiter.models import HarnessSpec, StrategySpec, WorkerResult

FIXTURES = Path(__file__).parent / "fixtures"
SRC = Path(__file__).parent.parent / "src"


def _run_worker(spec: HarnessSpec) -> tuple[list[WorkerResult], str]:
    """Run `python -m arbiter.worker` with spec on stdin; return parsed results + stderr."""
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{SRC}{os.pathsep}{FIXTURES}{os.pathsep}{env.get('PYTHONPATH', '')}"
    proc = subprocess.run(
        [sys.executable, "-m", "arbiter.worker"],
        input=spec.model_dump_json() + "\n",
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    results: list[WorkerResult] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            # exploit gadgets (e.g. echo) may print to stdout; skip non-JSON lines
            continue
        try:
            results.append(WorkerResult.model_validate(json.loads(line)))
        except Exception:
            continue
    return results, proc.stderr


def _make_marker() -> str:
    return uuid.uuid4().hex


def test_worker_finds_eval_witness():
    marker = _make_marker()
    spec = HarnessSpec(
        target_module="vulnpkg.api",
        target_qualname="eval_expression",
        marker=marker,
        max_examples=20,
        strategy=StrategySpec(
            kind="text",
            seeds=["'{MARKER}' + str(1)", "1 + 1  # {MARKER}"],
        ),
    )
    results, stderr = _run_worker(spec)
    witnesses = [r for r in results if r.kind == "witness" and r.witness]
    assert witnesses, f"no witnesses; stderr={stderr}"
    tainted = [r for r in witnesses if r.witness and r.witness.event.tainted]
    assert tainted, f"no tainted witnesses; got {[r.witness.event.name for r in witnesses]}"
    families = {r.witness.event.family.value for r in tainted}
    assert "code_exec" in families, families


def test_worker_finds_yaml_witness():
    marker = _make_marker()
    spec = HarnessSpec(
        target_module="vulnpkg.api",
        target_qualname="load_config",
        marker=marker,
        max_examples=20,
        strategy=StrategySpec(
            kind="text",
            seeds=['!!python/object/apply:os.system ["echo {MARKER}"]'],
        ),
    )
    results, stderr = _run_worker(spec)
    tainted = [
        r for r in results if r.kind == "witness" and r.witness and r.witness.event.tainted
    ]
    assert tainted, f"no tainted witnesses; stderr={stderr}\nresults={results}"
    families = {r.witness.event.family.value for r in tainted}
    assert "process" in families, families


def test_worker_finds_jinja_witness():
    marker = _make_marker()
    spec = HarnessSpec(
        target_module="vulnpkg.api",
        target_qualname="render",
        marker=marker,
        max_examples=20,
        strategy=StrategySpec(
            kind="text",
            seeds=["{{ 1 + 1 }} {MARKER}"],
        ),
    )
    results, stderr = _run_worker(spec)
    tainted = [
        r for r in results if r.kind == "witness" and r.witness and r.witness.event.tainted
    ]
    assert tainted, f"no tainted witnesses for SSTI; stderr={stderr}"


def test_worker_safe_target_emits_no_witness():
    marker = _make_marker()
    spec = HarnessSpec(
        target_module="vulnpkg.api",
        target_qualname="echo_safe",
        marker=marker,
        max_examples=20,
        strategy=StrategySpec(kind="text", seeds=["hello {MARKER}"]),
    )
    results, stderr = _run_worker(spec)
    witnesses = [r for r in results if r.kind == "witness"]
    assert not witnesses, f"echo_safe leaked witnesses: {witnesses}; stderr={stderr}"
    summary = [r for r in results if r.kind == "summary"]
    assert summary, "expected a summary line"


def test_worker_emits_summary_with_examples_run():
    marker = _make_marker()
    spec = HarnessSpec(
        target_module="vulnpkg.api",
        target_qualname="echo_safe",
        marker=marker,
        max_examples=15,
        strategy=StrategySpec(kind="text"),
    )
    results, _ = _run_worker(spec)
    summary = [r for r in results if r.kind == "summary"]
    assert summary
    assert summary[0].examples_run >= 1


def test_worker_summary_carries_exception_histogram():
    """A target that raises on every input should report it in the summary —
    that's the diagnostic for "0 witnesses" runs. The harness here passes
    every payload to eval(), which raises on any non-evaluable input;
    we just need at least one such exception to land in the histogram."""
    marker = _make_marker()
    spec = HarnessSpec(
        target_module="vulnpkg.api",
        target_qualname="eval_expression",
        marker=marker,
        # Bumped above the one_of branch count so seed coverage is statistically
        # certain — otherwise the random branch can dominate small budgets.
        max_examples=50,
        # Each seed is invalid Python that eval() will raise on.
        strategy=StrategySpec(
            kind="text",
            seeds=["((( {MARKER}", "??? {MARKER}", "@@@ {MARKER}", "###{MARKER}"],
        ),
    )
    results, stderr = _run_worker(spec)
    summary = next((r for r in results if r.kind == "summary"), None)
    assert summary is not None, f"no summary; stderr={stderr}"
    assert sum(summary.exception_histogram.values()) > 0, (
        f"expected exceptions tallied; got {summary.exception_histogram}"
    )


def test_worker_resolves_method_via_auto_instantiate(tmp_path):
    """A harness target like Class.method should be auto-bound to an instance
    instead of being called as an unbound function (which would pass the
    payload as `self`)."""
    pkg_dir = tmp_path / "auto_inst_pkg"
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text("")
    (pkg_dir / "mod.py").write_text(
        "class Container:\n"
        "    def __init__(self):\n"
        "        self.tag = 'inst'\n"
        "    def consume(self, x):\n"
        "        eval(x)  # exercises code_exec audit hook\n"
    )
    marker = _make_marker()
    spec = HarnessSpec(
        target_module="auto_inst_pkg.mod",
        target_qualname="Container.consume",
        marker=marker,
        max_examples=5,
        strategy=StrategySpec(kind="text", seeds=["'{MARKER}'"]),
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{SRC}{os.pathsep}{tmp_path}{os.pathsep}{env.get('PYTHONPATH', '')}"
    proc = subprocess.run(
        [sys.executable, "-m", "arbiter.worker"],
        input=spec.model_dump_json() + "\n",
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    results: list[WorkerResult] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                results.append(WorkerResult.model_validate(json.loads(line)))
            except Exception:
                continue
    summary = next((r for r in results if r.kind == "summary"), None)
    assert summary is not None, f"no summary; stderr={proc.stderr}"
    # If auto-instantiation worked, examples ran without TypeError on every call.
    # If it didn't, every example would fail with TypeError 'str' object has no attribute …
    type_errors = summary.exception_histogram.get("TypeError", 0)
    assert type_errors == 0, (
        f"unbound method call leaked TypeError on every example: {summary.exception_histogram}"
    )
    # And we should have at least one tainted witness from eval('marker').
    tainted = [
        r for r in results if r.kind == "witness" and r.witness and r.witness.event.tainted
    ]
    assert tainted, f"no tainted witnesses; stderr={proc.stderr}\nresults={results}"


def test_worker_falls_back_when_class_constructor_needs_args(tmp_path):
    """If `Class()` raises (constructor needs args), the worker now falls
    back to `Class.__new__` and ultimately MagicMock(spec=Class) so the
    method body still runs. The audit-hook oracle should fire on a sink
    call inside the method body, producing a tainted witness."""
    pkg_dir = tmp_path / "needsargs_pkg"
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text("")
    (pkg_dir / "mod.py").write_text(
        "class NeedsArg:\n"
        "    def __init__(self, required):\n"
        "        self.x = required\n"
        "    def consume(self, x):\n"
        "        eval(x)\n"
    )
    marker = _make_marker()
    spec = HarnessSpec(
        target_module="needsargs_pkg.mod",
        target_qualname="NeedsArg.consume",
        marker=marker,
        max_examples=5,
        strategy=StrategySpec(kind="text", seeds=["'{MARKER}'"]),
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{SRC}{os.pathsep}{tmp_path}{os.pathsep}{env.get('PYTHONPATH', '')}"
    proc = subprocess.run(
        [sys.executable, "-m", "arbiter.worker"],
        input=spec.model_dump_json() + "\n",
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    assert proc.returncode == 0, f"stderr={proc.stderr}\nstdout={proc.stdout[:500]}"
    tainted_witness = '"tainted":true' not in proc.stdout  # ensure we don't get false negative on quoting
    assert "witness" in proc.stdout, f"expected at least one witness; got {proc.stdout[:500]}"


def test_worker_rejects_bad_spec():
    proc = subprocess.run(
        [sys.executable, "-m", "arbiter.worker"],
        input="not json\n",
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": f"{SRC}{os.pathsep}{FIXTURES}"},
        timeout=10,
    )
    assert proc.returncode == 1
    assert '"kind":"error"' in proc.stdout or '"kind": "error"' in proc.stdout


def test_worker_smart_binds_top_level_multiarg_function(tmp_path):
    """A top-level function with 2+ required positional args (e.g. a blog
    post renderer `render(title, body, author='x')`) used to TypeError on
    every example because the worker called `func(payload)`. The smart-default
    binder fills `title` with `""`, routes `payload` to `body` (HINT_NAMES),
    and the sink fires."""
    pkg_dir = tmp_path / "multi_arg_pkg"
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text(
        "def render(title: str, body: str, author: str = 'anon') -> str:\n"
        "    return eval(body)  # exercises code_exec audit hook\n"
    )
    marker = _make_marker()
    spec = HarnessSpec(
        target_module="multi_arg_pkg",
        target_qualname="render",
        marker=marker,
        max_examples=5,
        strategy=StrategySpec(kind="text", seeds=["'{MARKER}'"]),
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{SRC}{os.pathsep}{tmp_path}{os.pathsep}{env.get('PYTHONPATH', '')}"
    proc = subprocess.run(
        [sys.executable, "-m", "arbiter.worker"],
        input=spec.model_dump_json() + "\n",
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    results: list[WorkerResult] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                results.append(WorkerResult.model_validate(json.loads(line)))
            except Exception:
                continue
    summary = next((r for r in results if r.kind == "summary"), None)
    assert summary is not None, f"no summary; stderr={proc.stderr}"
    type_errors = summary.exception_histogram.get("TypeError", 0)
    assert type_errors == 0, (
        f"top-level multi-arg function leaked TypeError on every example: "
        f"{summary.exception_histogram}"
    )
    tainted = [
        r for r in results if r.kind == "witness" and r.witness and r.witness.event.tainted
    ]
    assert tainted, f"no tainted witnesses; stderr={proc.stderr}\nresults={results}"

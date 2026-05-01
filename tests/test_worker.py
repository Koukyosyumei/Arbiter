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

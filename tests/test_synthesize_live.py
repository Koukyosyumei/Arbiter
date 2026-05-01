"""Live integration test — invokes `claude -p` for real and runs the result
through the worker. Skipped automatically when the `claude` CLI is not on PATH.

Run explicitly with:
    pytest tests/test_synthesize_live.py -v
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from arbiter.llm.sdk import ClaudeHeadlessClient
from arbiter.llm.synthesize import synthesize_strategy
from arbiter.models import Exposure, HarnessSpec, Sink, SinkFamily, Target, WorkerResult

FIXTURES = Path(__file__).parent / "fixtures"
SRC = Path(__file__).parent.parent / "src"

pytestmark = [
    pytest.mark.skipif(
        shutil.which("claude") is None,
        reason="claude CLI not on PATH — skipping live headless integration",
    ),
    pytest.mark.timeout(180),  # claude -p calls can take 30-60s each
]


def _run_worker(spec: HarnessSpec) -> list[WorkerResult]:
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{SRC}{os.pathsep}{FIXTURES}{os.pathsep}{env.get('PYTHONPATH', '')}"
    proc = subprocess.run(
        [sys.executable, "-m", "arbiter.worker"],
        input=spec.model_dump_json() + "\n",
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    out: list[WorkerResult] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            out.append(WorkerResult.model_validate(json.loads(line)))
        except Exception:
            continue
    return out


def test_headless_synthesizes_seeds_for_eval():
    target = Target(
        module="vulnpkg.api",
        qualname="eval_expression",
        signature="(expr: str) -> Any",
        docstring="Evaluate an arbitrary Python expression. Direct code_exec primitive.",
        exposure=Exposure.library,
    )
    sink = Sink(
        family=SinkFamily.code_exec,
        callable_qualname="eval",
        file="vulnpkg/api.py",
        line=14,
    )

    spec = synthesize_strategy(target, sink, llm=ClaudeHeadlessClient())

    assert spec.seeds, "headless claude produced no seeds"
    assert all("{MARKER}" in s for s in spec.seeds), spec.seeds
    assert spec.kind in {"text", "bytes"}


def test_headless_seeds_yield_witness_through_worker():
    """End-to-end: claude -p generates seeds, run through worker, expect tainted witness."""
    target = Target(
        module="vulnpkg.api",
        qualname="eval_expression",
        signature="(expr: str) -> Any",
        docstring="Evaluate an arbitrary Python expression.",
    )
    sink = Sink(
        family=SinkFamily.code_exec,
        callable_qualname="eval",
        file="vulnpkg/api.py",
        line=14,
    )
    spec = synthesize_strategy(target, sink, llm=ClaudeHeadlessClient())

    harness = HarnessSpec(
        target_module="vulnpkg.api",
        target_qualname="eval_expression",
        marker=uuid.uuid4().hex,
        max_examples=20,
        strategy=spec,
    )
    results = _run_worker(harness)
    tainted = [
        r for r in results if r.kind == "witness" and r.witness and r.witness.event.tainted
    ]
    assert tainted, f"no tainted witness from headless-synthesized seeds: results={results}"
    families = {r.witness.event.family.value for r in tainted}
    assert "code_exec" in families, families


def test_headless_synthesizes_for_yaml_unsafe_load():
    target = Target(
        module="vulnpkg.api",
        qualname="load_config",
        signature="(blob: str | bytes) -> Any",
        docstring="Parse YAML allowing arbitrary Python tags.",
    )
    sink = Sink(
        family=SinkFamily.deserialization,
        callable_qualname="yaml.unsafe_load",
        file="vulnpkg/api.py",
        line=18,
    )
    spec = synthesize_strategy(target, sink, llm=ClaudeHeadlessClient())
    assert spec.seeds
    assert all("{MARKER}" in s for s in spec.seeds), spec.seeds

    harness = HarnessSpec(
        target_module="vulnpkg.api",
        target_qualname="load_config",
        marker=uuid.uuid4().hex,
        max_examples=20,
        strategy=spec,
    )
    results = _run_worker(harness)
    tainted = [
        r for r in results if r.kind == "witness" and r.witness and r.witness.event.tainted
    ]
    assert tainted, f"no tainted witness for yaml.unsafe_load: results={results}"

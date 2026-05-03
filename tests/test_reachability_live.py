"""Live reachability test — `claude -p` agent mode traces flows from a known
vulnpkg target to the project's static sink inventory.

Skipped automatically when the `claude` CLI is not on PATH.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from arbiter.llm.reachability import analyze_reachability
from arbiter.models import Exposure, Target
from arbiter.sinks import scan_path

VULNPKG_PATH = Path(__file__).parent / "fixtures" / "vulnpkg"

pytestmark = [
    pytest.mark.skipif(
        shutil.which("claude") is None,
        reason="claude CLI not on PATH — skipping live reachability integration",
    ),
    pytest.mark.timeout(240),
]


def test_reachability_links_eval_expression_to_eval_sink():
    sinks = scan_path(VULNPKG_PATH)
    assert sinks, "static scan should find sinks in vulnpkg"

    target = Target(
        module="vulnpkg.api",
        qualname="eval_expression",
        signature="(expr: str) -> Any",
        docstring="Evaluate an arbitrary Python expression. Direct code_exec primitive.",
        exposure=Exposure.library,
    )

    flows = analyze_reachability(target, sinks, VULNPKG_PATH, max_turns=15)

    assert flows, "expected at least one flow from eval_expression to a sink"
    eval_flows = [f for f in flows if f.sink.callable_qualname == "eval"]
    assert eval_flows, f"expected a flow to eval; got {[f.sink.callable_qualname for f in flows]}"
    assert eval_flows[0].confidence >= 0.7, f"low confidence: {eval_flows[0].confidence}"

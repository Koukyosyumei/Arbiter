"""Orchestrator tests.

Strategy: monkeypatch the three LLM-using stages (`discover_targets`,
`analyze_reachability`, `synthesize_strategy`) but let the real static sink
scan and real worker subprocess run. The worker actually fires up a
Python subprocess against vulnpkg and the audit-hook oracle observes a real
exploit primitive — this is an integration test for the wiring.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from arbiter import orchestrator as orch
from arbiter.models import (
    Exposure,
    Flow,
    Sink,
    SinkFamily,
    StrategySpec,
    Target,
)

VULNPKG_PATH = Path(__file__).parent / "fixtures" / "vulnpkg"


def _eval_target() -> Target:
    return Target(
        module="vulnpkg.api",
        qualname="eval_expression",
        signature="(expr: str) -> Any",
        docstring="Evaluate an arbitrary Python expression.",
        exposure=Exposure.library,
    )


def _eval_sink() -> Sink:
    return Sink(
        family=SinkFamily.code_exec,
        callable_qualname="eval",
        file=str(VULNPKG_PATH / "api.py"),
        line=14,
    )


def _eval_strategy() -> StrategySpec:
    return StrategySpec(
        kind="text",
        seeds=["'{MARKER}' + str(1)", "1 + 1  # {MARKER}"],
    )


def test_run_campaign_finds_witnesses_with_stubbed_llm(monkeypatch):
    target = _eval_target()
    sink = _eval_sink()
    flow = Flow(
        target_fqn=target.fqn,
        sink=sink,
        intermediate=[],
        confidence=0.9,
        rationale="direct call eval(expr)",
    )

    monkeypatch.setattr(orch, "discover_targets", lambda *a, **kw: [target])
    monkeypatch.setattr(orch, "analyze_reachability", lambda *a, **kw: [flow])
    monkeypatch.setattr(orch, "synthesize_strategy", lambda *a, **kw: _eval_strategy())

    config = orch.CampaignConfig(
        package_path=VULNPKG_PATH,
        package_name="vulnpkg",
        max_examples_per_flow=15,
        worker_timeout_s=30.0,
        parallelism=1,
    )
    result = orch.run_campaign(config, llm=object())  # llm is unused once stages are stubbed

    assert result.targets == [target]
    assert result.flows == [flow]
    assert result.witnesses, f"expected at least one witness; errors={result.errors}"
    tainted = [w for w in result.witnesses if w.event.tainted]
    assert tainted, f"no tainted witnesses: {result.witnesses}"
    assert any(w.event.family is SinkFamily.code_exec for w in tainted)


def test_run_campaign_filters_by_confidence(monkeypatch):
    target = _eval_target()
    sink = _eval_sink()
    flow_high = Flow(target_fqn=target.fqn, sink=sink, confidence=0.9)
    flow_low = Flow(
        target_fqn=target.fqn,
        sink=Sink(
            family=SinkFamily.template,
            callable_qualname="jinja2.Environment",
            file=str(VULNPKG_PATH / "api.py"),
            line=24,
        ),
        confidence=0.2,
    )
    synth_calls: list[Flow] = []

    monkeypatch.setattr(orch, "discover_targets", lambda *a, **kw: [target])
    monkeypatch.setattr(orch, "analyze_reachability", lambda *a, **kw: [flow_high, flow_low])

    def fake_synth(t, s, flow=None, **kw):
        synth_calls.append(flow)
        return _eval_strategy()

    monkeypatch.setattr(orch, "synthesize_strategy", fake_synth)

    config = orch.CampaignConfig(
        package_path=VULNPKG_PATH,
        package_name="vulnpkg",
        max_examples_per_flow=10,
        flow_confidence_threshold=0.5,
        parallelism=1,
    )
    result = orch.run_campaign(config, llm=object())

    assert len(result.flows) == 2  # both retained in result
    assert len(synth_calls) == 1  # but only the above-threshold flow was synthesized
    assert synth_calls[0].confidence == 0.9


def test_run_campaign_records_discover_failure(monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("claude crashed")

    monkeypatch.setattr(orch, "discover_targets", boom)
    config = orch.CampaignConfig(
        package_path=VULNPKG_PATH,
        package_name="vulnpkg",
    )
    result = orch.run_campaign(config, llm=object())

    assert result.targets == []
    assert result.witnesses == []
    assert any("discover_targets failed" in e for e in result.errors)


def test_run_campaign_records_reachability_failure_continues(monkeypatch):
    target = _eval_target()
    monkeypatch.setattr(orch, "discover_targets", lambda *a, **kw: [target])
    monkeypatch.setattr(
        orch,
        "analyze_reachability",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    monkeypatch.setattr(orch, "synthesize_strategy", lambda *a, **kw: _eval_strategy())

    config = orch.CampaignConfig(
        package_path=VULNPKG_PATH,
        package_name="vulnpkg",
        parallelism=1,
    )
    result = orch.run_campaign(config, llm=object())

    assert result.targets == [target]
    assert result.flows == []
    assert any("analyze_reachability" in e for e in result.errors)


def test_run_campaign_short_circuits_when_no_targets(monkeypatch):
    monkeypatch.setattr(orch, "discover_targets", lambda *a, **kw: [])
    # Reachability/synthesize must NOT be called when targets are empty.
    monkeypatch.setattr(
        orch,
        "analyze_reachability",
        lambda *a, **kw: pytest.fail("reachability should not run"),
    )

    config = orch.CampaignConfig(
        package_path=VULNPKG_PATH,
        package_name="vulnpkg",
    )
    result = orch.run_campaign(config, llm=object())
    assert result.witnesses == []
    assert result.flows == []


def test_run_campaign_no_flows_means_no_workers(monkeypatch):
    target = _eval_target()
    monkeypatch.setattr(orch, "discover_targets", lambda *a, **kw: [target])
    monkeypatch.setattr(orch, "analyze_reachability", lambda *a, **kw: [])
    monkeypatch.setattr(
        orch,
        "synthesize_strategy",
        lambda *a, **kw: pytest.fail("synthesize should not run"),
    )

    config = orch.CampaignConfig(
        package_path=VULNPKG_PATH,
        package_name="vulnpkg",
    )
    result = orch.run_campaign(config, llm=object())
    assert result.witnesses == []


def test_run_campaign_merges_static_corpus_with_llm_seeds(monkeypatch):
    """Strategy fed to workers must include both static corpus and LLM seeds."""
    from arbiter.payloads import get_seed_corpus

    target = _eval_target()
    sink = _eval_sink()
    flow = Flow(target_fqn=target.fqn, sink=sink, confidence=0.9)
    llm_seeds = ["LLM_UNIQUE_{MARKER}_a", "LLM_UNIQUE_{MARKER}_b"]
    static_seeds = get_seed_corpus(SinkFamily.code_exec)

    monkeypatch.setattr(orch, "discover_targets", lambda *a, **kw: [target])
    monkeypatch.setattr(orch, "analyze_reachability", lambda *a, **kw: [flow])
    monkeypatch.setattr(
        orch,
        "synthesize_strategy",
        lambda *a, **kw: StrategySpec(kind="text", seeds=llm_seeds),
    )

    config = orch.CampaignConfig(
        package_path=VULNPKG_PATH,
        package_name="vulnpkg",
        max_examples_per_flow=5,
        parallelism=1,
    )
    result = orch.run_campaign(config, llm=object())

    assert len(result.strategies) == 1
    merged_strategy = next(iter(result.strategies.values()))
    merged = merged_strategy.seeds

    # Both streams represented
    assert any(s in merged for s in llm_seeds), f"LLM seeds missing: {merged}"
    assert any(s in merged for s in static_seeds), f"static seeds missing: {merged}"
    # No duplicates after dedupe
    assert len(merged) == len(set(merged))
    # Cap respected
    assert len(merged) <= orch.MAX_SEEDS_PER_STRATEGY


def test_run_campaign_caps_merged_seeds(monkeypatch):
    """If LLM returns many seeds, the cap still holds."""
    target = _eval_target()
    sink = _eval_sink()
    flow = Flow(target_fqn=target.fqn, sink=sink, confidence=0.9)
    # 50 unique LLM seeds — far above the cap
    llm_seeds = [f"LLM_{i}_{{MARKER}}" for i in range(50)]

    monkeypatch.setattr(orch, "discover_targets", lambda *a, **kw: [target])
    monkeypatch.setattr(orch, "analyze_reachability", lambda *a, **kw: [flow])
    monkeypatch.setattr(
        orch,
        "synthesize_strategy",
        lambda *a, **kw: StrategySpec(kind="text", seeds=llm_seeds),
    )

    config = orch.CampaignConfig(
        package_path=VULNPKG_PATH,
        package_name="vulnpkg",
        max_examples_per_flow=5,
        parallelism=1,
    )
    result = orch.run_campaign(config, llm=object())
    merged_strategy = next(iter(result.strategies.values()))
    assert len(merged_strategy.seeds) == orch.MAX_SEEDS_PER_STRATEGY

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
    # Triage runs at the end; scored_witnesses must mirror witnesses, ranked.
    assert len(result.scored_witnesses) == len(result.witnesses)
    scores = [sw.score.final for sw in result.scored_witnesses]
    assert scores == sorted(scores, reverse=True)


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


def test_run_campaign_uses_harness_target_when_flow_specifies_one(monkeypatch):
    """When a flow carries harness_module/harness_qualname, the worker should
    fuzz the leaf — not the entry."""
    target = Target(
        module="vulnpkg.api",
        qualname="eval_expression",
        signature="(expr: str) -> Any",
        exposure=Exposure.library,
    )
    sink = _eval_sink()
    # Flow's harness target is a *different* fuzzable function in vulnpkg —
    # we'll point it at echo_safe so we can verify routing without needing
    # eval_expression to be the actual call.
    flow = Flow(
        target_fqn=target.fqn,
        sink=sink,
        confidence=0.95,
        harness_module="vulnpkg.api",
        harness_qualname="echo_safe",
    )
    captured: list = []

    def fake_synth(t, s, flow=None, **kw):
        return _eval_strategy()

    def fake_run_worker(spec, timeout_s, pythonpath_extra=None):
        captured.append(spec)
        # Return an empty result so the campaign completes cleanly.
        return []

    monkeypatch.setattr(orch, "discover_targets", lambda *a, **kw: [target])
    monkeypatch.setattr(orch, "analyze_reachability", lambda *a, **kw: [flow])
    monkeypatch.setattr(orch, "synthesize_strategy", fake_synth)
    monkeypatch.setattr(orch, "_run_worker", fake_run_worker)

    config = orch.CampaignConfig(
        package_path=VULNPKG_PATH,
        package_name="vulnpkg",
        parallelism=1,
    )
    orch.run_campaign(config, llm=object())

    assert len(captured) == 1
    spec = captured[0]
    assert spec.target_module == "vulnpkg.api"
    assert spec.target_qualname == "echo_safe", (
        f"expected harness_qualname to override entry; got {spec.target_qualname}"
    )


def test_run_campaign_falls_back_to_entry_when_no_harness(monkeypatch):
    """Default case — no harness on the flow, worker fuzzes the entry."""
    target = _eval_target()
    sink = _eval_sink()
    flow = Flow(target_fqn=target.fqn, sink=sink, confidence=0.95)  # no harness
    captured: list = []

    monkeypatch.setattr(orch, "discover_targets", lambda *a, **kw: [target])
    monkeypatch.setattr(orch, "analyze_reachability", lambda *a, **kw: [flow])
    monkeypatch.setattr(orch, "synthesize_strategy", lambda *a, **kw: _eval_strategy())
    monkeypatch.setattr(
        orch,
        "_run_worker",
        lambda spec, t, pythonpath_extra=None: captured.append(spec) or [],
    )

    config = orch.CampaignConfig(
        package_path=VULNPKG_PATH,
        package_name="vulnpkg",
        parallelism=1,
    )
    orch.run_campaign(config, llm=object())

    assert captured[0].target_module == target.module
    assert captured[0].target_qualname == target.qualname


def test_run_campaign_caps_targets_by_exposure_tier(monkeypatch):
    """When discover returns more targets than max_targets, the orchestrator
    drops the lowest-exposure tier first."""
    targets = [
        Target(module="m", qualname=f"net_{i}", signature="()", exposure=Exposure.network)
        for i in range(2)
    ] + [
        Target(module="m", qualname=f"cli_{i}", signature="()", exposure=Exposure.cli)
        for i in range(2)
    ] + [
        Target(module="m", qualname=f"int_{i}", signature="()", exposure=Exposure.internal)
        for i in range(5)
    ]
    monkeypatch.setattr(orch, "discover_targets", lambda *a, **kw: list(targets))
    monkeypatch.setattr(orch, "analyze_reachability", lambda *a, **kw: [])
    monkeypatch.setattr(
        orch, "synthesize_strategy", lambda *a, **kw: pytest.fail("unreached")
    )

    config = orch.CampaignConfig(
        package_path=VULNPKG_PATH,
        package_name="vulnpkg",
        max_targets=4,  # keep all network + cli, drop internals
    )
    result = orch.run_campaign(config, llm=object())
    assert len(result.targets) == 4
    exposures = [t.exposure for t in result.targets]
    # Network must come first (highest priority)
    assert exposures.count(Exposure.network) == 2
    assert exposures.count(Exposure.cli) == 2
    assert Exposure.internal not in exposures


def test_run_campaign_does_not_cap_when_under_limit(monkeypatch):
    target = _eval_target()
    monkeypatch.setattr(orch, "discover_targets", lambda *a, **kw: [target])
    monkeypatch.setattr(orch, "analyze_reachability", lambda *a, **kw: [])

    config = orch.CampaignConfig(
        package_path=VULNPKG_PATH,
        package_name="vulnpkg",
        max_targets=12,
    )
    result = orch.run_campaign(config, llm=object())
    assert result.targets == [target]


def test_flow_key_distinguishes_sink_locations():
    """Two flows with the same target+sink_qualname but different file:line
    must produce distinct keys. Without this, the strategies dict silently
    overwrites earlier entries."""
    target_fqn = "pkg.api:entry"
    sink_a = Sink(
        family=SinkFamily.deserialization,
        callable_qualname="pickle.loads",
        file="pkg/a.py",
        line=10,
    )
    sink_b = Sink(
        family=SinkFamily.deserialization,
        callable_qualname="pickle.loads",
        file="pkg/a.py",
        line=99,
    )
    sink_c = Sink(
        family=SinkFamily.deserialization,
        callable_qualname="pickle.loads",
        file="pkg/b.py",
        line=10,
    )
    keys = {
        orch._flow_key(Flow(target_fqn=target_fqn, sink=s, confidence=0.9))
        for s in (sink_a, sink_b, sink_c)
    }
    assert len(keys) == 3, f"expected 3 distinct keys, got {keys}"


def test_run_campaign_distinct_sink_locations_get_distinct_strategies(monkeypatch):
    """End-to-end: two flows hitting the same sink callable at different
    locations must each get their own synthesized strategy entry."""
    target = _eval_target()
    sink_a = Sink(
        family=SinkFamily.deserialization,
        callable_qualname="pickle.loads",
        file=str(VULNPKG_PATH / "api.py"),
        line=10,
    )
    sink_b = Sink(
        family=SinkFamily.deserialization,
        callable_qualname="pickle.loads",
        file=str(VULNPKG_PATH / "api.py"),
        line=42,
    )
    flow_a = Flow(target_fqn=target.fqn, sink=sink_a, confidence=0.9)
    flow_b = Flow(target_fqn=target.fqn, sink=sink_b, confidence=0.9)
    synth_calls: list[Flow] = []

    def fake_synth(t, s, flow=None, **kw):
        synth_calls.append(flow)
        return _eval_strategy()

    monkeypatch.setattr(orch, "discover_targets", lambda *a, **kw: [target])
    monkeypatch.setattr(orch, "analyze_reachability", lambda *a, **kw: [flow_a, flow_b])
    monkeypatch.setattr(orch, "synthesize_strategy", fake_synth)
    monkeypatch.setattr(
        orch,
        "_run_worker",
        lambda spec, t, pythonpath_extra=None: [],
    )

    config = orch.CampaignConfig(
        package_path=VULNPKG_PATH,
        package_name="vulnpkg",
        parallelism=1,
    )
    result = orch.run_campaign(config, llm=object())

    assert len(synth_calls) == 2, "synthesize_strategy must be called per distinct sink site"
    assert len(result.strategies) == 2, (
        f"expected 2 strategy entries, got {list(result.strategies)}"
    )


def test_run_campaign_logs_worker_summary_with_histogram(monkeypatch, caplog):
    """When workers report a summary, the orchestrator must surface
    examples_run + exception histogram so '0 witnesses' runs are diagnosable."""
    import logging

    from arbiter.models import WorkerResult

    target = _eval_target()
    sink = _eval_sink()
    flow = Flow(target_fqn=target.fqn, sink=sink, confidence=0.9)

    monkeypatch.setattr(orch, "discover_targets", lambda *a, **kw: [target])
    monkeypatch.setattr(orch, "analyze_reachability", lambda *a, **kw: [flow])
    monkeypatch.setattr(orch, "synthesize_strategy", lambda *a, **kw: _eval_strategy())
    monkeypatch.setattr(
        orch,
        "_run_worker",
        lambda spec, t, pythonpath_extra=None: [
            WorkerResult(
                kind="summary",
                examples_run=42,
                exception_histogram={"TypeError": 41, "ValueError": 1},
            )
        ],
    )

    config = orch.CampaignConfig(
        package_path=VULNPKG_PATH,
        package_name="vulnpkg",
        parallelism=1,
    )
    with caplog.at_level(logging.WARNING, logger="arbiter.orchestrator"):
        orch.run_campaign(config, llm=object())

    matching = [r for r in caplog.records if "ran 42 examples" in r.getMessage()]
    assert matching, f"no summary log found; records={[r.getMessage() for r in caplog.records]}"
    # Most-frequent exception comes first.
    assert "TypeError" in matching[0].getMessage()
    assert "ValueError" in matching[0].getMessage()


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

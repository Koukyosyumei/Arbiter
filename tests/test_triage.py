"""Triage unit tests — scoring components and end-to-end campaign ranking."""

from __future__ import annotations

from arbiter.models import (
    AttackerModel,
    AuditEvent,
    Exposure,
    Flow,
    Sink,
    SinkFamily,
    Target,
    Witness,
)
from arbiter.triage import (
    ATTACKER_MODEL_SCORE,
    EXPOSURE_SCORE,
    INTENT_PENALTY,
    SEVERITY_SCORE,
    score_witness,
    triage_campaign,
)


def _audit_event(family: SinkFamily = SinkFamily.code_exec, tainted: bool = True) -> AuditEvent:
    return AuditEvent(
        name="compile",
        family=family,
        args_repr=["'M'"],
        stack_summary=["m.py:1 in f"],
        marker_hits=["M"] if tainted else [],
    )


def _sink(family: SinkFamily = SinkFamily.code_exec) -> Sink:
    return Sink(family=family, callable_qualname="eval", file="m.py", line=1)


def _target(
    docstring: str | None = None,
    exposure: Exposure = Exposure.library,
) -> Target:
    return Target(
        module="m",
        qualname="f",
        signature="(x: str)",
        docstring=docstring,
        exposure=exposure,
    )


def _witness_for(target: Target, sink: Sink, tainted: bool = True) -> Witness:
    flow = Flow(target_fqn=target.fqn, sink=sink, intermediate=[], confidence=0.9)
    return Witness(
        target_fqn=target.fqn,
        flow=flow,
        event=_audit_event(family=sink.family, tainted=tainted),
        input_repr="'M'",
    )


# --- per-component scoring ---


def test_severity_critical_family():
    target = _target()
    sink = _sink(SinkFamily.code_exec)  # critical
    flow = Flow(target_fqn=target.fqn, sink=sink, intermediate=[])
    w = Witness(target_fqn=target.fqn, flow=flow, event=_audit_event(), input_repr="'M'")
    sw = score_witness(w, target, flow)
    assert sw.score.severity == SEVERITY_SCORE["critical"]


def test_severity_template_is_high_not_critical():
    target = _target()
    sink = _sink(SinkFamily.template)
    flow = Flow(target_fqn=target.fqn, sink=sink)
    w = Witness(
        target_fqn=target.fqn,
        flow=flow,
        event=_audit_event(family=SinkFamily.template),
        input_repr="x",
    )
    sw = score_witness(w, target, flow)
    assert sw.score.severity == SEVERITY_SCORE["high"]


def test_exposure_network_outranks_internal():
    sink = _sink()
    flow = Flow(target_fqn="m:f", sink=sink)
    target_net = _target(exposure=Exposure.network)
    target_int = _target(exposure=Exposure.internal)
    w = Witness(
        target_fqn="m:f", flow=flow, event=_audit_event(), input_repr="x"
    )
    s_net = score_witness(w, target_net, flow).score.exposure
    s_int = score_witness(w, target_int, flow).score.exposure
    assert s_net > s_int
    assert s_net == EXPOSURE_SCORE[Exposure.network]


def test_directness_drops_with_intermediate_hops():
    target = _target()
    sink = _sink()
    direct = Flow(target_fqn=target.fqn, sink=sink, intermediate=[])
    indirect = Flow(target_fqn=target.fqn, sink=sink, intermediate=["a", "b", "c"])
    w = Witness(target_fqn=target.fqn, flow=direct, event=_audit_event(), input_repr="x")
    d = score_witness(w, target, direct).score.directness
    i = score_witness(w, target, indirect).score.directness
    assert d > i
    assert d == 1.0
    assert i < 0.5


def test_intent_penalty_applies_when_docstring_advertises_behavior():
    sink = _sink(SinkFamily.code_exec)
    flow = Flow(target_fqn="m:f", sink=sink)
    target = _target(docstring="Evaluate an arbitrary Python expression.")
    w = Witness(target_fqn="m:f", flow=flow, event=_audit_event(), input_repr="x")
    sw = score_witness(w, target, flow)
    assert sw.score.intent_penalty == INTENT_PENALTY
    assert sw.intended_behavior_reason is not None
    assert sw.score.final < sw.score.raw


def test_intent_penalty_zero_when_docstring_is_silent():
    sink = _sink(SinkFamily.code_exec)
    flow = Flow(target_fqn="m:f", sink=sink)
    target = _target(docstring="Compute the next prime number.")
    w = Witness(target_fqn="m:f", flow=flow, event=_audit_event(), input_repr="x")
    sw = score_witness(w, target, flow)
    assert sw.score.intent_penalty == 0.0
    assert sw.intended_behavior_reason is None
    assert sw.score.final == sw.score.raw


def test_intent_penalty_zero_when_no_docstring():
    sink = _sink()
    flow = Flow(target_fqn="m:f", sink=sink)
    target = _target(docstring=None)
    w = Witness(target_fqn="m:f", flow=flow, event=_audit_event(), input_repr="x")
    sw = score_witness(w, target, flow)
    assert sw.score.intent_penalty == 0.0


def test_score_handles_missing_target_and_flow():
    w = Witness(
        target_fqn="m:f",
        event=_audit_event(),
        input_repr="x",
    )
    sw = score_witness(w, target=None, flow=None)
    # Should not crash and should produce a non-zero score for a tainted critical event.
    assert sw.score.final > 0
    assert sw.score.intent_penalty == 0.0


# --- campaign-level ranking ---


def test_triage_campaign_sorts_descending_by_final_score():
    target_net = _target(exposure=Exposure.network)
    target_int = _target(exposure=Exposure.internal)
    sink_crit = _sink(SinkFamily.code_exec)
    sink_med = _sink(SinkFamily.path)
    flow_a = Flow(target_fqn=target_net.fqn, sink=sink_crit, intermediate=[])
    flow_b = Flow(
        target_fqn=target_int.fqn, sink=sink_med, intermediate=["a", "b"]
    )
    w_high = Witness(
        target_fqn=target_net.fqn,
        flow=flow_a,
        event=_audit_event(family=SinkFamily.code_exec),
        input_repr="x",
    )
    w_low = Witness(
        target_fqn=target_int.fqn,
        flow=flow_b,
        event=_audit_event(family=SinkFamily.path),
        input_repr="y",
    )
    ranked = triage_campaign([w_low, w_high], [target_net, target_int], [flow_a, flow_b])
    assert ranked[0].witness is w_high
    assert ranked[1].witness is w_low


def test_triage_campaign_ranks_tainted_above_untainted():
    target = _target()
    sink = _sink()
    flow = Flow(target_fqn=target.fqn, sink=sink)
    untainted = Witness(
        target_fqn=target.fqn,
        flow=flow,
        event=_audit_event(tainted=False),
        input_repr="x",
    )
    tainted = Witness(
        target_fqn=target.fqn,
        flow=flow,
        event=_audit_event(tainted=True),
        input_repr="y",
    )
    ranked = triage_campaign([untainted, tainted], [target], [flow])
    assert ranked[0].witness is tainted
    assert ranked[1].witness is untainted


def test_triage_campaign_dedupes_with_diminishing_novelty():
    target = _target()
    sink = _sink()
    flow = Flow(target_fqn=target.fqn, sink=sink)
    # Three witnesses with the same fingerprint.
    w1 = _witness_for(target, sink)
    w2 = _witness_for(target, sink)
    w3 = _witness_for(target, sink)
    ranked = triage_campaign([w1, w2, w3], [target], [flow])
    novelty = [sw.score.novelty for sw in ranked]
    # All same fingerprint → first sorted has rank 0 (novelty 1.0); duplicates lower.
    assert max(novelty) == 1.0
    assert min(novelty) < 1.0
    assert sorted(novelty, reverse=True) == novelty  # already sorted desc


def test_triage_campaign_links_target_and_flow_back_to_witness():
    target = _target()
    sink = _sink()
    flow = Flow(target_fqn=target.fqn, sink=sink)
    w = _witness_for(target, sink)
    ranked = triage_campaign([w], [target], [flow])
    assert ranked[0].target is target
    assert ranked[0].flow is flow


# --- attacker_model multiplier ---


def test_attacker_model_default_network_is_neutral():
    target = _target(exposure=Exposure.network)
    sink = _sink()
    flow = Flow(target_fqn=target.fqn, sink=sink, attacker_model=AttackerModel.network)
    w = _witness_for(target, sink)
    sw = score_witness(w, target, flow)
    assert sw.score.attacker_model == ATTACKER_MODEL_SCORE[AttackerModel.network] == 1.0


def test_attacker_model_loaded_file_content_drops_score():
    """Same target, same sink — only attacker_model differs. The file-content
    flow should sort below the network flow."""
    target = _target(exposure=Exposure.network)
    sink = _sink()
    flow_net = Flow(
        target_fqn=target.fqn,
        sink=sink,
        attacker_model=AttackerModel.network,
    )
    flow_file = Flow(
        target_fqn=target.fqn,
        sink=sink,
        attacker_model=AttackerModel.loaded_file_content,
    )
    w_net = Witness(
        target_fqn=target.fqn,
        flow=flow_net,
        event=_audit_event(),
        input_repr="x",
    )
    w_file = Witness(
        target_fqn=target.fqn,
        flow=flow_file,
        event=_audit_event(),
        input_repr="y",
    )
    sw_net = score_witness(w_net, target, flow_net)
    sw_file = score_witness(w_file, target, flow_file)
    assert sw_net.score.final > sw_file.score.final
    assert sw_file.score.attacker_model == ATTACKER_MODEL_SCORE[AttackerModel.loaded_file_content]


def test_attacker_model_inherits_from_target_when_flow_unset():
    """Flow without an attacker_model override should fall back to target's
    effective model for scoring."""
    target = Target(
        module="m",
        qualname="open_file",
        signature="(path)",
        exposure=Exposure.network,
        attacker_model=AttackerModel.loaded_file_content,
    )
    sink = _sink()
    flow = Flow(target_fqn=target.fqn, sink=sink)  # attacker_model=None
    w = _witness_for(target, sink)
    sw = score_witness(w, target, flow)
    assert sw.score.attacker_model == ATTACKER_MODEL_SCORE[AttackerModel.loaded_file_content]


def test_attacker_model_score_neutral_when_target_and_flow_missing():
    sink = _sink()
    w = Witness(
        target_fqn="m:f",
        event=_audit_event(),
        input_repr="x",
    )
    sw = score_witness(w, target=None, flow=None)
    assert sw.score.attacker_model == 1.0

"""Reachability unit tests — no network. Exercises prompt construction, sink
resolution (qualname matching, suffix fallback), and Flow coercion.
"""

from __future__ import annotations

from pathlib import Path

from conftest import FakeLLM

from arbiter.llm.reachability import (
    REACH_SCHEMA,
    REACH_SYSTEM,
    REACH_TOOLS,
    analyze_reachability,
)
from arbiter.models import Exposure, Flow, Sink, SinkFamily, Target


def _target() -> Target:
    return Target(
        module="vulnpkg.api",
        qualname="eval_expression",
        signature="(expr: str) -> Any",
        docstring="Evaluate an arbitrary Python expression.",
        exposure=Exposure.library,
    )


def _sinks() -> list[Sink]:
    return [
        Sink(
            family=SinkFamily.code_exec,
            callable_qualname="eval",
            file="vulnpkg/api.py",
            line=14,
        ),
        Sink(
            family=SinkFamily.deserialization,
            callable_qualname="yaml.unsafe_load",
            file="vulnpkg/api.py",
            line=18,
        ),
        Sink(
            family=SinkFamily.template,
            callable_qualname="jinja2.Environment",
            file="vulnpkg/api.py",
            line=24,
        ),
    ]


def test_analyze_reachability_returns_flow_list():
    fake = FakeLLM(
        response={
            "flows": [
                {
                    "sink_qualname": "eval",
                    "intermediate": [],
                    "confidence": 0.95,
                    "rationale": "direct call eval(expr)",
                }
            ]
        }
    )
    flows = analyze_reachability(_target(), _sinks(), Path("/tmp/pkg"), llm=fake)
    assert len(flows) == 1
    assert isinstance(flows[0], Flow)
    assert flows[0].sink.callable_qualname == "eval"
    assert flows[0].confidence == 0.95
    assert flows[0].target_fqn == "vulnpkg.api:eval_expression"


def test_analyze_reachability_passes_agent_mode_flags():
    fake = FakeLLM(response={"flows": []})
    analyze_reachability(_target(), _sinks(), Path("/tmp/pkg"), llm=fake)

    call = fake.last
    assert call["tools"] == REACH_TOOLS
    assert call["add_dirs"] == ["/tmp/pkg"]
    assert call["system_mode"] == "append"
    assert call["schema"] is REACH_SCHEMA
    assert call["system"][0].text == REACH_SYSTEM


def test_analyze_reachability_resolves_sink_via_suffix():
    """Model returns 'unsafe_load' instead of 'yaml.unsafe_load'."""
    fake = FakeLLM(
        response={
            "flows": [
                {"sink_qualname": "unsafe_load", "confidence": 0.8, "intermediate": []}
            ]
        }
    )
    flows = analyze_reachability(_target(), _sinks(), Path("/tmp/pkg"), llm=fake)
    assert len(flows) == 1
    assert flows[0].sink.callable_qualname == "yaml.unsafe_load"


def test_analyze_reachability_drops_unknown_sink():
    fake = FakeLLM(
        response={
            "flows": [
                {"sink_qualname": "nonexistent.fn", "confidence": 0.9, "intermediate": []},
                {"sink_qualname": "eval", "confidence": 0.5, "intermediate": []},
            ]
        }
    )
    flows = analyze_reachability(_target(), _sinks(), Path("/tmp/pkg"), llm=fake)
    assert len(flows) == 1
    assert flows[0].sink.callable_qualname == "eval"


def test_analyze_reachability_clamps_confidence():
    fake = FakeLLM(
        response={
            "flows": [
                {"sink_qualname": "eval", "confidence": 1.5, "intermediate": []},
                {"sink_qualname": "yaml.unsafe_load", "confidence": -0.2, "intermediate": []},
            ]
        }
    )
    flows = analyze_reachability(_target(), _sinks(), Path("/tmp/pkg"), llm=fake)
    confidences = {f.sink.callable_qualname: f.confidence for f in flows}
    assert confidences["eval"] == 1.0
    assert confidences["yaml.unsafe_load"] == 0.0


def test_analyze_reachability_sorts_by_confidence_descending():
    fake = FakeLLM(
        response={
            "flows": [
                {"sink_qualname": "eval", "confidence": 0.3, "intermediate": []},
                {"sink_qualname": "yaml.unsafe_load", "confidence": 0.9, "intermediate": []},
                {"sink_qualname": "jinja2.Environment", "confidence": 0.6, "intermediate": []},
            ]
        }
    )
    flows = analyze_reachability(_target(), _sinks(), Path("/tmp/pkg"), llm=fake)
    confidences = [f.confidence for f in flows]
    assert confidences == sorted(confidences, reverse=True)


def test_analyze_reachability_short_circuits_when_no_sinks():
    fake = FakeLLM(response={"flows": []})
    flows = analyze_reachability(_target(), [], Path("/tmp/pkg"), llm=fake)
    assert flows == []
    assert fake.calls == []  # no LLM call made when there are no sinks


def test_analyze_reachability_includes_sink_inventory_in_user_prompt():
    fake = FakeLLM(response={"flows": []})
    analyze_reachability(_target(), _sinks(), Path("/tmp/pkg"), llm=fake)
    user = fake.last["user"]
    assert "eval" in user
    assert "yaml.unsafe_load" in user
    assert "jinja2.Environment" in user
    assert "vulnpkg.api:eval_expression" in user or "eval_expression" in user

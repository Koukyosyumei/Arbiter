"""Synthesizer unit tests — no network. Exercises prompt construction,
JSON parsing, and StrategySpec coercion using a fake LLM client.
"""

from __future__ import annotations

from typing import Any

import pytest

from arbiter.llm.sdk import SystemBlock, _parse_json_lenient
from arbiter.llm.synthesize import (
    SINK_FAMILY_GUIDE,
    SYSTEM_BASE,
    build_system_blocks,
    build_user_prompt,
    synthesize_strategy,
)
from arbiter.models import Exposure, Sink, SinkFamily, StrategySpec, Target


def _eval_sink() -> Sink:
    return Sink(
        family=SinkFamily.code_exec,
        callable_qualname="eval",
        file="vulnpkg/api.py",
        line=14,
        note=None,
    )


def _eval_target() -> Target:
    return Target(
        module="vulnpkg.api",
        qualname="eval_expression",
        signature="(expr: str) -> Any",
        docstring="Evaluate an arbitrary Python expression.",
        exposure=Exposure.library,
    )


class _FakeLLM:
    """Captures the last request and returns a canned dict."""

    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        self.last_system: list[SystemBlock] | None = None
        self.last_user: str | None = None
        self.last_schema: dict[str, Any] | None = None
        self.calls = 0

    def complete_json(
        self,
        system: list[SystemBlock],
        user: str,
        max_tokens: int = 2048,
        schema: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.last_system = system
        self.last_user = user
        self.last_schema = schema
        self.calls += 1
        return self.response


# --- prompt construction ---


def test_build_system_blocks_includes_base_and_family_guide():
    blocks = build_system_blocks(_eval_sink())
    assert len(blocks) == 2
    assert SYSTEM_BASE in blocks[0].text
    assert SINK_FAMILY_GUIDE[SinkFamily.code_exec] in blocks[1].text
    assert all(b.cache for b in blocks)  # both should be cached


def test_build_user_prompt_includes_target_and_sink_info():
    user = build_user_prompt(_eval_target(), _eval_sink())
    assert "vulnpkg.api:eval_expression" in user
    assert "(expr: str) -> Any" in user
    assert "Evaluate an arbitrary Python expression." in user
    assert "code_exec" in user
    assert "vulnpkg/api.py:14" in user


def test_build_user_prompt_includes_intermediate_when_flow_given():
    from arbiter.models import Flow

    flow = Flow(
        target_fqn="vulnpkg.api:eval_expression",
        sink=_eval_sink(),
        intermediate=["preprocess", "validate"],
        rationale="parser pipeline routes user input",
    )
    user = build_user_prompt(_eval_target(), _eval_sink(), flow)
    assert "preprocess -> validate" in user
    assert "parser pipeline" in user


def test_build_user_prompt_handles_missing_flow():
    user = build_user_prompt(_eval_target(), _eval_sink())
    assert "(direct call)" in user


# --- coercion ---


def test_synthesize_strategy_returns_strategy_spec():
    fake = _FakeLLM(
        {
            "kind": "text",
            "params": {"max_size": 64},
            "seeds": ["'{MARKER}' + str(1)", "1 + 1  # {MARKER}"],
            "rationale": "two literal-embedding patterns",
        }
    )
    spec = synthesize_strategy(_eval_target(), _eval_sink(), llm=fake)
    assert isinstance(spec, StrategySpec)
    assert spec.kind == "text"
    assert spec.params == {"max_size": 64}
    assert len(spec.seeds) == 2
    assert all("{MARKER}" in s for s in spec.seeds)
    assert fake.calls == 1


def test_synthesize_strategy_passes_schema_to_client():
    from arbiter.llm.synthesize import STRATEGY_SCHEMA

    fake = _FakeLLM({"kind": "text", "seeds": ["{MARKER}"]})
    synthesize_strategy(_eval_target(), _eval_sink(), llm=fake)
    assert fake.last_schema is STRATEGY_SCHEMA


def test_synthesize_strategy_drops_seeds_without_marker():
    fake = _FakeLLM(
        {
            "kind": "text",
            "seeds": ["good {MARKER}", "bad seed", "another good {MARKER}"],
        }
    )
    spec = synthesize_strategy(_eval_target(), _eval_sink(), llm=fake)
    assert len(spec.seeds) == 2
    assert all("{MARKER}" in s for s in spec.seeds)


def test_synthesize_strategy_falls_back_when_no_valid_seeds():
    fake = _FakeLLM({"kind": "text", "seeds": ["no marker", "still none"]})
    spec = synthesize_strategy(_eval_target(), _eval_sink(), llm=fake)
    assert spec.seeds == ["{MARKER}"], "expected fallback marker-only seed"


def test_synthesize_strategy_normalizes_bad_kind():
    fake = _FakeLLM({"kind": "neither", "seeds": ["{MARKER}"]})
    spec = synthesize_strategy(_eval_target(), _eval_sink(), llm=fake)
    assert spec.kind == "text"


def test_synthesize_strategy_normalizes_non_dict_params():
    fake = _FakeLLM({"kind": "text", "params": "not a dict", "seeds": ["{MARKER}"]})
    spec = synthesize_strategy(_eval_target(), _eval_sink(), llm=fake)
    assert spec.params == {}


# --- JSON parsing robustness ---


def test_parse_json_lenient_strict():
    assert _parse_json_lenient('{"a": 1}') == {"a": 1}


def test_parse_json_lenient_strips_fences():
    text = '```json\n{"a": 1, "b": [2, 3]}\n```'
    assert _parse_json_lenient(text) == {"a": 1, "b": [2, 3]}


def test_parse_json_lenient_extracts_balanced_object():
    text = 'Here is your JSON: {"a": 1} — hope it helps.'
    assert _parse_json_lenient(text) == {"a": 1}


def test_parse_json_lenient_handles_nested_objects():
    text = 'Here you go: {"a": {"b": [1, {"c": 2}]}}'
    assert _parse_json_lenient(text) == {"a": {"b": [1, {"c": 2}]}}


def test_parse_json_lenient_handles_strings_with_braces():
    text = '{"s": "a {b} c", "x": 1}'
    assert _parse_json_lenient(text) == {"s": "a {b} c", "x": 1}


def test_parse_json_lenient_raises_when_no_object():
    with pytest.raises(ValueError):
        _parse_json_lenient("there is no json here")


def test_parse_json_lenient_raises_when_unterminated():
    with pytest.raises(ValueError):
        _parse_json_lenient('{"a": 1, "b": ')

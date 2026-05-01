"""Discover unit tests — no network. Exercises prompt construction, agent-mode
flags, and Target coercion using FakeLLM.
"""

from __future__ import annotations

from pathlib import Path

from conftest import FakeLLM

from arbiter.llm.discover import (
    DEFAULT_MAX_TURNS,
    DISCOVER_SCHEMA,
    DISCOVER_SYSTEM,
    DISCOVER_TOOLS,
    discover_targets,
)
from arbiter.models import Exposure, Target


def _canned_response() -> dict:
    return {
        "targets": [
            {
                "module": "vulnpkg.api",
                "qualname": "eval_expression",
                "signature": "(expr: str) -> Any",
                "docstring": "Evaluate an arbitrary Python expression.",
                "exposure": "library",
                "rationale": "exported from package __init__",
            },
            {
                "module": "vulnpkg.api",
                "qualname": "load_config",
                "signature": "(blob: str | bytes) -> Any",
                "docstring": "Parse YAML allowing arbitrary Python tags.",
                "exposure": "library",
            },
        ]
    }


def test_discover_targets_returns_target_list():
    fake = FakeLLM(response=_canned_response())
    targets = discover_targets(Path("/tmp/pkg"), "vulnpkg", llm=fake)

    assert len(targets) == 2
    assert all(isinstance(t, Target) for t in targets)
    assert targets[0].module == "vulnpkg.api"
    assert targets[0].qualname == "eval_expression"
    assert targets[0].exposure is Exposure.library


def test_discover_targets_passes_agent_mode_flags():
    fake = FakeLLM(response={"targets": []})
    discover_targets(Path("/tmp/pkg"), "vulnpkg", llm=fake)

    call = fake.last
    assert call["tools"] == DISCOVER_TOOLS
    assert call["add_dirs"] == ["/tmp/pkg"]
    assert call["max_turns"] == DEFAULT_MAX_TURNS
    assert call["system_mode"] == "append"
    assert call["schema"] is DISCOVER_SCHEMA


def test_discover_targets_includes_system_and_user_content():
    fake = FakeLLM(response={"targets": []})
    discover_targets(Path("/tmp/pkg"), "vulnpkg", llm=fake)

    call = fake.last
    assert call["system"][0].text == DISCOVER_SYSTEM
    assert "vulnpkg" in call["user"]
    assert "/tmp/pkg" in call["user"]


def test_discover_targets_drops_malformed_entries():
    fake = FakeLLM(
        response={
            "targets": [
                {"module": "p.m", "qualname": "good", "signature": "()", "exposure": "library"},
                {"module": "p.m"},  # missing required fields
                "not a dict",
                {"module": "p.m", "qualname": "also_good", "signature": "()", "exposure": "cli"},
            ]
        }
    )
    targets = discover_targets(Path("/tmp/pkg"), "p", llm=fake)
    qualnames = {t.qualname for t in targets}
    assert qualnames == {"good", "also_good"}


def test_discover_targets_normalizes_unknown_exposure():
    fake = FakeLLM(
        response={
            "targets": [
                {
                    "module": "p.m",
                    "qualname": "f",
                    "signature": "()",
                    "exposure": "internet",  # not in enum
                }
            ]
        }
    )
    targets = discover_targets(Path("/tmp/pkg"), "p", llm=fake)
    assert len(targets) == 1
    assert targets[0].exposure is Exposure.library  # fallback


def test_discover_targets_handles_empty_response():
    fake = FakeLLM(response={"targets": []})
    targets = discover_targets(Path("/tmp/pkg"), "p", llm=fake)
    assert targets == []


def test_discover_targets_respects_max_turns_override():
    fake = FakeLLM(response={"targets": []})
    discover_targets(Path("/tmp/pkg"), "p", llm=fake, max_turns=5)
    assert fake.last["max_turns"] == 5

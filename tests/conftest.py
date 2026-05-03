"""Pytest config — exposes the bundled vulnpkg fixture on sys.path and provides
a minimal FakeLLM that satisfies the LLMClient Protocol for unit tests.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Make `vulnpkg` importable from anywhere in the test session.
if str(FIXTURES_DIR) not in sys.path:
    sys.path.insert(0, str(FIXTURES_DIR))


@dataclass(slots=True)
class FakeLLM:
    """Records every complete_json call and returns a canned dict.

    Satisfies arbiter.llm.sdk.LLMClient. Tests can inspect `calls` after
    the run to assert prompt structure, schema passthrough, agent-mode flags.
    """

    response: dict[str, Any]
    calls: list[dict[str, Any]] = field(default_factory=list)

    def complete_json(
        self,
        system: list[Any],
        user: str,
        max_tokens: int = 2048,
        schema: dict[str, Any] | None = None,
        tools: str = "",
        add_dirs: list[str] | None = None,
        max_turns: int | None = None,
        system_mode: str = "override",
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "system": system,
                "user": user,
                "max_tokens": max_tokens,
                "schema": schema,
                "tools": tools,
                "add_dirs": add_dirs,
                "max_turns": max_turns,
                "system_mode": system_mode,
            }
        )
        return self.response

    @property
    def last(self) -> dict[str, Any]:
        return self.calls[-1]

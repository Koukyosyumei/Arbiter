"""LLM client — drives `claude -p` headless mode.

Why headless rather than the Anthropic SDK directly:
    - Reuses the user's existing Claude Code authentication (OAuth or API key).
      No separate `ANTHROPIC_API_KEY` needed.
    - `claude -p --json-schema` validates structured output natively; the parsed
      object lands in `wrapper.structured_output` so we don't text-parse JSON.
    - `--tools ""` disables tool use, turning the agent into a pure
      transformation (prompt → JSON), which is what we want for synthesize,
      triage, and report.

Per-call cost note: without `--bare`, Claude Code loads its full agent system
prompt (~6K tokens) but caches it across calls, so the marginal cost of an
additional call within a campaign is small. `--bare` would skip this overhead
but disables OAuth auth — for a v0 default we accept the tradeoff.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Protocol

DEFAULT_MODEL = "haiku"
DEFAULT_TIMEOUT_S = 120.0


@dataclass(slots=True)
class SystemBlock:
    """One element of the system prompt. The `cache` flag is informational —
    Claude Code handles caching of the system prompt internally; the flag is
    retained so the abstraction can host an SDK backend later."""

    text: str
    cache: bool = True


class LLMClient(Protocol):
    """The minimal surface synthesize/triage/report depend on.

    `tools`, `add_dirs`, `max_turns`, and `system_mode` matter only for agent-
    mode calls (discover, reachability). Pure-transformation callers
    (synthesize, triage, report) leave them at their defaults.
    """

    def complete_json(
        self,
        system: list[SystemBlock],
        user: str,
        max_tokens: int = 2048,
        schema: dict[str, Any] | None = None,
        tools: str = "",
        add_dirs: list[str] | None = None,
        max_turns: int | None = None,
        system_mode: str = "override",
    ) -> dict[str, Any]: ...


@dataclass(slots=True)
class ClaudeHeadlessClient:
    """Spawns `claude -p` per call. Inherits the user's Claude Code auth."""

    model: str = DEFAULT_MODEL
    binary: str = "claude"
    timeout_s: float = DEFAULT_TIMEOUT_S
    extra_args: list[str] = field(default_factory=list)

    def complete_json(
        self,
        system: list[SystemBlock],
        user: str,
        max_tokens: int = 2048,  # noqa: ARG002 — protocol parity; ignored by headless
        schema: dict[str, Any] | None = None,
        tools: str = "",
        add_dirs: list[str] | None = None,
        max_turns: int | None = None,
        system_mode: str = "override",
    ) -> dict[str, Any]:
        if shutil.which(self.binary) is None:
            raise RuntimeError(f"claude CLI not found on PATH (looked for {self.binary!r})")

        system_text = "\n\n".join(b.text for b in system)
        system_flag = "--system-prompt" if system_mode == "override" else "--append-system-prompt"
        cmd: list[str] = [
            self.binary,
            "-p",
            user,
            "--output-format",
            "json",
            "--no-session-persistence",
            system_flag,
            system_text,
            "--tools",
            tools,
            "--model",
            self.model,
            *self.extra_args,
        ]
        if schema is not None:
            cmd.extend(["--json-schema", json.dumps(schema)])
        if max_turns is not None:
            cmd.extend(["--max-turns", str(max_turns)])
        for d in add_dirs or []:
            cmd.extend(["--add-dir", d])

        proc = subprocess.run(
            cmd,
            input="",  # explicit empty stdin so claude doesn't wait
            capture_output=True,
            text=True,
            timeout=self.timeout_s,
            env={**os.environ},
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"claude -p exited {proc.returncode}: stderr={proc.stderr.strip()}"
            )

        try:
            wrapper = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"claude -p emitted non-JSON wrapper: {proc.stdout!r}") from exc

        if wrapper.get("is_error"):
            raise RuntimeError(
                f"claude -p reported error: {wrapper.get('result') or wrapper.get('subtype')}"
            )

        # When --json-schema is set, the parsed object is in `structured_output`.
        if schema is not None and "structured_output" in wrapper:
            return wrapper["structured_output"]

        # Otherwise, parse the result text leniently (handles fences and prose).
        result = wrapper.get("result") or ""
        return _parse_json_lenient(result)


def _parse_json_lenient(text: str) -> dict[str, Any]:
    """Try strict JSON first; on failure, extract the first balanced object.

    Defense-in-depth — even with --json-schema, models occasionally wrap output
    in ```json fences when the schema is omitted or rejected.
    """
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    fence = re.search(r"```(?:json)?\s*(.+?)\s*```", text, re.DOTALL)
    if fence:
        try:
            return json.loads(fence.group(1))
        except json.JSONDecodeError:
            pass

    start = text.find("{")
    if start == -1:
        raise ValueError(f"no JSON object found in response: {text!r}")
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if esc:
            esc = False
            continue
        if ch == "\\" and in_str:
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start : i + 1])
    raise ValueError(f"unterminated JSON in response: {text!r}")

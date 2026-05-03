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
import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

DEFAULT_MODEL = "haiku"
# 300s tolerates real-codebase reachability calls (the agent reads multiple
# files, traces calls, and emits structured output). Vulnpkg-scale calls
# finish in 20-80s; 300s is the safety margin on real packages.
DEFAULT_TIMEOUT_S = 300.0
DEFAULT_RETRIES = 1
RETRY_BACKOFF_S = 5.0  # brief delay between attempts on non-timeout errors

log = logging.getLogger(__name__)


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
    """Spawns `claude -p` per call. Inherits the user's Claude Code auth.

    On transient failures the client retries once before raising:
      - `subprocess.TimeoutExpired` → retry with doubled timeout
      - non-zero exit                → wait `RETRY_BACKOFF_S` then retry
    """

    model: str = DEFAULT_MODEL
    binary: str = "claude"
    timeout_s: float = DEFAULT_TIMEOUT_S
    extra_args: list[str] = field(default_factory=list)
    retries: int = DEFAULT_RETRIES

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

        timeout = self.timeout_s
        current_max_turns = max_turns
        last_err: Exception | None = None
        for attempt in range(self.retries + 1):
            cmd = self._build_cmd(
                system=system,
                user=user,
                schema=schema,
                tools=tools,
                add_dirs=add_dirs,
                max_turns=current_max_turns,
                system_mode=system_mode,
            )
            try:
                wrapper = self._invoke(cmd, timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                last_err = exc
                if attempt < self.retries:
                    timeout *= 2
                    log.warning(
                        "claude -p timed out after %.0fs; retrying with %.0fs",
                        exc.timeout if exc.timeout else timeout / 2,
                        timeout,
                    )
                    continue
                raise
            except RuntimeError as exc:
                last_err = exc
                if attempt < self.retries:
                    # `error_max_turns` means the agent ran out of turns before
                    # finishing; same budget on retry will fail the same way.
                    # Double the turn budget for the next attempt.
                    if "error_max_turns" in str(exc) and current_max_turns is not None:
                        new_turns = current_max_turns * 2
                        log.warning(
                            "claude -p hit max_turns=%d; retrying with %d",
                            current_max_turns,
                            new_turns,
                        )
                        current_max_turns = new_turns
                    else:
                        log.warning(
                            "claude -p failed (%s); retrying after %.1fs",
                            str(exc)[:120],
                            RETRY_BACKOFF_S,
                        )
                    time.sleep(RETRY_BACKOFF_S)
                    continue
                raise
            return _extract_json(wrapper, schema=schema)
        # unreachable — loop either returns or raises
        raise RuntimeError(f"unreachable: last_err={last_err!r}")

    def _build_cmd(
        self,
        system: list[SystemBlock],
        user: str,
        schema: dict[str, Any] | None,
        tools: str,
        add_dirs: list[str] | None,
        max_turns: int | None,
        system_mode: str,
    ) -> list[str]:
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
        return cmd

    def _invoke(self, cmd: list[str], timeout: float) -> dict[str, Any]:
        """Run claude -p once; raise RuntimeError on non-zero exit, propagate
        TimeoutExpired. Returns the parsed wrapper JSON on success."""
        proc = subprocess.run(
            cmd,
            input="",  # explicit empty stdin so claude doesn't wait
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ},
        )
        if proc.returncode != 0:
            raise RuntimeError(_format_exit_error(proc))

        try:
            wrapper = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"claude -p emitted non-JSON wrapper (returncode 0): {proc.stdout[:400]!r}"
            ) from exc

        if wrapper.get("is_error"):
            raise RuntimeError(
                f"claude -p reported error: {wrapper.get('result') or wrapper.get('subtype')}"
            )
        return wrapper


def _format_exit_error(proc: subprocess.CompletedProcess) -> str:
    """Build a useful error string from a non-zero exit. The wrapper JSON in
    stdout often carries the real diagnostic; surface it when present."""
    msg = f"claude -p exited {proc.returncode}"
    diag = (proc.stderr or "").strip()
    # On non-zero exit, claude still often emits the wrapper JSON to stdout
    # with `is_error: true` and a `result` field describing the failure.
    if proc.stdout:
        try:
            wrapper = json.loads(proc.stdout)
            inner = wrapper.get("result") or wrapper.get("subtype") or ""
            if inner:
                diag = f"{diag} | wrapper={inner}".strip(" |")
        except json.JSONDecodeError:
            head = proc.stdout.strip()[:300]
            if head:
                diag = f"{diag} | stdout={head}".strip(" |")
    return f"{msg}: {diag}" if diag else msg


def _extract_json(wrapper: dict[str, Any], schema: dict[str, Any] | None) -> dict[str, Any]:
    """Pull the actual JSON payload from the claude -p wrapper.

    With --json-schema, the parsed object lands in `structured_output`. Without,
    we lenient-parse the `result` text (which may have prose or code fences).
    """
    if schema is not None and "structured_output" in wrapper:
        return wrapper["structured_output"]
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

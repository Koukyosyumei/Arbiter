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
            t_call = time.monotonic()
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
            # Surface call shape so the operator can see model/turns/cost without
            # re-running with -v. Cost is in USD, num_turns reflects how many tool
            # cycles the agent ran (relevant for tools="" → expect 1).
            num_turns = wrapper.get("num_turns")
            cost = wrapper.get("total_cost_usd") or wrapper.get("cost_usd")
            cost_str = f", cost=${cost:.4f}" if isinstance(cost, (int, float)) else ""
            turns_str = f", turns={num_turns}" if num_turns is not None else ""
            log.info(
                "claude -p [%s] %.1fs%s%s",
                self.model,
                time.monotonic() - t_call,
                turns_str,
                cost_str,
            )
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
        """Run claude -p with stream-json output; surface tool calls in logs
        as they arrive, return the final result wrapper.

        Raises RuntimeError on non-zero exit, propagates TimeoutExpired.
        Tests monkeypatch the module-level `_stream_invoke` rather than
        `subprocess.Popen` so they don't have to fake a streaming process.
        """
        # Switch the cmd built by _build_cmd from json to stream-json so we get
        # one event per turn instead of a single wrapper at the end. --verbose
        # is required by stream-json (claude refuses otherwise).
        cmd = list(cmd)
        fmt_idx = cmd.index("--output-format")
        cmd[fmt_idx + 1] = "stream-json"
        if "--verbose" not in cmd:
            cmd.append("--verbose")
        return _stream_invoke(cmd, timeout)


def _summarize_tool_args(args: dict[str, Any]) -> str:
    """One-line summary of a tool's input arguments for the log."""
    if not args:
        return ""
    for key in ("pattern", "file_path", "path", "command", "query", "url"):
        if key in args:
            v = str(args[key])
            return f" {v[:120]}{'…' if len(v) > 120 else ''}"
    s = json.dumps(args, separators=(",", ":"))
    return f" {s[:120]}{'…' if len(s) > 120 else ''}"


def _stream_invoke(cmd: list[str], timeout: float) -> dict[str, Any]:
    """Spawn `claude -p` with stream-json output, log tool calls + final
    text as they arrive, and return the final `result` event wrapper.

    Without `--include-partial-messages`, claude emits one event per
    completed assistant message; each message's `content` is a list of
    blocks (`thinking`, `tool_use`, `text`). We walk that list, log
    `tool_use` and non-empty `text` blocks, and skip thinking. The final
    result event has the same shape as the json-mode wrapper, so
    `_extract_json` and the retry loop don't need to change.
    """
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ},
    )
    deadline = time.monotonic() + timeout
    result_event: dict[str, Any] | None = None
    try:
        while True:
            if time.monotonic() > deadline:
                proc.kill()
                proc.wait()
                raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout)
            line = proc.stdout.readline() if proc.stdout else ""
            if line == "":
                break
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            t = obj.get("type")
            if t == "result":
                result_event = obj
                continue
            if t != "assistant":
                continue
            content = (obj.get("message") or {}).get("content") or []
            for block in content:
                btype = block.get("type")
                if btype == "tool_use":
                    name = block.get("name", "?")
                    # StructuredOutput is the synthetic schema-emit "tool"; the
                    # orchestrator already surfaces the resulting payload in
                    # its next log line, and the truncated raw blob isn't
                    # readable anyway.
                    if name == "StructuredOutput":
                        continue
                    args = block.get("input") or {}
                    log.info("  ↳ %s%s", name, _summarize_tool_args(args))
                elif btype == "text":
                    text = (block.get("text") or "").strip()
                    if text:
                        log.info(
                            "  haiku: %s",
                            text[:240] + ("…" if len(text) > 240 else ""),
                        )
    finally:
        try:
            proc.wait(timeout=max(1.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    stderr = proc.stderr.read() if proc.stderr else ""

    if proc.returncode != 0:
        from types import SimpleNamespace
        view = SimpleNamespace(
            returncode=proc.returncode,
            stdout=json.dumps(result_event) if result_event else "",
            stderr=stderr,
        )
        raise RuntimeError(_format_exit_error(view))

    if result_event is None:
        raise RuntimeError(
            f"claude -p stream ended without a 'result' event (stderr={stderr[:300]!r})"
        )
    if result_event.get("is_error"):
        raise RuntimeError(
            f"claude -p reported error: "
            f"{result_event.get('result') or result_event.get('subtype')}"
        )
    return result_event


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

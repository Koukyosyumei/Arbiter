"""ClaudeHeadlessClient unit tests — error formatting + retry semantics.

The SDK streams `claude -p`'s stream-json output to log tool calls live;
tests monkeypatch the module-level `_stream_invoke` rather than subprocess
so they don't need to fake a streaming process.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from arbiter.llm.sdk import (
    DEFAULT_RETRIES,
    DEFAULT_TIMEOUT_S,
    ClaudeHeadlessClient,
    SystemBlock,
    _format_exit_error,
)


class _FakeProc:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _ok_wrapper(payload: dict | None = None) -> dict:
    """A minimal claude -p success wrapper, as `_stream_invoke` returns it."""
    return {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "result": "",
        "structured_output": payload or {"ok": True},
    }


def _shutil_present(monkeypatch):
    monkeypatch.setattr("arbiter.llm.sdk.shutil.which", lambda _b: "/usr/bin/claude")


# --- defaults ---


def test_default_timeout_bumped_to_300s():
    assert DEFAULT_TIMEOUT_S == 300.0


def test_default_retries_is_one():
    assert DEFAULT_RETRIES == 1


# --- error formatting on non-zero exit ---


def test_format_exit_error_extracts_wrapper_result():
    proc = _FakeProc(
        returncode=1,
        stdout=json.dumps({"is_error": True, "result": "Rate limit hit"}),
        stderr="",
    )
    msg = _format_exit_error(proc)
    assert "exited 1" in msg
    assert "Rate limit hit" in msg


def test_format_exit_error_falls_back_to_stdout_head_on_non_json():
    proc = _FakeProc(returncode=1, stdout="some non-json output", stderr="")
    msg = _format_exit_error(proc)
    assert "exited 1" in msg
    assert "some non-json output" in msg


def test_format_exit_error_uses_stderr_when_stdout_empty():
    proc = _FakeProc(returncode=1, stdout="", stderr="boom\n")
    msg = _format_exit_error(proc)
    assert "exited 1" in msg
    assert "boom" in msg


# --- retry on TimeoutExpired ---


def test_retry_on_timeout_with_doubled_budget(monkeypatch):
    _shutil_present(monkeypatch)
    calls: list[float] = []

    def fake_invoke(cmd, timeout):
        calls.append(timeout)
        if len(calls) == 1:
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout)
        return _ok_wrapper({"k": 1})

    monkeypatch.setattr("arbiter.llm.sdk._stream_invoke", fake_invoke)

    client = ClaudeHeadlessClient(timeout_s=60.0)
    out = client.complete_json(
        system=[SystemBlock(text="sys")], user="u", schema={"type": "object"}
    )
    assert out == {"k": 1}
    assert calls == [60.0, 120.0]  # second attempt got 2× budget


def test_retries_exhausted_propagates_timeout(monkeypatch):
    _shutil_present(monkeypatch)

    def always_timeout(cmd, timeout):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout)

    monkeypatch.setattr("arbiter.llm.sdk._stream_invoke", always_timeout)

    client = ClaudeHeadlessClient(timeout_s=60.0, retries=1)
    with pytest.raises(subprocess.TimeoutExpired):
        client.complete_json(system=[SystemBlock(text="sys")], user="u")


# --- retry on non-zero exit ---


def test_retry_on_nonzero_exit(monkeypatch):
    _shutil_present(monkeypatch)
    monkeypatch.setattr("arbiter.llm.sdk.time.sleep", lambda _s: None)
    calls: list[int] = []

    def fake_invoke(cmd, timeout):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("claude -p exited 1: rate limited")
        return _ok_wrapper({"k": "ok"})

    monkeypatch.setattr("arbiter.llm.sdk._stream_invoke", fake_invoke)

    client = ClaudeHeadlessClient()
    out = client.complete_json(
        system=[SystemBlock(text="sys")], user="u", schema={"type": "object"}
    )
    assert out == {"k": "ok"}
    assert len(calls) == 2


def test_retries_disabled_when_set_to_zero(monkeypatch):
    _shutil_present(monkeypatch)

    def always_fail(cmd, timeout):
        raise RuntimeError("claude -p exited 1: boom")

    monkeypatch.setattr("arbiter.llm.sdk._stream_invoke", always_fail)
    client = ClaudeHeadlessClient(retries=0)
    with pytest.raises(RuntimeError, match="exited 1"):
        client.complete_json(system=[SystemBlock(text="sys")], user="u")


# --- happy path still works ---


def test_happy_path_returns_structured_output(monkeypatch):
    _shutil_present(monkeypatch)

    def fake_invoke(cmd, timeout):
        return _ok_wrapper({"answer": 42})

    monkeypatch.setattr("arbiter.llm.sdk._stream_invoke", fake_invoke)

    client = ClaudeHeadlessClient()
    out = client.complete_json(
        system=[SystemBlock(text="sys")], user="u", schema={"type": "object"}
    )
    assert out == {"answer": 42}


def test_retry_doubles_max_turns_on_error_max_turns(monkeypatch):
    """When claude -p reports `error_max_turns`, retry must rebuild the cmd
    with a doubled --max-turns flag rather than re-issuing the same call."""
    _shutil_present(monkeypatch)
    monkeypatch.setattr("arbiter.llm.sdk.time.sleep", lambda _s: None)
    seen_max_turns: list[int] = []

    def fake_invoke(cmd, timeout):
        if "--max-turns" in cmd:
            idx = cmd.index("--max-turns")
            seen_max_turns.append(int(cmd[idx + 1]))
        if len(seen_max_turns) == 1:
            raise RuntimeError("claude -p exited 1 | wrapper=error_max_turns")
        return _ok_wrapper({"k": 1})

    monkeypatch.setattr("arbiter.llm.sdk._stream_invoke", fake_invoke)

    client = ClaudeHeadlessClient()
    out = client.complete_json(
        system=[SystemBlock(text="sys")], user="u", schema={"type": "object"}, max_turns=20
    )
    assert out == {"k": 1}
    assert seen_max_turns == [20, 40], (
        f"expected --max-turns to double on retry; got {seen_max_turns}"
    )


def test_happy_path_falls_back_to_result_text_when_no_schema(monkeypatch):
    _shutil_present(monkeypatch)

    def fake_invoke(cmd, timeout):
        return {
            "type": "result",
            "is_error": False,
            "result": '{"answer": 42}',
        }

    monkeypatch.setattr("arbiter.llm.sdk._stream_invoke", fake_invoke)

    client = ClaudeHeadlessClient()
    out = client.complete_json(system=[SystemBlock(text="sys")], user="u")
    assert out == {"answer": 42}

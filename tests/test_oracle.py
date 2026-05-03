"""Oracle tests — verify the audit-hook listener captures dangerous events with taint.

Each test runs in a fresh subprocess because `sys.addaudithook` is irrevocable;
state would leak across tests in a shared interpreter.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
SRC = Path(__file__).parent.parent / "src"


def _run_in_subprocess(body: str, marker: str) -> list[dict]:
    """Run a snippet under the Oracle in a fresh interpreter; return drained events.

    Events are written to a temp file rather than stdout — exploit gadgets like
    `os.system('echo X')` would otherwise interleave their own output into stdout
    and break JSON parsing.
    """
    with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as tmp:
        out_path = tmp.name
    code = textwrap.dedent(
        f"""
        import json, sys
        sys.path.insert(0, {str(SRC)!r})
        sys.path.insert(0, {str(FIXTURES)!r})
        from arbiter.oracle import Oracle
        oracle = Oracle(marker={marker!r})
        oracle.install()
        try:
{textwrap.indent(body, " " * 12)}
        except BaseException as exc:
            sys.stderr.write(f"target raised: {{exc!r}}\\n")
        events = oracle.drain()
        with open({out_path!r}, "w") as _fh:
            json.dump([e.model_dump(mode='json') for e in events], _fh)
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, f"stderr={result.stderr}\nstdout={result.stdout}"
    with open(out_path) as fh:
        return json.load(fh)


def test_oracle_captures_eval_with_marker():
    marker = "MARKERAAAA1111"
    events = _run_in_subprocess(
        f"""
        from vulnpkg.api import eval_expression
        eval_expression({marker!r} + ' + 1')
        """,
        marker=marker,
    )
    code_exec_events = [e for e in events if e["family"] == "code_exec"]
    assert code_exec_events, f"no code_exec event captured; got {events}"
    tainted = [e for e in code_exec_events if e["marker_hits"]]
    assert tainted, f"code_exec event was not marker-tainted: {code_exec_events}"


def test_oracle_captures_yaml_unsafe_load_with_marker():
    marker = "MARKERBBBB2222"
    # !!python/object/apply:F [arg, ...] calls F(*args). We want os.system("echo X").
    body = f"""
        from vulnpkg.api import load_config
        load_config('!!python/object/apply:os.system ["echo {marker}"]')
        """
    events = _run_in_subprocess(body, marker=marker)
    tainted = [e for e in events if e["marker_hits"]]
    assert tainted, f"expected at least one tainted event, got {events}"
    families = {e["family"] for e in tainted}
    assert "process" in families, families


def test_oracle_captures_jinja_ssti_with_marker():
    marker = "MARKERCCCC3333"
    # SSTI gadget: walk subclasses to find a code-execution primitive whose arg
    # carries the marker. Jinja2 evaluates the template, which compiles Python.
    body = f"""
        from vulnpkg.api import render
        render(\"{{{{ ''.__class__.__mro__[1].__subclasses__() | length }}}} {marker}\")
        """
    events = _run_in_subprocess(body, marker=marker)
    # SSTI rendering invokes compile/exec internally with the template source,
    # which contains the marker. Expect a tainted code_exec event.
    tainted = [e for e in events if e["marker_hits"]]
    assert tainted, f"expected tainted code_exec from SSTI render; got {events}"


def test_oracle_safe_function_emits_no_critical_events():
    marker = "MARKERSAFEXXXX"
    events = _run_in_subprocess(
        f"""
        from vulnpkg.api import echo_safe
        echo_safe({marker!r})
        """,
        marker=marker,
    )
    # echo_safe should not trigger any code_exec/process/deserialization audit events.
    interesting = [
        e for e in events if e["family"] in {"code_exec", "process", "deserialization"}
    ]
    assert not interesting, f"unexpected dangerous events: {interesting}"


def test_oracle_dedupes_high_volume_compile_without_marker():
    """compile/exec events without marker hits should be filtered out (MARKER_GATED)."""
    marker = "MARKERGATEDXXXX"
    events = _run_in_subprocess(
        """
        compile('1 + 1', '<test>', 'eval')
        # no marker present in the compiled source -> gated event suppressed
        """,
        marker=marker,
    )
    code_exec = [e for e in events if e["family"] == "code_exec"]
    assert code_exec == [], f"expected no untainted code_exec, got {code_exec}"

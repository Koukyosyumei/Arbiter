"""Report generator tests — markdown advisory shape + PoC script validity."""

from __future__ import annotations

from pathlib import Path

from arbiter.models import (
    AuditEvent,
    Exposure,
    Flow,
    ScoreBreakdown,
    ScoredWitness,
    Sink,
    SinkFamily,
    Target,
    Witness,
)
from arbiter.report import (
    generate_advisory,
    generate_poc,
    report_filename,
    write_reports,
)


def _scored() -> ScoredWitness:
    target = Target(
        module="vulnpkg.api",
        qualname="eval_expression",
        signature="(expr: str) -> Any",
        docstring="Evaluate an arbitrary Python expression.",
        exposure=Exposure.library,
    )
    sink = Sink(
        family=SinkFamily.code_exec,
        callable_qualname="eval",
        file="vulnpkg/api.py",
        line=14,
    )
    flow = Flow(
        target_fqn=target.fqn,
        sink=sink,
        intermediate=[],
        confidence=0.95,
        rationale="Direct eval of the expr parameter without validation.",
    )
    event = AuditEvent(
        name="compile",
        family=SinkFamily.code_exec,
        args_repr=["'M' + str(1)"],
        stack_summary=["vulnpkg/api.py:14 in eval_expression", "<test>:1"],
        marker_hits=["M"],
    )
    witness = Witness(
        target_fqn=target.fqn,
        flow=flow,
        event=event,
        input_repr="'M' + str(1)",
    )
    score = ScoreBreakdown(
        severity=1.0,
        exposure=0.6,
        directness=1.0,
        novelty=1.0,
        intent_penalty=0.4,
        raw=0.6,
        final=0.36,
    )
    return ScoredWitness(
        witness=witness,
        target=target,
        flow=flow,
        score=score,
        intended_behavior_reason="target docstring mentions 'evaluate'",
    )


# --- advisory rendering ---


def test_advisory_includes_target_sink_score():
    md = generate_advisory(_scored())
    assert "vulnpkg.api:eval_expression" in md
    assert "eval" in md
    assert "code_exec" in md
    assert "0.360" in md  # final score


def test_advisory_includes_intent_penalty_note():
    md = generate_advisory(_scored())
    assert "intent" in md.lower()
    assert "evaluate" in md.lower()


def test_advisory_includes_remediation():
    md = generate_advisory(_scored())
    assert "ast.literal_eval" in md or "asteval" in md


def test_advisory_includes_score_breakdown_table():
    md = generate_advisory(_scored())
    assert "severity" in md
    assert "exposure" in md
    assert "directness" in md
    assert "novelty" in md


def test_advisory_handles_missing_target():
    sw = _scored()
    sw_nt = sw.model_copy(update={"target": None})
    md = generate_advisory(sw_nt)
    assert "vulnpkg.api:eval_expression" in md  # fqn still appears
    assert "metadata unavailable" in md


# --- PoC script ---


def test_poc_is_syntactically_valid_python():
    src = generate_poc(_scored(), Path("/tmp/vulnpkg"))
    # Compile in exec mode — raises SyntaxError if malformed.
    compile(src, "<poc-test>", "exec")


def test_poc_includes_warning_header():
    src = generate_poc(_scored(), Path("/tmp/vulnpkg"))
    assert "WARNING" in src
    assert "isolated environment" in src.lower()


def test_poc_imports_target_module():
    src = generate_poc(_scored(), Path("/tmp/vulnpkg"))
    assert "from vulnpkg.api import" in src
    assert "PAYLOAD =" in src


def test_poc_payload_round_trips_input_repr():
    src = generate_poc(_scored(), Path("/tmp/vulnpkg"))
    # The PAYLOAD line should embed the literal repr from the witness.
    assert "PAYLOAD = 'M' + str(1)" in src


# --- file output ---


def test_write_reports_creates_md_and_py_per_witness(tmp_path: Path):
    written = write_reports([_scored()], tmp_path / "out", Path("/tmp/vulnpkg"))
    assert len(written) == 2
    suffixes = {p.suffix for p in written}
    assert suffixes == {".md", ".py"}
    for p in written:
        assert p.exists()
        assert p.stat().st_size > 0


def test_report_filename_is_filesystem_safe():
    sw = _scored()
    md_name = report_filename(sw, "md")
    py_name = report_filename(sw, "py")
    # ASCII alnum + underscore + dot only.
    import re as _re

    assert _re.match(r"^[a-z0-9_]+\.(md|py)$", md_name)
    assert _re.match(r"^[a-z0-9_]+\.(md|py)$", py_name)
    assert md_name != py_name
    assert md_name.endswith(".md")
    assert py_name.endswith(".py")


def test_write_reports_handles_multiple_witnesses(tmp_path: Path):
    sw_a = _scored()
    sw_b = _scored().model_copy(
        update={
            "witness": _scored().witness.model_copy(
                update={"target_fqn": "vulnpkg.api:load_config"}
            )
        }
    )
    written = write_reports([sw_a, sw_b], tmp_path, Path("/tmp/vulnpkg"))
    assert len(written) == 4
    # No two output paths should collide.
    assert len(set(written)) == 4

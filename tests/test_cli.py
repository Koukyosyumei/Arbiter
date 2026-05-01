"""CLI smoke tests — typer.testing.CliRunner against `arbiter scan`.

Stubs out `run_campaign` so the test is fast and deterministic; the CLI's job
is argument parsing, output formatting, and exit codes.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from arbiter import cli as cli_module
from arbiter.models import (
    AuditEvent,
    Exposure,
    Flow,
    Sink,
    SinkFamily,
    Target,
    Witness,
)
from arbiter.orchestrator import CampaignResult


def _sample_result() -> CampaignResult:
    target = Target(
        module="vulnpkg.api",
        qualname="eval_expression",
        signature="(expr: str) -> Any",
        exposure=Exposure.library,
    )
    sink = Sink(
        family=SinkFamily.code_exec,
        callable_qualname="eval",
        file="vulnpkg/api.py",
        line=14,
    )
    flow = Flow(target_fqn=target.fqn, sink=sink, confidence=0.9)
    event = AuditEvent(
        name="compile",
        family=SinkFamily.code_exec,
        args_repr=["'MARKER + 1'"],
        stack_summary=["vulnpkg/api.py:14 in eval_expression"],
        marker_hits=["MARKER"],
    )
    witness = Witness(target_fqn=target.fqn, flow=flow, event=event, input_repr="'MARKER + 1'")
    return CampaignResult(
        targets=[target],
        sinks=[sink],
        flows=[flow],
        witnesses=[witness],
    )


def test_scan_prints_summary_and_exits_zero_when_witnesses(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(cli_module, "run_campaign", lambda config: _sample_result())
    runner = CliRunner()
    result = runner.invoke(cli_module.app, ["scan", str(tmp_path)])
    assert result.exit_code == 0, result.stdout
    assert "witnesses: 1" in result.stdout
    assert "[TAINTED]" in result.stdout
    assert "vulnpkg.api:eval_expression" in result.stdout


def test_scan_exits_one_when_no_witnesses(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(cli_module, "run_campaign", lambda config: CampaignResult())
    runner = CliRunner()
    result = runner.invoke(cli_module.app, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    assert "witnesses: 0" in result.stdout


def test_scan_writes_output_json_when_requested(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(cli_module, "run_campaign", lambda config: _sample_result())
    out_path = tmp_path / "result.json"
    runner = CliRunner()
    result = runner.invoke(
        cli_module.app, ["scan", str(tmp_path), "--output-json", str(out_path)]
    )
    assert result.exit_code == 0, result.stdout
    assert out_path.exists()
    payload = json.loads(out_path.read_text())
    assert "targets" in payload
    assert "witnesses" in payload
    assert len(payload["witnesses"]) == 1


def test_scan_errors_when_path_missing():
    runner = CliRunner()
    result = runner.invoke(cli_module.app, ["scan", "/nonexistent/path/xyz"])
    assert result.exit_code == 2


def test_scan_passes_config_to_orchestrator(monkeypatch, tmp_path: Path):
    captured: dict = {}

    def fake_run(config):
        captured["config"] = config
        return CampaignResult()

    monkeypatch.setattr(cli_module, "run_campaign", fake_run)
    runner = CliRunner()
    runner.invoke(
        cli_module.app,
        [
            "scan",
            str(tmp_path),
            "--package-name",
            "mypkg",
            "--max-examples",
            "42",
            "--confidence-threshold",
            "0.7",
            "--parallelism",
            "2",
        ],
    )
    cfg = captured["config"]
    assert cfg.package_name == "mypkg"
    assert cfg.max_examples_per_flow == 42
    assert cfg.flow_confidence_threshold == 0.7
    assert cfg.parallelism == 2

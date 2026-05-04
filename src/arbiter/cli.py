"""Arbiter CLI — `arbiter scan <package_path>` runs an end-to-end campaign."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Annotated

import typer

from arbiter.orchestrator import CampaignConfig, CampaignResult, run_campaign
from arbiter.report import write_reports

app = typer.Typer(
    name="arbiter",
    help="LLM-augmented Hypothesis fuzzer for Python ACE detection.",
    no_args_is_help=True,
    add_completion=False,
)


# Forces typer to treat `scan` as a named subcommand even though it's the only
# one today; future stages (e.g. `arbiter discover`, `arbiter triage`) will
# attach without restructuring callers.
@app.callback()
def _root() -> None:  # pragma: no cover — typer wiring
    pass


def _format_summary(result: CampaignResult) -> str:
    lines = [
        f"sinks discovered: {len(result.sinks)}",
        f"targets discovered: {len(result.targets)}",
        f"flows hypothesized: {len(result.flows)}",
        f"strategies synthesized: {len(result.strategies)}",
        f"witnesses: {len(result.witnesses)}",
    ]
    if result.errors:
        lines.append(f"errors: {len(result.errors)}")
    if result.scored_witnesses:
        lines.append("")
        lines.append("ranked witnesses:")
        for sw in result.scored_witnesses:
            w = sw.witness
            tainted = "[TAINTED]" if w.event.tainted else "[untainted]"
            intent = " (intended)" if sw.intended_behavior_reason else ""
            lines.append(
                f"  {sw.score.final:.3f}  {tainted} {w.target_fqn} -> "
                f"{w.event.name} ({w.event.family.value}){intent}"
            )
    return "\n".join(lines)


@app.command()
def scan(
    package_path: Annotated[Path, typer.Argument(help="Path to the package source tree.")],
    package_name: Annotated[
        str | None,
        typer.Option("--package-name", "-n", help="Importable package name. Defaults to dir basename."),
    ] = None,
    max_examples: Annotated[
        int, typer.Option("--max-examples", help="Hypothesis examples per flow.")
    ] = 100,
    confidence_threshold: Annotated[
        float,
        typer.Option(
            "--confidence-threshold",
            "-c",
            min=0.0,
            max=1.0,
            help="Drop flows with confidence below this.",
        ),
    ] = 0.5,
    parallelism: Annotated[
        int, typer.Option("--parallelism", "-j", help="Concurrent worker subprocesses.")
    ] = 4,
    max_targets: Annotated[
        int,
        typer.Option(
            "--max-targets",
            help="Cap reachability/synthesize work to top-K targets by exposure tier.",
        ),
    ] = 12,
    worker_timeout: Annotated[
        float, typer.Option("--worker-timeout", help="Per-worker wall-clock seconds.")
    ] = 60.0,
    output_json: Annotated[
        Path | None,
        typer.Option("--output-json", "-o", help="Write full CampaignResult as JSON."),
    ] = None,
    report_dir: Annotated[
        Path | None,
        typer.Option(
            "--report-dir",
            "-r",
            help="Write per-witness markdown advisories + standalone PoC scripts.",
        ),
    ] = None,
    artifact_dir: Annotated[
        Path | None,
        typer.Option(
            "--artifact-dir",
            help="Write resumable campaign stage artifacts to this directory.",
        ),
    ] = None,
    resume_from: Annotated[
        Path | None,
        typer.Option(
            "--resume-from",
            help=(
                "Load campaign stage artifacts from this directory and continue "
                "from missing stages."
            ),
        ),
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose logs.")] = False,
) -> None:
    """Run a full ACE-detection campaign against a Python package."""
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if not package_path.exists():
        typer.echo(f"error: {package_path} does not exist", err=True)
        raise typer.Exit(2)

    config = CampaignConfig(
        package_path=package_path.resolve(),
        package_name=package_name or package_path.name,
        max_examples_per_flow=max_examples,
        flow_confidence_threshold=confidence_threshold,
        worker_timeout_s=worker_timeout,
        parallelism=parallelism,
        max_targets=max_targets,
        artifact_dir=artifact_dir,
        resume_from=resume_from,
    )

    typer.echo(f"scanning {config.package_path} as {config.package_name!r}", err=True)
    result = run_campaign(config)
    typer.echo(_format_summary(result))

    if output_json is not None:
        payload = {
            "targets": [t.model_dump(mode="json") for t in result.targets],
            "sinks": [s.model_dump(mode="json") for s in result.sinks],
            "flows": [f.model_dump(mode="json") for f in result.flows],
            "strategies": {k: v.model_dump(mode="json") for k, v in result.strategies.items()},
            "witnesses": [w.model_dump(mode="json") for w in result.witnesses],
            "scored_witnesses": [
                sw.model_dump(mode="json") for sw in result.scored_witnesses
            ],
            "errors": result.errors,
        }
        output_json.write_text(json.dumps(payload, indent=2, default=str))
        typer.echo(f"wrote {output_json}", err=True)

    if report_dir is not None and result.scored_witnesses:
        written = write_reports(result.scored_witnesses, report_dir, config.package_path)
        typer.echo(f"wrote {len(written)} report files to {report_dir}", err=True)

    raise typer.Exit(0 if result.witnesses else 1)


if __name__ == "__main__":
    app()

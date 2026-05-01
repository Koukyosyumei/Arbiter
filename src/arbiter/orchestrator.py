"""Campaign orchestrator — wires discover, sink scan, reachability, synthesize,
and worker pool into a single end-to-end run.

Pipeline:

    static sink scan ─┐
                      ├─→ reachability per target ─→ flows above threshold ─→ synth + worker
    LLM discover ─────┘                                                          │
                                                                                  ▼
                                                                              witnesses

LLM calls are serial today (parallel `claude -p` instances may hit rate limits).
Worker subprocesses run in a ThreadPoolExecutor — each thread blocks on its own
subprocess, GIL is released, so parallelism is real.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from arbiter.llm.discover import discover_targets
from arbiter.llm.reachability import analyze_reachability
from arbiter.llm.sdk import ClaudeHeadlessClient, LLMClient
from arbiter.llm.synthesize import synthesize_strategy
from arbiter.models import (
    Flow,
    HarnessSpec,
    Sink,
    StrategySpec,
    Target,
    Witness,
    WorkerResult,
)
from arbiter.sinks import scan_path

log = logging.getLogger(__name__)


@dataclass(slots=True)
class CampaignConfig:
    package_path: Path
    package_name: str
    max_examples_per_flow: int = 100
    flow_confidence_threshold: float = 0.5
    worker_timeout_s: float = 60.0
    rss_limit_mb: int = 512
    parallelism: int = 4
    discover_max_turns: int = 30
    reachability_max_turns: int = 20


@dataclass(slots=True)
class CampaignResult:
    targets: list[Target] = field(default_factory=list)
    sinks: list[Sink] = field(default_factory=list)
    flows: list[Flow] = field(default_factory=list)
    strategies: dict[str, StrategySpec] = field(default_factory=dict)
    witnesses: list[Witness] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _run_worker(
    spec: HarnessSpec,
    timeout_s: float,
    pythonpath_extra: list[Path] | None = None,
) -> list[WorkerResult]:
    """Spawn `python -m arbiter.worker` with `spec` on stdin, parse stdout JSONL."""
    env = os.environ.copy()
    if pythonpath_extra:
        prefix = os.pathsep.join(str(p) for p in pythonpath_extra)
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{prefix}{os.pathsep}{existing}" if existing else prefix
    proc = subprocess.run(
        [sys.executable, "-m", "arbiter.worker"],
        input=spec.model_dump_json() + "\n",
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout_s,
    )
    out: list[WorkerResult] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            out.append(WorkerResult.model_validate(json.loads(line)))
        except Exception as exc:
            log.debug("dropping unparseable worker line %r: %s", line, exc)
    return out


def _flow_key(flow: Flow) -> str:
    return f"{flow.target_fqn}|{flow.sink.callable_qualname}"


def run_campaign(
    config: CampaignConfig,
    llm: LLMClient | None = None,
) -> CampaignResult:
    """End-to-end campaign. Single shared `llm` so prompt caches accumulate."""
    client = llm or ClaudeHeadlessClient()
    result = CampaignResult()

    # 1. Static sink inventory — deterministic, no LLM.
    log.info("scanning sinks in %s", config.package_path)
    result.sinks = scan_path(config.package_path)
    log.info("found %d sinks", len(result.sinks))

    # 2. LLM discovery — public attack surface.
    log.info("discovering targets in %s", config.package_name)
    try:
        result.targets = discover_targets(
            config.package_path,
            config.package_name,
            llm=client,
            max_turns=config.discover_max_turns,
        )
    except Exception as exc:
        msg = f"discover_targets failed: {exc!r}"
        log.error(msg)
        result.errors.append(msg)
        return result
    log.info("found %d targets", len(result.targets))

    if not result.sinks or not result.targets:
        log.info("nothing to fuzz; returning")
        return result

    # 3. Reachability per target — serial to avoid concurrent claude -p invocations.
    all_flows: list[Flow] = []
    for target in result.targets:
        log.info("analyzing reachability for %s", target.fqn)
        try:
            flows = analyze_reachability(
                target,
                result.sinks,
                config.package_path,
                llm=client,
                max_turns=config.reachability_max_turns,
            )
        except Exception as exc:
            msg = f"analyze_reachability({target.fqn}) failed: {exc!r}"
            log.warning(msg)
            result.errors.append(msg)
            continue
        all_flows.extend(flows)
    result.flows = all_flows

    # 4. Filter by confidence; keep only what's worth fuzzing.
    fuzzable = [f for f in all_flows if f.confidence >= config.flow_confidence_threshold]
    log.info(
        "%d/%d flows above confidence threshold %.2f",
        len(fuzzable),
        len(all_flows),
        config.flow_confidence_threshold,
    )
    if not fuzzable:
        return result

    # 5. Synthesize a strategy per flow — serial.
    harnesses: list[HarnessSpec] = []
    for flow in fuzzable:
        target = next((t for t in result.targets if t.fqn == flow.target_fqn), None)
        if target is None:
            continue
        log.info("synthesizing strategy for %s -> %s", flow.target_fqn, flow.sink.callable_qualname)
        try:
            strategy = synthesize_strategy(target, flow.sink, flow=flow, llm=client)
        except Exception as exc:
            msg = f"synthesize_strategy({_flow_key(flow)}) failed: {exc!r}"
            log.warning(msg)
            result.errors.append(msg)
            continue
        result.strategies[_flow_key(flow)] = strategy
        harnesses.append(
            HarnessSpec(
                target_module=target.module,
                target_qualname=target.qualname,
                strategy=strategy,
                marker=uuid.uuid4().hex,
                max_examples=config.max_examples_per_flow,
                timeout_s=config.worker_timeout_s,
                rss_limit_mb=config.rss_limit_mb,
            )
        )

    if not harnesses:
        return result

    # 6. Worker pool — parallel subprocesses, blocking-per-thread.
    # PYTHONPATH gets both the package dir and its parent so the worker can
    # import the target whether `package_path` is the package itself or the
    # directory containing it.
    pkg_path = config.package_path
    pythonpath_extra = [pkg_path, pkg_path.parent]
    log.info("running %d harnesses with parallelism=%d", len(harnesses), config.parallelism)
    with ThreadPoolExecutor(max_workers=config.parallelism) as pool:
        futures = {
            pool.submit(
                _run_worker, spec, config.worker_timeout_s + 30, pythonpath_extra
            ): spec
            for spec in harnesses
        }
        for fut in as_completed(futures):
            spec = futures[fut]
            try:
                worker_results = fut.result()
            except subprocess.TimeoutExpired:
                msg = f"worker timeout: {spec.target_module}:{spec.target_qualname}"
                log.warning(msg)
                result.errors.append(msg)
                continue
            except Exception as exc:
                msg = f"worker failed for {spec.target_module}:{spec.target_qualname}: {exc!r}"
                log.warning(msg)
                result.errors.append(msg)
                continue
            for r in worker_results:
                if r.kind == "witness" and r.witness is not None:
                    result.witnesses.append(r.witness)
                elif r.kind == "error" and r.error:
                    result.errors.append(
                        f"worker {spec.target_module}:{spec.target_qualname}: {r.error}"
                    )

    log.info(
        "campaign complete: %d witnesses across %d harnesses",
        len(result.witnesses),
        len(harnesses),
    )
    return result

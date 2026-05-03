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
from arbiter.llm.reachability import analyze_reachability, filter_sinks_by_imports
from arbiter.llm.sdk import ClaudeHeadlessClient, LLMClient
from arbiter.llm.synthesize import synthesize_strategy
from arbiter.models import (
    AttackerModel,
    Exposure,
    Flow,
    HarnessSpec,
    ScoredWitness,
    Sink,
    StrategySpec,
    Target,
    Witness,
    WorkerResult,
)

# Reasonable file-suffix per format-bearing entry. Generic packages typically
# parse one of these; the suffix matters because some parsers dispatch on
# extension (`open(path).read()` is content-only, but `cls.open_file(path)`
# may sniff `.endswith(".leo")` first).
_DEFAULT_FILE_SUFFIX = ".dat"
_PACKAGE_FILE_SUFFIX_HINTS: dict[str, str] = {
    # Hand-tuned for common projects; future work: derive from sink families
    # in the flow (xml → ".xml", deserialization+pickle → ".pkl", etc.).
    "leo": ".leo",
}
from arbiter.payloads import get_seed_corpus
from arbiter.sinks import (
    _iter_python_files,
    find_wrapper_sinks,
    scan_file_with_registry,
    scan_path,
)
from arbiter.static_targets import find_decorator_targets, merge_targets
from arbiter.triage import triage_campaign

MAX_SEEDS_PER_STRATEGY = 30

# Reachability cost is the dominant pipeline expense (one LLM call per target,
# each ~30-180s). On real packages, discover often finds 30-100 callables;
# 12 keeps a real campaign under 30min wall-clock while still covering every
# network/cli entry point on most projects.
DEFAULT_MAX_TARGETS = 12

_EXPOSURE_PRIORITY: dict[Exposure, int] = {
    Exposure.network: 0,
    Exposure.cli: 1,
    Exposure.library: 2,
    Exposure.internal: 3,
}

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
    # 30 (→ 60 on retry) suits real packages where each sink needs several
    # offset/limit Read calls. Earlier 20 was tuned for vulnpkg only and
    # exhausted the budget on monolithic codebases like leo.
    reachability_max_turns: int = 30
    max_targets: int = DEFAULT_MAX_TARGETS


@dataclass(slots=True)
class CampaignResult:
    targets: list[Target] = field(default_factory=list)
    sinks: list[Sink] = field(default_factory=list)
    flows: list[Flow] = field(default_factory=list)
    strategies: dict[str, StrategySpec] = field(default_factory=dict)
    witnesses: list[Witness] = field(default_factory=list)
    scored_witnesses: list[ScoredWitness] = field(default_factory=list)
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
    # Include file:line so the same sink callable at different sites — e.g.
    # pickle.loads at four different locations in leoFileCommands.py — gets
    # its own strategy. Without the location the dedup map silently overwrites
    # synthesized strategies for distinct sites.
    return f"{flow.target_fqn}|{flow.sink.callable_qualname}@{flow.sink.file}:{flow.sink.line}"


def run_campaign(
    config: CampaignConfig,
    llm: LLMClient | None = None,
) -> CampaignResult:
    """End-to-end campaign. Single shared `llm` so prompt caches accumulate."""
    client = llm or ClaudeHeadlessClient()
    result = CampaignResult()

    # 1. Static sink inventory — deterministic, no LLM.
    #
    # Two passes:
    #   (a) Direct sink calls (subprocess.Popen, os.system, etc.).
    #   (b) Wrapper helpers — in-package functions that pass a parameter into
    #       a known process sink. Their callers are added as call-site sinks
    #       so reachability sees `g.execute_shell_commands(cmd)` as a sink at
    #       the *caller's* line, not just at leoGlobals.py:7465.
    log.info("scanning sinks in %s", config.package_path)
    direct_sinks = scan_path(config.package_path)
    wrappers = find_wrapper_sinks(
        config.package_path, config.package_path, config.package_name
    )
    wrapper_registry = {
        qual: (family, f"wraps {sink_qual} (shell helper)")
        for qual, (family, _, _, sink_qual) in wrappers.items()
    }
    wrapper_call_sites = []
    if wrapper_registry:
        for f in _iter_python_files(config.package_path):
            wrapper_call_sites.extend(scan_file_with_registry(f, wrapper_registry))
    result.sinks = direct_sinks + wrapper_call_sites
    log.info(
        "found %d sinks (%d direct + %d wrapper-call-sites from %d wrappers)",
        len(result.sinks),
        len(direct_sinks),
        len(wrapper_call_sites),
        len(wrappers),
    )

    # 2. LLM discovery — public attack surface — augmented with a static
    # decorator scan (catches `@g.command`/`@click.command`/`@route`/etc.
    # entries the LLM doesn't enumerate). Decorator targets are filtered to
    # files that contain at least one (direct or wrapper-call) sink, so we
    # don't drown the campaign in low-value command callbacks.
    log.info("discovering targets in %s", config.package_name)
    try:
        llm_targets = discover_targets(
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
    # Filter decorator targets to files that host a *wrapper-mediated*
    # shell call. These are the high-signal cases (the file's command
    # callbacks reach a shell exec via a helper function) — exactly the
    # pattern that LLM discovery misses because the dangerous call is one
    # indirection away. Files with direct sinks are typically already
    # covered by reachability from LLM-discovered entries, so we don't
    # supplement them.
    wrapper_call_site_files: set[Path] = {
        Path(s.file) for s in wrapper_call_sites
    }
    # Rank files by # of wrapper call sites they host. A file with five
    # `g.execute_shell_commands(...)` calls is much likelier to harbor an
    # exploitable decorator-registered command than a file with one — so
    # those targets float to the top of the merged target list.
    wrapper_density: dict[Path, int] = {}
    for s in wrapper_call_sites:
        wrapper_density[Path(s.file)] = wrapper_density.get(Path(s.file), 0) + 1
    decorator_targets = find_decorator_targets(
        config.package_path,
        config.package_path,
        config.package_name,
        sink_files=wrapper_call_site_files,
        file_rank=wrapper_density,
    )
    result.targets = merge_targets(llm_targets, decorator_targets)
    log.info(
        "found %d targets (%d LLM + %d decorator-registered)",
        len(result.targets),
        len(llm_targets),
        len(decorator_targets),
    )

    if not result.sinks or not result.targets:
        log.info("nothing to fuzz; returning")
        return result

    # Cap targets — reachability is the dominant cost and most real packages
    # only need the network/cli entry points fuzzed in a first campaign.
    if config.max_targets and len(result.targets) > config.max_targets:
        result.targets.sort(key=lambda t: _EXPOSURE_PRIORITY.get(t.exposure, 99))
        log.info(
            "capping targets to top %d by exposure (was %d)",
            config.max_targets,
            len(result.targets),
        )
        result.targets = result.targets[: config.max_targets]

    # 3. Reachability per target — serial to avoid concurrent claude -p invocations.
    all_flows: list[Flow] = []
    for target in result.targets:
        # Rank sinks by import-distance and cap the per-target prompt to a
        # tractable size. On large packages this is the difference between
        # the LLM finishing inside max_turns and the agent exhausting its
        # turn budget reading every sink site.
        target_sinks = filter_sinks_by_imports(
            target, result.sinks, config.package_path, config.package_name
        )
        if len(target_sinks) != len(result.sinks):
            log.info(
                "ranked sinks for %s: %d → %d (cap)",
                target.fqn,
                len(result.sinks),
                len(target_sinks),
            )
        log.info("analyzing reachability for %s", target.fqn)
        try:
            flows = analyze_reachability(
                target,
                target_sinks,
                config.package_path,
                llm=client,
                max_turns=config.reachability_max_turns,
                package_name=config.package_name,
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
        static_seeds = get_seed_corpus(flow.sink.family)
        try:
            strategy = synthesize_strategy(target, flow.sink, flow=flow, llm=client)
        except Exception as exc:
            # Common failure: Claude quota exhausted mid-campaign. The static
            # seed corpus alone covers most known patterns for each sink
            # family — a degraded run with no LLM-tailored seeds still fires
            # witnesses on canonical bugs.
            msg = f"synthesize_strategy({_flow_key(flow)}) failed (using static corpus): {exc!r}"
            log.warning(msg)
            result.errors.append(msg)
            if not static_seeds:
                continue
            strategy = StrategySpec(kind="text", params={}, seeds=list(static_seeds))
        # Merge curated static corpus with LLM-generated seeds. Static seeds
        # come first so they're tried before LLM variations; dict.fromkeys
        # preserves order while deduping; the cap keeps the strategy small.
        merged = list(dict.fromkeys([*static_seeds, *strategy.seeds]))[:MAX_SEEDS_PER_STRATEGY]
        strategy = strategy.model_copy(update={"seeds": merged})
        result.strategies[_flow_key(flow)] = strategy
        # If reachability identified a single-arg-fuzzable leaf inside the
        # call chain, fuzz it instead of the entry — most real entry points
        # have complex signatures the worker can't synthesize. The flow's
        # rationale already explains how the entry-to-leaf path preserves taint.
        harness_module = flow.harness_module or target.module
        harness_qualname = flow.harness_qualname or target.qualname
        leaf_overrides_entry = (
            flow.harness_module is not None and flow.harness_qualname is not None
            and (flow.harness_module, flow.harness_qualname)
            != (target.module, target.qualname)
        )
        # For loaded_file_content flows where the harness IS the entry, the
        # worker materializes the payload to a temp file and passes the path
        # to the parser. When reachability has descended past the file-loader
        # to a leaf taking scalar bytes (e.g. `run_asciidoctor(self, i_path,
        # o_path)`), file materialization is *wrong* — the payload should
        # arrive at the leaf as the literal string the function will splice
        # into a shell command, not as a tempfile path.
        effective_attacker = (
            flow.attacker_model
            or target.effective_attacker_model
        )
        file_suffix: str | None = None
        if (
            effective_attacker == AttackerModel.loaded_file_content
            and not leaf_overrides_entry
        ):
            top_pkg = config.package_name.split(".")[0]
            file_suffix = _PACKAGE_FILE_SUFFIX_HINTS.get(top_pkg, _DEFAULT_FILE_SUFFIX)
        harnesses.append(
            HarnessSpec(
                target_module=harness_module,
                target_qualname=harness_qualname,
                strategy=strategy,
                marker=uuid.uuid4().hex,
                max_examples=config.max_examples_per_flow,
                timeout_s=config.worker_timeout_s,
                rss_limit_mb=config.rss_limit_mb,
                payload_as_file_suffix=file_suffix,
            )
        )

    if not harnesses:
        return result

    # 6. Worker pool — parallel subprocesses, blocking-per-thread.
    # PYTHONPATH must let the worker `import {package_name}` and any submodule.
    # CRITICAL: do NOT put `pkg_path` itself on sys.path. If the package owns
    # files whose names collide with stdlib modules (e.g. aider/aider/io.py,
    # email/, string/, json/), placing pkg_path first shadows the stdlib and
    # produces "partially initialized module 'io'" circular-import crashes
    # before any user code runs. We only need the *parent* dir on the path so
    # `import {package_name}` works. For dotted package names ("leo.core"),
    # walk up to the directory whose basename matches the topmost segment.
    pkg_path = config.package_path
    pythonpath_extra: list[Path] = [pkg_path.parent]
    top_segment = config.package_name.split(".")[0]
    cur = pkg_path
    for _ in range(8):  # safety bound
        if cur.name == top_segment:
            grandparent = cur.parent
            if grandparent not in pythonpath_extra:
                pythonpath_extra.append(grandparent)
            break
        if cur.parent == cur:
            break
        cur = cur.parent
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
                elif r.kind == "summary":
                    # The summary fires once per worker. If no witnesses came
                    # from this harness, the histogram is the only diagnostic
                    # explaining why — escalate it to a warning so it lands in
                    # run.log without forcing the user to re-run with -v.
                    target_witnesses = sum(
                        1 for w in result.witnesses
                        if w.target_fqn == f"{spec.target_module}:{spec.target_qualname}"
                    )
                    hist = ", ".join(
                        f"{name}×{count}"
                        for name, count in sorted(
                            r.exception_histogram.items(), key=lambda kv: -kv[1]
                        )
                    ) or "none"
                    log_fn = log.info if target_witnesses > 0 else log.warning
                    log_fn(
                        "worker %s:%s ran %d examples, %d witnesses; exceptions: %s",
                        spec.target_module,
                        spec.target_qualname,
                        r.examples_run,
                        target_witnesses,
                        hist,
                    )

    log.info(
        "campaign complete: %d witnesses across %d harnesses",
        len(result.witnesses),
        len(harnesses),
    )

    # 7. Triage — rank witnesses for the report. Cheap, deterministic, no LLM.
    result.scored_witnesses = triage_campaign(
        result.witnesses, result.targets, result.flows
    )

    return result

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
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
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
    # When set, write stage artifacts as JSON so a campaign can be inspected
    # or resumed without repeating expensive LLM work.
    artifact_dir: Path | None = None
    # When set, load any existing stage artifacts from this directory and
    # continue from the first missing stage. New artifacts are written to
    # `artifact_dir` when supplied, otherwise back into `resume_from`.
    resume_from: Path | None = None


@dataclass(slots=True)
class CampaignResult:
    targets: list[Target] = field(default_factory=list)
    sinks: list[Sink] = field(default_factory=list)
    flows: list[Flow] = field(default_factory=list)
    strategies: dict[str, StrategySpec] = field(default_factory=dict)
    witnesses: list[Witness] = field(default_factory=list)
    scored_witnesses: list[ScoredWitness] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _artifact_output_dir(config: CampaignConfig) -> Path | None:
    return config.artifact_dir or config.resume_from


def _artifact_path(root: Path, name: str) -> Path:
    return root / name


def _write_artifact(root: Path | None, name: str, payload: object) -> None:
    if root is None:
        return
    root.mkdir(parents=True, exist_ok=True)
    _artifact_path(root, name).write_text(json.dumps(payload, indent=2, default=str))


def _reset_jsonl_artifact(root: Path | None, name: str) -> None:
    if root is None:
        return
    root.mkdir(parents=True, exist_ok=True)
    _artifact_path(root, name).write_text("")


def _append_jsonl_artifact(root: Path | None, name: str, payload: object) -> None:
    if root is None:
        return
    root.mkdir(parents=True, exist_ok=True)
    with _artifact_path(root, name).open("a") as f:
        f.write(json.dumps(payload, default=str) + "\n")


def _read_artifact(root: Path | None, name: str) -> object | None:
    if root is None:
        return None
    path = _artifact_path(root, name)
    if not path.exists():
        return None
    return json.loads(path.read_text())


def _read_model_list[T](root: Path | None, name: str, model: type[T]) -> list[T] | None:
    payload = _read_artifact(root, name)
    if payload is None:
        return None
    return [model.model_validate(item) for item in payload]  # type: ignore[attr-defined]


def _read_strategies(root: Path | None) -> dict[str, StrategySpec] | None:
    payload = _read_artifact(root, "strategies.json")
    if payload is None:
        return None
    return {
        str(key): StrategySpec.model_validate(value)
        for key, value in dict(payload).items()
    }


def _write_campaign_artifacts(root: Path | None, result: CampaignResult) -> None:
    """Write all currently populated campaign artifacts.

    Files are intentionally simple and stage-named so users can inspect or edit
    them by hand while debugging a campaign.
    """
    _write_artifact(root, "sinks.json", [s.model_dump(mode="json") for s in result.sinks])
    _write_artifact(root, "targets.json", [t.model_dump(mode="json") for t in result.targets])
    _write_artifact(root, "flows.json", [f.model_dump(mode="json") for f in result.flows])
    _write_artifact(
        root,
        "strategies.json",
        {k: v.model_dump(mode="json") for k, v in result.strategies.items()},
    )
    _write_artifact(
        root, "witnesses.json", [w.model_dump(mode="json") for w in result.witnesses]
    )
    _write_artifact(
        root,
        "scored_witnesses.json",
        [sw.model_dump(mode="json") for sw in result.scored_witnesses],
    )
    _write_artifact(root, "errors.json", result.errors)


def _load_resume_artifacts(root: Path | None, result: CampaignResult) -> None:
    """Populate `result` with any completed stage files from `root`."""
    result.sinks = _read_model_list(root, "sinks.json", Sink) or []
    result.targets = _read_model_list(root, "targets.json", Target) or []
    result.flows = _read_model_list(root, "flows.json", Flow) or []
    result.strategies = _read_strategies(root) or {}
    result.witnesses = _read_model_list(root, "witnesses.json", Witness) or []
    result.scored_witnesses = (
        _read_model_list(root, "scored_witnesses.json", ScoredWitness) or []
    )
    errors = _read_artifact(root, "errors.json")
    result.errors = list(errors) if isinstance(errors, list) else []


def _scan_sinks_with_wrappers(
    package_path: Path,
    package_name: str,
) -> tuple[list[Sink], list[Sink]]:
    """Return all sinks plus the wrapper-mediated call sites."""
    direct_sinks = scan_path(package_path)
    wrappers = find_wrapper_sinks(package_path, package_path, package_name)
    wrapper_registry = {
        qual: (family, f"wraps {sink_qual} (shell helper)")
        for qual, (family, _, _, sink_qual) in wrappers.items()
    }
    wrapper_call_sites: list[Sink] = []
    if wrapper_registry:
        for f in _iter_python_files(package_path):
            wrapper_call_sites.extend(scan_file_with_registry(f, wrapper_registry))
    return direct_sinks + wrapper_call_sites, wrapper_call_sites


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


def _cap_with_decorator_quota(
    llm_targets: list[Target],
    decorator_targets: list[Target],
    cap: int | None,
) -> list[Target]:
    """Merge LLM and decorator targets under a cap that reserves a quota for
    decorator-scan results.

    Decorator-target entries are pre-filtered to files containing wrapper-
    mediated sink call sites and ranked by sink density, so they are
    high-signal — co-located with a sink callable that an LLM-discovered
    network entry probably can't reach. Sorting purely by exposure tier (which
    the previous policy did) lets a moderately-sized batch of network targets
    crowd them out entirely.

    Policy:
      - With no cap, fall through to `merge_targets` (LLM first, dedup).
      - With a cap, give decorator targets up to `max(1, cap // 2)` slots
        (clamped to how many decorator targets actually exist), and let LLM
        targets — sorted by exposure tier — fill the remainder. The merge
        deduplicates by `(module, qualname)` so a target found by both
        sources doesn't consume two slots.
    """
    if not cap or cap <= 0 or len(llm_targets) + len(decorator_targets) <= cap:
        return merge_targets(llm_targets, decorator_targets)

    decorator_quota = min(len(decorator_targets), max(1, cap // 2))
    llm_quota = cap - decorator_quota

    llm_sorted = sorted(
        llm_targets, key=lambda t: _EXPOSURE_PRIORITY.get(t.exposure, 99)
    )
    return merge_targets(llm_sorted[:llm_quota], decorator_targets[:decorator_quota])


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
    artifact_dir = _artifact_output_dir(config)
    t_campaign_start = time.monotonic()
    if config.resume_from is not None:
        log.info("loading campaign artifacts from %s", config.resume_from)
        _load_resume_artifacts(config.resume_from, result)
        # A completed campaign can be inspected/reserialized without rerunning
        # fuzzers. If only witnesses exist, triage can be rebuilt below.
        if result.witnesses and result.scored_witnesses:
            _write_campaign_artifacts(artifact_dir, result)
            return result

    # 1. Static sink inventory — deterministic, no LLM.
    #
    # Two passes:
    #   (a) Direct sink calls (subprocess.Popen, os.system, etc.).
    #   (b) Wrapper helpers — in-package functions that pass a parameter into
    #       a known process sink. Their callers are added as call-site sinks
    #       so reachability sees `g.execute_shell_commands(cmd)` as a sink at
    #       the *caller's* line, not just at leoGlobals.py:7465.
    wrapper_call_sites: list[Sink] = []
    if result.sinks:
        log.info("using %d sinks from resume artifacts", len(result.sinks))
    else:
        log.info("scanning sinks in %s", config.package_path)
        t_sink_scan = time.monotonic()
        result.sinks, wrapper_call_sites = _scan_sinks_with_wrappers(
            config.package_path, config.package_name
        )
        log.info("found %d sinks (%.1fs)", len(result.sinks), time.monotonic() - t_sink_scan)
        _write_artifact(
            artifact_dir, "sinks.json", [s.model_dump(mode="json") for s in result.sinks]
        )

    # 2. LLM discovery — public attack surface — augmented with a static
    # decorator scan (catches `@g.command`/`@click.command`/`@route`/etc.
    # entries the LLM doesn't enumerate). Decorator targets are filtered to
    # files that contain at least one (direct or wrapper-call) sink, so we
    # don't drown the campaign in low-value command callbacks.
    if result.targets:
        log.info("using %d targets from resume artifacts", len(result.targets))
    else:
        if not wrapper_call_sites:
            _, wrapper_call_sites = _scan_sinks_with_wrappers(
                config.package_path, config.package_name
            )
        log.info("discovering targets in %s", config.package_name)
        t_discover = time.monotonic()
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
            _write_artifact(artifact_dir, "errors.json", result.errors)
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
        result.targets = _cap_with_decorator_quota(
            llm_targets, decorator_targets, config.max_targets
        )
        log.info(
            "found %d targets (%d LLM + %d decorator-registered, cap=%s) in %.1fs",
            len(result.targets),
            len(llm_targets),
            len(decorator_targets),
            config.max_targets or "∞",
            time.monotonic() - t_discover,
        )
        _write_artifact(
            artifact_dir,
            "targets.json",
            [t.model_dump(mode="json") for t in result.targets],
        )

    if not result.sinks or not result.targets:
        log.info("nothing to fuzz; returning")
        _write_campaign_artifacts(artifact_dir, result)
        return result

    # Resume-only fallback cap. Fresh discovery already capped via
    # `_cap_with_decorator_quota`; this path runs only when the resumed
    # targets.json exceeds the configured cap, in which case provenance
    # (LLM vs decorator scan) isn't recoverable and we fall back to a plain
    # exposure-priority sort.
    if config.max_targets and len(result.targets) > config.max_targets:
        result.targets.sort(key=lambda t: _EXPOSURE_PRIORITY.get(t.exposure, 99))
        log.info(
            "capping resumed targets to top %d by exposure (was %d)",
            config.max_targets,
            len(result.targets),
        )
        result.targets = result.targets[: config.max_targets]
        _write_artifact(
            artifact_dir,
            "targets.json",
            [t.model_dump(mode="json") for t in result.targets],
        )

    # 3. Reachability per target — serial to avoid concurrent claude -p invocations.
    if result.flows:
        log.info("using %d flows from resume artifacts", len(result.flows))
    else:
        t_reach_loop = time.monotonic()
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
                log.debug(
                    "ranked sinks for %s: %d → %d (cap)",
                    target.fqn,
                    len(result.sinks),
                    len(target_sinks),
                )
            log.info("analyzing reachability for %s", target.fqn)
            t_reach = time.monotonic()
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
            log.info(
                "reachability for %s: %d flow(s) (%.1fs)",
                target.fqn,
                len(flows),
                time.monotonic() - t_reach,
            )
            all_flows.extend(flows)
        result.flows = all_flows
        log.info(
            "reachability complete: %d total flow(s) from %d target(s) in %.1fs",
            len(result.flows),
            len(result.targets),
            time.monotonic() - t_reach_loop,
        )
        _write_artifact(
            artifact_dir, "flows.json", [f.model_dump(mode="json") for f in result.flows]
        )
        _write_artifact(artifact_dir, "errors.json", result.errors)

    if result.witnesses:
        log.info("using %d witnesses from resume artifacts", len(result.witnesses))
        if not result.scored_witnesses:
            result.scored_witnesses = triage_campaign(
                result.witnesses, result.targets, result.flows
            )
        _write_campaign_artifacts(artifact_dir, result)
        return result

    # 4. Filter by confidence; keep only what's worth fuzzing.
    fuzzable = [f for f in result.flows if f.confidence >= config.flow_confidence_threshold]
    log.info(
        "%d/%d flows above confidence threshold %.2f",
        len(fuzzable),
        len(result.flows),
        config.flow_confidence_threshold,
    )
    if not fuzzable:
        _write_campaign_artifacts(artifact_dir, result)
        return result

    # PYTHONPATH for workers — computed up front so we can dispatch harnesses
    # inside the synthesis loop. Workers `import {package_name}`, so the parent
    # dir must be on sys.path. CRITICAL: do NOT put `pkg_path` itself on
    # sys.path — if the package owns files whose names collide with stdlib
    # (e.g. aider/aider/io.py, email/, string/, json/), placing pkg_path first
    # shadows the stdlib and produces "partially initialized module 'io'"
    # circular-import crashes before any user code runs. For dotted package
    # names ("leo.core"), walk up to the topmost segment's parent.
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

    _reset_jsonl_artifact(artifact_dir, "workers.jsonl")

    # 5+6. Synthesize a strategy per flow and dispatch its harness as soon as
    # the strategy is ready, so worker subprocesses overlap with the remaining
    # synthesis calls. Synthesis is API-bound (each `claude -p` call is
    # 30-180s); without pipelining the worker pool sits idle for that entire
    # phase. Drain runs from the same executor once synthesis is done.
    futures: dict[Future, HarnessSpec] = {}
    with ThreadPoolExecutor(max_workers=config.parallelism) as pool:
        for flow in fuzzable:
            target = next((t for t in result.targets if t.fqn == flow.target_fqn), None)
            if target is None:
                continue
            flow_key = _flow_key(flow)
            if flow_key in result.strategies:
                strategy = result.strategies[flow_key]
                log.info("using strategy for %s from resume artifacts", flow_key)
            else:
                log.info(
                    "synthesizing strategy for %s -> %s",
                    flow.target_fqn,
                    flow.sink.callable_qualname,
                )
                t_synth = time.monotonic()
                static_seeds = get_seed_corpus(flow.sink.family)
                try:
                    strategy = synthesize_strategy(target, flow.sink, flow=flow, llm=client)
                except Exception as exc:
                    # Common failure: Claude quota exhausted mid-campaign. The
                    # static seed corpus alone covers most known patterns for
                    # each sink family — a degraded run with no LLM-tailored
                    # seeds still fires witnesses on canonical bugs.
                    msg = f"synthesize_strategy({flow_key}) failed (using static corpus): {exc!r}"
                    log.warning(msg)
                    result.errors.append(msg)
                    if not static_seeds:
                        continue
                    strategy = StrategySpec(kind="text", params={}, seeds=list(static_seeds))
                # Merge curated static corpus with LLM-generated seeds. Static
                # seeds come first so they're tried before LLM variations;
                # dict.fromkeys preserves order while deduping; the cap keeps
                # the strategy small.
                merged = list(dict.fromkeys([*static_seeds, *strategy.seeds]))[
                    :MAX_SEEDS_PER_STRATEGY
                ]
                strategy = strategy.model_copy(update={"seeds": merged})
                result.strategies[flow_key] = strategy
                sample = repr(strategy.seeds[0])[:100] if strategy.seeds else "<empty>"
                log.info(
                    "synthesized %d seed(s) for %s (%.1fs); sample: %s",
                    len(strategy.seeds),
                    flow_key,
                    time.monotonic() - t_synth,
                    sample,
                )
                _write_artifact(
                    artifact_dir,
                    "strategies.json",
                    {k: v.model_dump(mode="json") for k, v in result.strategies.items()},
                )
                _write_artifact(artifact_dir, "errors.json", result.errors)
            # If reachability identified a single-arg-fuzzable leaf inside the
            # call chain, fuzz it instead of the entry — most real entry points
            # have complex signatures the worker can't synthesize. The flow's
            # rationale already explains how the entry-to-leaf path preserves
            # taint.
            harness_module = flow.harness_module or target.module
            harness_qualname = flow.harness_qualname or target.qualname
            leaf_overrides_entry = (
                flow.harness_module is not None and flow.harness_qualname is not None
                and (flow.harness_module, flow.harness_qualname)
                != (target.module, target.qualname)
            )
            # For loaded_file_content flows where the harness IS the entry, the
            # worker materializes the payload to a temp file and passes the
            # path to the parser. When reachability has descended past the
            # file-loader to a leaf taking scalar bytes (e.g.
            # `run_asciidoctor(self, i_path, o_path)`), file materialization is
            # *wrong* — the payload should arrive at the leaf as the literal
            # string the function will splice into a shell command, not as a
            # tempfile path.
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
            spec = HarnessSpec(
                target_module=harness_module,
                target_qualname=harness_qualname,
                strategy=strategy,
                marker=uuid.uuid4().hex,
                max_examples=config.max_examples_per_flow,
                timeout_s=config.worker_timeout_s,
                rss_limit_mb=config.rss_limit_mb,
                payload_as_file_suffix=file_suffix,
                sink_family=flow.sink.family,
            )
            future = pool.submit(
                _run_worker, spec, config.worker_timeout_s + 30, pythonpath_extra
            )
            futures[future] = spec
            log.info(
                "dispatched harness %s:%s (queued=%d)",
                spec.target_module,
                spec.target_qualname,
                len(futures),
            )

        if not futures:
            _write_campaign_artifacts(artifact_dir, result)
            return result

        log.info(
            "draining %d harnesses with parallelism=%d",
            len(futures),
            config.parallelism,
        )
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
                msg = (
                    f"worker failed for {spec.target_module}:"
                    f"{spec.target_qualname}: {exc!r}"
                )
                log.warning(msg)
                result.errors.append(msg)
                continue
            for r in worker_results:
                _append_jsonl_artifact(
                    artifact_dir,
                    "workers.jsonl",
                    {
                        "target_module": spec.target_module,
                        "target_qualname": spec.target_qualname,
                        "result": r.model_dump(mode="json"),
                    },
                )
                if r.kind == "witness" and r.witness is not None:
                    result.witnesses.append(r.witness)
                    _write_artifact(
                        artifact_dir,
                        "witnesses.json",
                        [w.model_dump(mode="json") for w in result.witnesses],
                    )
                elif r.kind == "error" and r.error:
                    result.errors.append(
                        f"worker {spec.target_module}:{spec.target_qualname}: {r.error}"
                    )
                    _write_artifact(artifact_dir, "errors.json", result.errors)
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
        "campaign complete: %d witnesses across %d harnesses in %.1fs",
        len(result.witnesses),
        len(futures),
        time.monotonic() - t_campaign_start,
    )

    # 7. Triage — rank witnesses for the report. Cheap, deterministic, no LLM.
    result.scored_witnesses = triage_campaign(
        result.witnesses, result.targets, result.flows
    )
    _write_campaign_artifacts(artifact_dir, result)

    return result

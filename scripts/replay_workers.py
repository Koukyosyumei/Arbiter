"""Replay the worker stage on flows saved by an earlier campaign.

Skips discovery, reachability, and LLM synthesis — uses the static seed
corpus only. Useful when the campaign was halted mid-run (e.g. quota
exhausted) and you want to verify witnesses without paying the LLM cost
again.

Reads flows from a CampaignResult JSON file (`--output-json`) and runs
workers in parallel against each flow's harness leaf.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from arbiter.models import (
    AttackerModel,
    Flow,
    HarnessSpec,
    Sink,
    StrategySpec,
    Target,
    Witness,
    WorkerResult,
)
from arbiter.orchestrator import (
    _DEFAULT_FILE_SUFFIX,
    _PACKAGE_FILE_SUFFIX_HINTS,
    MAX_SEEDS_PER_STRATEGY,
    _flow_key,
    _run_worker,
)
from arbiter.payloads import get_seed_corpus

log = logging.getLogger("replay")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("result_json", type=Path, help="CampaignResult JSON")
    parser.add_argument("--package-path", type=Path, required=True)
    parser.add_argument("--package-name", required=True)
    parser.add_argument("--max-examples", type=int, default=30)
    parser.add_argument("--worker-timeout", type=float, default=60.0)
    parser.add_argument("--parallelism", "-j", type=int, default=4)
    parser.add_argument("--out", type=Path, help="Append witnesses to this JSON file")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    raw = json.loads(args.result_json.read_text())
    flows = [Flow.model_validate(f) for f in raw["flows"]]
    targets = {t["module"] + ":" + t["qualname"]: Target.model_validate(t) for t in raw["targets"]}

    if not flows:
        print("no flows to replay", file=sys.stderr)
        return 1

    harnesses: list[HarnessSpec] = []
    for flow in flows:
        target = targets.get(flow.target_fqn)
        if target is None:
            log.warning("dropping flow with unknown target %s", flow.target_fqn)
            continue
        seeds = get_seed_corpus(flow.sink.family)
        if not seeds:
            log.warning("no static seeds for family %s; skipping flow", flow.sink.family.value)
            continue
        seeds = list(dict.fromkeys(seeds))[:MAX_SEEDS_PER_STRATEGY]
        strategy = StrategySpec(kind="text", params={}, seeds=seeds)

        harness_module = flow.harness_module or target.module
        harness_qualname = flow.harness_qualname or target.qualname
        leaf_overrides_entry = (
            flow.harness_module is not None and flow.harness_qualname is not None
            and (flow.harness_module, flow.harness_qualname)
            != (target.module, target.qualname)
        )

        effective_attacker = (
            flow.attacker_model or target.effective_attacker_model
        )
        file_suffix: str | None = None
        if effective_attacker == AttackerModel.loaded_file_content and not leaf_overrides_entry:
            top_pkg = args.package_name.split(".")[0]
            file_suffix = _PACKAGE_FILE_SUFFIX_HINTS.get(top_pkg, _DEFAULT_FILE_SUFFIX)

        harnesses.append(
            HarnessSpec(
                target_module=harness_module,
                target_qualname=harness_qualname,
                strategy=strategy,
                marker=uuid.uuid4().hex,
                max_examples=args.max_examples,
                timeout_s=args.worker_timeout,
                payload_as_file_suffix=file_suffix,
                sink_family=flow.sink.family,
            )
        )

    log.info("running %d harnesses with parallelism=%d", len(harnesses), args.parallelism)

    pkg_path = args.package_path.resolve()
    pythonpath_extra = [pkg_path.parent]
    top_segment = args.package_name.split(".")[0]
    cur = pkg_path
    for _ in range(8):
        if cur.name == top_segment:
            grandparent = cur.parent
            if grandparent not in pythonpath_extra:
                pythonpath_extra.append(grandparent)
            break
        if cur.parent == cur:
            break
        cur = cur.parent

    witnesses: list[Witness] = []
    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=args.parallelism) as pool:
        futures = {
            pool.submit(_run_worker, spec, args.worker_timeout + 30, pythonpath_extra): spec
            for spec in harnesses
        }
        for fut in as_completed(futures):
            spec = futures[fut]
            try:
                results = fut.result()
            except subprocess.TimeoutExpired:
                errors.append(f"timeout: {spec.target_module}:{spec.target_qualname}")
                continue
            except Exception as exc:
                errors.append(f"worker {spec.target_module}:{spec.target_qualname}: {exc!r}")
                continue
            for r in results:
                if r.kind == "witness" and r.witness:
                    witnesses.append(r.witness)
                    if r.witness.event.tainted:
                        print(
                            f"[+] TAINTED witness  {r.witness.target_fqn}  "
                            f"-> {r.witness.event.name}  "
                            f"args[{len(r.witness.event.args_repr)}]={r.witness.event.args_repr[1] if len(r.witness.event.args_repr) > 1 else r.witness.event.args_repr[0] if r.witness.event.args_repr else ''}"
                        )
                elif r.kind == "summary":
                    log.info(
                        "worker %s:%s summary: %d examples, exceptions=%s",
                        spec.target_module,
                        spec.target_qualname,
                        r.examples_run,
                        r.exception_histogram,
                    )

    print()
    print(f"=== summary: {len(witnesses)} witnesses ({sum(1 for w in witnesses if w.event.tainted)} tainted) across {len(harnesses)} harnesses ===")
    for e in errors:
        print(f"  err: {e}")

    if args.out:
        payload = {
            "witnesses": [w.model_dump(mode="json") for w in witnesses],
            "errors": errors,
        }
        args.out.write_text(json.dumps(payload, indent=2, default=str))

    return 0 if any(w.event.tainted for w in witnesses) else 1


if __name__ == "__main__":
    sys.exit(main())

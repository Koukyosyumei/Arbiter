# Arbiter

LLM-augmented property-based fuzzer for detecting **arbitrary code execution
(ACE)** primitives in Python packages.

> **Status:** v0.4 (pre-alpha). End-to-end campaign pipeline is wired:
> static sink scan → LLM target discovery → LLM reachability per target →
> LLM strategy synthesis (with a curated static seed corpus merged in) →
> parallel worker subprocesses → witness collection → triage ranking →
> markdown advisory + standalone PoC scripts per witness.
> The CLI (`arbiter scan`) drives the whole thing.

Arbiter combines three signals that, individually, miss real-world exploits:

1. **Static sink inventory** — AST scan locates calls to dangerous APIs
   (`eval`, `pickle.loads`, `subprocess`, `yaml.unsafe_load`, unsafe Jinja2
   environments, etc.) across a target package.
2. **Audit-hook oracle** — `sys.addaudithook` listener inside each worker
   subprocess captures runtime events tied to those sinks.
3. **Marker taint** — every fuzzed input embeds a UUID marker; the oracle
   records an event only when the marker survives into the sink argument,
   distinguishing *attacker-controlled influence* from incidental sink use.

Together these give a high-precision signal: a witness is a confirmed flow
from a public callable to a dangerous sink with attacker-controlled bytes
reaching the sink.

## Install

Requires Python 3.12+. Use [uv](https://github.com/astral-sh/uv) (recommended) or pip:

```bash
uv venv --python 3.12
uv pip install -e ".[dev]"
```

## Usage

```bash
arbiter scan path/to/package --package-name mypkg --output-json result.json
```

End-to-end campaign: static sink scan → LLM-driven target discovery and
reachability → strategy synthesis → parallel worker subprocesses →
witness aggregation. Exits 0 if any witnesses are found, 1 otherwise.

Useful flags:

| Flag                     | Default | What it does                                      |
|--------------------------|---------|---------------------------------------------------|
| `--package-name, -n`     | dirname | Importable name passed to workers                 |
| `--max-examples`         | 100     | Hypothesis examples per flow                      |
| `--confidence-threshold` | 0.5     | Drop flows below this reachability confidence     |
| `--parallelism, -j`      | 4       | Concurrent worker subprocesses                    |
| `--worker-timeout`       | 60      | Per-worker wall-clock seconds                     |
| `--output-json, -o`      | (none)  | Write the full `CampaignResult` as JSON           |
| `--report-dir, -r`       | (none)  | Write per-witness markdown advisories + PoC scripts |
| `--verbose, -v`          | off     | Stage-by-stage progress logs                      |

The worker can also be driven directly for debugging — see
[`DESIGN.md`](DESIGN.md) §5.2 for the IPC contract.

Run the test suite to validate the core end-to-end against a deliberately
vulnerable fixture package:

```bash
pytest
```

Live LLM tests are skipped automatically unless the `claude` CLI is on
PATH (Arbiter reuses your existing Claude Code authentication — no
separate API key required):

```bash
pytest tests/test_synthesize_live.py -v
```

## Layout

```
src/arbiter/
  models.py           Pydantic IPC contracts (Sink, Flow, Witness, HarnessSpec)
  sinks.py            AST sink inventory (7 sink families, alias resolution)
  oracle.py           Audit-hook listener + marker taint + internal-frame filter
  worker.py           Subprocess entry; Hypothesis-driven harness runner
  orchestrator.py     Campaign pipeline + worker pool (ThreadPoolExecutor)
  cli.py              `arbiter scan` typer entry point
  llm/
    sdk.py            ClaudeHeadlessClient (`claude -p`) + LLMClient Protocol
    synthesize.py     Strategy synthesizer: (target, sink) -> StrategySpec
    discover.py       Target discovery via claude -p agent mode
    reachability.py   Flow generation via claude -p agent mode
tests/
  fixtures/vulnpkg/   Known-vulnerable package (eval / yaml / jinja2)
  test_sinks.py       test_oracle.py      test_worker.py
  test_synthesize.py  test_discover.py    test_reachability.py
  test_orchestrator.py test_cli.py
  test_*_live.py      (skipped when `claude` CLI is missing)
```

See [`DESIGN.md`](DESIGN.md) for the architecture, threat model, detection
mechanism, and roadmap.

## License

See [`LICENSE`](LICENSE).

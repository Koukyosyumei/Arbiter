# Arbiter

LLM-augmented property-based fuzzer for detecting **arbitrary code execution
(ACE)** primitives in Python packages.

> **Status:** v0 (pre-alpha). The deterministic core — static sink inventory,
> audit-hook oracle, Hypothesis-driven worker — is implemented and tested.
> The LLM-driven discovery, reachability, and strategy-synthesis layer is not
> yet wired up.

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

The end-user CLI is not yet wired. The worker subprocess is functional and
can be driven directly:

```bash
echo '{
  "target_module": "vulnpkg.api",
  "target_qualname": "eval_expression",
  "marker": "abcd1234",
  "max_examples": 50,
  "strategy": {
    "kind": "text",
    "seeds": ["{MARKER} + 1", "__import__(\"os\").system(\"echo {MARKER}\")"]
  }
}' | python -m arbiter.worker
```

The worker emits one JSON line per witness on stdout, then a summary line.

Run the test suite to validate the core end-to-end against a deliberately
vulnerable fixture package:

```bash
pytest
```

## Layout

```
src/arbiter/
  models.py    Pydantic IPC contracts (Sink, Flow, Witness, HarnessSpec, ...)
  sinks.py     AST sink inventory (7 sink families, alias resolution)
  oracle.py    Audit-hook listener + marker taint + internal-frame filter
  worker.py    Subprocess entry; Hypothesis-driven harness runner
tests/
  fixtures/vulnpkg/    Known-vulnerable package (eval / yaml / jinja2)
  test_sinks.py        AST scan tests
  test_oracle.py       Audit-hook tests (subprocess-isolated)
  test_worker.py       End-to-end worker tests
```

See [`DESIGN.md`](DESIGN.md) for the architecture, threat model, detection
mechanism, and roadmap.

## License

See [`LICENSE`](LICENSE).

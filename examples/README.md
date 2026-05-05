# Arbiter Examples

Four tiny packages, each containing exactly one **arbitrary code execution
(ACE) primitive**. They exist to give you a fast end-to-end demo of Arbiter:
each scan should finish in well under a minute on a developer laptop and
produce at least one tainted witness.

| Example                              | Sink family       | Bug                                               |
|--------------------------------------|-------------------|---------------------------------------------------|
| [`eval_calc`](eval_calc)             | `code_exec`       | `eval()` on a user-supplied math expression       |
| [`shell_cat`](shell_cat)             | `process`         | `subprocess.run(..., shell=True)` with a path arg |
| [`pickle_session`](pickle_session)   | `deserialization` | `pickle.loads()` on a client-supplied blob        |
| [`jinja_render`](jinja_render)       | `template`        | `jinja2.Template(body)` — SSTI on a post body     |

Every package is a single-file package:

```
examples/<name>/
    __init__.py   # public entry point with the bug
```

So you can scan any of them with:

```bash
arbiter scan examples/<name>
```

`--package-name` defaults to the directory basename, which is also the
importable module name — no extra flag needed.

---

## Prerequisites

1. Install Arbiter in editable mode (from the repo root):
   ```bash
   uv venv
   source .venv/bin/activate
   uv pip install -e ".[dev]"
   ```
   This puts the `arbiter` command on your `PATH`. The `[dev]` extra also
   pulls in `jinja2`, which `jinja_render` needs.
2. Arbiter reuses your existing Claude Code authentication — no separate
   `ANTHROPIC_API_KEY` is required, but you do need to be logged into
   `claude` locally.

---

## Running each example

### 1. `eval_calc` — `code_exec` via `eval()`

```bash
arbiter scan examples/eval_calc \
  --max-targets 4 --max-examples 50 \
  --report-dir /tmp/eval_calc-report
```

What you should see:

- One sink discovered: `eval` in `eval_calc/__init__.py`.
- One target: `eval_calc.evaluate(expression: str) -> float`.
- One **TAINTED** witness against audit event `compile` or `exec` — the
  marker survives into the compiled code object, since Python `compile`s
  the string before evaluating it.
- A markdown advisory + standalone PoC script under
  `/tmp/eval_calc-report/`.

### 2. `shell_cat` — `process` via shell injection

```bash
arbiter scan examples/shell_cat \
  --max-targets 4 --max-examples 50 \
  --report-dir /tmp/shell_cat-report
```

What you should see:

- Sink: `subprocess.run` (note also that `subprocess.Popen` fires under
  the hood).
- Target: `shell_cat.head_file(path: str, lines: int = 10) -> str`.
- A **TAINTED** witness against `subprocess.Popen` — Hypothesis will shrink
  the input to something like `; <marker>` because the marker survives the
  f-string interpolation into the command line.

### 3. `pickle_session` — `deserialization` via `pickle.loads`

```bash
arbiter scan examples/pickle_session \
  --max-targets 4 --max-examples 50 \
  --report-dir /tmp/pickle_session-report
```

What you should see:

- Sink: `pickle.loads`.
- Target: `pickle_session.load_session(blob: bytes) -> Session`.
- A witness against `pickle.find_class` (recorded *unconditionally* as an
  `ALWAYS_RECORD` family event — see DESIGN.md §4.1) when the strategy
  synthesizer emits a `__reduce__`-style gadget. Triage will rank this
  high because the entry point is network-shaped (`bytes` parameter).

### 4. `jinja_render` — `template` (SSTI)

```bash
arbiter scan examples/jinja_render \
  --max-targets 4 --max-examples 50 \
  --report-dir /tmp/jinja_render-report
```

What you should see:

- Sink: `jinja2.Template`.
- Target: `jinja_render.render_post(title, body, author="anonymous")`.
- A **TAINTED** witness against `compile` or `exec` — Jinja2 compiles the
  template body to Python bytecode, and the marker survives into the
  generated source.

---

## Reading the output

Each scan prints a summary like:

```
sinks discovered: 1
targets discovered: 1
flows hypothesized: 1
strategies synthesized: 1
witnesses: 1

ranked witnesses:
  0.842  [TAINTED] eval_calc.evaluate -> compile (code_exec)
```

With `--report-dir`, you also get:

- `<witness>.md` — a triage-ranked advisory with reproduction steps,
  stack trace at the sink, and the minimal shrunk input.
- `<witness>_poc.py` — a standalone Python file that re-triggers the
  primitive without needing Arbiter on the path.

---

## What these examples are not

- They are **not** representative of how Arbiter performs on real packages.
  Real targets have hundreds of files, dozens of plausible entry points,
  and only a few of them actually reach a sink. The discovery and
  reachability stages are where Arbiter earns its keep on real code; here
  there is one entry point and one sink per package, so those stages are
  trivial.
- They are **not** a benchmark suite. They exist to verify the toolchain
  end-to-end — install, auth, sink scan, LLM discovery, fuzzing, oracle,
  triage, report — in under a minute per example. For real evaluation
  targets, see the projects under `audit/`.

# Arbiter — Design

## 1. Goals

Arbiter detects **arbitrary code execution (ACE) primitives** in Python
packages: code paths from a public callable to a dangerous API where
attacker-controlled bytes reach the dangerous call.

Concretely, a finding is reportable iff:

1. There exists an entry point `f(...)` callable from outside the package.
2. There exists a runtime audit event of family `code_exec`,
   `deserialization`, `process`, `template`, `xml`, or `import_` reachable
   from `f`.
3. A marker embedded in the input to `f` survives into the audit event's
   arguments.

The output is a minimal reproducer plus a triage-ranked advisory.

### Non-goals

- General correctness bug finding — see [Maaz et al., 2025][maaz] for that
  framing. Arbiter borrows the agent skeleton but targets a stricter oracle.
- Static-only analysis. Arbiter is greybox: static + dynamic + LLM-guided.
- Languages other than Python (planned, not in scope for v0).
- Non-determinism reduction across the LLM layer. Strategy synthesis is
  amortized once per `(target, sink)` pair; the inner fuzzing loop is
  deterministic given a seed.

[maaz]: https://arxiv.org/abs/2510.09907

---

## 2. Threat model

### What counts as ACE

A *primitive* is a runtime configuration in which an attacker, controlling
the bytes flowing into one public entry point, can cause the interpreter to
execute attacker-chosen code. The canonical examples:

| Family            | Sink                                  | Mechanism                              |
|-------------------|---------------------------------------|----------------------------------------|
| `code_exec`       | `eval`, `exec`, `compile`             | Direct evaluation of attacker source   |
| `deserialization` | `pickle.loads`, `yaml.unsafe_load`    | Gadget chain via `__reduce__` / tags   |
| `process`         | `os.system`, `subprocess(shell=True)` | Shell or argv injection                |
| `template`        | unsafe Jinja2 / Mako                  | SSTI → reaches `compile`/`subprocess`  |
| `xml`             | `etree.parse` without `defusedxml`    | XXE: file/network exfil, billion laughs|
| `import_`         | `__import__`, `importlib.import_module` | Module-name injection → side effects |

### What we explicitly do not claim

- *Crash ≠ exploit.* A `TypeError` deep inside `pickle.loads` is not a
  finding; the oracle requires marker-tainted dispatch into a sink.
- *Sink reached ≠ exploitable.* If a CLI tool legitimately calls
  `subprocess.run(user_arg)` and that's its documented purpose, the triage
  layer downgrades it as intended behavior.
- *Soundness.* Static reachability in Python is undecidable (dynamic
  dispatch, `getattr`, plugin loaders). We trade soundness for an LLM-guided
  best-effort with a high-precision oracle.

---

## 3. Architecture

```
       ┌──────────────────────────────────────────────────────────────┐
       │ Orchestrator                                                 │
       │   discover  ── reachability ── synthesize ── schedule ──┐    │
       └──────────────┬────────────────┬───────────────────┬─────┴────┘
                      │                │                   │
       ┌──────────────▼──────┐  ┌──────▼────────┐  ┌───────▼────────┐
       │ static sink scan    │  │ flow hypoth.  │  │ strategy synth.│
       │ (deterministic)     │  │ (claude -p)   │  │ (claude -p HL) │
       └──────────────┬──────┘  └──────┬────────┘  └───────┬────────┘
                      │                │                   │
                      └────────────────┼───────────────────┘
                                       ▼
                              ┌──────────────────┐
                              │   HarnessSpec    │  (JSON, stdin)
                              └────────┬─────────┘
                                       ▼
       ┌─────────────────────────────────────────────────────────────┐
       │ Worker subprocess (one per harness; isolated)               │
       │                                                             │
       │   resource limits ─ sys.addaudithook ─ Hypothesis @given    │
       │              │              │                  │            │
       │              ▼              ▼                  ▼            │
       │        RLIMIT_AS       Oracle            mutation +         │
       │                     (marker taint)        shrinking         │
       │                                                             │
       │   on tainted event: raise _WitnessFound → Hypothesis        │
       │   shrinks to minimal repro → emit Witness JSON              │
       └────────────────────────┬────────────────────────────────────┘
                                ▼
                       Orchestrator collects ──► triage ──► report
```

---

## 4. Detection mechanism

### 4.1 Audit-hook oracle

`sys.addaudithook` (PEP 578) registers a callback for every Python audit
event. Arbiter maps a curated subset of event names to sink families
(`oracle.py:AUDIT_FAMILY`) and partitions them into two policies:

- **`ALWAYS_RECORD`** — low-volume, unconditionally dangerous events
  (`pickle.find_class`, `subprocess.Popen`, `os.system`, `os.exec`,
  `os.posix_spawn`, `marshal.loads`). Recorded regardless of marker hits;
  triage decides if the bare event is a finding.
- **`MARKER_GATED`** — high-volume events (`compile`, `exec`,
  `code.__new__`, `import`). Recorded only when the input marker appears
  in any argument's `repr`. Without this gate the witness stream drowns in
  Python's own internal `compile`/`exec` activity.

### 4.2 Marker taint

Every fuzzed input embeds a UUID4 hex marker. The worker passes the marker
to the `Oracle`. On each audit event, the oracle stringifies every argument
(`repr` with broad exception suppression) and tests for marker-substring
membership.

This is **not** symbolic taint tracking. It is a low-fidelity but high-yield
heuristic that survives the operations attackers actually use:

- string concatenation, `.format`, f-strings → marker preserved
- `.encode()` / `.decode()` round-trips → marker preserved
- JSON serialization → marker preserved
- gadget chains that pass the marker as a literal argument (e.g.
  `os.system("echo " + marker)`) → marker preserved

Operations that defeat the heuristic — base64 round-trip, hashing, integer
conversion — are accepted limitations for v0. A v1 upgrade path (subclass-
based `TaintedStr`/`TaintedBytes`) is in §10.

### 4.3 Two non-obvious invariants

These are pinned as h5i claims; both took an iteration to get right.

**(a) Marker substring match runs on the full repr, not the truncated one.**
`oracle.py` truncates each arg's repr to 512 characters for storage in the
`AuditEvent`. That truncation must happen *after* the marker check.
Compiled Jinja2 templates are long preamble + template body; the marker
typically lives past byte 512, so a pre-truncation match silently misses
SSTI.

**(b) Internal-frame filter checks `stack[0]` only.**
`marshal.loads` fires every time CPython loads a `.pyc`. Filtering only
when the *immediate caller* is in `<frozen importlib._bootstrap*>` correctly
suppresses the .pyc flood while still recording user-driven
`marshal.loads(attacker_bytes)`. A whole-stack check is wrong: a user's
`import x` always sits at the bottom of the stack but didn't initiate the
marshal call.

### 4.4 Static sink inventory

`sinks.py` walks the AST of every `.py` file in the target. For each `Call`
node it resolves the callable to a fully-qualified name using a per-module
import-alias map (handles `import os as o`, `from os import system as run`,
attribute chains), then matches against `SINK_REGISTRY`. Family-specific
escape hatches suppress safe variants:

- `yaml.load(..., Loader=SafeLoader)` → suppressed.
- `jinja2.Environment(autoescape=True)` or `autoescape=select_autoescape(...)`
  → suppressed.
- `subprocess.X(..., shell=True)` → flagged with a `shell=True` note, not a
  separate severity tier.

Limitations: no inter-procedural alias analysis, no tracking through
collections (`f = os.system; f(x)` is missed), `open` and other path sinks
are not flagged because they're too noisy without taint.

---

## 5. Worker model

### 5.1 Subprocess isolation is mandatory, not optional

`sys.addaudithook` is one-way: hooks cannot be removed once installed.
This forces every fuzzing job into a fresh subprocess. Side benefits:

- RSS limits via `RLIMIT_AS` are scoped per job.
- A worker that hits a real exploit and crashes the interpreter doesn't
  poison the orchestrator.
- Hypothesis state (database, settings) is reset per run.

### 5.2 IPC

```
stdin  : one HarnessSpec JSON line
stdout : N×WorkerResult JSON lines, then one summary line
exit   : 0 normal, 1 internal error
```

The orchestrator enforces wall-clock timeout via `kill -9`. The worker
enforces memory via `setrlimit(RLIMIT_AS)`.

### 5.3 Hypothesis integration

A `_WitnessFound` exception is raised inside the `@given` test whenever
the oracle drains a tainted event. Hypothesis treats this as a failing
example and shrinks the input toward the minimal form that still triggers
the exception. Because every shrink iteration also fires the audit hook
and re-checks marker hits, shrinking converges on the *smallest input
that still flows the marker into the sink* — which is exactly the minimal
PoC.

The Hypothesis test never fails on target exceptions; the oracle is the
sole signal.

### 5.4 Strategy translation

`StrategySpec.kind` selects a generator family:

- `text` — `st.text()` with marker prefix prepended; one_of with seed strategies.
- `bytes` — `st.binary()` with marker bytes prepended.

`seeds` are literal payloads carrying the `{MARKER}` placeholder; the worker
substitutes the real UUID and registers each as `st.just(...)` so they're
always tried. This is how known-bad payloads (pickle gadgets, YAML
`!!python/object/apply`, Jinja SSTI fragments) enter the corpus.

---

## 6. LLM integration

### 6.1 Where the LLM fires

| Stage                    | Mode                          | Tools     | Frequency         |
|--------------------------|-------------------------------|-----------|-------------------|
| Target discovery         | `claude -p` (default tools)   | enabled   | once per package  |
| Sink note enrichment     | `claude -p --tools ""`        | disabled  | once per package  |
| Reachability             | `claude -p` (default tools)   | enabled   | once per module   |
| **Strategy synthesis**   | **`claude -p --tools ""`**    | disabled  | **once per flow** |
| Intended-behavior triage | `claude -p --tools ""`        | disabled  | once per witness  |
| Report generation        | `claude -p --tools ""`        | disabled  | once per finding  |

**Hard rule:** no LLM call in the inner fuzzing loop. LLM cost is amortized
over thousands of trials. Default model: `haiku` (alias resolves to the
current Haiku release; v0 was developed against `claude-haiku-4-5-20251001`).

### 6.2 Why headless rather than the Anthropic SDK directly

- Reuses the user's existing Claude Code authentication (OAuth or API key) —
  no separate `ANTHROPIC_API_KEY` to provision and rotate.
- `claude -p --json-schema <schema>` validates structured output natively;
  the parsed object lands in `wrapper.structured_output` so we never
  text-parse JSON in the happy path.
- `--tools ""` collapses the agent into a pure transformation
  (prompt → JSON), which is what synthesize/triage/report need. Discovery
  and reachability keep tools enabled because the agent's file-exploration
  is the whole point.
- The `LLMClient` Protocol in `arbiter.llm.sdk` is the seam — an SDK-backed
  implementation can be added later without touching call sites if
  per-call latency or scale ever justify the swap.

### 6.3 Prompt structure and caching

Each call assembles a system prompt from a stable preamble plus a
sink-family-specific guide; both are kept in source as constants so
content is identical across calls within a family. Claude Code caches
the system prompt internally — successive calls within the campaign get
cache hits on the prefix. We do **not** manage `cache_control` blocks
ourselves; that's Claude Code's job and would require the SDK path.

The unstable suffix (per-target, per-sink details) is delivered as the
user message and is the only per-call cost.

### 6.4 Model defaults

- `haiku` for everything in v0.
- Promotion path: if strategy synthesis produces weak payloads on a hard
  flow (low witness yield over N campaigns), promote that single call site
  to `sonnet` by passing `model="sonnet"` to `ClaudeHeadlessClient`. No
  other code changes.

---

## 7. Triage and ranking

After confirmation and minimization, each witness is scored:

```
final = severity × exposure × directness × novelty × (1 − intent_penalty)
```

- **severity** — `critical` (1.0) for code_exec / deserialization / process;
  `high` (0.7) for template / xml / import_; `medium` (0.5) for path.
- **exposure** — `network` (1.0) > `cli` (0.8) > `library` (0.6) > `internal` (0.3).
- **directness** — `1 / (1 + len(flow.intermediate))`. Direct call → 1.0;
  one hop → 0.5; two hops → 0.33.
- **novelty** — within-campaign fingerprint dedup. First witness with a
  given `(family, sink_qualname, top_stack_frame)` gets 1.0; repeats get
  0.5, 0.3, 0.2, ... Cross-campaign novelty is a v0.5 concern.
- **intent_penalty** — multiplicative; capped at 0.4 in v0.4. Triggered by
  per-family keyword matches in the target docstring (e.g. "evaluate" /
  "expression" / "compile" for code_exec). Multiplicative rather than
  subtractive so even fully-intended sinks still report at 60% strength —
  the entry point is still attacker-reachable; security review may still
  want auth or a sandbox.

The LLM-driven intent classifier (read the docstring, return JSON
`{intended, confidence, rationale}`) is a v0.5 follow-up; the v0.4
heuristic catches the obvious cases without an extra Haiku call.

This rubric is borrowed from [Maaz et al.][maaz] (their 56% → 86%
precision-after-ranking gain) and adapted for ACE: severity floor instead
of subjective bug-worthiness, and an explicit intended-behavior subtraction
because security tools cannot afford `subprocess.run` in a CLI being a
top-ranked finding.

---

## 8. Sandbox and Safety

### 8.1 Implementation Status (v0)
The current isolation model relies on standard OS primitives and Python’s internal hook system to prevent worker crashes or resource exhaustion from affecting the orchestrator.

* **Subprocess Isolation:** Every fuzzing harness is executed in a fresh worker subprocess via `python -m arbiter.worker`. This is a functional necessity because `sys.addaudithook` is permanent once installed; a new process ensures each campaign begins with a clean slate of audit hooks.
* **Resource Constraints:** * **Memory:** The worker calls `resource.setrlimit(resource.RLIMIT_AS, ...)` at startup to enforce RSS (Resident Set Size) limits. This prevents a target package or a specific payload from inducing a system-wide Out-Of-Memory (OOM) event.
    * **Timeouts:** The orchestrator manages worker lifecycles using `subprocess.run(..., timeout=timeout_s)`. This provides a hard wall-clock stop to prevent the fuzzer from hanging on infinite loops or network-blocked calls.
* **Environmental Resilience:** * **Auto-Mocking:** To prevent the fuzzer from crashing due to missing optional dependencies (e.g., GUI libraries like `tkinter` or `PyQt`), the worker uses an auto-mocking loop. It catches `ModuleNotFoundError` and registers `MagicMock` objects in `sys.modules` to allow the import of the target package to proceed even in restricted environments.
    * **Safe Instantiation:** When fuzzing unbound methods, the worker attempts real construction with type-derived defaults before falling back to `MagicMock`. This ensures that "0 witnesses" results are typically due to reachability issues rather than simple instantiation failures.
* **Oracle Safety:** The audit hook includes a re-entrance guard via `threading.local()` to prevent infinite recursion if the hook itself triggers an audit event. Additionally, the hook is wrapped in a broad exception handler to ensure that fuzzer errors never mask target behavior.

### 8.2 Roadmap: v1 Hardened Sandbox
While current isolation protects the orchestrator, the worker remains theoretically vulnerable to malicious payloads that could perform unauthorized file system or network operations.

* **Linux User Namespaces:** Future iterations will use `unshare -Urn` to provide workers with a fresh UID and a `tmpfs` root filesystem, limiting visibility to only the target package and the Python standard library.
* **Seccomp-BPF:** Implementing syscall filtering to deny `execve`, socket creation, and unauthorized disk writes.
* **Observational Execution:** For the `process` family specifically, `SECCOMP_RET_TRACE` will be used to log attempted system calls. This allows the fuzzer to prove an exploit primitive exists (by observing the `execve` attempt) while killing the process before the shell command actually executes.

### 8.3 Security Policy for Witnesses
Until the v1 sandbox is fully integrated, Arbiter operates under a "harmless observation" policy:
* Generated seeds use non-destructive payloads (e.g., `echo {MARKER}` instead of `rm -rf /`).
* Witnesses are recorded even if the worker terminates abnormally, as the oracle drains events incrementally during the Hypothesis loop.
* Users are advised not to run campaigns on untrusted, unreviewed packages outside of containerized or virtualized environments.

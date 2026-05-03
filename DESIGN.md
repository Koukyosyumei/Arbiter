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
       │ Orchestrator (in-progress)                                   │
       │   discover  ── reachability ── synthesize ── schedule ──┐    │
       └──────────────┬─────────────────┬───────────────────┬────┴────┘
                      │                 │                   │
       ┌──────────────▼──────┐  ┌──────▼────────┐  ┌────────▼────────┐
       │ static sink scan    │  │ flow hypoth.  │  │ strategy synth. │
       │ (deterministic)     │  │ (claude -p)   │  │ (claude -p HL)  │
       └──────────────┬──────┘  └──────┬────────┘  └────────┬────────┘
                      │                 │                   │
                      └─────────────────┼───────────────────┘
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

Components currently implemented are bold; the rest are designed but not
yet wired:

| Module                  | Role                                      | Status     |
|-------------------------|-------------------------------------------|------------|
| **`arbiter.models`**    | IPC contracts (Sink, Flow, Witness, …)    | done       |
| **`arbiter.sinks`**     | Static AST sink inventory                 | done       |
| **`arbiter.oracle`**    | Audit-hook listener + marker taint        | done       |
| **`arbiter.worker`**    | Subprocess harness runner (Hypothesis)    | done       |
| **`arbiter.llm.sdk`**   | `claude -p` headless client + JSON parser | done       |
| **`arbiter.llm.synthesize`** | Strategy synthesizer (Haiku via headless) | done   |
| **`arbiter.llm.discover`**   | Target discovery (agent mode)         | done       |
| **`arbiter.llm.reachability`**| Flow generator (agent mode)          | done       |
| **`arbiter.orchestrator`**| Campaign coordinator + worker pool      | done       |
| **`arbiter.cli`**       | `arbiter scan <pkg>`                      | done       |
| **`arbiter.triage`**    | Ranking rubric                            | done       |
| **`arbiter.report`**    | Markdown advisory + standalone PoC        | done       |
| **`arbiter.payloads`**  | Curated static seed library (PayloadsAllTheThings) | done |

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

## 8. Sandbox and safety

### 8.1 v0 isolation (current)

- Per-job fresh subprocess; oracle can't leak across jobs.
- `RLIMIT_AS` memory cap.
- Wall-clock timeout enforced by orchestrator.

This is **not sufficient** for high-trust targets — a worker can still
fork, write files, open sockets, or actually run `os.system("rm -rf …")`
if a payload triggers it.

### 8.2 v1 sandbox (planned)

For each worker:

- **Linux user namespace** (`unshare -Urn`) with a fresh UID and a tmpfs
  rootfs containing only the target package's installed files plus
  `/usr/lib/python3.12/`.
- **seccomp-bpf** denying `execve`, `network`, `ptrace`, and write syscalls
  outside the tmpfs.
- For `process`-family campaigns specifically, a `SECCOMP_RET_TRACE` setup
  so that an attempted `execve` is *observed and logged* (counts as a
  witness) rather than denied. The audit hook fires, the seccomp tracer
  confirms it as a syscall-level event, and the child is killed before the
  exec actually happens. This is the difference between "the audit hook
  said `Popen` was called" and "we have syscall-level proof of an exec
  attempt."
- macOS dev path: `sandbox-exec` with a permissive profile, no parity
  claim.

### 8.3 What we accept as a witness pre-sandbox

For v0 the audit hook is the oracle. A worker can technically execute the
exploit during a fuzz trial. We mitigate by:

- Using harmless seed payloads in tests (`echo {MARKER}`, not `rm`).
- Running test suites in CI with seccomp wrapping where possible.
- Documenting the limitation prominently and not pointing v0 at production
  packages outside controlled environments.

---

## 9. Limitations

- **Marker taint heuristic** — defeats: base64 round-trip, hashing,
  numeric conversion. v1: subclass-based propagation.
- **Static reachability is undecidable in Python** — `getattr`, plugin
  registries, dynamic dispatch. The LLM reachability step is a partial
  remedy; it's not a soundness story.
- **Coverage feedback is not yet integrated.** v0 relies on
  Hypothesis's built-in mutator + LLM-supplied seeds. Coverage-guided
  exploration via `sys.monitoring` is in the roadmap.
- **Single-process Hypothesis only.** Worker pool / parallel Hypothesis is
  not yet implemented.
- **No transitive-dep scan.** Sinks living in third-party deps (the common
  case) are caught at runtime by the audit hook, but the static inventory
  only sees the target package.
- **No replay determinism.** v0 logs the input but not the Hypothesis
  random seed; minimal repros are concrete inputs, not Hypothesis seeds.

---

## 10. Open questions

1. **Coverage scope.** Module-only, package-only, or include third-party
   deps? Including deps explodes the search space but is where many sinks
   actually live.
2. **Hypothesis coupling depth.** v0 uses public Hypothesis APIs only.
   Custom shrink-target predicates would give better minimization but
   require touching internal IR. Pin a Hypothesis version, or pursue an
   upstream "interestingness predicate" hook?
3. **Synthetic audit events.** `yaml.unsafe_load`, `jinja2 from_string`,
   and `lxml` parsing have no built-in audit event. v0 catches them
   transitively (the gadget chain ends up at `compile`/`subprocess`/`import`,
   which do have events). Should we monkey-patch in a synthetic event for
   each, to short-circuit the chain and improve witness quality?
4. **Differential intent check.** Run the package's own test suite under
   the audit hook; sinks reached under canonical use get a triage penalty.
   Cheap and high-signal — landing it early is probably correct.

---

## 11. Roadmap

**v0 (current)** — deterministic core: AST sink scan, audit-hook oracle,
Hypothesis worker, vulnpkg fixture, 22 tests passing.

**v0.1** — thin Haiku integration: `arbiter.llm.synthesize` replaces
hand-written seeds in the worker pipeline. Single LLM touchpoint, validated
end-to-end on vulnpkg.

**v0.2** — Claude Code headless `discover` + `reachability`, orchestrator
that wires sinks → flows → strategies → workers, basic CLI.

**v0.3** — triage engine + report generator. End-to-end campaign on a real
package (target: a pinned older PyYAML or jinja2 release with a known CVE).

**v0.4** — coverage feedback (`sys.monitoring`), corpus persistence,
cross-package payload reuse.

**v1.0** — full sandbox (user namespaces + seccomp), differential intent
check, replay determinism via Hypothesis seed capture, multi-worker pool.

**Beyond** — multi-language. The audit-hook + marker-taint + LLM-strategy
pattern generalizes; Node has `process.binding('inspector')` and similar
hooks; Ruby has `TracePoint`; Go has runtime hooks via the race detector
infrastructure. Each is a separate engineering project but shares the
core architecture.

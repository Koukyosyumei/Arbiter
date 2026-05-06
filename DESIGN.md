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
       │   resource limits ─ sys.addaudithook ─  mutator loop       │
       │              │              │                  │            │
       │              ▼              ▼                  ▼            │
       │        RLIMIT_AS       Oracle           seeds + variants    │
       │                     (marker taint)        per family        │
       │                                                             │
       │   on tainted drain: capture input + events,                 │
       │   emit Witness JSON, break the inner loop                   │
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
- No shared mutable state across workers — each one starts with a fresh
  audit hook, a fresh oracle, and a fresh payload iterator.

### 5.2 IPC

```
stdin  : one HarnessSpec JSON line
stdout : N×WorkerResult JSON lines, then one summary line
exit   : 0 normal, 1 internal error
```

The orchestrator enforces wall-clock timeout via `kill -9`. The worker
enforces memory via `setrlimit(RLIMIT_AS)`.

### 5.3 Mutator-driven fuzz loop

The worker drives a hand-rolled iterator, not a property-based test
framework. `arbiter.mutators.variations(family, seeds, marker, budget,
kind)` yields payloads in three tiers:

1. **Seeds verbatim** — every LLM-, static-corpus-, and witness-corpus-
   derived seed with the `{MARKER}` placeholder substituted, in order.
2. **Family-specific structural variants** — see §5.5. Each family with a
   registered grammar yields the cross-product of its alternation/
   concatenation tree (e.g. YAML tag × callable × body-form). Code_exec
   additionally runs token-aware mutations on the canonical forms via
   Python's `tokenize` module.
3. **Cycled re-yields** of the seeds, until `max_examples` is reached.

For each yielded payload, the worker calls `invoke(payload)`, then drains
the oracle. The first drain that contains any tainted event captures the
input and breaks the loop — that's the witness. Target-side exceptions
are tallied into the summary histogram but never gate the witness signal:
the oracle is the sole signal.

This replaces an earlier design that used `hypothesis.@given` as the
driver and raised a sentinel exception to drive shrinking. Empirically
the shrink phase contributed nothing measurable to witness rate at
Arbiter's scale: the LLM-curated seeds already hit on the first or
second example, and the structural seeds the shrinker tried to minimize
(YAML tag forms, Jinja globals chains) have no smaller equivalent that
still reaches the sink. The current loop is ~90 LOC shorter, has no
flakiness path, and stops on the first witness rather than continuing
to shrink past it.

### 5.4 Strategy → mutator hand-off

`StrategySpec.kind` is the on-the-wire payload type:

- `text` — seeds and variants are passed to the target as `str`.
- `bytes` — seeds and variants are UTF-8 encoded before being passed.

`seeds` carries the literal `{MARKER}` placeholder; the worker
substitutes the real UUID at materialization time. `HarnessSpec.sink_family`
selects which family-specific extender (if any) the mutator runs after
the canonical seeds. Families with no registered extender (xml, path,
import) fall straight through from canonical seeds to seed cycling — the
LLM and the static corpus carry the load there.

The orchestrator merges *three* sources of seeds before sending them to
the worker, in priority order: cross-campaign **witness corpus** (§5.5)
→ curated **static corpus** (`payloads/`) → LLM-synthesized variations.
Earliest-yielded seeds dominate the worker's budget, so a payload that
worked yesterday is tried before today's LLM guess.

### 5.5 Cross-campaign witness corpus

`arbiter.corpus.WitnessCorpus` persists tainted-witness payloads to disk
so future campaigns can replay them as zeroth-tier seeds. The on-disk
schema is borrowed from Hypothesis's `ExampleDatabase` (key-addressed
bytes store with `save`/`fetch`), but the *key schema* is hierarchical
because ACE payloads transfer well across targets:

```
Scope = (sink_family, package?, target_fqn?)

tier 1 (narrowest): (family, package, target_fqn)
tier 2:             (family, package)
tier 3 (broadest):  (family,)
```

`save(scope, payload, marker, score)` broadcasts the payload to every
tier of `scope`. `fetch(scope)` unions across tiers, deduplicates, and
yields in descending **depth-feedback score** order — the score is
captured at save time as the count of audit events triggered by the
payload, so payloads that exercised more of the call chain (parser →
resolver → sink) outrank shallow short-circuits on replay.

The corpus is scoped per-user under `~/.arbiter/corpus/` by default
(overridable via `--corpus-root` or disabled via `--no-corpus`).
Storage is append-only JSONL — single-line writes are atomic for
sub-PIPE_BUF sizes on POSIX, which covers ACE payloads comfortably,
so no locking is needed across worker subprocesses.

The live UUID marker is substituted back to the literal `{MARKER}`
placeholder before storage so each campaign's payload is reusable
across campaigns whose markers differ.

### 5.6 Grammar engine + token-aware mutator

The family extenders in §5.3 tier 2 are not hand-rolled string
templates; they delegate to a tiny grammar DFS in
`arbiter.mutators.grammar`:

```python
@dataclass(frozen=True)
class Rule:    parts:   tuple[Node, ...]   # concatenation
@dataclass(frozen=True)
class Choice:  options: tuple[Node, ...]   # alternation
```

`enumerate_rule(rule, marker)` walks the cross-product depth-first and
substitutes `{MARKER}` at yield. Each family's grammar lives in
`arbiter.mutators.grammars`:

| Family            | Grammar shape                                              | Cross-product size |
|-------------------|------------------------------------------------------------|--------------------|
| `deserialization` | `tag(2) × callable(6) × body-form(2)`                      | 24                 |
| `process`         | `prefix(7) × payload(2) × suffix(3) + 4 substitution forms` | 46                 |
| `template`        | `4 literal forms + 4 globals walkers × 1 op`               | 8                  |

We deliberately don't support recursion, weights, or shrinker-friendly
representations — generation is one DFS, no backtracking. The corpus
this produces is finite and small (typically <100 payloads per family);
the worker's `max_examples` cap clips it.

For `code_exec`, structural grammar isn't expressive enough — every
variant has to be a syntactically valid Python expression. The
`arbiter.mutators.tokens` module re-tokenizes each canonical seed via
the standard library's `tokenize` module and yields token-level
mutations: swap STRING-token quote forms (`'X'` ↔ `"X"` ↔ `f'X'` ↔
`r'X'`), wrap the whole expression in parens or an identity tuple, and
append marker-bearing trailing comments. Every yield is a valid
expression by construction; we never produce a string that
`compile()` would reject.

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
* Witnesses are recorded even if the worker terminates abnormally, as the oracle drains events incrementally during the fuzz loop.
* Users are advised not to run campaigns on untrusted, unreviewed packages outside of containerized or virtualized environments.

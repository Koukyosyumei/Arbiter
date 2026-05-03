"""Core data models — the contracts between Arbiter components.

These types serialize to/from JSON, so they double as the IPC payload between the
orchestrator and worker subprocesses.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SinkFamily(str, Enum):
    code_exec = "code_exec"
    deserialization = "deserialization"
    process = "process"
    template = "template"
    xml = "xml"
    import_ = "import"
    path = "path"


SEVERITY: dict[SinkFamily, str] = {
    SinkFamily.code_exec: "critical",
    SinkFamily.deserialization: "critical",
    SinkFamily.process: "critical",
    SinkFamily.template: "high",
    SinkFamily.xml: "high",
    SinkFamily.import_: "high",
    SinkFamily.path: "medium",
}


class Exposure(str, Enum):
    network = "network"
    cli = "cli"
    library = "library"
    internal = "internal"


class AttackerModel(str, Enum):
    """Where the attacker's bytes originate. Orthogonal to `Exposure`, which
    describes who *invokes* the entry point. The same target can be classified
    under different attacker models depending on which data path you're
    following — discovery sets the entry-level guess, reachability refines per
    Flow once the actual taint path is known.

    `network`             — bytes arrive over a socket (HTTP body, RPC payload).
    `argv`                — bytes are an argument on the shell command line.
    `loaded_file_content` — the entry takes a path/handle, but the dangerous
                            bytes live inside the file's content. Exploitation
                            requires the user/operator to open a malicious file.
    `env`                 — bytes come from an environment variable.
    `prompt_injected`     — bytes are produced by a downstream LLM whose
                            prompt the attacker influences (tool-use chains).
    """

    network = "network"
    argv = "argv"
    loaded_file_content = "loaded_file_content"
    env = "env"
    prompt_injected = "prompt_injected"


# Discovery doesn't always know the attacker model, so we infer a sensible
# default from the entry's exposure when the LLM omits it.
DEFAULT_ATTACKER_MODEL: dict[Exposure, AttackerModel] = {
    Exposure.network: AttackerModel.network,
    Exposure.cli: AttackerModel.argv,
    Exposure.library: AttackerModel.network,  # most library entries get fuzzed as if remote
    Exposure.internal: AttackerModel.network,
}


class Sink(BaseModel):
    """A static finding — an occurrence of a dangerous API call in source."""

    model_config = ConfigDict(frozen=True)

    family: SinkFamily
    callable_qualname: str
    file: str
    line: int
    note: str | None = None

    @property
    def severity(self) -> str:
        return SEVERITY[self.family]


class Target(BaseModel):
    """A candidate entry point — a callable on the package's attack surface."""

    module: str
    qualname: str
    signature: str
    docstring: str | None = None
    exposure: Exposure = Exposure.library
    # Discovery's best guess for the attacker model at the *entry*. Reachability
    # may refine per-flow once the real taint path is known. Unset → inferred
    # from `exposure` via DEFAULT_ATTACKER_MODEL at use time.
    attacker_model: AttackerModel | None = None

    @property
    def fqn(self) -> str:
        return f"{self.module}:{self.qualname}"

    @property
    def effective_attacker_model(self) -> AttackerModel:
        return self.attacker_model or DEFAULT_ATTACKER_MODEL[self.exposure]


class Flow(BaseModel):
    """A hypothesized path from a Target to a Sink.

    `target_fqn` is the entry point an external attacker reaches. The
    `harness_*` pair, when set, names the *fuzzable* leaf function inside
    the call chain — the function that actually calls (or directly leads to)
    the sink. Most real-world entry points (CLI `main`, class constructors,
    network handlers) have signatures the worker can't synthesize inputs for;
    fuzzing the leaf instead lets the audit-hook oracle still fire, with the
    LLM rationale explaining how the entry-to-leaf chain preserves taint.
    """

    target_fqn: str
    sink: Sink
    intermediate: list[str] = Field(default_factory=list)
    confidence: float = 0.5
    rationale: str | None = None
    harness_module: str | None = None
    harness_qualname: str | None = None
    # Reachability's per-flow refinement. Unset → use the target's effective
    # attacker model at scoring/synthesis time. Set explicitly when the data
    # path on this flow uses a different vector than the entry's primary one
    # (e.g. a network entry that immediately opens an attacker-controlled file).
    attacker_model: AttackerModel | None = None


class AuditEvent(BaseModel):
    """A runtime observation: a dangerous audit event fired in the worker."""

    name: str
    family: SinkFamily
    args_repr: list[str]
    stack_summary: list[str]
    marker_hits: list[str] = Field(default_factory=list)

    @property
    def tainted(self) -> bool:
        return bool(self.marker_hits)


class Witness(BaseModel):
    """A confirmed audit-hook firing tied to an input. The reportable artifact."""

    target_fqn: str
    flow: Flow | None = None
    event: AuditEvent
    input_repr: str
    replay_seed: int | None = None

    def fingerprint(self) -> str:
        """Stable identity for dedup — same sink + similar stack collapses."""
        top_frame = self.event.stack_summary[0] if self.event.stack_summary else ""
        return f"{self.event.family.value}|{self.event.name}|{top_frame}"


class ScoreBreakdown(BaseModel):
    """Per-witness score components. Final = raw × (1 − intent_penalty)."""

    severity: float
    exposure: float
    directness: float
    novelty: float
    # Multiplier applied for the attacker model — file-content / env / prompt-
    # injected paths are real but require more steps to weaponize than direct
    # network requests, so they sit lower on the report at otherwise-equal raw.
    attacker_model: float = 1.0
    intent_penalty: float = 0.0
    raw: float
    final: float


class ScoredWitness(BaseModel):
    """A Witness annotated with its triage score and contextual handles."""

    witness: Witness
    target: Target | None = None
    flow: Flow | None = None
    score: ScoreBreakdown
    intended_behavior_reason: str | None = None


# --- worker IPC ---


class HarnessSpec(BaseModel):
    """Sent from orchestrator to worker on stdin. Defines a single fuzzing job."""

    target_module: str
    target_qualname: str
    strategy: StrategySpec
    marker: str  # UUID4 hex; embedded in inputs to detect taint at the sink
    max_examples: int = 200
    timeout_s: float = 30.0
    rss_limit_mb: int = 512
    # When set, the worker writes each generated payload to a temp file with
    # this suffix and passes the file *path* to the target callable. Used
    # for `loaded_file_content` flows where the entry takes a filename and
    # parses the contents — without this, the fuzzer would feed payload bytes
    # directly to a parameter the target tries to `open()` as a filesystem path.
    payload_as_file_suffix: str | None = None


class StrategySpec(BaseModel):
    """A description of how to generate inputs. Worker translates to Hypothesis.

    `kind` selects a generator family; `params` carries family-specific options.
    `seeds` is a small corpus the worker mixes into the strategy via `one_of`.
    """

    kind: str  # "text" | "bytes" | "yaml" | "pickle" | "template" | "shell" | "path"
    params: dict[str, Any] = Field(default_factory=dict)
    seeds: list[str] = Field(default_factory=list)


class WorkerResult(BaseModel):
    """Sent from worker to orchestrator on stdout (one JSON line)."""

    kind: str  # "witness" | "summary" | "error"
    witness: Witness | None = None
    examples_run: int = 0
    # Map of exception class name → count, tallied across every example the
    # harness ran. A summary with examples_run=100 and {"TypeError": 100} is the
    # smoking gun for "the harness target's signature doesn't match what the
    # fuzzer feeds it" — without this, "0 witnesses" is unfalsifiable.
    exception_histogram: dict[str, int] = Field(default_factory=dict)
    error: str | None = None


HarnessSpec.model_rebuild()

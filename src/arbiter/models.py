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

    @property
    def fqn(self) -> str:
        return f"{self.module}:{self.qualname}"


class Flow(BaseModel):
    """A hypothesized path from a Target to a Sink."""

    target_fqn: str
    sink: Sink
    intermediate: list[str] = Field(default_factory=list)
    confidence: float = 0.5
    rationale: str | None = None


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
    error: str | None = None


HarnessSpec.model_rebuild()

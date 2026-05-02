"""Triage — rank witnesses so the top of the report is what a developer
should actually act on.

    score = severity × exposure × directness × novelty × attacker_model
            × (1 − intent_penalty)

- severity        : sink-family tier (critical=1.0, high=0.7, medium=0.5)
- exposure        : how the entry point is reachable (network=1.0 .. internal=0.3)
- directness      : 1 / (1 + len(flow.intermediate)); direct call → 1.0
- novelty         : 1.0 for the first witness with a given fingerprint within
                    a campaign, 0.5 / 0.3 / ... for repeats. Cross-campaign
                    novelty is a v0.5 concern.
- attacker_model  : where the bytes come from. network=1.0 (direct);
                    loaded_file_content=0.6 (needs social engineering);
                    env=0.5; argv=0.85; prompt_injected=0.7. See
                    AttackerModel for the full taxonomy.
- intent_penalty  : 0.0–0.5 heuristic penalty when the target's docstring
                    advertises the dangerous behavior (sink "is the feature").
                    Multiplicative so even fully-intended sinks still report
                    at half strength rather than zero.

The LLM-driven intent classifier (DESIGN.md §7) is a v0.5 follow-up; the
heuristic here is a string-keyword check that catches the obvious cases
without an extra Haiku call.
"""

from __future__ import annotations

from collections import Counter

from arbiter.models import (
    AttackerModel,
    Exposure,
    Flow,
    ScoreBreakdown,
    ScoredWitness,
    Sink,
    SinkFamily,
    Target,
    Witness,
)

SEVERITY_SCORE: dict[str, float] = {
    "critical": 1.0,
    "high": 0.7,
    "medium": 0.5,
    "low": 0.3,
}

EXPOSURE_SCORE: dict[Exposure, float] = {
    Exposure.network: 1.0,
    Exposure.cli: 0.8,
    Exposure.library: 0.6,
    Exposure.internal: 0.3,
}

# Multiplier for the attacker model. Higher = more directly weaponizable from
# the attacker's perspective. `loaded_file_content` requires social engineering
# (the user has to open the malicious file); `env` requires having already
# influenced the process environment; `prompt_injected` requires a tool-use
# chain. These don't change exploitability — only the urgency — so the
# multipliers are gentle.
ATTACKER_MODEL_SCORE: dict[AttackerModel, float] = {
    AttackerModel.network: 1.0,
    AttackerModel.argv: 0.85,
    AttackerModel.loaded_file_content: 0.6,
    AttackerModel.env: 0.5,
    AttackerModel.prompt_injected: 0.7,
}

# Keywords that indicate a docstring is *advertising* the dangerous behavior.
# A match implies "the function is supposed to do this", which lowers
# triage priority but never zeros it (the entry point is still attacker-
# reachable; security review may still want to require auth or sandboxing).
_INTENT_KEYWORDS: dict[SinkFamily, frozenset[str]] = {
    SinkFamily.code_exec: frozenset(
        {"evaluate", "execute", "compile", "expression", "eval ", "interpret"}
    ),
    SinkFamily.deserialization: frozenset(
        {"deserialize", "deserialise", "unmarshal", "unpickle", "load yaml", "parse yaml"}
    ),
    SinkFamily.process: frozenset(
        {"command", "shell", "subprocess", "spawn process", "run process", "exec("}
    ),
    SinkFamily.template: frozenset({"render template", "template", "jinja", "mako"}),
    SinkFamily.xml: frozenset({"parse xml", "xml document", "etree"}),
    SinkFamily.import_: frozenset({"import module", "load module", "dynamic import"}),
    SinkFamily.path: frozenset({"open file", "read file", "file path"}),
}

INTENT_PENALTY = 0.4  # Multiplicative; final score halves at most.

# Diminishing-returns curve for repeats with the same fingerprint.
_NOVELTY_BY_RANK: tuple[float, ...] = (1.0, 0.5, 0.3, 0.2, 0.1)


def _severity_score(sink: Sink) -> float:
    return SEVERITY_SCORE.get(sink.severity, 0.5)


def _exposure_score(target: Target | None) -> float:
    if target is None:
        return EXPOSURE_SCORE[Exposure.library]  # default mid-band when unknown
    return EXPOSURE_SCORE.get(target.exposure, EXPOSURE_SCORE[Exposure.library])


def _attacker_model_score(flow: Flow | None, target: Target | None) -> float:
    """Per-flow override wins over target's model; both unknown → network default."""
    if flow is not None and flow.attacker_model is not None:
        return ATTACKER_MODEL_SCORE.get(flow.attacker_model, 1.0)
    if target is not None:
        return ATTACKER_MODEL_SCORE.get(target.effective_attacker_model, 1.0)
    return 1.0


def _directness_score(flow: Flow | None) -> float:
    """Closer to 1.0 = fewer intermediate hops between entry and sink."""
    if flow is None:
        return 0.6  # unknown reachability — middling
    return 1.0 / (1.0 + len(flow.intermediate))


def _novelty_score(rank: int) -> float:
    """rank=0 is the first witness with this fingerprint; rank=1 is the second."""
    if rank < len(_NOVELTY_BY_RANK):
        return _NOVELTY_BY_RANK[rank]
    return 0.05


def _intent_penalty(target: Target | None, sink: Sink) -> tuple[float, str | None]:
    """Heuristic: penalize when the target docstring advertises this behavior."""
    if target is None or not target.docstring:
        return 0.0, None
    keywords = _INTENT_KEYWORDS.get(sink.family, frozenset())
    if not keywords:
        return 0.0, None
    doc = target.docstring.lower()
    for kw in keywords:
        if kw in doc:
            return INTENT_PENALTY, f"target docstring mentions {kw!r}"
    return 0.0, None


def score_witness(
    witness: Witness,
    target: Target | None,
    flow: Flow | None,
    fingerprint_rank: int = 0,
) -> ScoredWitness:
    """Score one witness in isolation. `fingerprint_rank` is supplied by the
    campaign-level pass so within-campaign novelty applies."""
    # The Witness carries the audit event (family, args) but no Sink object.
    # The Flow's Sink has richer attributes (severity, file:line, note); use
    # it when available, otherwise fall back to family-default severity.
    sink_obj = flow.sink if flow is not None else None
    severity = _severity_score(sink_obj) if sink_obj else SEVERITY_SCORE.get(
        # fall back to family-default severity when no Sink object is around
        {
            SinkFamily.code_exec: "critical",
            SinkFamily.deserialization: "critical",
            SinkFamily.process: "critical",
            SinkFamily.template: "high",
            SinkFamily.xml: "high",
            SinkFamily.import_: "high",
            SinkFamily.path: "medium",
        }.get(witness.event.family, "medium"),
        0.5,
    )
    exposure = _exposure_score(target)
    directness = _directness_score(flow)
    novelty = _novelty_score(fingerprint_rank)
    attacker_model_mult = _attacker_model_score(flow, target)
    raw = severity * exposure * directness * novelty * attacker_model_mult

    if sink_obj is not None:
        penalty, reason = _intent_penalty(target, sink_obj)
    else:
        penalty, reason = 0.0, None

    final = raw * (1.0 - penalty)

    breakdown = ScoreBreakdown(
        severity=severity,
        exposure=exposure,
        directness=directness,
        novelty=novelty,
        attacker_model=attacker_model_mult,
        intent_penalty=penalty,
        raw=raw,
        final=final,
    )
    return ScoredWitness(
        witness=witness,
        target=target,
        flow=flow,
        score=breakdown,
        intended_behavior_reason=reason,
    )


def _find_target(targets: list[Target], fqn: str) -> Target | None:
    for t in targets:
        if t.fqn == fqn:
            return t
    return None


def _find_flow(flows: list[Flow], witness: Witness) -> Flow | None:
    for f in flows:
        if f.target_fqn == witness.target_fqn and f.sink.family is witness.event.family:
            return f
    return None


def triage_campaign(
    witnesses: list[Witness],
    targets: list[Target],
    flows: list[Flow],
) -> list[ScoredWitness]:
    """Score every witness from a campaign and return them sorted by descending
    final score. Within-campaign fingerprint duplicates get diminishing
    novelty; tainted witnesses always rank above untainted ones at equal raw."""
    seen: Counter[str] = Counter()
    scored: list[ScoredWitness] = []
    for w in witnesses:
        target = _find_target(targets, w.target_fqn)
        flow = _find_flow(flows, w)
        rank = seen[w.fingerprint()]
        seen[w.fingerprint()] += 1
        sw = score_witness(w, target, flow, fingerprint_rank=rank)
        scored.append(sw)

    # Sort: tainted witnesses first, then by final score desc, then stable.
    scored.sort(
        key=lambda s: (s.witness.event.tainted, s.score.final),
        reverse=True,
    )
    return scored

"""Curated seed payloads, organized by sink family.

Each payload contains the literal ``{MARKER}`` placeholder at a position where
attacker-controlled bytes flow into the sink, so the audit-hook oracle's
substring match can confirm taint at runtime.

Side effects are kept harmless (`echo`, `:`, `true`, integer math, no-op
construction). The detector may execute these in v0 environments that lack a
sandbox; never include `rm`, `curl`, network calls, or filesystem writes
outside `/tmp`.

# Attribution

Many payloads here are adapted from PayloadsAllTheThings (MIT-licensed):

    https://github.com/swisskyrepo/PayloadsAllTheThings

Each family file cites the specific section of PayloadsAllTheThings the
payloads were derived from. Where the original payload performed a real
exploit (e.g. `os.system("whoami")`), the side effect has been replaced with
a marker-bearing benign equivalent (`os.system("echo {MARKER}")`).
"""

from __future__ import annotations

from arbiter.models import SinkFamily
from arbiter.payloads import (
    code_exec,
    deserialization,
    imports,
    path,
    process,
    template,
    xml,
)

_REGISTRY: dict[SinkFamily, list[str]] = {
    SinkFamily.code_exec: code_exec.SEEDS,
    SinkFamily.deserialization: deserialization.SEEDS,
    SinkFamily.process: process.SEEDS,
    SinkFamily.template: template.SEEDS,
    SinkFamily.xml: xml.SEEDS,
    SinkFamily.import_: imports.SEEDS,
    SinkFamily.path: path.SEEDS,
}


def get_seed_corpus(family: SinkFamily) -> list[str]:
    """Return a fresh copy of the curated seed list for `family`.

    Returns an empty list for families with no curated corpus rather than
    raising — the orchestrator merges this with LLM-generated seeds and a
    missing family is non-fatal.
    """
    return list(_REGISTRY.get(family, []))


__all__ = ["get_seed_corpus"]

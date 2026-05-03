"""Live discovery test — `claude -p` agent mode runs against the bundled
vulnpkg fixture and is expected to enumerate its public API.

Skipped automatically when the `claude` CLI is not on PATH.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from arbiter.llm.discover import discover_targets

VULNPKG_PATH = Path(__file__).parent / "fixtures" / "vulnpkg"

pytestmark = [
    pytest.mark.skipif(
        shutil.which("claude") is None,
        reason="claude CLI not on PATH — skipping live discover integration",
    ),
    pytest.mark.timeout(240),
]


def test_discover_finds_vulnpkg_public_callables():
    targets = discover_targets(VULNPKG_PATH, "vulnpkg", max_turns=20)
    assert targets, "discover_targets returned empty list"

    qualnames = {t.qualname for t in targets}
    # vulnpkg exposes exactly four callables; the agent should find at least
    # the three vulnerable ones — echo_safe is sometimes filtered as boring.
    assert "eval_expression" in qualnames, qualnames
    assert "load_config" in qualnames, qualnames
    assert "render" in qualnames, qualnames

    by_qualname = {t.qualname: t for t in targets}
    assert by_qualname["eval_expression"].module.endswith("api") or "vulnpkg" in by_qualname[
        "eval_expression"
    ].module

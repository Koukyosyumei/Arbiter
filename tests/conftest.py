"""Pytest config — exposes the bundled vulnpkg fixture on sys.path."""

from __future__ import annotations

import sys
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Make `vulnpkg` importable from anywhere in the test session.
if str(FIXTURES_DIR) not in sys.path:
    sys.path.insert(0, str(FIXTURES_DIR))

"""path sink-family seeds (`open`, `os.path.*`, `Path` with traversal).

Traversal sequences with the marker in the resolved path. Path sinks have
no built-in audit event; this corpus is here for when monkey-patched path
sinks land in v0.4.

Source: PayloadsAllTheThings — Directory Traversal
    https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/README.md
"""

from __future__ import annotations

SEEDS: list[str] = [
    # --- vanilla traversal
    "../{MARKER}",
    "../../{MARKER}",
    "../../../etc/{MARKER}",
    # --- Windows-style separators
    "..\\{MARKER}",
    "..\\..\\{MARKER}",
    # --- absolute
    "/tmp/{MARKER}",
    # --- URL encoding (single)
    "..%2f{MARKER}",
    # --- URL encoding (double)
    "..%252f{MARKER}",
    # --- null-byte truncation (legacy CPython, still occasional)
    "{MARKER}\x00.txt",
    # --- four-dot bypass
    "....//{MARKER}",
]

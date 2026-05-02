"""import sink-family seeds (`__import__`, `importlib.import_module`).

The marker rides as part of the module-name string passed to the sink. The
import will fail (the module doesn't exist) but the `import` audit event
fires *before* failure with the requested name in its args.

Source: PayloadsAllTheThings — File Inclusion / Dependency Confusion
    https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Dependency%20Confusion
"""

from __future__ import annotations

SEEDS: list[str] = [
    "not_a_real_module_{MARKER}",
    "{MARKER}_pkg",
    "os.system_{MARKER}",
    "../{MARKER}",
    "json.{MARKER}",
    "..{MARKER}",
    "pkg.{MARKER}.subpkg",
]

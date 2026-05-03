"""code_exec sink-family seeds (eval, exec, compile, runpy).

The marker arrives as a literal in the Python source passed to the sink, so
the `compile` / `exec` audit event captures it in the args repr.

Source: PayloadsAllTheThings — Code Injection
    https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Code%20Injection
"""

from __future__ import annotations

SEEDS: list[str] = [
    # --- literal embedding (marker survives compile)
    "'{MARKER}'",
    "'{MARKER}' + str(1)",
    "f'{MARKER}'",
    "1 + 1  # {MARKER}",
    "[1, 2, '{MARKER}']",
    # --- import + attribute (also fires `import` audit event)
    "__import__('os').name + '{MARKER}'",
    "__import__('sys').version + '{MARKER}'",
    # --- callable wrappers
    "(lambda: '{MARKER}')()",
    "''.join(['{MARKER}'])",
    # --- builtins lookup (gadget probe)
    "__builtins__.__dict__.get('len')('{MARKER}')",
    # --- error path (compile fires before raise; marker still in source)
    "raise ValueError('{MARKER}')",
]

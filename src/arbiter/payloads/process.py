"""process sink-family seeds (os.system, subprocess.*, os.exec*).

The marker becomes part of the command string or argv. For shell-evaluated
sinks (shell=True, os.system, os.popen) the metacharacter variants matter;
for argv-based sinks, the marker just needs to appear in one of the args.

Source: PayloadsAllTheThings — Command Injection
    https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/README.md
"""

from __future__ import annotations

SEEDS: list[str] = [
    # --- direct argument
    "echo {MARKER}",
    # --- shell separators
    "; echo {MARKER}",
    "&& echo {MARKER}",
    "|| echo {MARKER}",
    "| echo {MARKER}",
    # --- command substitution
    "$(echo {MARKER})",
    "`echo {MARKER}`",
    # --- whitespace / line injection
    "\necho {MARKER}",
    "\techo {MARKER}",
    # --- quote escape
    "\"; echo {MARKER}; \"",
    "'; echo {MARKER}; '",
    # --- background + chain
    "& echo {MARKER} &",
    # --- argv-form (passed verbatim when shell=False)
    "echo\necho {MARKER}",
]

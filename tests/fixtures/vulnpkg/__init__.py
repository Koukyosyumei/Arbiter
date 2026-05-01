"""vulnpkg — a deliberately-vulnerable test fixture for Arbiter.

Each public function exposes one ACE primitive of a different sink family:

    eval_expression  -> code_exec       (eval)
    load_config      -> deserialization (yaml.unsafe_load)
    render           -> template        (jinja2 unsafe env -> ultimately code_exec)

`echo_safe` is a negative control: no dangerous call.
"""

from vulnpkg.api import echo_safe, eval_expression, load_config, render

__all__ = ["eval_expression", "load_config", "render", "echo_safe"]

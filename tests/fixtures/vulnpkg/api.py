"""Public API surface — every function here is intentionally insecure."""

from __future__ import annotations

from typing import Any

import jinja2
import yaml


def eval_expression(expr: str) -> Any:
    """Evaluate an arbitrary Python expression. Direct code_exec primitive."""
    return eval(expr)  # noqa: S307


def load_config(blob: str | bytes) -> Any:
    """Parse YAML allowing arbitrary Python tags. Deserialization primitive."""
    return yaml.unsafe_load(blob)


def render(template_str: str, context: dict[str, Any] | None = None) -> str:
    """Render a Jinja2 template without autoescape. SSTI primitive."""
    env = jinja2.Environment(autoescape=False)
    template = env.from_string(template_str)
    return template.render(**(context or {}))


def echo_safe(text: str) -> str:
    """No-op echo. Negative control — should never trigger any oracle."""
    return text

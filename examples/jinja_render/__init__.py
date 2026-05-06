"""jinja_render — toy template renderer with an SSTI ACE bug.

Public entry point: :func:`render_post`. Intended for a hypothetical blog
service where users submit posts containing Jinja2 expressions for
inline math / formatting. Exposure: ``network`` / ``library``.
"""

from __future__ import annotations

import jinja2

__all__ = ["render_post"]


def render_post(title: str, body: str, author: str = "anonymous") -> str:
    """Render a blog post body as a Jinja2 template and return HTML.

    Bug: ``jinja2.Template`` defaults to ``autoescape=False`` and exposes
    Python attribute traversal, so a body of
    ``{{ self.__init__.__globals__['__builtins__'].exec('...') }}`` reaches
    ``compile``/``exec``. The fix is to disable expression rendering for
    untrusted bodies (``Markup.escape`` / ``SandboxedEnvironment``).
    """
    template = jinja2.Template(body)
    return template.render(title=title, author=author)

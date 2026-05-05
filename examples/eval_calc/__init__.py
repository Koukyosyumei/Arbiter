"""eval_calc — toy calculator with an ACE bug.

Public entry point: :func:`evaluate`. Reachable as a CLI (``python -m eval_calc EXPR``)
and as a library function. Arbiter should classify exposure as ``cli`` / ``library``.
"""

from __future__ import annotations

__all__ = ["evaluate", "main"]


def evaluate(expression: str) -> float:
    """Evaluate a math expression supplied by the user and return the result.

    >>> evaluate("1 + 2 * 3")
    7

    Bug: ``eval`` runs arbitrary Python — ``evaluate("__import__('os').system('id')")``
    spawns a shell. The intended fix is ``ast.literal_eval`` plus a numeric guard.
    """
    return eval(expression)  # noqa: S307


def main(argv: list[str] | None = None) -> int:
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("usage: eval_calc EXPR", file=sys.stderr)
        return 2
    print(evaluate(" ".join(args)))
    return 0

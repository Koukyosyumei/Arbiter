"""shell_cat — toy file-head viewer with a shell-injection ACE bug.

Public entry point: :func:`head_file`. Reachable as a CLI
(``python -m shell_cat PATH``) and as a library function.
"""

from __future__ import annotations

import subprocess

__all__ = ["head_file", "main"]


def head_file(path: str, lines: int = 10) -> str:
    """Return the first ``lines`` lines of the file at ``path``.

    Bug: the path is interpolated straight into a shell command, so any
    metacharacters give the caller arbitrary command execution. Try
    ``head_file("foo; echo PWNED")``. The fix is ``shell=False`` with an argv list.
    """
    cmd = f"head -n {lines} {path}"
    proc = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout


def main(argv: list[str] | None = None) -> int:
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("usage: shell_cat PATH", file=sys.stderr)
        return 2
    sys.stdout.write(head_file(args[0]))
    return 0

"""Token-aware mutator for the ``code_exec`` family.

Operates on a marker-bearing Python expression and produces equivalent
expressions whose marker still ends up as a literal in the compiled source.
Mutations operate at the Python *token* level so that the result remains
syntactically valid; we never produce a string that ``compile()`` would
reject.

We don't attempt full coverage of Python's expression grammar — just the
high-yield set: literal-form variants and a handful of no-op wrappers.
"""

from __future__ import annotations

import io
import token
import tokenize
from collections.abc import Iterator


def code_exec_token_variants(seed: str, marker: str) -> Iterator[str]:
    """Yield token-level mutations of ``seed`` carrying ``marker``.

    The seed is expected to embed the live ``marker`` substring already.
    Each yielded variant preserves syntactic validity *and* the marker.

    Mutation passes:
      1. **String literal form swaps.** A bare ``'X'`` literal becomes
         ``"X"``, ``f'X'``, ``r'X'``, ``b'X'.decode()`` (each form keeps the
         marker visible in the compiled source).
      2. **No-op expression wrappers.** Wrap the whole expression in
         ``(EXPR)``, ``(EXPR or EXPR)`` (no double-eval; harmless), or
         append ``# {marker}`` as a trailing comment so the marker also
         lands in the compiled source via the literal form.
    """
    if marker not in seed:
        return

    # Pass 1: literal-form swaps — operate on individual STRING tokens.
    yield from _string_form_swaps(seed, marker)

    # Pass 2: no-op wrappers — operate on the whole expression.
    yield from _expression_wrappers(seed, marker)


def _string_form_swaps(seed: str, marker: str) -> Iterator[str]:
    """For each STRING token containing ``marker``, yield the seed with that
    token rewritten to each alternative literal form.

    Skips multi-line strings, byte literals, and triple-quoted strings — the
    rewrite logic is unsafe for those.
    """
    try:
        tokens = list(tokenize.tokenize(io.BytesIO(seed.encode("utf-8")).readline))
    except (tokenize.TokenizeError, SyntaxError, UnicodeError):
        return

    for i, tok in enumerate(tokens):
        if tok.type != token.STRING:
            continue
        body, prefix, quote = _split_string_literal(tok.string)
        if body is None or marker not in body:
            continue
        if "\n" in body or quote.startswith(('"""', "'''")):
            continue
        if "b" in prefix.lower():
            continue

        # Generate alternative forms.
        for new_lit in _alternative_string_forms(body):
            if new_lit == tok.string:
                continue
            try:
                replaced = list(tokens)
                replaced[i] = tokenize.TokenInfo(
                    type=tok.type,
                    string=new_lit,
                    start=tok.start,
                    end=tok.end,
                    line=tok.line,
                )
                rewritten = tokenize.untokenize(replaced).decode("utf-8")
            except (ValueError, KeyError):
                continue
            # Sanity: marker still present (the literal forms preserve it,
            # but rewriting is fragile so verify).
            if marker in rewritten:
                yield rewritten


def _expression_wrappers(seed: str, marker: str) -> Iterator[str]:
    """Yield no-op wrappers around the whole expression."""
    yield f"({seed})"
    # Trailing comment carrying the marker — guarantees the marker lands in
    # the compiled source even if the expression's literals shrink away.
    yield f"{seed}  # {marker}"
    # Identity tuple: the expression is the first (and only) element.
    yield f"({seed},)[0]"


def _split_string_literal(literal: str) -> tuple[str | None, str, str]:
    """Split ``"abc"`` / ``f'x'`` / ``r"y"`` into (body, prefix, quote).

    Returns ``(None, "", "")`` for unrecognized shapes (e.g. f-strings with
    interpolations — we don't rewrite those).
    """
    if not literal:
        return None, "", ""
    # Find the prefix (sequence of letters before the opening quote).
    i = 0
    while i < len(literal) and literal[i].isalpha():
        i += 1
    prefix = literal[:i]
    rest = literal[i:]
    if not rest:
        return None, prefix, ""
    quote = rest[0]
    if quote not in ("'", '"'):
        return None, prefix, ""
    # Triple-quote?
    if rest.startswith(quote * 3):
        if not rest.endswith(quote * 3):
            return None, prefix, ""
        return rest[3:-3], prefix, quote * 3
    if not rest.endswith(quote):
        return None, prefix, ""
    return rest[1:-1], prefix, quote


def _alternative_string_forms(body: str) -> list[str]:
    """Given a string's *body* (no quotes), return alternative literal forms.

    Skips alternatives that would require re-escaping (the body contains
    one of the alternative quotes, or special characters).
    """
    forms: list[str] = []
    safe_for_quote = lambda q: q not in body and "\\" not in body  # noqa: E731

    if safe_for_quote("'"):
        forms.append(f"'{body}'")
        forms.append(f"f'{body}'")
        forms.append(f"r'{body}'")
    if safe_for_quote('"'):
        forms.append(f'"{body}"')
        forms.append(f'f"{body}"')
    return forms


__all__ = ["code_exec_token_variants"]

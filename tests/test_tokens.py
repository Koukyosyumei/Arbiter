"""Unit tests for the code_exec token-level mutator."""

from __future__ import annotations

from arbiter.mutators.tokens import code_exec_token_variants


def test_swaps_single_quote_to_double_quote():
    out = list(code_exec_token_variants("'mark' + str(1)", marker="mark"))
    assert any('"mark"' in v for v in out), out


def test_yields_fstring_form():
    out = list(code_exec_token_variants("'mark'", marker="mark"))
    assert any("f'mark'" in v or 'f"mark"' in v for v in out), out


def test_wraps_expression_in_parens():
    out = list(code_exec_token_variants("'mark'", marker="mark"))
    assert "('mark')" in out


def test_appends_trailing_comment():
    out = list(code_exec_token_variants("1 + 1", marker="mark"))
    # 1 + 1 has no string literal containing the marker, so the literal
    # swaps yield nothing; but the wrappers fire because the marker is in
    # the seed. Wait — our contract requires marker substring in seed.
    # Update: 1+1 has no marker → mutator yields nothing.
    assert out == [], (
        "if the seed does not contain the marker, the mutator must yield "
        f"nothing (got {out})"
    )


def test_skips_when_marker_absent():
    out = list(code_exec_token_variants("1 + 1", marker="mark"))
    assert out == []


def test_appends_trailing_comment_when_marker_present():
    out = list(code_exec_token_variants("1 + 1  # mark", marker="mark"))
    # No string literal swaps fire (marker is in a comment, not a STRING token);
    # the wrapper pass still produces wrapped variants.
    assert "(1 + 1  # mark)" in out or any("# mark" in v for v in out)


def test_all_yields_preserve_marker():
    seeds = [
        "'mark'",
        "'mark' + str(1)",
        '("mark",)[0]',
    ]
    for seed in seeds:
        for v in code_exec_token_variants(seed, marker="mark"):
            assert "mark" in v, f"variant lost the marker: {v!r}"


def test_skips_byte_literals():
    """Byte-string mutations are unsafe (different runtime behavior)."""
    out = list(code_exec_token_variants("b'mark'", marker="mark"))
    # Wrapper-pass variants still fire, but no string-form swaps.
    assert all("b'mark'" in v or v.endswith("# mark") for v in out), out


def test_yields_identity_tuple_wrapper():
    out = list(code_exec_token_variants("'mark'", marker="mark"))
    assert "('mark',)[0]" in out

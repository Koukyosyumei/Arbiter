"""Unit tests for the grammar engine."""

from __future__ import annotations

from arbiter.mutators.grammar import Choice, Rule, enumerate_rule


def test_string_leaf():
    out = list(enumerate_rule("hello", marker="m"))
    assert out == ["hello"]


def test_choice_alternation():
    rule = Choice(("a", "b", "c"))
    out = list(enumerate_rule(rule, marker="m"))
    assert out == ["a", "b", "c"]


def test_rule_concatenation():
    rule = Rule(("x", "y", "z"))
    out = list(enumerate_rule(rule, marker="m"))
    assert out == ["xyz"]


def test_marker_placeholder_substituted_at_yield():
    rule = Rule(("hi ", "{MARKER}", "!"))
    out = list(enumerate_rule(rule, marker="m"))
    assert out == ["hi m!"]


def test_choice_inside_rule_cross_product():
    rule = Rule((
        "echo ",
        Choice(("foo", "bar")),
        " ",
        "{MARKER}",
    ))
    out = list(enumerate_rule(rule, marker="abc"))
    assert sorted(out) == ["echo bar abc", "echo foo abc"]


def test_nested_choices_cross_product():
    rule = Rule((
        Choice(("a", "b")),
        Choice(("1", "2")),
    ))
    out = list(enumerate_rule(rule, marker="m"))
    assert sorted(out) == ["a1", "a2", "b1", "b2"]


def test_budget_truncates_output():
    rule = Choice(("a", "b", "c", "d"))
    out = list(enumerate_rule(rule, marker="m", budget=2))
    assert out == ["a", "b"]


def test_empty_string_option_yields_skipped_part():
    """Empty-string options are how we express 'this slot is optional'."""
    rule = Rule((
        "x",
        Choice(("y", "")),
        "z",
    ))
    out = list(enumerate_rule(rule, marker="m"))
    assert sorted(out) == ["xyz", "xz"]


def test_realistic_deserialization_grammar_size():
    """Sanity-check the cross-product expansion the worker will see."""
    grammar = Rule((
        "!!python/",
        Choice(("object/apply", "object/new", "name", "module")),
        ":",
        Choice(("os.system", "subprocess.getoutput", "os.popen", "builtins.eval")),
        ' ["echo {MARKER}"]',
    ))
    out = list(enumerate_rule(grammar, marker="X"))
    assert len(out) == 16  # 4 tags × 4 callables
    # Spot-check a known-good combination.
    assert any('!!python/object/apply:os.system ["echo X"]' == p for p in out)

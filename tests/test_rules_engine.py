"""Tests for util/rules_engine.py."""

import copy

import pytest

from jibrilcon.util.rules_engine import _compile_regex, evaluate_rules


@pytest.fixture(autouse=True)
def _clear_regex_cache():
    """Clear the regex LRU cache between tests."""
    _compile_regex.cache_clear()
    yield
    _compile_regex.cache_clear()


# ------------------------------------------------------------------ #
# P0 regression: returned dicts must be independent copies
# ------------------------------------------------------------------ #


def test_returned_dicts_are_independent_copies():
    """Mutating a returned violation must NOT affect subsequent calls."""
    rules = [
        {
            "id": "always_match",
            "type": "alert",
            "description": "Always matches",
            "logic": "and",
            "conditions": [{"field": "x", "operator": "equals", "value": 1}],
        }
    ]
    data = {"x": 1}

    result1 = evaluate_rules(data, rules)
    assert len(result1) == 1

    # Mutate the returned dict (simulating what scanners do)
    result1[0]["source"] = "/container_A/config.json"
    result1[0]["lines"] = ["Privileged = true"]

    # Second call must return a clean dict without source/lines
    result2 = evaluate_rules(data, rules)
    assert len(result2) == 1
    assert "source" not in result2[0]
    assert "lines" not in result2[0]


def test_original_rules_list_unchanged_after_evaluation():
    """The canonical rules list must never be modified."""
    rules = [
        {
            "id": "test",
            "type": "warning",
            "logic": "and",
            "conditions": [{"field": "a", "operator": "equals", "value": True}],
        }
    ]
    original = copy.deepcopy(rules)

    result = evaluate_rules({"a": True}, rules)
    result[0]["extra_key"] = "injected"

    assert rules == original


# ------------------------------------------------------------------ #
# Basic matching
# ------------------------------------------------------------------ #


def test_matching_rule_returned():
    rules = [
        {
            "id": "r1",
            "type": "alert",
            "logic": "and",
            "conditions": [{"field": "x", "operator": "equals", "value": 1}],
        },
        {
            "id": "r2",
            "type": "warning",
            "logic": "and",
            "conditions": [{"field": "x", "operator": "equals", "value": 99}],
        },
    ]
    matched = evaluate_rules({"x": 1}, rules)
    ids = [m["id"] for m in matched]
    assert ids == ["r1"]


def test_no_match_returns_empty():
    rules = [
        {
            "id": "r1",
            "type": "alert",
            "logic": "and",
            "conditions": [{"field": "x", "operator": "equals", "value": 999}],
        },
    ]
    assert evaluate_rules({"x": 1}, rules) == []


def test_empty_rules():
    assert evaluate_rules({"x": 1}, []) == []


def test_empty_data():
    rules = [
        {
            "id": "r1",
            "type": "alert",
            "logic": "and",
            "conditions": [{"field": "x", "operator": "equals", "value": 1}],
        },
    ]
    assert evaluate_rules({}, rules) == []


# ------------------------------------------------------------------ #
# Logic: AND / OR
# ------------------------------------------------------------------ #


def test_and_logic_all_must_match():
    rules = [
        {
            "id": "r1",
            "type": "alert",
            "logic": "and",
            "conditions": [
                {"field": "a", "operator": "equals", "value": 1},
                {"field": "b", "operator": "equals", "value": 2},
            ],
        },
    ]
    assert len(evaluate_rules({"a": 1, "b": 2}, rules)) == 1
    assert len(evaluate_rules({"a": 1, "b": 999}, rules)) == 0


def test_or_logic_any_can_match():
    rules = [
        {
            "id": "r1",
            "type": "alert",
            "logic": "or",
            "conditions": [
                {"field": "a", "operator": "equals", "value": 1},
                {"field": "b", "operator": "equals", "value": 2},
            ],
        },
    ]
    assert len(evaluate_rules({"a": 1, "b": 999}, rules)) == 1
    assert len(evaluate_rules({"a": 999, "b": 999}, rules)) == 0


# ------------------------------------------------------------------ #
# Operators
# ------------------------------------------------------------------ #


def test_operator_not_equals():
    rules = [_rule("not_equals", "x", 1)]
    assert len(evaluate_rules({"x": 2}, rules)) == 1
    assert len(evaluate_rules({"x": 1}, rules)) == 0


def test_operator_contains():
    rules = [_rule("contains", "x", "foo")]
    assert len(evaluate_rules({"x": ["foo", "bar"]}, rules)) == 1
    assert len(evaluate_rules({"x": "foobar"}, rules)) == 1
    assert len(evaluate_rules({"x": ["bar"]}, rules)) == 0


def test_operator_not_contains():
    rules = [_rule("not_contains", "x", "foo")]
    assert len(evaluate_rules({"x": ["bar"]}, rules)) == 1
    assert len(evaluate_rules({"x": ["foo"]}, rules)) == 0


def test_operator_exists():
    rules = [_rule("exists", "x", None)]
    assert len(evaluate_rules({"x": "anything"}, rules)) == 1
    assert len(evaluate_rules({}, rules)) == 0


def test_operator_not_exists():
    rules = [_rule("not_exists", "x", None)]
    assert len(evaluate_rules({}, rules)) == 1
    assert len(evaluate_rules({"x": "val"}, rules)) == 0


def test_operator_regex_match():
    rules = [_rule("regex_match", "x", r"^hello\s+world$")]
    assert len(evaluate_rules({"x": "hello  world"}, rules)) == 1
    assert len(evaluate_rules({"x": "goodbye"}, rules)) == 0


def test_operator_gt():
    rules = [_rule("gt", "x", 5)]
    assert len(evaluate_rules({"x": 10}, rules)) == 1
    assert len(evaluate_rules({"x": 5}, rules)) == 0


def test_operator_gte():
    rules = [_rule("gte", "x", 5)]
    assert len(evaluate_rules({"x": 5}, rules)) == 1
    assert len(evaluate_rules({"x": 4}, rules)) == 0


def test_operator_lt():
    rules = [_rule("lt", "x", 5)]
    assert len(evaluate_rules({"x": 3}, rules)) == 1
    assert len(evaluate_rules({"x": 5}, rules)) == 0


def test_operator_lte():
    rules = [_rule("lte", "x", 5)]
    assert len(evaluate_rules({"x": 5}, rules)) == 1
    assert len(evaluate_rules({"x": 6}, rules)) == 0


def test_operator_in():
    rules = [_rule("in", "x", [1, 2, 3])]
    assert len(evaluate_rules({"x": 2}, rules)) == 1
    assert len(evaluate_rules({"x": 99}, rules)) == 0


def test_operator_not_in():
    rules = [_rule("not_in", "x", [1, 2, 3])]
    assert len(evaluate_rules({"x": 99}, rules)) == 1
    assert len(evaluate_rules({"x": 2}, rules)) == 0


def test_operator_not_regex_match():
    rules = [_rule("not_regex_match", "x", r"^valid$")]
    assert len(evaluate_rules({"x": "invalid"}, rules)) == 1
    assert len(evaluate_rules({"x": "valid"}, rules)) == 0


def test_operator_not_regex_match_none_field():
    rules = [_rule("not_regex_match", "x", r"^valid$")]
    assert len(evaluate_rules({}, rules)) == 0


def test_empty_conditions_always_false():
    rule_and = {
        "id": "empty_and",
        "type": "alert",
        "logic": "and",
        "conditions": [],
    }
    rule_or = {
        "id": "empty_or",
        "type": "alert",
        "logic": "or",
        "conditions": [],
    }
    assert evaluate_rules({"x": 1}, [rule_and]) == []
    assert evaluate_rules({"x": 1}, [rule_or]) == []


# ------------------------------------------------------------------ #
# Helper
# ------------------------------------------------------------------ #


def _rule(operator: str, field: str = "x", value=None):
    return {
        "id": f"test_{operator}",
        "type": "alert",
        "logic": "and",
        "conditions": [{"field": field, "operator": operator, "value": value}],
    }


# ------------------------------------------------------------------ #
# Regex DoS protection
# ------------------------------------------------------------------ #


def test_nested_quantifier_rejected():
    """Regex with nested quantifiers should not match (graceful failure)."""
    rules = [_rule("regex_match", "x", r"(a+)+b")]
    result = evaluate_rules({"x": "aaaaaab"}, rules)
    assert result == []


def test_overly_long_regex_rejected():
    """Regex exceeding max length should not match (graceful failure)."""
    rules = [_rule("regex_match", "x", "a" * 2000)]
    result = evaluate_rules({"x": "a"}, rules)
    assert result == []


def test_valid_regex_still_works():
    """Normal regex patterns must still function correctly."""
    rules = [_rule("regex_match", "x", r"^root$")]
    assert len(evaluate_rules({"x": "root"}, rules)) == 1
    assert len(evaluate_rules({"x": "nonroot"}, rules)) == 0


def test_invalid_regex_syntax_handled():
    """Malformed regex (bad syntax) should not crash."""
    rules = [_rule("regex_match", "x", r"[invalid")]
    result = evaluate_rules({"x": "test"}, rules)
    assert result == []

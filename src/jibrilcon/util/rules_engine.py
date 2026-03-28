# Copyright (c) 2025 IanYHChu
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for full license information.

"""
rules_engine.py

Evaluate rule sets defined in JSON files against a data dictionary.

Rule structure
--------------
{
  "id": "root_user",
  "type": "alert" | "warning" | "info",
  "description": "Service runs as root",
  "logic": "and" | "or",
  "conditions": [
    {"field": "User", "operator": "equals", "value": "root"}
  ]
}

Each condition uses a simple operator over *field* extracted from the
data dict provided by scanner modules.
"""

from __future__ import annotations

import copy
import logging
import re
import threading
from functools import lru_cache, wraps
from typing import Any, Callable, Dict, List

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------
# Operator helpers
# ---------------------------------------------------------------------


def _equals(a: Any, b: Any) -> bool:
    return a == b


def _not_equals(a: Any, b: Any) -> bool:
    return a != b


def _contains(a: Any, b: Any) -> bool:
    return b in a if isinstance(a, (list, str)) else False


def _not_contains(a: Any, b: Any) -> bool:
    return not _contains(a, b)


def _exists(a: Any, _b: Any) -> bool:
    return a is not None


def _not_exists(a: Any, _b: Any) -> bool:
    return a is None


def _regex_match(a: Any, pattern: str) -> bool:
    if a is None:
        return False
    return bool(_compile_regex(pattern).search(str(a)))


def _not_regex_match(a: Any, pattern: str) -> bool:
    if a is None:
        return False
    return not bool(_compile_regex(pattern).search(str(a)))


def _gt(a: Any, b: Any) -> bool:
    return a > b


def _gte(a: Any, b: Any) -> bool:
    return a >= b


def _lt(a: Any, b: Any) -> bool:
    return a < b


def _lte(a: Any, b: Any) -> bool:
    return a <= b


def _in_op(a: Any, b: List[Any]) -> bool:
    return a in b


def _not_in_op(a: Any, b: List[Any]) -> bool:
    return a not in b


# Map operator string to implementation
_OPERATOR_MAP: Dict[str, Callable[[Any, Any], bool]] = {
    "equals": _equals,
    "not_equals": _not_equals,
    "contains": _contains,
    "not_contains": _not_contains,
    "exists": _exists,
    "not_exists": _not_exists,
    "regex_match": _regex_match,
    "not_regex_match": _not_regex_match,
    "gt": _gt,
    "gte": _gte,
    "lt": _lt,
    "lte": _lte,
    "in": _in_op,
    "not_in": _not_in_op,
}

# ---------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------


_MAX_REGEX_LEN = 1024
_NESTED_QUANTIFIER_RE = re.compile(
    r"(\([^)]*[+*][^)]*\))[+*]"
    r"|"
    r"([+*]\??\))[+*]"
)


def _validate_regex(pattern: str) -> None:
    """Raise ValueError if *pattern* looks dangerous or too long."""
    if len(pattern) > _MAX_REGEX_LEN:
        raise ValueError(f"Regex pattern exceeds {_MAX_REGEX_LEN} characters")
    if _NESTED_QUANTIFIER_RE.search(pattern):
        raise ValueError(
            f"Regex pattern contains nested quantifiers (potential ReDoS): {pattern!r}"
        )


def _threadsafe_lru_cache(maxsize: int = 128):
    """
    Decorator combining @lru_cache with a threading.Lock.

    Python's @lru_cache is not fully thread-safe on cache misses before
    Python 3.12.  Since all scanners call evaluate_rules from parallel
    threads, we guard cache access with a lock.

    The wrapper exposes cache_info() and cache_clear() for compatibility
    with existing test fixtures.
    """

    def decorator(fn):
        cached = lru_cache(maxsize=maxsize)(fn)
        lock = threading.Lock()

        @wraps(fn)
        def wrapper(*args, **kwargs):
            with lock:
                return cached(*args, **kwargs)

        wrapper.cache_clear = cached.cache_clear
        wrapper.cache_info = cached.cache_info
        return wrapper

    return decorator


@_threadsafe_lru_cache(maxsize=256)
def _compile_regex(pattern: str) -> re.Pattern:
    """
    Validate and compile *pattern*, caching the result.

    Thread-safe: all scanners invoke evaluate_rules -> _regex_match ->
    _compile_regex concurrently from the ThreadPoolExecutor.
    """
    _validate_regex(pattern)
    return re.compile(pattern)


def _match_condition(data: Dict[str, Any], cond: Dict[str, Any]) -> bool:
    """Return True if *cond* matches *data*, else False."""
    field = cond.get("field")
    operator = str(cond.get("operator", "")).lower()
    expected = cond.get("value")
    actual = data.get(field)

    func = _OPERATOR_MAP.get(operator)
    if func is None:
        logger.warning("Unsupported operator '%s' in rule condition", operator)
        return False

    try:
        return func(actual, expected)
    except (TypeError, AttributeError, ValueError, KeyError, re.error) as exc:
        logger.error("Condition evaluation error: %s", exc, exc_info=True)
        return False


_VALID_LOGIC = {"and", "or"}


def _evaluate_rule_group(data: Dict[str, Any], rule: Dict[str, Any]) -> bool:
    """Evaluate all conditions in *rule* according to its logic."""
    logic = str(rule.get("logic", "and")).lower()
    if logic not in _VALID_LOGIC:
        logger.warning(
            "Unknown logic '%s' in rule '%s', defaulting to 'and'",
            rule.get("logic"),
            rule.get("id", "<unknown>"),
        )
        logic = "and"
    conditions = rule.get("conditions", [])
    if not conditions:
        return False
    results = [_match_condition(data, c) for c in conditions]

    if logic == "or":
        return any(results)
    return all(results)


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------


def evaluate_rules(
    data: Dict[str, Any], rules: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Evaluate *rules* against *data*.

    Parameters
    ----------
    data : dict
        Key–value pairs produced by a scanner (e.g., parsed container config).
    rules : list[dict]
        Rule set loaded from JSON.

    Returns
    -------
    list[dict]
        All rules that matched; each element is the original rule dict.
        An empty list means the input passed without violations.
    """
    output: List[Dict[str, Any]] = []
    for rule in rules:
        if _evaluate_rule_group(data, rule):
            output.append(copy.deepcopy(rule))
    return output

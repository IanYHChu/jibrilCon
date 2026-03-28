"""Tests for util/io_helpers.py."""

import json

from jibrilcon.util.io_helpers import deep_merge, load_json_or_empty


# ------------------------------------------------------------------ #
# deep_merge
# ------------------------------------------------------------------ #

def test_deep_merge_non_overlapping():
    dst = {"a": 1}
    src = {"b": 2}
    result = deep_merge(dst, src)
    assert result == {"a": 1, "b": 2}
    assert result is dst  # mutates in place


def test_deep_merge_nested_override():
    dst = {"host": {"Privileged": False, "Binds": []}}
    src = {"host": {"Privileged": True}}
    deep_merge(dst, src)
    assert dst["host"]["Privileged"] is True
    assert dst["host"]["Binds"] == []  # untouched


def test_deep_merge_scalar_replaces_dict():
    dst = {"a": {"nested": True}}
    src = {"a": "flat"}
    deep_merge(dst, src)
    assert dst["a"] == "flat"


def test_deep_merge_dict_replaces_scalar():
    dst = {"a": "flat"}
    src = {"a": {"nested": True}}
    deep_merge(dst, src)
    assert dst["a"] == {"nested": True}


def test_deep_merge_empty_src():
    dst = {"a": 1}
    deep_merge(dst, {})
    assert dst == {"a": 1}


def test_deep_merge_empty_dst():
    dst = {}
    deep_merge(dst, {"a": 1})
    assert dst == {"a": 1}


# ------------------------------------------------------------------ #
# load_json_or_empty
# ------------------------------------------------------------------ #

def test_load_json_or_empty_valid(tmp_path):
    f = tmp_path / "data.json"
    f.write_text(json.dumps({"key": "value"}))
    assert load_json_or_empty(str(f)) == {"key": "value"}


def test_load_json_or_empty_missing():
    assert load_json_or_empty("/nonexistent/file.json") == {}


def test_load_json_or_empty_invalid_json(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("{bad json")
    assert load_json_or_empty(str(f)) == {}

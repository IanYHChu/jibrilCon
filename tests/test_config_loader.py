"""Tests for util/config_loader.py."""

import json

import pytest

from jibrilcon.util.config_loader import (
    ConfigLoadError,
    clear_cache,
    load_json_config,
    load_rules,
)


@pytest.fixture(autouse=True)
def _fresh_cache(fresh_cache):
    """Delegate to the shared fresh_cache fixture in conftest."""
    yield


def test_load_json_config_basic(tmp_path):
    f = tmp_path / "cfg.json"
    f.write_text(json.dumps({"rules": [1, 2, 3]}))
    data = load_json_config(f)
    assert data == {"rules": [1, 2, 3]}


def test_load_json_config_caching(tmp_path):
    f = tmp_path / "cfg.json"
    f.write_text(json.dumps({"a": 1}))
    a = load_json_config(f)
    b = load_json_config(f)
    assert a is b  # same object from cache


def test_load_json_config_missing_file():
    with pytest.raises(ConfigLoadError, match="Cannot read config file"):
        load_json_config("/nonexistent/path.json")


def test_load_json_config_invalid_json(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("{invalid json")
    with pytest.raises(ConfigLoadError, match="Invalid JSON"):
        load_json_config(f)


def test_load_json_config_schema_ok(tmp_path):
    f = tmp_path / "cfg.json"
    f.write_text(json.dumps({"rules": [], "meta": {}}))
    data = load_json_config(f, schema=frozenset({"rules", "meta"}))
    assert "rules" in data


def test_load_json_config_schema_missing_key(tmp_path):
    f = tmp_path / "cfg.json"
    f.write_text(json.dumps({"rules": []}))
    with pytest.raises(ConfigLoadError, match="Missing top-level keys"):
        load_json_config(f, schema=frozenset({"rules", "meta"}))


def test_clear_cache_forces_reload(tmp_path):
    f = tmp_path / "cfg.json"
    f.write_text(json.dumps({"v": 1}))
    a = load_json_config(f)

    clear_cache()
    f.write_text(json.dumps({"v": 2}))
    b = load_json_config(f)

    assert a["v"] == 1
    assert b["v"] == 2


def test_load_rules_convenience(tmp_path):
    f = tmp_path / "rules.json"
    f.write_text(json.dumps({"rules": [{"id": "r1"}]}))
    assert load_rules(f) == [{"id": "r1"}]


def test_load_rules_missing_key(tmp_path):
    f = tmp_path / "empty.json"
    f.write_text(json.dumps({"other": 1}))
    assert load_rules(f) == []

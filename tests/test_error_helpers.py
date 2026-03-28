"""Tests for util/error_helpers.py."""

import json
from pathlib import Path

import pytest

from jibrilcon.util.error_helpers import SoftIOError, load_json_safe


def test_load_json_safe_valid(tmp_path):
    f = tmp_path / "ok.json"
    f.write_text(json.dumps({"key": "val"}))
    result = load_json_safe(f)
    assert result == {"key": "val"}


def test_load_json_safe_missing_file(tmp_path):
    with pytest.raises(SoftIOError):
        load_json_safe(tmp_path / "nope.json")


def test_load_json_safe_invalid_json(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("{not valid json")
    with pytest.raises(SoftIOError):
        load_json_safe(f)


def test_load_json_safe_permission_error(tmp_path):
    f = tmp_path / "noperm.json"
    f.write_text('{"a":1}')
    f.chmod(0o000)
    try:
        with pytest.raises(SoftIOError):
            load_json_safe(f)
    finally:
        f.chmod(0o644)


def test_load_json_safe_unicode_error(tmp_path):
    """Regression: non-UTF-8 files must raise SoftIOError, not UnicodeDecodeError."""
    f = tmp_path / "binary.json"
    f.write_bytes(b"\x80\x81\x82\xff invalid bytes")
    with pytest.raises(SoftIOError):
        load_json_safe(f)

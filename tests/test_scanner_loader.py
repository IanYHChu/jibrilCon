"""Tests for util/scanner_loader.py."""

from concurrent.futures import ThreadPoolExecutor
from types import ModuleType
from unittest.mock import patch

import pytest

from jibrilcon.util.context import ScanContext
from jibrilcon.util.scanner_loader import run_scanners


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _make_scanner_module(name: str, scan_fn) -> ModuleType:
    """Build a minimal ModuleType with a scan() callable."""
    mod = ModuleType(name)
    mod.scan = scan_fn
    return mod


# ------------------------------------------------------------------ #
# Tests
# ------------------------------------------------------------------ #


def test_run_scanners_returns_list(fixtures_dir):
    """run_scanners with a real fixture rootfs returns a list of dicts."""
    rootfs = fixtures_dir / "rootfs_docker_rootful_01"
    if not rootfs.is_dir():
        pytest.skip("rootfs_docker_rootful_01 fixture not available")

    ctx = ScanContext()
    results = run_scanners(str(rootfs), context=ctx)

    assert isinstance(results, list)
    for item in results:
        assert isinstance(item, dict)


@patch("jibrilcon.util.scanner_loader._iter_scanner_modules")
def test_run_scanners_empty_when_no_scanners(mock_iter):
    """When no scanner modules are found, run_scanners returns an empty list."""
    mock_iter.return_value = []

    results = run_scanners("/nonexistent", context=ScanContext())

    assert results == []


@patch("jibrilcon.util.scanner_loader._iter_scanner_modules")
def test_scanner_exception_isolated(mock_iter):
    """If one scanner raises, the other still contributes its result."""

    def good_scan(mount_path, *, context=None):
        return {"scanner": "good", "findings": []}

    def bad_scan(mount_path, *, context=None):
        raise RuntimeError("deliberate failure")

    mock_iter.return_value = [
        _make_scanner_module("jibrilcon.scanners.good", good_scan),
        _make_scanner_module("jibrilcon.scanners.bad", bad_scan),
    ]

    results = run_scanners("/fake/rootfs", context=ScanContext())

    assert len(results) == 1
    assert results[0]["scanner"] == "good"


@patch("jibrilcon.util.scanner_loader._iter_scanner_modules")
def test_scanner_non_dict_result_filtered(mock_iter, caplog):
    """Scanners that return non-dict values are filtered out with a warning."""

    def string_scan(mount_path, *, context=None):
        return "not a dict"

    def none_scan(mount_path, *, context=None):
        return None

    def dict_scan(mount_path, *, context=None):
        return {"scanner": "valid", "findings": []}

    mock_iter.return_value = [
        _make_scanner_module("jibrilcon.scanners.str_scanner", string_scan),
        _make_scanner_module("jibrilcon.scanners.none_scanner", none_scan),
        _make_scanner_module("jibrilcon.scanners.dict_scanner", dict_scan),
    ]

    results = run_scanners("/fake/rootfs", context=ScanContext())

    assert len(results) == 1
    assert results[0]["scanner"] == "valid"

    non_dict_warnings = [r for r in caplog.records if "non-dict result" in r.message]
    assert len(non_dict_warnings) == 2


@patch("jibrilcon.util.scanner_loader.ThreadPoolExecutor", wraps=ThreadPoolExecutor)
@patch("jibrilcon.util.scanner_loader._iter_scanner_modules")
def test_max_workers_parameter(mock_iter, mock_executor_cls):
    """Custom max_workers value is forwarded to ThreadPoolExecutor."""

    def scan_fn(mount_path, *, context=None):
        return {"scanner": "stub"}

    mock_iter.return_value = [
        _make_scanner_module("jibrilcon.scanners.stub", scan_fn),
    ]

    run_scanners("/fake/rootfs", context=ScanContext(), max_workers=3)

    # With 1 scanner and max_workers=3, min(3, 1) = 1
    mock_executor_cls.assert_called_once_with(max_workers=1)

    mock_executor_cls.reset_mock()

    # Add more scanners so min(3, N) = 3
    mock_iter.return_value = [
        _make_scanner_module(f"jibrilcon.scanners.s{i}", scan_fn) for i in range(5)
    ]

    run_scanners("/fake/rootfs", context=ScanContext(), max_workers=3)

    mock_executor_cls.assert_called_once_with(max_workers=3)

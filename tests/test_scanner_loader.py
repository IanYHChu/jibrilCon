"""Tests for util/scanner_loader.py."""

import threading
from concurrent.futures import ThreadPoolExecutor
from types import ModuleType
from unittest.mock import patch

import pytest

from jibrilcon.util.context import ScanContext
from jibrilcon.util.scanner_loader import _iter_scanner_modules, run_scanners

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


@patch("jibrilcon.util.scanner_loader._iter_scanner_modules")
def test_scanner_type_error_logged_as_bug(mock_iter, caplog):
    """TypeError from a scanner is logged as a likely bug, not silently swallowed."""

    def good_scan(mount_path, *, context=None):
        return {"scanner": "good", "findings": []}

    def buggy_scan(mount_path, *, context=None):
        raise TypeError("unsupported operand type(s)")

    mock_iter.return_value = [
        _make_scanner_module("jibrilcon.scanners.good", good_scan),
        _make_scanner_module("jibrilcon.scanners.buggy", buggy_scan),
    ]

    results = run_scanners("/fake/rootfs", context=ScanContext())

    # Good scanner still produces its result
    assert len(results) == 1
    assert results[0]["scanner"] == "good"

    # TypeError is logged with the bug indicator
    bug_records = [r for r in caplog.records if "likely a bug" in r.message]
    assert len(bug_records) == 1
    assert "TypeError" in bug_records[0].message
    assert bug_records[0].levelname == "ERROR"


@patch("jibrilcon.util.scanner_loader._iter_scanner_modules")
def test_scanner_value_error_logged_as_bug(mock_iter, caplog):
    """ValueError from a scanner is logged as a likely bug, not silently swallowed."""

    def good_scan(mount_path, *, context=None):
        return {"scanner": "good", "findings": []}

    def buggy_scan(mount_path, *, context=None):
        raise ValueError("invalid literal for int()")

    mock_iter.return_value = [
        _make_scanner_module("jibrilcon.scanners.good", good_scan),
        _make_scanner_module("jibrilcon.scanners.buggy", buggy_scan),
    ]

    results = run_scanners("/fake/rootfs", context=ScanContext())

    assert len(results) == 1
    assert results[0]["scanner"] == "good"

    bug_records = [r for r in caplog.records if "likely a bug" in r.message]
    assert len(bug_records) == 1
    assert "ValueError" in bug_records[0].message
    assert bug_records[0].levelname == "ERROR"


@patch("jibrilcon.util.scanner_loader._iter_scanner_modules")
def test_scanner_runtime_error_logged_as_recoverable(mock_iter, caplog):
    """RuntimeError is logged at ERROR level without the 'bug' indicator."""

    def failing_scan(mount_path, *, context=None):
        raise RuntimeError("some runtime issue")

    mock_iter.return_value = [
        _make_scanner_module("jibrilcon.scanners.failing", failing_scan),
    ]

    results = run_scanners("/fake/rootfs", context=ScanContext())

    assert results == []

    error_records = [r for r in caplog.records if "some runtime issue" in r.message]
    assert len(error_records) == 1
    # Recoverable errors should NOT have the bug indicator
    assert "likely a bug" not in error_records[0].message


@patch("jibrilcon.util.scanner_loader.importlib.import_module")
def test_package_import_failure_does_not_crash(mock_import, caplog):
    """If the scanner package itself fails to import, return empty list gracefully."""
    mock_import.side_effect = ImportError("No module named 'jibrilcon.scanners'")

    results = run_scanners("/fake/rootfs", context=ScanContext())

    assert results == []

    import_errors = [
        r for r in caplog.records if "Failed to import scanner package" in r.message
    ]
    assert len(import_errors) == 1


def test_individual_module_import_failure_does_not_crash(caplog):
    """If one scanner module fails to import, the others still load."""
    from collections import namedtuple

    pkg_module = _make_scanner_module("jibrilcon.scanners", lambda *a, **kw: None)
    pkg_module.__file__ = "/fake/path/scanners/__init__.py"

    working_module = _make_scanner_module(
        "jibrilcon.scanners.working",
        lambda mount_path, *, context=None: {"scanner": "working", "findings": []},
    )

    def import_side_effect(name):
        if name == "jibrilcon.scanners":
            return pkg_module
        if name == "jibrilcon.scanners.broken":
            raise SyntaxError("invalid syntax in broken scanner")
        if name == "jibrilcon.scanners.working":
            return working_module
        raise ImportError(f"Unknown module {name}")

    ModInfo = namedtuple("ModInfo", ["module_finder", "name", "ispkg"])
    fake_modules = [
        ModInfo(None, "broken", False),
        ModInfo(None, "working", False),
    ]

    # Apply iter_modules patch first, then import_module, so that the
    # patch() machinery itself does not route through our mock.
    with (
        patch(
            "jibrilcon.util.scanner_loader.pkgutil.iter_modules",
            return_value=fake_modules,
        ),
        patch(
            "jibrilcon.util.scanner_loader.importlib.import_module",
            side_effect=import_side_effect,
        ),
    ):
        modules = _iter_scanner_modules()

    # Only the working module should be returned
    assert len(modules) == 1
    assert modules[0].__name__ == "jibrilcon.scanners.working"

    import_errors = [
        r for r in caplog.records if "Failed to import scanner module" in r.message
    ]
    assert len(import_errors) == 1
    assert "broken" in import_errors[0].message


@patch("jibrilcon.util.scanner_loader._iter_scanner_modules")
def test_scanner_timeout_handled_gracefully(mock_iter, caplog):
    """A scanner exceeding the timeout is logged and other scanners still run."""

    # Use an Event so the slow scanner blocks without relying on wall-clock
    # timing.  The short scanner_timeout causes the executor deadline to
    # expire, and we set the event afterwards to unblock cleanup.
    release = threading.Event()

    def slow_scan(mount_path, *, context=None):
        release.wait(timeout=30)  # safety cap; normally released below
        return {"scanner": "slow", "findings": []}

    def fast_scan(mount_path, *, context=None):
        return {"scanner": "fast", "findings": []}

    mock_iter.return_value = [
        _make_scanner_module("jibrilcon.scanners.slow", slow_scan),
        _make_scanner_module("jibrilcon.scanners.fast", fast_scan),
    ]

    try:
        results = run_scanners(
            "/fake/rootfs", context=ScanContext(), scanner_timeout=0.5
        )

        # The fast scanner should still produce its result
        assert len(results) == 1
        assert results[0]["scanner"] == "fast"

        # The slow scanner should be logged as timed out
        timeout_records = [r for r in caplog.records if "timed out" in r.message]
        assert len(timeout_records) == 1
        assert "slow" in timeout_records[0].message
        assert timeout_records[0].levelname == "ERROR"
    finally:
        # Unblock the slow scanner thread so it can exit cleanly
        release.set()

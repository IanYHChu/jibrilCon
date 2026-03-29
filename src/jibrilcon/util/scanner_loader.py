# Copyright (c) 2025 IanYHChu
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for full license information.

"""
scanner_loader.py
-----------------
Dynamic import and thread-parallel execution of every scanner module
inside the *jibrilcon.scanners* package.

Public helper
-------------
run_scanners(mount_path: str, context: ScanContext | None) -> list[dict]
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
import time as _time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path
from types import ModuleType
from typing import Any

from jibrilcon.util.context import ScanContext

# ---------------------------------------------------------------------
# Constants and logger
# ---------------------------------------------------------------------

logger = logging.getLogger(__name__)

_SCANNER_PKG = "jibrilcon.scanners"
_SCAN_FUNC = "scan"
# Default pool size when caller does not specify.
_MAX_WORKERS = 8
# Default per-scanner timeout in seconds (5 minutes).
_SCANNER_TIMEOUT: float = 300.0

# ---------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------


def _iter_scanner_modules() -> list[ModuleType]:
    """Import every *.py file under scanners/ and yield modules."""
    try:
        pkg = importlib.import_module(_SCANNER_PKG)
    except (ImportError, AttributeError, TypeError, ValueError, SyntaxError):
        logger.exception("Failed to import scanner package %s", _SCANNER_PKG)
        return []

    base_dir = Path(pkg.__file__).parent

    modules: list[ModuleType] = []
    for info in sorted(pkgutil.iter_modules([str(base_dir)]), key=lambda x: x.name):
        full_name = f"{_SCANNER_PKG}.{info.name}"
        try:
            modules.append(importlib.import_module(full_name))
        except (ImportError, AttributeError, TypeError, ValueError, SyntaxError):
            logger.exception("Failed to import scanner module %s", full_name)
    return modules


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------


def run_scanners(
    mount_path: str,
    *,
    context: ScanContext | None = None,
    max_workers: int = _MAX_WORKERS,
    scanner_timeout: float = _SCANNER_TIMEOUT,
) -> list[dict[str, Any]]:
    """
    Locate every scanner's scan() and execute them in a ThreadPool.

    Parameters
    ----------
    mount_path : str
        Mounted Linux rootfs path.
    context : ScanContext | None
        Shared object for cross-scanner coordination.
    max_workers : int
        Maximum number of concurrent scanner threads.
    scanner_timeout : float
        Per-scanner timeout in seconds.  When a scanner exceeds this
        limit a :class:`concurrent.futures.TimeoutError` is caught,
        an error is logged, and processing continues with remaining
        scanners.

    Returns
    -------
    list[dict]
        Result blocks produced by individual scanners.
    """
    scanners = []
    for mod in _iter_scanner_modules():
        fn = getattr(mod, _SCAN_FUNC, None)
        if callable(fn):
            scanners.append((mod.__name__, fn))

    if not scanners:
        logger.warning("No scanners found under %s", _SCANNER_PKG)
        return []

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(scanners))) as exe:
        future_map = {
            exe.submit(fn, mount_path, context=context): name for name, fn in scanners
        }
        deadline = _time.monotonic() + scanner_timeout
        pending = set(future_map)

        while pending:
            remaining = max(0.0, deadline - _time.monotonic())
            done, pending = wait(
                pending, timeout=remaining, return_when=FIRST_COMPLETED
            )

            # If wait() returned with no completed futures, every
            # remaining future has exceeded the deadline.
            if not done:
                for fut in pending:
                    name = future_map[fut]
                    logger.error(
                        "Scanner %s timed out after %.0f seconds",
                        name,
                        scanner_timeout,
                    )
                    fut.cancel()
                break

            for fut in done:
                name = future_map[fut]
                try:
                    res = fut.result(timeout=0)
                    if isinstance(res, dict):
                        results.append(res)
                    else:
                        logger.warning("Scanner %s returned non-dict result", name)
                except (RuntimeError, OSError) as exc:
                    logger.error("Scanner %s raised: %s", name, exc)
                except (TypeError, ValueError) as exc:
                    logger.exception(
                        "Scanner %s raised %s -- this is likely a bug in the scanner",
                        name,
                        type(exc).__name__,
                    )
                except Exception as exc:
                    logger.exception(
                        "Scanner %s raised unexpected %s",
                        name,
                        type(exc).__name__,
                    )

    return results

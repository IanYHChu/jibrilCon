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
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, List

from util.context import ScanContext

# ---------------------------------------------------------------------
# Constants and logger
# ---------------------------------------------------------------------

logger = logging.getLogger(__name__)

_SCANNER_PKG = "scanners"
_SCAN_FUNC = "scan"
# Default pool size when caller does not specify.
_MAX_WORKERS = 8

# ---------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------

def _iter_scanner_modules() -> List[ModuleType]:
    """Import every *.py file under scanners/ and yield modules."""
    pkg = importlib.import_module(_SCANNER_PKG)
    base_dir = Path(pkg.__file__).parent

    modules: List[ModuleType] = []
    for info in sorted(pkgutil.iter_modules([str(base_dir)]), key=lambda x: x.name):
        full_name = f"{_SCANNER_PKG}.{info.name}"
        modules.append(importlib.import_module(full_name))
    return modules

# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

def run_scanners(
    mount_path: str,
    *,
    context: ScanContext | None = None,
    max_workers: int = _MAX_WORKERS,
) -> List[Dict[str, Any]]:
    """
    Locate every scanner's scan() and execute them in a ThreadPool.

    Parameters
    ----------
    mount_path : str
        Mounted Linux rootfs path.
    context : ScanContext | None
        Shared object for cross-scanner coordination.

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

    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(scanners))) as exe:
        future_map = {
            exe.submit(fn, mount_path, context=context): name for name, fn in scanners
        }
        for fut in as_completed(future_map):
            name = future_map[fut]
            try:
                res = fut.result()
                if isinstance(res, dict):
                    results.append(res)
                else:
                    logger.warning("Scanner %s returned non-dict result", name)
            except Exception as exc:  # pragma: no cover
                logger.error("Scanner %s raised: %s", name, exc)

    return results

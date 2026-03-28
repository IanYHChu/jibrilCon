# Copyright (c) 2025 IanYHChu
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for full license information.

"""
core.py
=======
Central coordinator for **jibrilcon**.

High-level flow
---------------
1. Detect which init system (systemd / sysvinit / openrc / unknown) is
   present inside the mounted rootfs.
2. Prime :class:`util.context.ScanContext` with any systemd container
   metadata (so scanners can reuse it cheaply).
3. Dynamically import every scanner module under ``scanners/`` and run
   them in a thread pool.
4. Merge individual scanner results into a single report dict via
   :pyfunc:`util.summary_utils.generate_final_report`.

**Note**: This module contains **no** argument parsing; see
``jibrilcon.cli`` for user-facing CLI glue.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional

from util.context import ScanContext
from jibrilcon.init_manager_finder import detect_init_system

from util.systemd_unit_parser import collect_systemd_containers
from util.scanner_loader import run_scanners
from util.summary_utils import generate_final_report

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------- #
# Public API                                                                   #
# ---------------------------------------------------------------------------- #
def run_scan(
    mount_path: str | Path,
    *,
    filters_path: Optional[Path] = None,
    max_workers: int = 8,
) -> Dict[str, object]:
    """
    Execute all scanners against *mount_path* and return the final report.

    Parameters
    ----------
    mount_path
        Path to a rootfs directory.
    filters_path
        Optional override for ``config/systemd.json``.
    max_workers
        ThreadPool size (I/O-bound scanners benefit from modest parallelism).
    """
    mount_path = Path(mount_path)
    context = ScanContext()

    # 1. Init-system detection & pre-collection
    init_sys = detect_init_system(mount_path)
    logger.info("Detected init system: %s", init_sys or "<unknown>")

    if init_sys == "systemd":
        collect_systemd_containers(
            mount_path, ctx=context, filters_path=filters_path
        )

    context.init_system = init_sys

    # 2. Run scanners (thread-parallel) via util.scanner_loader
    results: List[Dict[str, object]] = run_scanners(str(mount_path), context=context, max_workers=max_workers)

    # 3. Build final report (filtering to blocks that contain the "scanner" key)
    clean_results = [r for r in results if isinstance(r, dict) and r.get("scanner")]
    return generate_final_report(clean_results)

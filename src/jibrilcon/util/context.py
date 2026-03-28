# Copyright (c) 2025 IanYHChu
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for full license information.

"""
context.py

ScanContext – an in-memory coordination object shared by scanner modules.

Primary responsibilities
------------------------
1. Record which containers were launched via systemd (per engine).
2. Record which of those services lacked a non-root `User=` directive.
3. Offer read APIs so other scanners can adjust their risk evaluation.

The class is deliberately lightweight; only in-memory state is kept for
the lifetime of a single jibrilcon run.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Dict, Set, List, Tuple

# ---------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------

class ScanContext:
    """
    Shared scanning context across all scanner modules.

    All write operations are protected by a lock to stay safe if scanners
    are executed in parallel in the future (e.g., ThreadPool).
    """

    # class-wide lock so every instance (normally one) shares the same guard
    _lock = threading.RLock()

    def __init__(self) -> None:
        # engine name (e.g. "docker", "lxc") -> set of container names
        self._systemd_started: Dict[str, Set[str]] = defaultdict(set)
        # containers whose systemd service lacks a non-root User= setting
        self._user_missing: Set[str] = set()
        # key: (engine, container) -> list of Exec* command lines
        self._exec_lines: Dict[Tuple[str, str], List[str]] = defaultdict(list)

    # -----------------------------------------------------------------
    # Mutators
    # -----------------------------------------------------------------

    def mark_systemd_started(self, engine: str, container_name: str) -> None:
        """
        Record that *container_name* (under *engine*) was launched by
        systemd.

        Example
        -------
        >>> ctx.mark_systemd_started("docker", "web01")
        """
        with self._lock:
            self._systemd_started[engine].add(container_name)

    def mark_user_missing(self, container_name: str) -> None:
        """
        Record that the systemd unit controlling *container_name*
        had no non-root User= directive (hence runs as UID 0).
        """
        with self._lock:
            self._user_missing.add(container_name)
    
    def add_exec_lines(
        self, engine: str, container_name: str, lines: List[str]
    ) -> None:
        """
        Cache full ExecStart / ExecStartPre command lines for *container_name*
        so other scanners can reuse them without re-reading .service files.
        """
        with self._lock:
            self._exec_lines[(engine, container_name)] = list(lines)  # store copy

    def get_exec_lines(self, engine: str, container_name: str) -> List[str]:
        """
        Return cached Exec* command lines for the given container, or [] if absent.
        """
        with self._lock:
            return self._exec_lines.get((engine, container_name), [])

    # -----------------------------------------------------------------
    # Accessors
    # -----------------------------------------------------------------

    def is_systemd_started(self, engine: str, container_name: str) -> bool:
        """
        Return True if *container_name* was detected in a systemd unit
        for the specified *engine*.
        """
        with self._lock:
            return container_name in self._systemd_started.get(engine, set())

    def is_user_missing(self, container_name: str) -> bool:
        """
        Return True if the container's systemd service lacked a non-root
        User= directive (implying it runs as root).
        """
        with self._lock:
            return container_name in self._user_missing

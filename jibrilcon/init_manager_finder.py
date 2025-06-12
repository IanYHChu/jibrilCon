"""
init_manager_finder.py
======================
Lightweight heuristics to:

* Pinpoint the init system inside a *static* rootfs image by peeking at
  the ``/sbin/init`` binary – falls back to directory hints if needed.
* If systemd is detected, parse all ``*.service`` units to pre-collect
  container-related information (container name, engine, ExecStart, …)
  and stash it in :class:`util.context.ScanContext`.

Public helpers
--------------
``detect_init_system(rootfs)``  
    → ``"systemd" | "sysvinit" | "openrc" | ""``

``collect_systemd_containers(rootfs, ctx)``  
    → ``None`` (context is mutated in-place)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------

def _bytes_contains(path: Path, marker: bytes, limit: int = 4096) -> bool:
    try:
        with path.open("rb") as fh:
            data = fh.read(limit)
        return marker in data
    except OSError:
        return False


def _elf_contains(path: Path, marker: bytes) -> bool:
    """
    Extremely lightweight ELF string scan: looks for *marker* beyond ELF header.
    Suitable for tiny heuristics only – NOT a full parser.
    """
    try:
        with path.open("rb") as fh:
            hdr = fh.read(16)
            if hdr[:4] != b"\x7fELF":
                return False
            # EI_CLASS @ byte 4 → 1 = 32-bit, 2 = 64-bit
            is_64 = hdr[4] == 2
            # Skip to section header string table offset to bound our search
            fh.seek(0)
            data = fh.read(65536 if is_64 else 32768)
        return marker in data
    except OSError:
        return False


def _is_systemd_binary(path: Path) -> bool:
    return (
        _bytes_contains(path, b"systemd") or
        _elf_contains(path, b"systemd")
    )


def _is_sysv_binary(path: Path) -> bool:
    # classical sysvinit often contains "sysvinit" / "telinit"
    return (
        _bytes_contains(path, b"sysvinit") or
        _elf_contains(path, b"sysvinit")
    )

_CANDIDATE_BINARIES = (
    Path("sbin/init"),
    Path("bin/init"),
    Path("usr/lib/systemd/systemd"),
)

# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

def detect_init_system(rootfs: Path | str) -> str:
    """
    Guess the init system by inspecting the init binary first, then directories.

    Returns one of: ``"systemd"``, ``"sysvinit"``, ``"openrc"``, or ``""``.
    """
    root = Path(rootfs)

    # 1. Inspect candidate binaries
    for rel in _CANDIDATE_BINARIES:
        p = root / rel
        if not p.is_file():
            continue
        if _is_systemd_binary(p):
            return "systemd"
        if _is_sysv_binary(p):
            return "sysvinit"

    # 2. Directory hints (fallback)
    if (root / "etc/systemd").is_dir():
        return "systemd"
    if (root / "etc/init.d").is_dir():
        return "sysvinit"
    if (root / "etc/runlevels").is_dir():
        return "openrc"
    return ""

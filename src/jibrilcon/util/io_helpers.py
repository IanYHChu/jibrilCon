# Copyright (c) 2025 IanYHChu
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for full license information.

"""
io_helpers.py

Small I/O and data-structure utilities shared by scanner modules.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from jibrilcon.util.error_helpers import load_json_safe, SoftIOError


_MAX_MERGE_DEPTH = 32


def deep_merge(
    dst: Dict[str, Any], src: Dict[str, Any], *, _depth: int = 0
) -> Dict[str, Any]:
    """Recursively merge *src* into *dst*; *src* values take precedence."""
    if _depth > _MAX_MERGE_DEPTH:
        raise RecursionError("deep_merge exceeded maximum depth")
    for key, val in src.items():
        if (
            key in dst
            and isinstance(dst[key], dict)
            and isinstance(val, dict)
        ):
            deep_merge(dst[key], val, _depth=_depth + 1)
        else:
            dst[key] = val
    return dst


def load_json_or_empty(path: str | Path) -> Dict[str, Any]:
    """Read *path* as JSON; return {} on expected I/O or parse errors."""
    try:
        return load_json_safe(Path(path))
    except SoftIOError:
        return {}

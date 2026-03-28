# Copyright (c) 2025 IanYHChu
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for full license information.

"""
error_helpers.py

Lightweight helpers for controlled error handling.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class SoftIOError(RuntimeError):
    """Raised when we meet an expected IO condition but want to continue."""

    pass


def load_json_safe(path: Path) -> dict[str, Any]:
    """
    Read *path* as UTF-8 JSON.

    Only FileNotFoundError, PermissionError, and JSONDecodeError are
    converted to SoftIOError so that the caller can decide whether to
    continue.  Any other exception should propagate.
    """
    try:
        text = path.read_text(encoding="utf-8")
        return json.loads(text)
    except (
        FileNotFoundError,
        PermissionError,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as exc:
        logger.warning("Skipped %s: %s", path, exc)
        raise SoftIOError(str(path)) from exc

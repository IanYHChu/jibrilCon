# Copyright (c) 2025 IanYHChu
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for full license information.

"""
config_loader.py

Load and cache JSON config / rule files used by scanners.

Key points
----------
1. Thread-safe LRU cache guarded by a lock.
2. Optional top-level key schema validation.
3. Detailed error message containing the file path.
"""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, FrozenSet

# ---------------------------------------------------------------------
# Constants and logger
# ---------------------------------------------------------------------

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------

class ConfigLoadError(RuntimeError):
    """Raised when a config file is missing or contains invalid JSON."""

# ---------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------

def _read_json_file(path: Path) -> Dict[str, Any]:
    """Read *path* as UTF-8 JSON and return the parsed dict."""
    try:
        text = path.read_text(encoding="utf-8")
        return json.loads(text)
    except FileNotFoundError as exc:
        raise ConfigLoadError(f"Config file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigLoadError(f"Invalid JSON in config file: {path}") from exc

# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

@lru_cache(maxsize=128)
def load_json_config(
    path: str | Path,
    *,
    schema: FrozenSet[str] | None = None,
) -> Dict[str, Any]:
    """
    Read a UTF-8 JSON file and return its data as a dict.  The result is
    cached; pass the same *path* value to reuse the cached object.

    Parameters
    ----------
    path : str | Path
        File location on disk.
    schema : frozenset[str] | None
        Optional frozenset of required top-level keys (must be hashable
        for lru_cache).

    Raises
    ------
    ConfigLoadError
        If the file is absent, malformed, or lacks required keys.
    """
    path = Path(path)
    data = _read_json_file(path)

    if schema:
        missing = schema - data.keys()
        if missing:
            raise ConfigLoadError(
                f"Missing top-level keys {sorted(missing)} in config: {path}"
            )

    logger.debug("Loaded config file: %s", path)
    return data

def load_rules(path: str | Path) -> list[dict]:
    """Convenience wrapper that returns data['rules'] or an empty list."""
    return load_json_config(path).get("rules", [])

def clear_cache() -> None:
    """Flush the LRU cache (useful in unit tests)."""
    load_json_config.cache_clear()

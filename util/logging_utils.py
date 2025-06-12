# Copyright (c) 2025 IanYHChu
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for full license information.

"""
logging_utils.py
----------------
Single-point logger initialisation for jibrilcon.
"""

from __future__ import annotations

import logging
from typing import Final

_FORMAT: Final[str] = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
_DATEFMT: Final[str] = "%Y-%m-%d %H:%M:%S"


def init_logging(level: str = "INFO") -> None:  # noqa: D401  (imperative mood)
    """Initialise the *root* logger exactly once."""
    logging.basicConfig(
        level=level.upper(),
        format=_FORMAT,
        datefmt=_DATEFMT,
        # Client code adds handlers if it really needs something special.
    )
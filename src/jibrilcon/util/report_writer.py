# Copyright (c) 2025 IanYHChu
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for full license information.

"""
report_writer.py

Serialize the final jibrilcon scan report to disk (JSON or gzipped JSON).

Features
--------
1. Auto-create parent directories if missing.
2. Atomic write: data is written to a temp file in the same directory and
   then moved into place with os.replace(), avoiding partial files.
3. Optional gzip compression; enabled automatically if the output file
   name ends with ".gz".
"""

from __future__ import annotations

import gzip
import json
import os
import tempfile
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------


def _atomic_write(binary: bytes, target: Path) -> None:
    """
    Write *binary* to *target* in an atomic fashion:

    1. Create a temporary file in the same directory.
    2. fsync() the temp file.
    3. Rename it to the final path with os.replace().

    This guarantees either the full file is present or none at all.
    """
    target.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(prefix=".tmp.", dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as fp:
            fp.write(binary)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(tmp_path, target)
    finally:
        # If os.replace() raised, ensure the temp file does not linger
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------


def write_report(
    report: Any,
    output_path: str | Path,
    *,
    gzip_on_ext: bool = True,
) -> None:
    """
    Serialize *report* (JSON-serialisable) to *output_path*.

    Parameters
    ----------
    report : Any
        Data structure produced by jibrilcon core (dict).
    output_path : str | Path
        Destination file path.  Parent directories will be created.
    gzip_on_ext : bool, default True
        If True and *output_path* ends with ".gz", the JSON will be
        compressed with gzip.
    """
    path = Path(output_path)

    text = json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True)
    binary: bytes = text.encode("utf-8")

    if gzip_on_ext and path.suffix == ".gz":
        binary = gzip.compress(binary)

    _atomic_write(binary, path)

# Copyright (c) 2025 IanYHChu
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for full license information.

"""
passwd_utils.py

Parse /etc/passwd inside a mounted rootfs to discover user home directories.
Shared by Docker and Podman scanners for rootless runtime discovery.
"""

from __future__ import annotations

import logging
import os

from jibrilcon.util.path_utils import safe_join

logger = logging.getLogger(__name__)


def get_user_home_dirs(rootfs: str) -> list[str]:
    """Parse /etc/passwd under *rootfs* and return resolved home directory paths.

    Validates that each path stays within the rootfs boundary using safe_join,
    and returns absolute paths (already prefixed with *rootfs*).
    """
    homes: list[str] = []
    passwd = os.path.join(rootfs, "etc/passwd")
    if not os.path.exists(passwd):
        return homes

    try:
        fh = open(passwd, encoding="utf-8")  # noqa: SIM115
    except PermissionError:
        logger.warning("Cannot read %s: permission denied", passwd)
        return homes
    except UnicodeDecodeError:
        logger.warning("Cannot read %s: not valid UTF-8", passwd)
        return homes

    lineno = 0
    with fh:
        try:
            for lineno, line in enumerate(fh, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                parts = stripped.split(":")
                if len(parts) < 6:
                    logger.debug(
                        "Skipping malformed passwd line %d in %s: "
                        "expected >= 6 fields, got %d",
                        lineno,
                        passwd,
                        len(parts),
                    )
                    continue
                home = parts[5].strip()
                if home:
                    try:
                        safe_home = safe_join(rootfs, home.lstrip("/"))
                        homes.append(str(safe_home))
                    except ValueError:
                        logger.warning(
                            "Skipping passwd home directory that escapes rootfs: %s",
                            home,
                        )
        except UnicodeDecodeError:
            logger.warning(
                "Stopped reading %s at line %d: encoding error",
                passwd,
                lineno,
            )

    return homes

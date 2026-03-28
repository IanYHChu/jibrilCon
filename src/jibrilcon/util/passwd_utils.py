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
from typing import List

from jibrilcon.util.path_utils import safe_join

logger = logging.getLogger(__name__)


def get_user_home_dirs(rootfs: str) -> List[str]:
    """Parse /etc/passwd under *rootfs* and return resolved home directory paths.

    Validates that each path stays within the rootfs boundary using safe_join,
    and returns absolute paths (already prefixed with *rootfs*).
    """
    homes: List[str] = []
    passwd = os.path.join(rootfs, "etc/passwd")
    if not os.path.exists(passwd):
        return homes

    with open(passwd, encoding="utf-8") as fh:
        for line in fh:
            parts = line.strip().split(":")
            if len(parts) >= 6:
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
    return homes

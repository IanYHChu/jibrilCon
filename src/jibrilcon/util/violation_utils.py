# Copyright (c) 2025 IanYHChu
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for full license information.

"""
violation_utils.py

Shared helper for converting raw rule-engine results into the violation
dicts used by all scanners.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Dict, List, Set


def process_violations(
    vios_raw: List[Dict[str, Any]],
    cfg_path: str,
    mount_path: str,
    line_resolver: Callable[[Dict[str, Any], Set[str]], List[str]],
) -> List[Dict[str, Any]]:
    """Transform raw rule-engine hits into scanner-output violation dicts.

    Shared across Docker, Podman, and LXC scanners.  Each scanner provides
    its own *line_resolver* callback to populate the ``lines`` field because
    the underlying config format differs.

    Parameters
    ----------
    vios_raw:
        Output of ``evaluate_rules()``.
    cfg_path:
        Absolute path of the config file that triggered the violations.
    mount_path:
        Root of the mounted filesystem (used to compute relative source).
    line_resolver:
        ``(violation, used_fields) -> list[str]``  Builds the human-readable
        ``lines`` list for a single violation.

    Returns
    -------
    list[dict]
        Cleaned violation dicts with ``source`` and ``lines`` set and
        internal keys (``conditions``, ``logic``) removed.
    """
    vios: List[Dict[str, Any]] = []
    for v in vios_raw:
        used_fields: Set[str] = {
            c.get("field") for c in v.get("conditions", []) if c.get("field")
        }
        v["source"] = "/" + os.path.relpath(cfg_path, mount_path)
        v["lines"] = line_resolver(v, used_fields)
        v.pop("conditions", None)
        v.pop("logic", None)
        vios.append(v)
    return vios

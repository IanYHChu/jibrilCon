# Copyright (c) 2025 IanYHChu
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for full license information.

"""
docker_native.py

Statically analyse Docker container configuration files located inside
a mounted root filesystem image.

Focus areas
-----------
* Privileged containers
* Read-only rootfs not enabled
* Bind mounts that are not read-only
* Containers inferred to run as root via `ScanContext`

The module exposes:

    scan(mount_path: str, context: ScanContext) -> dict
"""

from __future__ import annotations

import os
import time
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from jibrilcon.util.path_utils import resolve_path, safe_join
from jibrilcon.util.config_loader import load_json_config
from jibrilcon.util.context import ScanContext
from jibrilcon.util.rules_engine import evaluate_rules
from jibrilcon.util.io_helpers import deep_merge, load_json_or_empty

# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
RULE_PATH = BASE_DIR.parent / "rules" / "docker_config_rules.json"

_CONFIG_RE = re.compile(r"(?:^|\s)--config\s+(?P<confdir>\S+)")

# Map rule field names to JSON keys (for pretty printing if needed)
_FIELD_TO_CONFIG_KEY = {
    "privileged": "HostConfig.Privileged",
    "readonly_rootfs": "HostConfig.ReadonlyRootfs",
    "binds_not_readonly": "HostConfig.Binds",
    "service_user_missing": "service_user_missing",
}

# ---------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------
def _to_bool(value: Any) -> bool:
    """
    Convert common string / int representations to bool.

    Docker JSON sometimes stores Booleans as string "true"/"false".
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() == "true"
    if isinstance(value, (int, float)):
        return bool(value)
    return False

def _get_docker_data_root(rootfs: str) -> str:
    """
    Parse /etc/docker/daemon.json for "data-root"; default to
    /var/lib/docker if not found.
    """
    cfg = load_json_or_empty(os.path.join(rootfs, "etc/docker/daemon.json"))
    return cfg.get("data-root", "/var/lib/docker")

def _get_user_docker_roots(rootfs: str) -> List[str]:
    """
    Return a list of rootless Docker data directories discovered in each
    user's home directory.
    """
    roots: List[str] = []
    passwd = os.path.join(rootfs, "etc/passwd")
    if not os.path.exists(passwd):
        return roots

    with open(passwd, encoding="utf-8") as fh:
        for line in fh:
            parts = line.split(":")
            if len(parts) >= 6:
                home = parts[5].strip()
                if home:
                    roots.append(os.path.join(rootfs, home.lstrip("/"), ".local/share/docker"))
    return roots

def _discover_container_dirs(rootfs: str) -> List[Tuple[str, str, str]]:
    """
    Return a list of tuples:

        (container_name, config_path, hostconfig_path)
    """
    roots = [str(safe_join(rootfs, _get_docker_data_root(rootfs).lstrip("/")))]
    roots += _get_user_docker_roots(rootfs)

    discovered: List[Tuple[str, str, str]] = []

    for base in roots:
        cont_dir = os.path.join(base, "containers")
        if not os.path.isdir(cont_dir):
            continue

        for cid in os.listdir(cont_dir):
            cdir = os.path.join(cont_dir, cid)
            cfg = os.path.join(cdir, "config.v2.json")
            host = os.path.join(cdir, "hostconfig.json")
            if os.path.exists(cfg) and os.path.exists(host):
                name = cid[:12]
                # try to read name from config
                cfg_json = load_json_or_empty(cfg)
                name = cfg_json.get("Name", "").lstrip("/") or name
                discovered.append((name, cfg, host))
    return discovered

def _extract_fields(cfg: Dict[str, Any], host: Dict[str, Any]) -> Dict[str, Any]:
    """Pick out the fields needed by rules_engine."""
    sec_opts = host.get("SecurityOpt") or []
    binds = host.get("Binds") or []

    privileged_raw = host.get("Privileged", False) or ("label=disable" in sec_opts)
    privileged = _to_bool(privileged_raw)

    readonly_rootfs = _to_bool(host.get("ReadonlyRootfs", False))
    binds_not_readonly = any(not str(b).endswith(":ro") for b in binds)

    return {
        "privileged": privileged,
        "readonly_rootfs": readonly_rootfs,
        "binds_not_readonly": binds_not_readonly,
    }


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

def scan(mount_path: str, context: ScanContext | None = None) -> Dict[str, Any]:
    """
    Scan Docker container configurations under *mount_path*.

    Parameters
    ----------
    mount_path : str
        Path where the filesystem image is mounted read-only.
    context : ScanContext
        Shared context; must be provided by caller.

    Returns
    -------
    dict
        Result structure compatible with jibrilcon summary generator.
    """
    if context is None:
        raise ValueError("ScanContext must be supplied by core.run_scan")

    rules = load_json_config(RULE_PATH).get("rules", [])
    containers: Dict[str, Dict[str, Any]] = {}
    alert_count = 0
    warn_count = 0
    start_ts = time.time()

    for name, cfg_path, host_path in _discover_container_dirs(mount_path):
        # 1) load default config
        cfg_json = load_json_or_empty(resolve_path(cfg_path, mount_path))
        host_json = load_json_or_empty(resolve_path(host_path, mount_path))

        # 2) acquire Exec* command lines  -----------------
        exec_lines: Tuple[str, ...] = context.get_exec_lines("docker", name)
        override_cfg_dir: str | None = None
        for line in exec_lines:
            m = _CONFIG_RE.search(line)
            if m:
                override_cfg_dir = m.group("confdir")
                break

        if override_cfg_dir:
            conf_json_path = safe_join(
                mount_path,
                override_cfg_dir.lstrip("/"),
                "config.json",
            )
            if os.path.exists(conf_json_path):
                override_cfg = load_json_or_empty(conf_json_path)
                if override_cfg:
                    # merge into main config
                    deep_merge(cfg_json, override_cfg)
                    # merge HostConfig block if provided
                    host_override = override_cfg.get("HostConfig")
                    if isinstance(host_override, dict):
                        deep_merge(host_json, host_override)

        data = _extract_fields(cfg_json, host_json)

        # merge systemd inference: service_user_missing flag
        data["service_user_missing"] = context.is_user_missing(name)

        vios_raw = evaluate_rules(data, rules)
        vios = []
        for v in vios_raw:
            used_fields = {c.get("field") for c in v.get("conditions", []) if c.get("field")}
            v["source"] = "/" + os.path.relpath(cfg_path, mount_path)
            v["lines"] = []
            for f in used_fields:
                cfg_key = _FIELD_TO_CONFIG_KEY.get(f, f)
                val = cfg_json if "HostConfig" not in cfg_key else host_json
                for part in cfg_key.split("."):
                    val = val.get(part, {}) if isinstance(val, dict) else {}
                if val:
                    v["lines"].append(f"{cfg_key} = {val}")
                else:
                    v["lines"].append(f"<missing> {cfg_key}")
            vios.append(v)

        status = "violated" if vios else "clean"
        if any(v["type"] == "alert" for v in vios):
            alert_count += 1
        elif any(v["type"] == "warning" for v in vios):
            warn_count += 1

        containers[name] = {
            "container": name,
            "violations": vios,
            "status": status,
        }

    summary = {
        "docker_scanned": len(containers),
        "alerts": alert_count,
        "warnings": warn_count,
        "elapsed": round(time.time() - start_ts, 3),
    }

    return {"scanner": "docker", "summary": summary, "results": list(containers.values())}

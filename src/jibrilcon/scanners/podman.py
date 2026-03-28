# Copyright (c) 2025 IanYHChu
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for full license information.

"""
podman.py

Statically analyse Podman container configuration files located in a
mounted root filesystem image.

Focus areas
-----------
* Containers running as UID 0
* CAP_SYS_ADMIN present in bounding set (privileged)
* Bind mounts that are not read-only
* Missing seccomp profile
* Containers inferred to run as root via `ScanContext`

The module exposes:

    scan(mount_path: str, context: ScanContext) -> dict
"""

from __future__ import annotations

import logging
import os
import re
import time
from pathlib import Path
from typing import Any

from jibrilcon.util.config_loader import ConfigLoadError, load_json_config
from jibrilcon.util.context import ScanContext
from jibrilcon.util.io_helpers import deep_merge, load_json_or_empty
from jibrilcon.util.passwd_utils import get_user_home_dirs
from jibrilcon.util.path_utils import resolve_path, safe_join
from jibrilcon.util.rules_engine import evaluate_rules
from jibrilcon.util.violation_utils import process_violations

logger = logging.getLogger(__name__)

try:
    import tomllib as toml  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    import tomli as toml  # type: ignore

# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
RULE_PATH = BASE_DIR.parent / "rules" / "podman_config_rules.json"

_CONTAINER_ID_DISPLAY_LEN = 12

_CONFIG_RE = re.compile(r"(?:^|\s)--config\s+(?P<confdir>\S+)")
_MODULE_RE = re.compile(r"(?:^|\s)--module\s+(?P<modfile>\S+)")

# Capabilities considered dangerous for container isolation
_DANGEROUS_CAPS = frozenset(
    {
        "CAP_SYS_ADMIN",
        "CAP_SYS_PTRACE",
        "CAP_SYS_MODULE",
        "CAP_NET_RAW",
        "CAP_NET_ADMIN",
    }
)

# Map rule field names to JSON keys (used by report writer if needed)
_FIELD_TO_CONFIG_KEY = {
    "process.user.uid": "process.user.uid",
    "has_cap_sys_admin": "process.capabilities.bounding",
    "binds_not_readonly": "mounts",
    "seccomp_disabled": "linux.seccompProfilePath",
    "readonly_rootfs": "root.readonly",
    "service_user_missing": "service_user_missing",
    "host_pid_namespace": "linux.namespaces",
    "host_network_namespace": "linux.namespaces",
    "host_ipc_namespace": "linux.namespaces",
    "dangerous_caps_present": "process.capabilities.bounding",
}

# ---------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------


def _get_podman_data_root(rootfs: str) -> str:
    """
    Parse /etc/containers/storage.conf for graphRoot; fall back to
    /var/lib/containers/storage.
    """
    cfg_path = os.path.join(rootfs, "etc/containers/storage.conf")
    if not os.path.exists(cfg_path):
        return "/var/lib/containers/storage"

    with open(cfg_path, encoding="utf-8") as fh:
        for line in fh:
            # Match both quoted ("...") and unquoted values
            m = re.match(r'^\s*graphRoot\s*=\s*(?:"(.*?)"|(\S+))', line)
            if m:
                return m.group(1) or m.group(2)
    return "/var/lib/containers/storage"


def _get_user_podman_roots(rootfs: str) -> list[str]:
    """Return rootless Podman storage directories under each user's home."""
    return [
        os.path.join(home, ".local/share/containers/storage")
        for home in get_user_home_dirs(rootfs)
    ]


def _discover_configs(rootfs: str) -> list[tuple[str, str]]:
    """
    Return list of *(container_name, config_path)* tuples.
    """
    try:
        roots = [str(safe_join(rootfs, _get_podman_data_root(rootfs).lstrip("/")))]
    except ValueError as exc:
        logger.warning("Skipping Podman data-root: %s", exc)
        roots = []
    roots += _get_user_podman_roots(rootfs)

    discovered: list[tuple[str, str]] = []

    for base in roots:
        index_path = os.path.join(base, "overlay-containers", "containers.json")
        if not os.path.exists(index_path):
            continue

        index_data = load_json_or_empty(index_path)
        for entry in index_data:
            cid = entry.get("id")
            names = entry.get("names", [])
            name = names[0] if names else cid[:_CONTAINER_ID_DISPLAY_LEN]
            cfg_path = os.path.join(
                base, "overlay-containers", cid, "userdata", "config.json"
            )
            if os.path.exists(cfg_path):
                discovered.append((name, cfg_path))
    return discovered


def _extract_fields(cfg: dict[str, Any]) -> dict[str, Any]:
    """Produce data dict for rules_engine."""
    uid = cfg.get("process", {}).get("user", {}).get("uid", 0)
    if not isinstance(uid, int):
        logger.warning(
            "UID is not an integer (%s), defaulting to 0", type(uid).__name__
        )
        uid = 0

    mounts = cfg.get("mounts", []) or []
    if not isinstance(mounts, list):
        logger.warning("mounts is not a list, ignoring: %s", type(mounts).__name__)
        mounts = []

    caps_obj = cfg.get("process", {}).get("capabilities", {})
    caps_bounding = caps_obj.get("bounding", [])
    if not isinstance(caps_bounding, list):
        logger.warning(
            "capabilities.bounding is not a list, ignoring: %s",
            type(caps_bounding).__name__,
        )
        caps_bounding = []
    caps_effective = caps_obj.get("effective", [])
    if not isinstance(caps_effective, list):
        logger.warning(
            "capabilities.effective is not a list, ignoring: %s",
            type(caps_effective).__name__,
        )
        caps_effective = []

    seccomp_present = "seccompProfilePath" in cfg.get("linux", {})

    binds_not_readonly = any(
        isinstance(m, dict)
        and m.get("type") == "bind"
        and "ro" not in m.get("options", [])
        for m in mounts
    )
    has_cap_sys_admin = "CAP_SYS_ADMIN" in caps_bounding

    # OCI spec: root.readonly indicates read-only rootfs
    readonly_rootfs = cfg.get("root", {}).get("readonly", False)

    # Dangerous capabilities in bounding OR effective sets
    all_caps = set(caps_bounding) | set(caps_effective)
    dangerous_caps_present = bool(all_caps & _DANGEROUS_CAPS)

    # OCI spec: linux.namespaces is an array of {"type": ..., "path": ...}
    # If a namespace type is NOT listed, the container inherits the host namespace
    namespaces = cfg.get("linux", {}).get("namespaces", [])
    if not isinstance(namespaces, list):
        logger.warning(
            "linux.namespaces is not a list, ignoring: %s", type(namespaces).__name__
        )
        namespaces = []
    ns_types_present = {ns.get("type") for ns in namespaces if isinstance(ns, dict)}
    host_pid_namespace = "pid" not in ns_types_present
    host_network_namespace = "network" not in ns_types_present
    host_ipc_namespace = "ipc" not in ns_types_present

    return {
        "process.user.uid": uid,
        "has_cap_sys_admin": has_cap_sys_admin,
        "binds_not_readonly": binds_not_readonly,
        "seccomp_disabled": not seccomp_present,
        "readonly_rootfs": readonly_rootfs,
        "host_pid_namespace": host_pid_namespace,
        "host_network_namespace": host_network_namespace,
        "host_ipc_namespace": host_ipc_namespace,
        "dangerous_caps_present": dangerous_caps_present,
    }


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------


def scan(mount_path: str, context: ScanContext | None = None) -> dict[str, Any]:
    """
    Scan Podman container configurations under *mount_path*.

    Raises
    ------
    ValueError
        If *context* is None (must be supplied by core.run_scan).
    """
    if context is None:
        raise ValueError("ScanContext must be supplied by core.run_scan")

    try:
        rules_cfg = load_json_config(RULE_PATH)
    except ConfigLoadError:
        logger.error("Failed to load Podman rules from %s", RULE_PATH)
        rules_cfg = {"rules": []}
    rules = rules_cfg.get("rules", [])
    if not rules:
        logger.warning("No rules loaded from %s; all containers will pass", RULE_PATH)
    containers: dict[str, dict[str, Any]] = {}
    alert_count = 0
    warn_count = 0
    start_ts = time.time()

    for name, cfg_path in _discover_configs(mount_path):
        # 1) load default config
        cfg_json = load_json_or_empty(resolve_path(cfg_path, mount_path))

        # 2) acquire Exec* command lines  -----------------
        exec_lines: list[str] = context.get_exec_lines("podman", name)
        for line in exec_lines:
            # --config <dir>
            m_cfg = _CONFIG_RE.search(line)
            if m_cfg:
                conf_dir = m_cfg.group("confdir")
                try:
                    conf_json_path = safe_join(
                        mount_path,
                        conf_dir.lstrip("/"),
                        "config.json",
                    )
                except ValueError as exc:
                    logger.warning("Skipping Podman config override: %s", exc)
                    conf_json_path = None
                if conf_json_path and os.path.exists(conf_json_path):
                    override_cfg = load_json_or_empty(conf_json_path)
                    if override_cfg:
                        deep_merge(cfg_json, override_cfg)

            # --module <file>
            m_mod = _MODULE_RE.search(line)
            if m_mod:
                mod_arg = m_mod.group("modfile")
                try:
                    if "/" in mod_arg:
                        mod_path = safe_join(mount_path, mod_arg.lstrip("/"))
                    else:
                        mod_path = safe_join(
                            mount_path,
                            "etc/podman/modules",
                            f"{mod_arg}.toml",
                        )
                except ValueError as exc:
                    logger.warning("Skipping Podman module override: %s", exc)
                    mod_path = None
                if mod_path and os.path.exists(mod_path):
                    try:
                        with open(mod_path, "rb") as fp:
                            mod_data = toml.load(fp)
                        if isinstance(mod_data, dict):
                            deep_merge(cfg_json, mod_data)
                    except (OSError, ValueError, KeyError) as exc:
                        logger.warning(
                            "Skipping malformed module %s: %s", mod_path, exc
                        )

        data = _extract_fields(cfg_json)

        # merge systemd inference: flag if service lacks non-root User=
        data["service_user_missing"] = context.is_user_missing(name)

        vios_raw = evaluate_rules(data, rules)

        def _resolve_lines(_v, used_fields):
            lines = []
            for f in used_fields:
                cfg_key = _FIELD_TO_CONFIG_KEY.get(f, f)
                val = cfg_json
                for part in cfg_key.split("."):
                    val = val.get(part, {}) if isinstance(val, dict) else {}
                if val:
                    lines.append(f"{cfg_key} = {val}")
                else:
                    lines.append(f"<missing> {cfg_key}")
            return lines

        vios = process_violations(vios_raw, cfg_path, mount_path, _resolve_lines)

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
        "podman_scanned": len(containers),
        "alerts": alert_count,
        "warnings": warn_count,
        "elapsed": round(time.time() - start_ts, 3),
    }

    return {
        "scanner": "podman",
        "summary": summary,
        "results": list(containers.values()),
    }

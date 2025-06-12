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

    priority : int  (for scanner_loader ordering)
    scan(mount_path: str, context: ScanContext) -> dict
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from util.path_utils import resolve_path, safe_join
from util.config_loader import load_json_config
from util.context import ScanContext
from util.rules_engine import evaluate_rules
from util.error_helpers import load_json_safe, SoftIOError

try:
    import tomllib as toml  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    import tomli as toml  # type: ignore

# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
RULE_PATH = BASE_DIR.parent / "rule" / "podman_config_rules.json"

_CONFIG_RE = re.compile(r"(?:^|\s)--config\s+(?P<confdir>\S+)")
_MODULE_RE = re.compile(r"(?:^|\s)--module\s+(?P<modfile>\S+)")

# Map rule field names to JSON keys (used by report writer if needed)
_FIELD_TO_CONFIG_KEY = {
    "process.user.uid": "process.user.uid",
    "has_cap_sys_admin": "process.capabilities.bounding",
    "binds_not_readonly": "mounts",
    "seccomp": "linux.seccompDefault",
}

# ---------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------

def _deep_merge(dst: Dict[str, Any], src: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge *src* into *dst*; values in *src* take precedence.

    Mirrors the behaviour in docker_native.py / lxc.py for consistent
    override semantics.
    """
    for k, v in src.items():
        if (
            k in dst
            and isinstance(dst[k], dict)
            and isinstance(v, dict)
        ):
            _deep_merge(dst[k], v)
        else:
            dst[k] = v
    return dst

def _load_json(path: str) -> Dict[str, Any]:
    try:
        return load_json_safe(Path(path))
    except SoftIOError:
        return {}

def _get_podman_data_root(rootfs: str) -> str:
    """
    Parse /etc/containers/storage.conf for graphRoot; fall back to
    /var/lib/containers/storage.
    """
    cfg_path = os.path.join(rootfs, "etc/containers/storage.conf")
    if not os.path.exists(cfg_path):
        return "/var/lib/containers/storage"

    for line in open(cfg_path, encoding="utf-8"):
        m = re.match(r'^\s*graphRoot\s*=\s*"(.*?)"', line)
        if m:
            return m.group(1)
    return "/var/lib/containers/storage"

def _get_user_podman_roots(rootfs: str) -> List[str]:
    """Return rootless Podman storage directories under each user's home."""
    roots: List[str] = []
    passwd = os.path.join(rootfs, "etc/passwd")
    if not os.path.exists(passwd):
        return roots

    for line in open(passwd, encoding="utf-8"):
        parts = line.strip().split(":")
        if len(parts) >= 6:
            home = parts[5].strip()
            if home:
                roots.append(os.path.join(rootfs, home.lstrip("/"), ".local/share/containers/storage"))
    return roots

def _discover_configs(rootfs: str) -> List[Tuple[str, str]]:
    """
    Return list of *(container_name, config_path)* tuples.
    """
    roots = [str(safe_join(rootfs, _get_podman_data_root(rootfs).lstrip("/")))]
    roots += _get_user_podman_roots(rootfs)

    discovered: List[Tuple[str, str]] = []

    for base in roots:
        index_path = os.path.join(base, "overlay-containers", "containers.json")
        if not os.path.exists(index_path):
            continue

        index_data = _load_json(index_path)
        for entry in index_data:
            cid = entry.get("id")
            names = entry.get("names", [])
            name = names[0] if names else cid[:12]
            cfg_path = os.path.join(base, "overlay-containers", cid, "userdata", "config.json")
            if os.path.exists(cfg_path):
                discovered.append((name, cfg_path))
    return discovered

def _extract_fields(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Produce data dict for rules_engine."""
    uid = cfg.get("process", {}).get("user", {}).get("uid", 0)
    mounts = cfg.get("mounts", []) or []
    ro_paths = cfg.get("linux", {}).get("readonlyPaths", [])
    caps = cfg.get("process", {}).get("capabilities", {}).get("bounding", [])
    seccomp_present = "seccompProfilePath" in cfg.get("linux", {})

    binds_not_readonly = any(
        m.get("type") == "bind" and "ro" not in m.get("options", []) for m in mounts
    )
    has_cap_sys_admin = "CAP_SYS_ADMIN" in caps
    readonly_rootfs = bool(ro_paths)  # not used by rules now but may be in future

    return {
        "process.user.uid": uid,
        "has_cap_sys_admin": has_cap_sys_admin,
        "binds_not_readonly": binds_not_readonly,
        "seccomp": seccomp_present,
        "readonly_rootfs": readonly_rootfs,
    }

# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

def scan(mount_path: str, context: ScanContext | None = None) -> Dict[str, Any]:
    """
    Scan Podman container configurations under *mount_path*.

    Raises
    ------
    ValueError
        If *context* is None (must be supplied by core.run_scan).
    """
    if context is None:
        raise ValueError("ScanContext must be supplied by core.run_scan")

    rules = load_json_config(RULE_PATH).get("rules", [])
    containers: Dict[str, Dict[str, Any]] = {}
    alert_count = 0
    warn_count = 0
    start_ts = time.time()

    for name, cfg_path in _discover_configs(mount_path):
        # 1) load default config
        cfg_json = _load_json(resolve_path(cfg_path, mount_path))

        # 2) acquire Exec* command lines  -----------------
        exec_lines: Tuple[str, ...] = context.get_exec_lines("podman", name)
        for line in exec_lines:
            # --config <dir>
            m_cfg = _CONFIG_RE.search(line)
            if m_cfg:
                conf_dir = m_cfg.group("confdir")
                conf_json_path = safe_join(
                    mount_path,
                    conf_dir.lstrip("/"),
                    "config.json",
                )
                if os.path.exists(conf_json_path):
                    override_cfg = _load_json(conf_json_path)
                    if override_cfg:
                        _deep_merge(cfg_json, override_cfg)

            # --module <file>
            m_mod = _MODULE_RE.search(line)
            if m_mod:
                mod_arg = m_mod.group("modfile")
                # Decide absolute path
                if "/" in mod_arg:
                    mod_path = safe_join(mount_path, mod_arg.lstrip("/"))
                else:
                    mod_path = safe_join(
                        mount_path,
                        "etc/podman/modules",
                        f"{mod_arg}.toml",
                    )
                if os.path.exists(mod_path):
                    try:
                        with open(mod_path, "rb") as fp:
                            mod_data = toml.load(fp)
                        if isinstance(mod_data, dict):
                            _deep_merge(cfg_json, mod_data)
                    except Exception:  # noqa: BLE001
                        # Gracefully ignore malformed TOML
                        pass
        
        data = _extract_fields(cfg_json)

        # merge systemd inference: if service lacks non-root User=
        data["process.user.uid"] = 0 if context.is_user_missing(name) else data["process.user.uid"]

        vios_raw = evaluate_rules(data, rules)
        vios = []
        for v in vios_raw:
            used_fields = {c.get("field") for c in v.get("conditions", []) if c.get("field")}
            v["source"] = "/" + os.path.relpath(cfg_path, mount_path)
            v["lines"] = []
            for f in used_fields:
                cfg_key = _FIELD_TO_CONFIG_KEY.get(f, f)
                val = cfg_json
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
        "podman_scanned": len(containers),
        "alerts": alert_count,
        "warnings": warn_count,
        "elapsed": round(time.time() - start_ts, 3),
    }

    return {"scanner": "podman", "summary": summary, "results": list(containers.values())}

# Copyright (c) 2025 IanYHChu
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for full license information.

"""
lxc.py

Statically analyse LXC container configuration files inside a mounted
root filesystem image.

Focus areas
-----------
* UID / GID map presence and format
* Dropped capabilities
* Mount entry safety (e.g., /proc, /sys, /run)
* Containers inferred to run as root via `ScanContext`

Exports
-------
scan(mount_path: str, context: ScanContext) -> dict
"""

from __future__ import annotations

import logging
import os
import re
import shlex
import time
from functools import lru_cache
from pathlib import Path

from jibrilcon.util.config_loader import ConfigLoadError, load_json_config
from jibrilcon.util.context import ScanContext
from jibrilcon.util.path_utils import safe_join
from jibrilcon.util.rules_engine import evaluate_rules
from jibrilcon.util.systemd_unit_parser import scan_systemd_container_units
from jibrilcon.util.violation_utils import process_violations

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
RULE_PATH = BASE_DIR.parent / "rules" / "lxc_config_rules.json"

# Regex patterns
_IDMAP_RE = re.compile(r"^([ug])\s+(\d+)\s+(\d+)\s+(\d+)")

_RCFILE_RE = re.compile(r"(?:^|\s)(?:-f|--rcfile)\s+(?P<rcfile>\S+)")
_DEFINE_RE = re.compile(
    r"(?:^|\s)(?:-s|--define)\s+(?:'(?P<kvq1>[^']+)'|\"(?P<kvq2>[^\"]+)\"|(?P<kvq3>\S+))"
)

_EXCLUDE_DIRS = {"/dev", "/proc", "/run", "/sys", "/tmp", "/mnt", "/media"}  # nosec B108

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB safeguard

_MAX_INCLUDE_DEPTH = 20

_DANGEROUS_CAPS_KEEP = frozenset(
    {
        "sys_admin",
        "sys_ptrace",
        "sys_module",
        "net_raw",
        "net_admin",
        "sys_rawio",
        "dac_override",
        "dac_read_search",
    }
)

# Map rule field name -> config key (for pretty reporting if needed)
_FIELD_TO_CONFIG_KEY = {
    "uidmap": "lxc.idmap",
    "gidmap": "lxc.idmap",
    "cap_drop": "lxc.cap.drop",
    "source": "lxc.mount.entry",
    "options": "lxc.mount.entry",
    "apparmor_profile": "lxc.apparmor.profile",
    "net_type": "lxc.net.0.type",
    "no_new_privs_missing": "lxc.no_new_privs",
    "seccomp_profile_missing": "lxc.seccomp.profile",
    "cap_keep_dangerous": "lxc.cap.keep",
}

# ---------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------


@lru_cache(maxsize=8192)
def _is_text_file(path: str) -> bool:
    """
    Return True if *path* is a small UTF-8 text file.

    Thread-safety note: no lock needed.  This function is only called
    from _file_contains_rootfs -> _get_lxc_rootfs_config_candidates ->
    scan(), all within the single LXC scanner thread.
    """
    try:
        if os.path.getsize(path) > MAX_FILE_SIZE:
            return False
        with open(path, "rb") as fp:
            fp.read().decode("utf-8")
        return True
    except (UnicodeDecodeError, OSError):
        return False


def _file_contains_rootfs(
    path: Path,
    rootfs: str,
    visited: set[Path] | None = None,
    depth: int = 0,
) -> bool:
    """
    Recursively check if *path* (and its included configs) define
    ``lxc.rootfs.path``.  Included paths are resolved within the
    *rootfs* boundary to prevent symlink traversal.
    """
    if depth > _MAX_INCLUDE_DEPTH:
        logger.warning("Include depth exceeded %d at %s", _MAX_INCLUDE_DEPTH, path)
        return False
    visited = visited or set()
    if path in visited:
        return False  # circular include
    visited.add(path)

    if not _is_text_file(str(path)):
        return False

    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if line.startswith("lxc.rootfs.path"):
            return True
        if line.startswith("lxc.include") and "=" in line:
            _, inc = line.split("=", 1)
            inc_raw = inc.strip()
            # Resolve include path within rootfs boundary
            try:
                if os.path.isabs(inc_raw):
                    inc_path = safe_join(rootfs, inc_raw.lstrip("/"))
                else:
                    rel = os.path.relpath(path.parent / inc_raw, rootfs)
                    inc_path = safe_join(rootfs, rel)
            except ValueError:
                continue  # include escapes rootfs, skip
            if _file_contains_rootfs(inc_path, rootfs, visited, depth + 1):
                return True
    return False


def _get_lxc_rootfs_config_candidates(rootfs: str) -> set[Path]:
    """
    Search all files under rootfs that define 'lxc.rootfs.path'.
    These are considered LXC configuration candidates.

    Parameters
    ----------
    rootfs : str
        The mounted container filesystem path.

    Returns
    -------
    Set[Path]
        All LXC config file paths found in the filesystem.
    """
    configs: set[Path] = set()
    exclude_abs = {os.path.join(rootfs, d.lstrip("/")) for d in _EXCLUDE_DIRS}
    for dirpath, dirnames, filenames in os.walk(rootfs):
        # Prune excluded directories in-place so os.walk skips them entirely
        dirnames[:] = [
            d for d in dirnames if os.path.join(dirpath, d) not in exclude_abs
        ]
        for fname in filenames:
            # full = Path(dirpath) / fname
            full = safe_join(rootfs, os.path.relpath(Path(dirpath) / fname, rootfs))
            try:
                if _file_contains_rootfs(full, rootfs):
                    configs.add(full)
            except (OSError, ValueError, UnicodeDecodeError):
                continue
    return configs


def _filter_active_lxc_configs(configs: set[Path], rootfs: str) -> set[Path]:
    """
    From *configs* pick only those actively referenced by lxc-monitord.
    If lxc-monitord binary is missing, return configs unchanged.
    """
    monitord = Path(rootfs) / "usr/libexec/lxc/lxc-monitord"
    if not monitord.is_file():
        return configs  # fallback – cannot determine active set

    data = monitord.read_bytes().decode("utf-8", errors="ignore")
    used: set[Path] = set()

    for cfg in configs:
        # heuristic: check if parent path appears in monitord text dump
        parent = cfg.parent.parent  # typically <container-name>/
        if str(parent.name) in data:
            used.add(cfg)
    return used or configs


def _parse_lxc_config(path: Path) -> dict[str, list[str]]:
    """Parse key = value lines into mapping key -> list[str]."""
    result: dict[str, list[str]] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        logger.warning("Cannot read LXC config %s: %s", path, exc)
        return result
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        result.setdefault(key, []).append(value)
    return result


@lru_cache(maxsize=4096)
def _find_systemd_exec_lines(rootfs: str, cname: str) -> list[str]:
    """
    Fallback helper -- call the central systemd parser so we respect the
    JSON-configured `unit_dirs` and `exec_keys`.  Filters rows to the LXC
    container *cname* and flattens all Exec* command lines.

    Thread-safety note: no lock needed.  This function is only called
    from scan() within the single LXC scanner thread.
    """
    rows = scan_systemd_container_units(rootfs)
    lines: list[str] = []
    for row in rows:
        if row.get("engine") != "lxc" or row.get("container") != cname:
            continue
        raw = row.get("raw_lines", {})
        # `raw` keys are lower-cased: "execstart", "execstartpre", …
        for k, v in raw.items():
            if k.startswith("execstart"):
                lines.extend(v)
    return lines


def _extract_cli_params(
    exec_lines: list[str],
) -> tuple[str | None, list[str]]:
    """
    Extract rcfile path and ordered KEY=VAL CLI overrides.
    """
    rcfile: str | None = None
    overrides: list[str] = []

    for cmd in exec_lines:
        if m := _RCFILE_RE.search(cmd):
            rcfile = m.group("rcfile")

        for dm in _DEFINE_RE.finditer(cmd):
            kv = dm.group("kvq1") or dm.group("kvq2") or dm.group("kvq3") or ""
            # shlex.split handles escaped spaces inside quotes
            for token in shlex.split(kv):
                if "=" in token:
                    overrides.append(token)  # keep order
    return rcfile, overrides


def _merge_entries(
    base: dict[str, list[str]], extra: dict[str, list[str]]
) -> dict[str, list[str]]:
    """Return new dict: *extra* replaces same-name keys in *base*."""
    merged = base.copy()
    for k, v in extra.items():
        merged[k] = v
    return merged


def _apply_cli_overrides(
    entries: dict[str, list[str]], override_tokens: list[str]
) -> None:
    """
    In-place patch of entries with KEY=VAL list.
    Last occurrence of the same key wins (order preserved by caller).
    """
    for tok in override_tokens:
        key, val = tok.split("=", 1)
        entries[key.strip()] = [val.strip()]


def _extract_idmap(entries: dict[str, list[str]]) -> dict[str, str]:
    """Return uidmap / gidmap strings if present."""
    uidmap = gidmap = None
    for val in entries.get("lxc.idmap", []):
        if not isinstance(val, str):
            continue
        m = _IDMAP_RE.match(val.strip())
        if not m:
            continue
        # lxc.idmap format: <u|g> <container_id> <host_id> <range>
        tag, container_id, host_id, id_range = m.groups()
        mapping = f"{container_id} {host_id} {id_range}"
        if tag == "u":
            uidmap = mapping
        else:
            gidmap = mapping
    return {"uidmap": uidmap, "gidmap": gidmap}


def _extract_cap_drop(entries: dict[str, list[str]]) -> dict[str, list[str]]:
    """Return list of dropped capabilities."""
    drops: list[str] = []
    for val in entries.get("lxc.cap.drop", []):
        if not isinstance(val, str):
            continue
        stripped = val.strip()
        if stripped:
            drops.extend(stripped.split())
    return {"cap_drop": drops or None}


def _extract_apparmor_profile(entries: dict[str, list[str]]) -> dict[str, str | None]:
    """Return the AppArmor profile if set."""
    vals = entries.get("lxc.apparmor.profile", [])
    # Last value wins (LXC config override semantics)
    profile = vals[-1].strip() if vals else None
    return {"apparmor_profile": profile}


def _extract_net_type(entries: dict[str, list[str]]) -> dict[str, str | None]:
    """Return the network type for the primary interface (lxc.net.0.type)."""
    vals = entries.get("lxc.net.0.type", [])
    net_type = vals[-1].strip() if vals else None
    return {"net_type": net_type}


def _extract_no_new_privs(entries: dict[str, list[str]]) -> dict[str, bool]:
    """Check if lxc.no_new_privs is set to 1."""
    vals = entries.get("lxc.no_new_privs", [])
    enabled = any(v.strip() == "1" for v in vals if isinstance(v, str))
    return {"no_new_privs_missing": not enabled}


def _extract_seccomp_profile(entries: dict[str, list[str]]) -> dict[str, bool]:
    """Check if lxc.seccomp.profile is configured."""
    # LXC supports both lxc.seccomp.profile (v3) and lxc.seccomp (v2)
    vals = entries.get("lxc.seccomp.profile", []) + entries.get("lxc.seccomp", [])
    has_profile = any(isinstance(v, str) and v.strip() for v in vals)
    return {"seccomp_profile_missing": not has_profile}


def _extract_cap_keep(entries: dict[str, list[str]]) -> dict[str, bool]:
    """Check if lxc.cap.keep contains dangerous capabilities."""
    keeps: list[str] = []
    for val in entries.get("lxc.cap.keep", []):
        if not isinstance(val, str):
            continue
        stripped = val.strip()
        if stripped:
            keeps.extend(stripped.lower().split())
    normalised = {k.removeprefix("cap_") for k in keeps}
    dangerous = bool(normalised & _DANGEROUS_CAPS_KEEP)
    return {"cap_keep_dangerous": dangerous}


def _parse_mount_entry(entry: str) -> dict[str, str]:
    """
    Given a single ``lxc.mount.entry`` line, return mapping:

        {"source": str, "options": str}

    lxc.mount.entry format (fstab-style):
        <source> <dest> <type> <options> [<dump> <pass>]
    """
    parts = entry.split("=", 1)[-1].strip().split()
    source = parts[0] if parts else ""
    # options are at index 3 (fstab field 4)
    options = parts[3] if len(parts) >= 4 else ""
    return {"source": source, "options": options}


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------


def scan(mount_path: str, context: ScanContext | None = None) -> dict[str, object]:
    """
    Scan LXC container configs under *mount_path*.

    Raises
    ------
    ValueError
        If *context* is None (must be supplied by core.run_scan).
    """
    if context is None:
        raise ValueError("lxc: ScanContext must be supplied by core.run_scan")

    try:
        rules_cfg = load_json_config(RULE_PATH)
    except ConfigLoadError:
        logger.error("Failed to load LXC rules from %s", RULE_PATH)
        rules_cfg = {"rules": []}
    all_rules = rules_cfg.get("rules", [])
    if not all_rules:
        logger.warning("No rules loaded from %s; all containers will pass", RULE_PATH)
    config_rules = [r for r in all_rules if not r["id"].startswith("mount_")]
    mount_rules = [r for r in all_rules if r["id"].startswith("mount_")]

    results: list[dict[str, object]] = []
    alert_count = warning_count = total_containers = 0
    start_ts = time.time()

    all_cfgs = _get_lxc_rootfs_config_candidates(mount_path)
    active_cfgs = _filter_active_lxc_configs(all_cfgs, mount_path)

    for cfg_path in active_cfgs:
        container_name = cfg_path.parent.name

        # 1) load default config
        entries = _parse_lxc_config(cfg_path)

        # 2) acquire Exec* command lines  -----------------
        exec_lines = context.get_exec_lines("lxc", container_name)
        if not exec_lines:
            exec_lines = _find_systemd_exec_lines(mount_path, container_name)

        # 3) derive rcfile / -s CLI overrides ------------
        rcfile_path, override_tokens = _extract_cli_params(exec_lines)

        # merge rcfile if present
        if rcfile_path:
            try:
                rc_abs = safe_join(mount_path, rcfile_path.lstrip("/"))
            except ValueError:
                rc_abs = None
            if rc_abs and rc_abs.is_file():
                rc_entries = _parse_lxc_config(rc_abs)
                entries = _merge_entries(entries, rc_entries)

        # apply -s/--define overrides (highest priority)
        if override_tokens:
            _apply_cli_overrides(entries, override_tokens)

        idmap_info = _extract_idmap(entries)
        capdrop_info = _extract_cap_drop(entries)
        apparmor_info = _extract_apparmor_profile(entries)
        net_info = _extract_net_type(entries)
        privs_info = _extract_no_new_privs(entries)
        seccomp_info = _extract_seccomp_profile(entries)
        capkeep_info = _extract_cap_keep(entries)

        # infer runs_as_root from context or missing mappings
        systemd_root = context.is_systemd_started(
            "lxc", container_name
        ) and context.is_user_missing(container_name)
        mapping_root = (
            idmap_info.get("uidmap") is None and idmap_info.get("gidmap") is None
        )
        runs_as_root = systemd_root or mapping_root

        base_data = {
            **idmap_info,
            **capdrop_info,
            **apparmor_info,
            **net_info,
            **privs_info,
            **seccomp_info,
            **capkeep_info,
            "runs_as_root": runs_as_root,
        }

        # ------------------ config rules ------------------
        config_vios_raw = evaluate_rules(base_data, config_rules)

        def _resolve_config_lines(_v, used_fields):
            lines = []
            for f in used_fields:
                cfg_key = _FIELD_TO_CONFIG_KEY.get(f, f)
                raw_lines = entries.get(cfg_key)
                if raw_lines:
                    lines.extend(raw_lines)
                else:
                    lines.append(f"<missing> {cfg_key}")
            return lines

        config_vios = process_violations(
            config_vios_raw,
            str(cfg_path),
            mount_path,
            _resolve_config_lines,
        )

        # ------------------ mount rules -------------------
        mount_results = []
        for line in entries.get("lxc.mount.entry", []):
            if not isinstance(line, str):
                continue
            mentry = _parse_mount_entry(line)
            vios_raw = evaluate_rules(mentry, mount_rules)

            def _resolve_mount_lines(_v, used_fields, _line=line):
                lines = [_line] if _line else []
                for f in used_fields - {"source", "options"}:
                    lines.append(f"<missing> {f}")
                return lines

            mount_results.extend(
                process_violations(
                    vios_raw, str(cfg_path), mount_path, _resolve_mount_lines
                )
            )

        all_vios = config_vios + mount_results
        status = "violated" if all_vios else "clean"
        if any(v["type"] == "alert" for v in all_vios):
            alert_count += 1
        elif any(v["type"] == "warning" for v in all_vios):
            warning_count += 1

        results.append(
            {
                "container": container_name,
                "violations": all_vios,
                "status": status,
            }
        )
        total_containers += 1

    summary = {
        "lxc_scanned": total_containers,
        "alerts": alert_count,
        "warnings": warning_count,
        "elapsed": round(time.time() - start_ts, 3),
    }

    return {"scanner": "lxc", "summary": summary, "results": results}

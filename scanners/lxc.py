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

import os
import re
import shlex
import time
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Set, Tuple

from util.config_loader import load_json_config
from util.context import ScanContext
from util.rules_engine import evaluate_rules
from util.path_utils import safe_join
from util.systemd_unit_parser import scan_systemd_container_units

# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
RULE_PATH = BASE_DIR.parent / "rule" / "lxc_config_rules.json"

# Regex patterns
_IDMAP_RE = re.compile(r"^lxc\.idmap\s*=\s*([ug])\s+(\d+)\s+(\d+)\s+(\d+)")
_CAPDROP_RE = re.compile(r"^lxc\.cap\.drop\s*=\s*(.+)$")

_RCFILE_RE = re.compile(r"(?:^|\s)(?:-f|--rcfile)\s+(?P<rcfile>\S+)")
_DEFINE_RE = re.compile(
    r"(?:^|\s)(?:-s|--define)\s+(?:'(?P<kvq1>[^']+)'|\"(?P<kvq2>[^\"]+)\"|(?P<kvq3>\S+))"
)

_EXCLUDE_DIRS = {"/dev", "/proc", "/run", "/sys", "/tmp", "/mnt", "/media"}

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB safeguard

# Map rule field name -> config key (for pretty reporting if needed)
_FIELD_TO_CONFIG_KEY = {
    "uidmap": "lxc.idmap",
    "gidmap": "lxc.idmap",
    "cap_drop": "lxc.cap.drop",
    "source": "lxc.mount.entry",
    "options": "lxc.mount.entry",
}

# ---------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------

@lru_cache(maxsize=8192)
def _is_text_file(path: str) -> bool:
    """Return True if *path* is a small UTF-8 text file."""
    try:
        if os.path.getsize(path) > MAX_FILE_SIZE:
            return False
        with open(path, "rb") as fp:
            fp.read().decode("utf-8")
        return True
    except (UnicodeDecodeError, OSError):
        return False

def _file_contains_rootfs(path: Path, visited: Set[Path] | None = None) -> bool:
    """
    Recursively check if *path* (and its included configs) define
    ``lxc.rootfs.path``.
    """
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
        if line.startswith("lxc.include"):
            _, inc = line.split("=", 1)
            inc_path = (path.parent / inc.strip()).resolve()
            if _file_contains_rootfs(inc_path, visited):
                return True
    return False

def _get_lxc_rootfs_config_candidates(rootfs: str) -> Set[Path]:
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
    configs: Set[Path] = set()
    exclude_abs = {os.path.join(rootfs, d.lstrip("/")) for d in _EXCLUDE_DIRS}
    for dirpath, dirnames, filenames in os.walk(rootfs):
        # Prune excluded directories in-place so os.walk skips them entirely
        dirnames[:] = [
            d for d in dirnames
            if os.path.join(dirpath, d) not in exclude_abs
        ]
        for fname in filenames:
            # full = Path(dirpath) / fname
            full = safe_join(rootfs, os.path.relpath(Path(dirpath) / fname, rootfs))
            try:
                if _file_contains_rootfs(full):
                    configs.add(full)
            except Exception:
                # ignore unreadable files
                continue
    return configs

def _filter_active_lxc_configs(configs: Set[Path], rootfs: str) -> Set[Path]:
    """
    From *configs* pick only those actively referenced by lxc-monitord.
    If lxc-monitord binary is missing, return configs unchanged.
    """
    monitord = Path(rootfs) / "usr/libexec/lxc/lxc-monitord"
    if not monitord.is_file():
        return configs  # fallback – cannot determine active set

    data = monitord.read_bytes().decode("utf-8", errors="ignore")
    used: Set[Path] = set()

    for cfg in configs:
        # heuristic: check if parent path appears in monitord text dump
        parent = cfg.parent.parent  # typically <container-name>/
        if str(parent.name) in data:
            used.add(cfg)
    return used or configs


def _parse_lxc_config(path: Path) -> Dict[str, List[str]]:
    """Parse key = value lines into mapping key -> list[str]."""
    result: Dict[str, List[str]] = {}
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        result.setdefault(key, []).append(value)
    return result


@lru_cache(maxsize=4096)
def _find_systemd_exec_lines(rootfs: str, cname: str) -> List[str]:
    """
    Fallback helper – call the central systemd parser so we respect the
    JSON-configured `unit_dirs` and `exec_keys`.  Filters rows to the LXC
    container *cname* and flattens all Exec* command lines.
    """
    rows = scan_systemd_container_units(rootfs)
    lines: List[str] = []
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
    exec_lines: List[str],
) -> Tuple[str | None, List[str]]:
    """
    Extract rcfile path and ordered KEY=VAL CLI overrides.
    """
    rcfile: str | None = None
    overrides: List[str] = []

    for cmd in exec_lines:
        if (m := _RCFILE_RE.search(cmd)):
            rcfile = m.group("rcfile")

        for dm in _DEFINE_RE.finditer(cmd):
            kv = dm.group("kvq1") or dm.group("kvq2") or dm.group("kvq3") or ""
            # shlex.split handles escaped spaces inside quotes
            for token in shlex.split(kv):
                if "=" in token:
                    overrides.append(token)  # keep order
    return rcfile, overrides


def _merge_entries(
    base: Dict[str, List[str]], extra: Dict[str, List[str]]
) -> Dict[str, List[str]]:
    """Return new dict: *extra* replaces same-name keys in *base*."""
    merged = base.copy()
    for k, v in extra.items():
        merged[k] = v
    return merged


def _apply_cli_overrides(
    entries: Dict[str, List[str]], override_tokens: List[str]
) -> None:
    """
    In-place patch of entries with KEY=VAL list.
    Last occurrence of the same key wins (order preserved by caller).
    """
    for tok in override_tokens:
        key, val = tok.split("=", 1)
        entries[key.strip()] = [val.strip()]


def _extract_idmap(entries: Dict[str, List[str]]) -> Dict[str, str]:
    """Return uidmap / gidmap strings if present."""
    uidmap = gidmap = None
    for val in entries.get("lxc.idmap", []):
        m = _IDMAP_RE.match(f"lxc.idmap = {val}")
        if not m:
            continue
        tag, start, size, count = m.groups()
        mapping = f"{start} {size} {count}"
        if tag == "u":
            uidmap = mapping
        else:
            gidmap = mapping
    return {"uidmap": uidmap, "gidmap": gidmap}


def _extract_cap_drop(entries: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """Return list of dropped capabilities."""
    drops: List[str] = []
    for val in entries.get("lxc.cap.drop", []):
        m = _CAPDROP_RE.match(f"lxc.cap.drop = {val}")
        if m:
            drops.extend(m.group(1).split())
    return {"cap_drop": drops or None}


def _parse_mount_entry(entry: str) -> Dict[str, str]:
    """
    Given a single ``lxc.mount.entry`` line, return mapping:

        {"source": str, "options": str}
    """
    parts = entry.split("=", 1)[-1].strip().split()
    source = parts[0] if parts else ""
    options = parts[-1] if parts else ""
    return {"source": source, "options": options}


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------


def scan(mount_path: str, context: ScanContext | None = None) -> Dict[str, object]:
    """
    Scan LXC container configs under *mount_path*.

    Raises
    ------
    ValueError
        If *context* is None (must be supplied by core.run_scan).
    """
    if context is None:
        raise ValueError("ScanContext must be supplied by core.run_scan")

    all_rules = load_json_config(RULE_PATH).get("rules", [])
    config_rules = [r for r in all_rules if not r["id"].startswith("mount_")]
    mount_rules = [r for r in all_rules if r["id"].startswith("mount_")]

    results: List[Dict[str, object]] = []
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
            rc_abs = safe_join(mount_path, rcfile_path.lstrip("/"))
            if rc_abs and rc_abs.is_file():
                rc_entries = _parse_lxc_config(rc_abs)
                entries = _merge_entries(entries, rc_entries)

        # apply -s/--define overrides (highest priority)
        if override_tokens:
            _apply_cli_overrides(entries, override_tokens)

        idmap_info = _extract_idmap(entries)
        capdrop_info = _extract_cap_drop(entries)

        # infer runs_as_root from context or missing mappings
        systemd_root = context.is_systemd_started("lxc", container_name) and context.is_user_missing(container_name)
        mapping_root = idmap_info.get("uidmap") is None or idmap_info.get("gidmap") is None
        runs_as_root = systemd_root or mapping_root

        base_data = {**idmap_info, **capdrop_info, "runs_as_root": runs_as_root}

        # ------------------ config rules ------------------
        config_vios_raw = evaluate_rules(base_data, config_rules)
        config_vios = []
        for v in config_vios_raw:
            used_fields = {c.get("field") for c in v.get("conditions", []) if c.get("field")}
            v["source"] = "/" + os.path.relpath(cfg_path, mount_path)
            v["lines"] = []
            for f in used_fields:
                cfg_key = _FIELD_TO_CONFIG_KEY.get(f, f)
                raw_lines = entries.get(cfg_key)
                if raw_lines:
                    v["lines"].extend(raw_lines)
                else:
                    v["lines"].append(f"<missing> {cfg_key}")
            config_vios.append(v)

        # ------------------ mount rules -------------------
        mount_results = []
        for line in entries.get("lxc.mount.entry", []):
            mentry = _parse_mount_entry(line)
            vios_raw = evaluate_rules(mentry, mount_rules)
            vios = []
            for v in vios_raw:
                used_fields = {c.get("field") for c in v.get("conditions", []) if c.get("field")}
                v["source"] = "/" + os.path.relpath(cfg_path, mount_path)
                v["lines"] = [line] if line else []
                for f in used_fields - {"source", "options"}:
                    v["lines"].append(f"<missing> {f}")
                vios.append(v)
            mount_results.extend(vios)

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

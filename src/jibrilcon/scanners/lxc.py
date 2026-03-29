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
    "namespace_sharing_enabled": "lxc.namespace.share.*",
    "namespace_keep_enabled": "lxc.namespace.keep",
    "mount_auto_dangerous": "lxc.mount.auto",
    "selinux_unconfined": "lxc.selinux.context",
    "apparmor_nesting_dangerous": "lxc.apparmor.allow_nesting/allow_incomplete/raw",
    "seccomp_nesting_enabled": "lxc.seccomp.allow_nesting",
    "cgroup_devices_unrestricted": "lxc.cgroup.devices.allow",
    "memory_limit_missing": "lxc.cgroup.memory.limit_in_bytes",
    "nproc_limit_missing": "lxc.prlimit.nproc",
    "rootfs_not_readonly": "lxc.rootfs.options",
    "systemd_service_found": "systemd.service",
    "systemd_caps_unrestricted": "systemd.CapabilityBoundingSet",
    "nested_lxc_detected": "lxc.rootfs.path (contains lxc-start)",
    "has_dangerous_mount_options": "lxc.mount.entry (options)",
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


def _extract_namespace_sharing(entries: dict[str, list[str]]) -> dict[str, bool]:
    """Check for explicit namespace sharing with other containers or host."""
    share_keys = [
        "lxc.namespace.share.net",
        "lxc.namespace.share.ipc",
        "lxc.namespace.share.pid",
        "lxc.namespace.share.uts",
        "lxc.namespace.share.mnt",
        "lxc.namespace.share.user",
    ]
    has_sharing = any(entries.get(k) for k in share_keys)
    return {"namespace_sharing_enabled": has_sharing}


def _extract_namespace_keep(entries: dict[str, list[str]]) -> dict[str, bool]:
    """Check if namespaces are explicitly kept (NOT isolated from host)."""
    vals = entries.get("lxc.namespace.keep", [])
    has_keep = any(isinstance(v, str) and v.strip() for v in vals)
    return {"namespace_keep_enabled": has_keep}


def _extract_mount_auto(entries: dict[str, list[str]]) -> dict[str, bool]:
    """Check if lxc.mount.auto contains dangerous writable mounts."""
    dangerous_patterns = {"proc:rw", "sys:rw", "cgroup:rw", "cgroup2:rw"}
    vals = entries.get("lxc.mount.auto", [])
    has_dangerous = False
    for val in vals:
        if not isinstance(val, str):
            continue
        # lxc.mount.auto values are space-separated tokens
        tokens = val.strip().split()
        if any(t in dangerous_patterns for t in tokens):
            has_dangerous = True
            break
    return {"mount_auto_dangerous": has_dangerous}


def _extract_selinux_context(entries: dict[str, list[str]]) -> dict[str, bool]:
    """Check if SELinux context is explicitly set to unconfined."""
    vals = entries.get("lxc.selinux.context", [])
    if not vals:
        # SELinux not configured -- AppArmor may be in use instead.
        # Do not flag as unconfined.
        return {"selinux_unconfined": False}
    context = vals[-1].strip()
    selinux_unconfined = not context or "unconfined" in context.lower()
    return {"selinux_unconfined": selinux_unconfined}


def _extract_apparmor_nesting(entries: dict[str, list[str]]) -> dict[str, bool]:
    """Detect dangerous AppArmor nesting/incomplete/raw directives."""
    allow_nesting = any(
        v.strip() == "1"
        for v in entries.get("lxc.apparmor.allow_nesting", [])
        if isinstance(v, str)
    )
    allow_incomplete = any(
        v.strip() == "1"
        for v in entries.get("lxc.apparmor.allow_incomplete", [])
        if isinstance(v, str)
    )
    has_raw = bool(entries.get("lxc.apparmor.raw"))
    return {"apparmor_nesting_dangerous": allow_nesting or allow_incomplete or has_raw}


def _extract_seccomp_nesting(entries: dict[str, list[str]]) -> dict[str, bool]:
    """Detect seccomp nesting which weakens privilege boundary."""
    allow_nesting = any(
        v.strip() == "1"
        for v in entries.get("lxc.seccomp.allow_nesting", [])
        if isinstance(v, str)
    )
    return {"seccomp_nesting_enabled": allow_nesting}


def _extract_cgroup_devices(entries: dict[str, list[str]]) -> dict[str, bool]:
    """Detect unrestricted device access via cgroup device allow rules."""
    dangerous_patterns = {"a", "a *:* rwm", "c *:* rwm", "b *:* rwm", "c 1:* rwm"}
    allows = entries.get("lxc.cgroup.devices.allow", []) + entries.get(
        "lxc.cgroup2.devices.allow", []
    )
    has_dangerous = any(
        isinstance(v, str) and v.strip() in dangerous_patterns for v in allows
    )
    return {"cgroup_devices_unrestricted": has_dangerous}


def _extract_resource_limits(entries: dict[str, list[str]]) -> dict[str, bool]:
    """Check for missing resource limits."""
    mem_vals = entries.get("lxc.cgroup.memory.limit_in_bytes", []) + entries.get(
        "lxc.cgroup2.memory.max", []
    )
    memory_limit_missing = not any(isinstance(v, str) and v.strip() for v in mem_vals)

    nproc_vals = entries.get("lxc.prlimit.nproc", [])
    nproc_limit_missing = not any(isinstance(v, str) and v.strip() for v in nproc_vals)

    return {
        "memory_limit_missing": memory_limit_missing,
        "nproc_limit_missing": nproc_limit_missing,
    }


def _extract_rootfs_readonly(entries: dict[str, list[str]]) -> dict[str, bool]:
    """Check if rootfs is mounted read-only."""
    vals = entries.get("lxc.rootfs.options", [])
    is_ro = any(isinstance(v, str) and "ro" in v.split(",") for v in vals)
    return {"rootfs_not_readonly": not is_ro}


def _extract_fstab_entries(entries: dict[str, list[str]], rootfs: str) -> list[str]:
    """Read lxc.mount.fstab referenced file and return mount lines."""
    vals = entries.get("lxc.mount.fstab", [])
    if not vals:
        return []
    fstab_path = vals[-1].strip()
    if not fstab_path:
        return []
    try:
        abs_path = safe_join(rootfs, fstab_path.lstrip("/"))
    except ValueError:
        return []
    if not abs_path.is_file():
        return []
    try:
        text = abs_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    mount_lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            mount_lines.append(stripped)
    return mount_lines


def _extract_nested_lxc(entries: dict[str, list[str]], rootfs: str) -> dict[str, bool]:
    """Detect LXC installation inside container (nested LXC)."""
    rootfs_path_val = entries.get("lxc.rootfs.path", [""])[-1].strip()
    if not rootfs_path_val:
        return {"nested_lxc_detected": False}
    try:
        container_rootfs = safe_join(rootfs, rootfs_path_val.lstrip("/"))
    except ValueError:
        return {"nested_lxc_detected": False}
    lxc_binaries = ["usr/bin/lxc-start", "usr/sbin/lxc-start", "usr/bin/lxc-create"]
    for binary in lxc_binaries:
        try:
            check = safe_join(str(container_rootfs), binary)
            if check.is_file():
                return {"nested_lxc_detected": True}
        except (ValueError, OSError):
            continue
    return {"nested_lxc_detected": False}


_DANGEROUS_MOUNT_OPTS = frozenset({"rbind", "loop", "remount"})


def _parse_mount_entry(entry: str) -> dict[str, str | bool]:
    """
    Given a single ``lxc.mount.entry`` line, return mapping:

        {"source": str, "options": str, "has_dangerous_mount_options": bool}

    lxc.mount.entry format (fstab-style):
        <source> <dest> <type> <options> [<dump> <pass>]
    """
    parts = entry.split("=", 1)[-1].strip().split()
    source = parts[0] if parts else ""
    # options are at index 3 (fstab field 4)
    options = parts[3] if len(parts) >= 4 else ""
    has_dangerous_mount_options = (
        bool(set(options.split(",")) & _DANGEROUS_MOUNT_OPTS) if options else False
    )
    return {
        "source": source,
        "options": options,
        "has_dangerous_mount_options": has_dangerous_mount_options,
    }


# ---------------------------------------------------------------------
# Shared per-container analysis helper
# ---------------------------------------------------------------------

_MOUNT_ENTRY_RULE_IDS = frozenset(
    {
        "mount_proc_dangerous",
        "mount_sys_dangerous",
        "mount_run_dangerous",
        "mount_usr_should_be_ro",
        "mount_dev_should_be_ro",
        "mount_dangerous_options",
    }
)


def _analyze_lxc_container(
    container_name: str,
    cfg_path: Path,
    entries: dict[str, list[str]],
    context: ScanContext,
    config_rules: list[dict],
    mount_rules: list[dict],
    mount_path: str,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    """
    Analyse one LXC container.

    Parameters
    ----------
    container_name : str
        Logical container name (typically directory name).
    cfg_path : Path
        Resolved config file path on the host filesystem.
    entries : dict
        Already-merged (base + rcfile + CLI overrides) config entries.
    context : ScanContext
        Thread-safe shared state.
    config_rules, mount_rules : list[dict]
        Pre-split rule lists.
    mount_path : str
        Mounted rootfs path.

    Returns
    -------
    (base_data, all_violations)
    """
    idmap_info = _extract_idmap(entries)
    capdrop_info = _extract_cap_drop(entries)
    apparmor_info = _extract_apparmor_profile(entries)
    net_info = _extract_net_type(entries)
    privs_info = _extract_no_new_privs(entries)
    seccomp_info = _extract_seccomp_profile(entries)
    capkeep_info = _extract_cap_keep(entries)
    ns_share_info = _extract_namespace_sharing(entries)
    ns_keep_info = _extract_namespace_keep(entries)
    mount_auto_info = _extract_mount_auto(entries)
    selinux_info = _extract_selinux_context(entries)
    aa_nesting_info = _extract_apparmor_nesting(entries)
    seccomp_nesting_info = _extract_seccomp_nesting(entries)
    cgroup_dev_info = _extract_cgroup_devices(entries)
    resource_info = _extract_resource_limits(entries)
    rootfs_ro_info = _extract_rootfs_readonly(entries)
    nested_lxc_info = _extract_nested_lxc(entries, mount_path)

    # infer runs_as_root from context or missing mappings
    systemd_root = context.is_systemd_started(
        "lxc", container_name
    ) and context.is_user_missing(container_name)
    mapping_root = idmap_info.get("uidmap") is None and idmap_info.get("gidmap") is None
    runs_as_root = systemd_root or mapping_root

    # Systemd service cross-validation (automotive: all containers
    # MUST have a corresponding systemd service)
    svc_meta = context.get_service_meta("lxc", container_name)
    systemd_service_found = bool(svc_meta)
    systemd_caps_unrestricted = systemd_service_found and not svc_meta.get(
        "cap_bounding_set"
    )

    base_data: dict[str, object] = {
        **idmap_info,
        **capdrop_info,
        **apparmor_info,
        **net_info,
        **privs_info,
        **seccomp_info,
        **capkeep_info,
        **ns_share_info,
        **ns_keep_info,
        **mount_auto_info,
        **selinux_info,
        **aa_nesting_info,
        **seccomp_nesting_info,
        **cgroup_dev_info,
        **resource_info,
        **rootfs_ro_info,
        **nested_lxc_info,
        "runs_as_root": runs_as_root,
        "systemd_service_found": systemd_service_found,
        "systemd_caps_unrestricted": systemd_caps_unrestricted,
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
    mount_results: list[dict[str, object]] = []

    # Collect mount lines from lxc.mount.entry
    all_mount_lines: list[str] = [
        line for line in entries.get("lxc.mount.entry", []) if isinstance(line, str)
    ]

    # Also collect mount lines from lxc.mount.fstab referenced file
    fstab_lines = _extract_fstab_entries(entries, mount_path)
    all_mount_lines.extend(fstab_lines)

    for line in all_mount_lines:
        mentry = _parse_mount_entry(line)
        vios_raw = evaluate_rules(mentry, mount_rules)

        def _resolve_mount_lines(_v, used_fields, _line=line):
            lines = [_line] if _line else []
            for f in used_fields - {"source", "options", "has_dangerous_mount_options"}:
                lines.append(f"<missing> {f}")
            return lines

        mount_results.extend(
            process_violations(
                vios_raw, str(cfg_path), mount_path, _resolve_mount_lines
            )
        )

    all_vios = config_vios + mount_results
    return base_data, all_vios


def _prepare_entries(
    container_name: str,
    cfg_path: Path,
    context: ScanContext,
    mount_path: str,
) -> dict[str, list[str]]:
    """
    Load, merge rcfile, and apply CLI overrides for a single container.

    Returns the fully merged config entries dict.
    """
    # 1) load default config
    entries = _parse_lxc_config(cfg_path)

    # 2) acquire Exec* command lines
    exec_lines = context.get_exec_lines("lxc", container_name)
    if not exec_lines:
        exec_lines = _find_systemd_exec_lines(mount_path, container_name)

    # 3) derive rcfile / -s CLI overrides
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

    return entries


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------


def scan(mount_path: str, context: ScanContext | None = None) -> dict[str, object]:
    """
    Scan LXC container configs under *mount_path*.

    Discovery model
    ---------------
    Phase 1 (systemd-driven):
        Process containers that ScanContext knows about from systemd
        services first.  If a systemd-registered container has no
        matching config on disk, emit a ``systemd_service_broken``
        violation.

    Phase 2 (file-path sweep):
        Walk rootfs for all LXC configs (existing os.walk logic), skip
        those already handled in Phase 1, mark remainder as orphaned
        (``managed=False``).

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
    # Mount-entry rules operate on per-entry dicts (source/options fields);
    # mount_auto_dangerous evaluates base_data so it belongs in config_rules.
    mount_rules = [r for r in all_rules if r["id"] in _MOUNT_ENTRY_RULE_IDS]
    config_rules = [r for r in all_rules if r["id"] not in _MOUNT_ENTRY_RULE_IDS]

    results: list[dict[str, object]] = []
    alert_count = warning_count = total_containers = 0
    start_ts = time.time()

    # ----- Discover all configs on disk (os.walk preserved) -----
    all_cfgs = _get_lxc_rootfs_config_candidates(mount_path)
    active_cfgs = _filter_active_lxc_configs(all_cfgs, mount_path)

    # Build name -> cfg_path lookup for on-disk configs
    on_disk: dict[str, Path] = {
        cfg_path.parent.name: cfg_path for cfg_path in active_cfgs
    }

    # Track names handled in Phase 1 so Phase 2 skips them
    phase1_names: set[str] = set()

    # ----- Phase 1: systemd-driven containers -----
    systemd_names = context.get_started_containers("lxc")
    for name in sorted(systemd_names):
        phase1_names.add(name)
        cfg_path = on_disk.get(name)

        if cfg_path is None:
            # Broken service: systemd says container exists but config
            # is not found on disk.
            svc_meta = context.get_service_meta("lxc", name)
            svc_path = svc_meta.get("path", "<unknown>")
            broken_vio: dict[str, object] = {
                "id": "systemd_service_broken",
                "type": "alert",
                "severity": 8.0,
                "description": (
                    "Systemd service references an LXC container whose "
                    "configuration was not found on disk"
                ),
                "risk": (
                    "The systemd service will fail to start this container "
                    "at boot via lxc-start. This may indicate a deleted "
                    "container, moved config, or filesystem corruption."
                ),
                "remediation": (
                    "Verify the LXC container config exists, or remove "
                    "the obsolete systemd service."
                ),
                "source": f"/{svc_path}",
                "lines": [f"Container '{name}' not found in any LXC config path"],
            }
            results.append(
                {
                    "container": name,
                    "violations": [broken_vio],
                    "status": "violated",
                    "managed": True,
                }
            )
            alert_count += 1
            total_containers += 1
            continue

        entries = _prepare_entries(name, cfg_path, context, mount_path)
        base_data, all_vios = _analyze_lxc_container(
            name, cfg_path, entries, context, config_rules, mount_rules, mount_path
        )

        status = "violated" if all_vios else "clean"
        if any(v["type"] == "alert" for v in all_vios):
            alert_count += 1
        elif any(v["type"] == "warning" for v in all_vios):
            warning_count += 1

        results.append(
            {
                "container": name,
                "violations": all_vios,
                "status": status,
                "managed": True,
            }
        )
        total_containers += 1

    # ----- Phase 2: file-path sweep (orphaned containers) -----
    for name in sorted(on_disk):
        if name in phase1_names:
            continue  # already handled in Phase 1

        cfg_path = on_disk[name]
        entries = _prepare_entries(name, cfg_path, context, mount_path)
        base_data, all_vios = _analyze_lxc_container(
            name, cfg_path, entries, context, config_rules, mount_rules, mount_path
        )

        status = "violated" if all_vios else "clean"
        if any(v["type"] == "alert" for v in all_vios):
            alert_count += 1
        elif any(v["type"] == "warning" for v in all_vios):
            warning_count += 1

        results.append(
            {
                "container": name,
                "violations": all_vios,
                "status": status,
                "managed": False,
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

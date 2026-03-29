# Copyright (c) 2025 IanYHChu
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for full license information.

"""
podman.py

Statically analyse Podman container configuration files located in a
mounted root filesystem image.

Discovery model
---------------
Phase 1 (systemd-driven): Process containers that ScanContext knows about
from systemd services FIRST.  These are "managed" containers.

Phase 2 (file-path sweep): Discover all containers from file paths, skip
those already handled in Phase 1, mark remainder as orphaned (managed=False).

Broken service detection: If systemd says a container should exist but its
config is NOT on disk, emit a ``systemd_service_broken`` violation.

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

_CRITICAL_MASKED = frozenset(
    {"/proc/kcore", "/proc/sysrq-trigger", "/proc/mem", "/proc/kmsg"}
)

_CRITICAL_READONLY = frozenset({"/proc/sys", "/proc/irq", "/proc/bus", "/sys/firmware"})

_DANGEROUS_BIND_PATHS = frozenset(
    {
        "/",
        "/proc",
        "/sys",
        "/dev",
        "/etc",
        "/root",
        "/home",
        "/var/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/var/run/crio/crio.sock",
    }
)

_DANGEROUS_DEVICE_PATHS = frozenset(
    {"/dev/mem", "/dev/kmem", "/dev/port", "/dev/sda", "/dev/fuse"}
)

_SENSITIVE_ENV_RE = re.compile(
    r"(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|AWS_ACCESS|AWS_SECRET"
    r"|LD_PRELOAD|LD_LIBRARY_PATH)=",
    re.IGNORECASE,
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
    "dangerous_bind_path": "mounts[].source",
    "no_new_privileges_missing": "process.noNewPrivileges",
    "apparmor_disabled": "process.apparmorProfile",
    "mount_propagation_shared": "mounts[].options",
    "memory_limit_missing": "linux.resources.memory.limit",
    "pids_limit_missing": "linux.resources.pids.limit",
    "critical_masks_missing": "linux.maskedPaths",
    "runtime_mode": "runtime_mode",
    "critical_readonly_missing": "linux.readonlyPaths",
    "selinux_privileged": "process.selinuxLabel",
    "systemd_service_found": "systemd.service",
    "systemd_user": "systemd.User",
    "systemd_caps_unrestricted": "systemd.CapabilityBoundingSet",
    "dangerous_devices_allowed": "linux.devices",
    "rootfs_propagation_shared": "linux.rootfsPropagation",
    "sensitive_env_detected": "process.env",
    "containers_conf_no_seccomp": "containers.conf.seccomp_profile",
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

    try:
        with open(cfg_path, encoding="utf-8") as fh:
            for line in fh:
                # Match both quoted ("...") and unquoted values
                m = re.match(r'^\s*graphRoot\s*=\s*(?:"(.*?)"|(\S+))', line)
                if m:
                    return m.group(1) or m.group(2)
    except OSError as exc:
        logger.warning("Cannot read %s: %s", cfg_path, exc)
    return "/var/lib/containers/storage"


def _get_user_podman_roots(rootfs: str) -> list[str]:
    """Return rootless Podman storage directories under each user's home."""
    return [
        os.path.join(home, ".local/share/containers/storage")
        for home in get_user_home_dirs(rootfs)
    ]


def _discover_configs(rootfs: str) -> list[tuple[str, str, str]]:
    """
    Return list of *(container_name, config_path, runtime_mode)* tuples.

    *runtime_mode* is ``"rootful"`` or ``"rootless"``.
    """
    try:
        data_root = _get_podman_data_root(rootfs).lstrip("/")
        roots_rootful = [str(safe_join(rootfs, data_root))]
    except ValueError as exc:
        logger.warning("Skipping Podman data-root: %s", exc)
        roots_rootful = []
    roots_rootless = _get_user_podman_roots(rootfs)

    discovered: list[tuple[str, str, str]] = []

    for base, mode in [(r, "rootful") for r in roots_rootful] + [
        (r, "rootless") for r in roots_rootless
    ]:
        index_path = os.path.join(base, "overlay-containers", "containers.json")
        if not os.path.exists(index_path):
            continue

        index_data = load_json_or_empty(index_path)
        for entry in index_data:
            cid = entry.get("id")
            if not cid:
                continue
            names = entry.get("names", [])
            name = names[0] if names else cid[:_CONTAINER_ID_DISPLAY_LEN]
            cfg_path = os.path.join(
                base, "overlay-containers", cid, "userdata", "config.json"
            )
            if os.path.exists(cfg_path):
                discovered.append((name, cfg_path, mode))
    return discovered


def _extract_containers_conf_defaults(rootfs: str) -> dict[str, Any]:
    """Check system-level containers.conf for weak defaults."""
    conf_path = os.path.join(rootfs, "etc/containers/containers.conf")
    if not os.path.exists(conf_path):
        return {"containers_conf_missing": True, "containers_conf_no_seccomp": False}
    try:
        with open(conf_path, "rb") as fh:
            data = toml.load(fh)
    except (OSError, ValueError, KeyError):
        return {"containers_conf_missing": False, "containers_conf_no_seccomp": False}
    containers_section = data.get("containers", {})
    seccomp_profile = containers_section.get("seccomp_profile", "")
    return {
        "containers_conf_missing": False,
        "containers_conf_no_seccomp": not seccomp_profile,
    }


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
    caps_ambient = caps_obj.get("ambient", [])
    if not isinstance(caps_ambient, list):
        caps_ambient = []
    caps_inheritable = caps_obj.get("inheritable", [])
    if not isinstance(caps_inheritable, list):
        caps_inheritable = []
    caps_permitted = caps_obj.get("permitted", [])
    if not isinstance(caps_permitted, list):
        caps_permitted = []

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

    # Dangerous capabilities in any of the 5 OCI capability sets
    all_caps = (
        set(caps_bounding)
        | set(caps_effective)
        | set(caps_ambient)
        | set(caps_inheritable)
        | set(caps_permitted)
    )
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

    # --- Dangerous bind paths ---
    dangerous_bind_path = any(
        isinstance(m, dict)
        and m.get("type") == "bind"
        and m.get("source", "") in _DANGEROUS_BIND_PATHS
        for m in mounts
    )

    # --- no-new-privileges ---
    no_new_privs = cfg.get("process", {}).get("noNewPrivileges", False)
    no_new_privileges_missing = no_new_privs is not True

    # --- AppArmor disabled ---
    aa_profile = cfg.get("process", {}).get("apparmorProfile", "")
    apparmor_disabled = aa_profile == "unconfined"

    # --- Mount propagation shared/rshared ---
    mount_propagation_shared = any(
        isinstance(m, dict)
        and ("shared" in m.get("options", []) or "rshared" in m.get("options", []))
        for m in mounts
    )

    # OCI resource limits
    resources = cfg.get("linux", {}).get("resources", {})
    memory_cfg = resources.get("memory", {})
    memory_limit = memory_cfg.get("limit") if isinstance(memory_cfg, dict) else None
    memory_limit_missing = memory_limit is None or memory_limit <= 0

    pids_cfg = resources.get("pids", {})
    pids_limit = pids_cfg.get("limit") if isinstance(pids_cfg, dict) else None
    pids_limit_missing = pids_limit is None or pids_limit <= 0

    # Critical kernel interfaces that should be masked
    masked_paths = set(cfg.get("linux", {}).get("maskedPaths", []))
    critical_masks_missing = bool(_CRITICAL_MASKED - masked_paths)

    # Critical readonly paths that should be present
    readonly_paths = set(cfg.get("linux", {}).get("readonlyPaths", []))
    critical_readonly_missing = bool(_CRITICAL_READONLY - readonly_paths)

    # SELinux label -- spc_t (super privileged container) is effectively unconfined
    selinux_label = cfg.get("process", {}).get("selinuxLabel", "")
    selinux_privileged = isinstance(selinux_label, str) and "spc_t" in selinux_label

    # Device allowlist -- check if dangerous host devices are exposed
    devices = cfg.get("linux", {}).get("devices", [])
    if not isinstance(devices, list):
        devices = []
    dangerous_devices_allowed = any(
        isinstance(d, dict) and d.get("path", "") in _DANGEROUS_DEVICE_PATHS
        for d in devices
    )

    # rootfsPropagation -- shared/rshared allows mount escape
    rootfs_propagation = cfg.get("linux", {}).get("rootfsPropagation", "")
    rootfs_propagation_shared = rootfs_propagation in ("shared", "rshared")

    # Sensitive environment variables (secrets, preloads)
    process_env = cfg.get("process", {}).get("env", [])
    if not isinstance(process_env, list):
        process_env = []
    sensitive_env_detected = any(
        isinstance(e, str) and _SENSITIVE_ENV_RE.search(e) for e in process_env
    )

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
        "dangerous_bind_path": dangerous_bind_path,
        "no_new_privileges_missing": no_new_privileges_missing,
        "apparmor_disabled": apparmor_disabled,
        "mount_propagation_shared": mount_propagation_shared,
        "memory_limit_missing": memory_limit_missing,
        "pids_limit_missing": pids_limit_missing,
        "critical_masks_missing": critical_masks_missing,
        "critical_readonly_missing": critical_readonly_missing,
        "selinux_privileged": selinux_privileged,
        "dangerous_devices_allowed": dangerous_devices_allowed,
        "rootfs_propagation_shared": rootfs_propagation_shared,
        "sensitive_env_detected": sensitive_env_detected,
    }


def _analyze_container(
    name: str,
    cfg_path: str,
    runtime_mode: str,
    context: ScanContext,
    rules: list[dict[str, Any]],
    mount_path: str,
    conf_defaults: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Load config, apply overrides, evaluate rules. Return (data, vios).

    Shared analysis logic used by both Phase 1 (managed) and Phase 2
    (orphaned) to avoid code duplication.
    """
    # 1) load default config
    try:
        cfg_json = load_json_or_empty(resolve_path(cfg_path, mount_path))
    except RuntimeError as exc:
        logger.warning("Skipping container %s: %s", name, exc)
        return {}, []

    # 2) acquire Exec* command lines
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
                    else:
                        logger.warning(
                            "TOML module %s is not a dict (got %s), skipping",
                            mod_path,
                            type(mod_data).__name__,
                        )
                except (OSError, ValueError, KeyError) as exc:
                    logger.warning("Skipping malformed module %s: %s", mod_path, exc)

    data = _extract_fields(cfg_json)
    data["runtime_mode"] = runtime_mode
    if conf_defaults:
        data.update(conf_defaults)

    # merge systemd inference: flag if service lacks non-root User=
    data["service_user_missing"] = context.is_user_missing(name)

    # Systemd service cross-validation (automotive: all containers
    # MUST have a corresponding systemd service)
    svc_meta = context.get_service_meta("podman", name)
    data["systemd_service_found"] = bool(svc_meta)
    data["systemd_user"] = svc_meta.get("user", "")
    data["systemd_caps_unrestricted"] = bool(svc_meta) and not svc_meta.get(
        "cap_bounding_set"
    )

    vios_raw = evaluate_rules(data, rules)

    def _resolve_lines(_v: dict[str, Any], used_fields: set[str]) -> list[str]:
        lines = []
        for f in used_fields:
            cfg_key = _FIELD_TO_CONFIG_KEY.get(f, f)
            val: Any = cfg_json
            for part in cfg_key.split("."):
                val = val.get(part, {}) if isinstance(val, dict) else {}
            if val:
                lines.append(f"{cfg_key} = {val}")
            else:
                lines.append(f"<missing> {cfg_key}")
        return lines

    vios = process_violations(vios_raw, cfg_path, mount_path, _resolve_lines)
    return data, vios


def _make_broken_service_violation(name: str, service_path: str) -> dict[str, Any]:
    """Create a violation for a systemd service whose container is missing on disk."""
    return {
        "id": "systemd_service_broken",
        "type": "alert",
        "severity": 8.0,
        "description": (
            "Systemd service references a Podman container whose "
            "configuration was not found on disk"
        ),
        "risk": (
            "The systemd service will fail to start this container at boot. "
            "This may indicate a deleted container, misconfigured storage "
            "path, or filesystem corruption."
        ),
        "remediation": (
            "Verify the container exists and the Podman storage path is "
            "correct, or remove the obsolete systemd service."
        ),
        "source": f"/{service_path}",
        "lines": [f"Container '{name}' not found in any Podman storage root"],
    }


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------


def scan(mount_path: str, context: ScanContext | None = None) -> dict[str, Any]:
    """
    Scan Podman container configurations under *mount_path*.

    Uses a two-phase systemd-driven discovery model:

    **Phase 1** -- iterate containers known to systemd (managed).
    If a container's config is not found on disk, emit a
    ``systemd_service_broken`` violation.

    **Phase 2** -- sweep file paths for remaining containers not
    already processed in Phase 1 (orphaned, managed=False).

    Raises
    ------
    ValueError
        If *context* is None (must be supplied by core.run_scan).
    """
    if context is None:
        raise ValueError("podman: ScanContext must be supplied by core.run_scan")

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

    # Extract system-level containers.conf defaults (once, shared)
    conf_defaults = _extract_containers_conf_defaults(mount_path)

    # Build lookup of all containers found on disk
    disk_configs = _discover_configs(mount_path)
    disk_lookup: dict[str, tuple[str, str]] = {}
    for name, cfg_path, runtime_mode in disk_configs:
        disk_lookup[name] = (cfg_path, runtime_mode)

    # Track which on-disk containers are consumed by Phase 1
    phase1_names: set[str] = set()

    # -----------------------------------------------------------------
    # Phase 1: systemd-driven (managed containers)
    # -----------------------------------------------------------------
    systemd_names = context.get_started_containers("podman")
    for name in sorted(systemd_names):
        phase1_names.add(name)

        if name not in disk_lookup:
            # Broken service: systemd references container but config not on disk
            svc_meta = context.get_service_meta("podman", name)
            service_path = svc_meta.get("path", "unknown")
            vios = [_make_broken_service_violation(name, service_path)]
            alert_count += 1
            containers[name] = {
                "container": name,
                "violations": vios,
                "status": "violated",
                "managed": True,
            }
            continue

        cfg_path, runtime_mode = disk_lookup[name]
        data, vios = _analyze_container(
            name,
            cfg_path,
            runtime_mode,
            context,
            rules,
            mount_path,
            conf_defaults=conf_defaults,
        )
        if not data and not vios:
            # _analyze_container returned empty due to read error
            continue

        status = "violated" if vios else "clean"
        if any(v["type"] == "alert" for v in vios):
            alert_count += 1
        elif any(v["type"] == "warning" for v in vios):
            warn_count += 1

        containers[name] = {
            "container": name,
            "violations": vios,
            "status": status,
            "managed": True,
        }

    # -----------------------------------------------------------------
    # Phase 2: file-path sweep (orphaned containers)
    # -----------------------------------------------------------------
    for name, cfg_path, runtime_mode in disk_configs:
        if name in phase1_names:
            continue  # already handled in Phase 1

        data, vios = _analyze_container(
            name,
            cfg_path,
            runtime_mode,
            context,
            rules,
            mount_path,
            conf_defaults=conf_defaults,
        )
        if not data and not vios:
            continue

        status = "violated" if vios else "clean"
        if any(v["type"] == "alert" for v in vios):
            alert_count += 1
        elif any(v["type"] == "warning" for v in vios):
            warn_count += 1

        containers[name] = {
            "container": name,
            "violations": vios,
            "status": status,
            "managed": False,
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

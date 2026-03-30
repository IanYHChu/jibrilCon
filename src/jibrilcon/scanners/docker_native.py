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

# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
RULE_PATH = BASE_DIR.parent / "rules" / "docker_config_rules.json"

_CONTAINER_ID_DISPLAY_LEN = 12

_CONFIG_RE = re.compile(r"(?:^|\s)--config\s+(?P<confdir>\S+)")

# Capabilities considered dangerous when added to a container.
# Docker may store caps with or without the "CAP_" prefix.
_DANGEROUS_CAPS = frozenset(
    {
        "SYS_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "NET_RAW",
        "NET_ADMIN",
    }
)

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

# Map rule field names to JSON keys (for pretty printing if needed)
_FIELD_TO_CONFIG_KEY = {
    "privileged": "HostConfig.Privileged",
    "readonly_rootfs": "HostConfig.ReadonlyRootfs",
    "binds_not_readonly": "HostConfig.Binds",
    "seccomp_disabled": "HostConfig.SecurityOpt",
    "service_user_missing": "service_user_missing",
    "pid_mode_is_host": "HostConfig.PidMode",
    "network_mode_is_host": "HostConfig.NetworkMode",
    "ipc_mode_is_host": "HostConfig.IpcMode",
    "dangerous_caps_added": "HostConfig.CapAdd",
    "cap_drop_missing": "HostConfig.CapDrop",
    "apparmor_disabled": "HostConfig.SecurityOpt",
    "dangerous_bind_path": "HostConfig.Binds",
    "no_new_privileges_missing": "HostConfig.SecurityOpt",
    "mount_propagation_shared": "HostConfig.Binds",
    "image_tag_latest": "Config.Image",
    "runtime_mode": "runtime_mode",
    "container_user_is_root": "Config.User",
    "memory_limit_missing": "HostConfig.Memory",
    "pids_limit_missing": "HostConfig.PidsLimit",
    "restart_always": "HostConfig.RestartPolicy",
    "logging_disabled": "HostConfig.LogConfig",
    "daemon_userns_remap_missing": "/etc/docker/daemon.json userns-remap",
    "daemon_icc_enabled": "/etc/docker/daemon.json icc",
    "dangerous_device_cgroup": "HostConfig.DeviceCgroupRules",
    "dangerous_device_mounted": "HostConfig.Devices",
    "socket_mount_writable": "HostConfig.Binds",
    "has_extra_hosts": "HostConfig.ExtraHosts",
    "ulimits_excessive": "HostConfig.Ulimits",
    "selinux_privileged": "HostConfig.SecurityOpt",
    "systemd_service_found": "systemd.service",
    "systemd_user": "systemd.User",
    "systemd_caps_unrestricted": "systemd.CapabilityBoundingSet",
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


def _get_user_docker_roots(rootfs: str) -> list[str]:
    """
    Return a list of rootless Docker data directories discovered in each
    user's home directory.
    """
    return [
        os.path.join(home, ".local/share/docker") for home in get_user_home_dirs(rootfs)
    ]


def _discover_container_dirs(rootfs: str) -> list[tuple[str, str, str, str]]:
    """
    Return a list of tuples:

        (container_name, config_path, hostconfig_path, runtime_mode)

    runtime_mode is "rootful" or "rootless".
    """
    try:
        data_root = _get_docker_data_root(rootfs).lstrip("/")
        roots_rootful = [str(safe_join(rootfs, data_root))]
    except ValueError as exc:
        logger.warning("Skipping Docker data-root: %s", exc)
        roots_rootful = []
    roots_rootless = _get_user_docker_roots(rootfs)

    discovered: list[tuple[str, str, str, str]] = []

    for base, mode in [(r, "rootful") for r in roots_rootful] + [
        (r, "rootless") for r in roots_rootless
    ]:
        cont_dir = os.path.join(base, "containers")
        if not os.path.isdir(cont_dir):
            continue

        try:
            cid_list = os.listdir(cont_dir)
        except OSError as exc:
            logger.warning("Cannot list containers in %s: %s", cont_dir, exc)
            continue
        for cid in cid_list:
            cdir = os.path.join(cont_dir, cid)
            cfg = os.path.join(cdir, "config.v2.json")
            host = os.path.join(cdir, "hostconfig.json")
            if os.path.exists(cfg) and os.path.exists(host):
                name = cid[:_CONTAINER_ID_DISPLAY_LEN]
                # try to read name from config
                cfg_json = load_json_or_empty(cfg)
                name = cfg_json.get("Name", "").lstrip("/") or name
                discovered.append((name, cfg, host, mode))
    return discovered


def _extract_daemon_fields(rootfs: str) -> dict[str, Any]:
    """Extract security fields from /etc/docker/daemon.json."""
    cfg = load_json_or_empty(os.path.join(rootfs, "etc/docker/daemon.json"))
    if not cfg:
        return {
            "daemon_userns_remap_missing": True,
            "daemon_icc_enabled": True,
        }
    return {
        "daemon_userns_remap_missing": "userns-remap" not in cfg,
        "daemon_icc_enabled": cfg.get("icc", True) is not False,
    }


def _extract_fields(cfg: dict[str, Any], host: dict[str, Any]) -> dict[str, Any]:
    """Pick out the fields needed by rules_engine."""
    sec_opts = host.get("SecurityOpt") or []
    if not isinstance(sec_opts, list):
        logger.warning(
            "SecurityOpt is not a list, ignoring: %s", type(sec_opts).__name__
        )
        sec_opts = []
    binds = host.get("Binds") or []
    if not isinstance(binds, list):
        logger.warning("Binds is not a list, ignoring: %s", type(binds).__name__)
        binds = []

    # label=disable disables all MAC enforcement (SELinux/AppArmor),
    # which Docker sets automatically in --privileged mode.
    privileged_raw = host.get("Privileged", False) or ("label=disable" in sec_opts)
    privileged = _to_bool(privileged_raw)

    readonly_rootfs = _to_bool(host.get("ReadonlyRootfs", False))

    # Docker bind format: src:dst[:opts] where opts is comma-separated
    # (e.g. "ro", "ro,rslave"). A bind is readonly if "ro" appears in opts.
    def _bind_is_writable(b: str) -> bool:
        s = str(b)
        # Handle bracketed IPv6 addresses like [::1]:/mnt:ro
        if s.startswith("["):
            bracket_end = s.find("]")
            if bracket_end == -1:
                return True
            remainder = s[bracket_end + 1 :]
            # remainder starts with ":" separating src from dst
            parts = remainder.lstrip(":").split(":")
            # parts[0] is dst; parts[1:] are opts if present
            if len(parts) < 2:
                return True  # no options means default (rw)
            opts = parts[1].split(",")
        else:
            parts = s.split(":")
            if len(parts) < 3:
                return True  # no options means default (rw)
            opts = parts[2].split(",")
        return "ro" not in opts

    binds_not_readonly = any(_bind_is_writable(b) for b in binds)

    # Docker --mount syntax stores structured objects in HostConfig.Mounts
    mounts = host.get("Mounts") or []
    if not isinstance(mounts, list):
        logger.warning("Mounts is not a list, ignoring: %s", type(mounts).__name__)
        mounts = []
    mounts = [m for m in mounts if isinstance(m, dict) and m.get("Type") == "bind"]

    if not binds_not_readonly:
        binds_not_readonly = any(not m.get("ReadOnly", False) for m in mounts)

    seccomp_disabled = any(str(o).startswith("seccomp=unconfined") for o in sec_opts)

    # Host namespace sharing
    pid_mode_is_host = host.get("PidMode", "") == "host"
    network_mode_is_host = host.get("NetworkMode", "") == "host"
    ipc_mode_is_host = host.get("IpcMode", "") == "host"

    # Dangerous capabilities -- normalise away the optional "CAP_" prefix
    cap_add = host.get("CapAdd") or []
    if not isinstance(cap_add, list):
        logger.warning("CapAdd is not a list, ignoring: %s", type(cap_add).__name__)
        cap_add = []
    normalised_caps = {str(c).removeprefix("CAP_").upper() for c in cap_add}
    dangerous_caps_added = bool(normalised_caps & _DANGEROUS_CAPS)

    # No capabilities explicitly dropped
    cap_drop_missing = not (host.get("CapDrop") or [])

    # AppArmor disabled
    apparmor_disabled = any(str(o) == "apparmor=unconfined" for o in sec_opts)

    # --- Dangerous bind paths ---
    def _bind_src(b: str) -> str:
        return str(b).split(":")[0]

    dangerous_bind_path = any(
        _bind_src(b) in _DANGEROUS_BIND_PATHS for b in binds
    ) or any(m.get("Source", "") in _DANGEROUS_BIND_PATHS for m in mounts)

    # --- no-new-privileges ---
    no_new_privileges_missing = not any(
        str(o) == "no-new-privileges" or str(o) == "no-new-privileges=true"
        for o in sec_opts
    )

    # --- Mount propagation shared/rshared ---
    # Docker bind format: src:dst[:opts] where opts can include
    # propagation modes like "shared", "rshared", "slave", etc.
    def _has_shared_propagation(b: str) -> bool:
        parts = str(b).split(":")
        if len(parts) < 3:
            return False
        opts = parts[2].split(",")
        return "shared" in opts or "rshared" in opts

    mount_propagation_shared = any(_has_shared_propagation(b) for b in binds) or any(
        isinstance(m.get("BindOptions"), dict)
        and m["BindOptions"].get("Propagation") in ("shared", "rshared")
        for m in mounts
    )

    # --- Image tag :latest or missing ---
    image = cfg.get("Config", {}).get("Image", "") or cfg.get("Image", "")
    if isinstance(image, str) and image:
        has_digest = "@" in image
        img_no_digest = image.split("@")[0]
        if has_digest and ":" not in img_no_digest:
            # Image pinned by digest without explicit tag — not "latest"
            image_tag_latest = False
        elif ":" not in img_no_digest:
            image_tag_latest = True
        else:
            tag = img_no_digest.rsplit(":", 1)[-1]
            image_tag_latest = tag == "latest"
    else:
        image_tag_latest = False

    # Container user -- empty or "root" or "0" means UID 0 inside container
    user_raw = cfg.get("Config", {}).get("User", "")
    container_user_is_root = not user_raw or user_raw in ("root", "0")

    # Resource limits -- 0 or missing means unlimited
    memory_limit = host.get("Memory", 0)
    memory_limit_missing = not isinstance(memory_limit, int) or memory_limit <= 0
    pids_limit = host.get("PidsLimit", 0)
    # PidsLimit can be 0, -1, or None for unlimited
    pids_limit_missing = not isinstance(pids_limit, int) or pids_limit <= 0

    # Restart policy -- always or unless-stopped is a persistence vector
    restart_policy = host.get("RestartPolicy") or {}
    restart_always = restart_policy.get("Name") in ("always", "unless-stopped")

    # Logging -- disabled means no audit trail
    log_config = host.get("LogConfig") or {}
    logging_disabled = log_config.get("Type") == "none"

    # Dangerous device cgroup rules (e.g., "a *:* rwm" = all devices)
    device_cgroup_rules = host.get("DeviceCgroupRules") or []
    if not isinstance(device_cgroup_rules, list):
        device_cgroup_rules = []
    _DANGEROUS_DEVICE_RULES = {"a *:* rwm", "a *:* rw", "a *:* rm", "a *:* wm"}
    dangerous_device_cgroup = any(
        isinstance(r, str) and r.strip() in _DANGEROUS_DEVICE_RULES
        for r in device_cgroup_rules
    )

    # Dangerous individual device mappings
    _DANGEROUS_DEVICES = frozenset(
        {"/dev/mem", "/dev/kmem", "/dev/fuse", "/dev/net/tun", "/dev/sda", "/dev/port"}
    )
    devices = host.get("Devices") or []
    if not isinstance(devices, list):
        devices = []
    dangerous_device_mounted = any(
        isinstance(d, dict) and d.get("PathOnHost", "") in _DANGEROUS_DEVICES
        for d in devices
    )

    # Docker socket mounted writable (container escape vector)
    def _socket_writable(b: str) -> bool:
        s = str(b)
        parts = s.split(":")
        if len(parts) < 2:
            return False
        src = parts[0]
        _SOCKET_PATHS = {
            "/var/run/docker.sock",
            "/run/docker.sock",
            "/run/containerd/containerd.sock",
            "/var/run/crio/crio.sock",
        }
        if src not in _SOCKET_PATHS:
            return False
        if len(parts) < 3:
            return True  # no options = default rw
        return "ro" not in parts[2].split(",")

    _SOCKET_PATHS_SET = {
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/var/run/crio/crio.sock",
    }
    socket_mount_writable = any(_socket_writable(b) for b in binds) or any(
        m.get("Source", "") in _SOCKET_PATHS_SET and not m.get("ReadOnly", False)
        for m in mounts
    )

    # ExtraHosts -- custom /etc/hosts entries
    extra_hosts = host.get("ExtraHosts") or []
    if not isinstance(extra_hosts, list):
        extra_hosts = []
    has_extra_hosts = bool(extra_hosts)

    # Ulimits -- excessively high nofile limit
    ulimits = host.get("Ulimits") or []
    if not isinstance(ulimits, list):
        ulimits = []
    _ULIMIT_NOFILE_THRESHOLD = 1048576  # 1M file descriptors is excessive
    ulimits_excessive = any(
        isinstance(u, dict)
        and u.get("Name") == "nofile"
        and (
            u.get("Hard", 0) > _ULIMIT_NOFILE_THRESHOLD
            or u.get("Soft", 0) > _ULIMIT_NOFILE_THRESHOLD
        )
        for u in ulimits
    )

    # SELinux super-privileged container type (spc_t)
    selinux_privileged = any(
        isinstance(o, str) and "label=type:spc_t" in o for o in sec_opts
    )

    return {
        "privileged": privileged,
        "readonly_rootfs": readonly_rootfs,
        "binds_not_readonly": binds_not_readonly,
        "seccomp_disabled": seccomp_disabled,
        "pid_mode_is_host": pid_mode_is_host,
        "network_mode_is_host": network_mode_is_host,
        "ipc_mode_is_host": ipc_mode_is_host,
        "dangerous_caps_added": dangerous_caps_added,
        "cap_drop_missing": cap_drop_missing,
        "apparmor_disabled": apparmor_disabled,
        "dangerous_bind_path": dangerous_bind_path,
        "no_new_privileges_missing": no_new_privileges_missing,
        "mount_propagation_shared": mount_propagation_shared,
        "image_tag_latest": image_tag_latest,
        "container_user_is_root": container_user_is_root,
        "memory_limit_missing": memory_limit_missing,
        "pids_limit_missing": pids_limit_missing,
        "restart_always": restart_always,
        "logging_disabled": logging_disabled,
        "dangerous_device_cgroup": dangerous_device_cgroup,
        "dangerous_device_mounted": dangerous_device_mounted,
        "socket_mount_writable": socket_mount_writable,
        "has_extra_hosts": has_extra_hosts,
        "ulimits_excessive": ulimits_excessive,
        "selinux_privileged": selinux_privileged,
    }


# ---------------------------------------------------------------------
# Per-container analysis helper
# ---------------------------------------------------------------------


def _analyze_container(
    name: str,
    cfg_path: str,
    host_path: str,
    runtime_mode: str,
    context: ScanContext,
    rules: list[dict[str, Any]],
    mount_path: str,
    daemon_data: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], str]:
    """
    Load config, apply overrides, evaluate rules for a single container.

    Returns
    -------
    tuple[list[dict], str]
        (violations, status) where status is "violated" or "clean".
    """
    # 1) load default config
    try:
        cfg_json = load_json_or_empty(resolve_path(cfg_path, mount_path))
        host_json = load_json_or_empty(resolve_path(host_path, mount_path))
    except RuntimeError as exc:
        logger.warning("Skipping container %s: %s", name, exc)
        return [], "clean"

    # 2) acquire Exec* command lines
    exec_lines: list[str] = context.get_exec_lines("docker", name)
    override_cfg_dir: str | None = None
    for line in exec_lines:
        m = _CONFIG_RE.search(line)
        if m:
            override_cfg_dir = m.group("confdir")
            break

    if override_cfg_dir:
        try:
            conf_json_path = safe_join(
                mount_path,
                override_cfg_dir.lstrip("/"),
                "config.json",
            )
        except ValueError as exc:
            logger.warning("Skipping Docker config override: %s", exc)
            conf_json_path = None
        if conf_json_path and os.path.exists(conf_json_path):
            override_cfg = load_json_or_empty(conf_json_path)
            if override_cfg:
                # merge into main config
                deep_merge(cfg_json, override_cfg)
                # merge HostConfig block if provided
                host_override = override_cfg.get("HostConfig")
                if isinstance(host_override, dict):
                    deep_merge(host_json, host_override)

    data = _extract_fields(cfg_json, host_json)
    data["runtime_mode"] = runtime_mode
    if daemon_data:
        data.update(daemon_data)

    # merge systemd inference: service_user_missing flag
    data["service_user_missing"] = context.is_user_missing(name)

    # Systemd service cross-validation (automotive: all containers
    # MUST have a corresponding systemd service)
    svc_meta = context.get_service_meta("docker", name)
    data["systemd_service_found"] = bool(svc_meta)
    data["systemd_user"] = svc_meta.get("user", "")
    data["systemd_caps_unrestricted"] = bool(svc_meta) and not svc_meta.get(
        "cap_bounding_set"
    )

    vios_raw = evaluate_rules(data, rules)

    def _resolve_lines(_v: Any, used_fields: set[str]) -> list[str]:
        lines: list[str] = []
        for f in used_fields:
            cfg_key = _FIELD_TO_CONFIG_KEY.get(f, f)
            val: Any = cfg_json if "HostConfig" not in cfg_key else host_json
            for part in cfg_key.split("."):
                val = val.get(part, {}) if isinstance(val, dict) else {}
            if val:
                lines.append(f"{cfg_key} = {val}")
            else:
                lines.append(f"<missing> {cfg_key}")
        return lines

    vios = process_violations(vios_raw, cfg_path, mount_path, _resolve_lines)

    status = "violated" if vios else "clean"
    return vios, status


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------


def scan(mount_path: str, context: ScanContext | None = None) -> dict[str, Any]:
    """
    Scan Docker container configurations under *mount_path*.

    Uses a two-phase systemd-driven discovery model:

    * **Phase 1** -- Process containers that ScanContext knows about from
      systemd services first.  If systemd references a container whose
      config is not found on disk, emit a ``systemd_service_broken``
      violation.
    * **Phase 2** -- Sweep file paths for all containers on disk, skip
      those already processed in Phase 1, and mark the remainder as
      orphaned (``managed=False``).

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
        raise ValueError("docker_native: ScanContext must be supplied by core.run_scan")

    try:
        rules_cfg = load_json_config(RULE_PATH)
    except ConfigLoadError:
        logger.error("Failed to load Docker rules from %s", RULE_PATH)
        rules_cfg = {"rules": []}
    rules = rules_cfg.get("rules", [])
    if not rules:
        logger.warning("No rules loaded from %s; all containers will pass", RULE_PATH)
    containers: dict[str, dict[str, Any]] = {}
    alert_count = 0
    warn_count = 0
    start_ts = time.time()

    # Extract daemon-level security fields once for all containers
    daemon_data = _extract_daemon_fields(mount_path)

    # Build a lookup of ALL containers found on disk
    on_disk: dict[str, tuple[str, str, str]] = {}
    for name, cfg_path, host_path, runtime_mode in _discover_container_dirs(mount_path):
        on_disk[name] = (cfg_path, host_path, runtime_mode)

    # ---- Phase 1: systemd-managed containers (primary discovery path) ----
    systemd_names = context.get_started_containers("docker")

    for name in sorted(systemd_names):
        if name in on_disk:
            cfg_path, host_path, runtime_mode = on_disk[name]
            vios, status = _analyze_container(
                name,
                cfg_path,
                host_path,
                runtime_mode,
                context,
                rules,
                mount_path,
                daemon_data=daemon_data,
            )
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
        else:
            # Broken service: systemd references container not found on disk
            svc_meta = context.get_service_meta("docker", name)
            source = "/" + svc_meta.get("path", "unknown")
            containers[name] = {
                "container": name,
                "violations": [
                    {
                        "id": "systemd_service_broken",
                        "type": "alert",
                        "severity": 8.0,
                        "description": (
                            "Systemd service references a Docker container "
                            "whose configuration was not found on disk"
                        ),
                        "risk": (
                            "The systemd service will fail to start this "
                            "container at boot. This may indicate a deleted "
                            "container, misconfigured data-root, or "
                            "filesystem corruption."
                        ),
                        "remediation": (
                            "Verify the container exists and the Docker "
                            "data-root path is correct, or remove the "
                            "obsolete systemd service."
                        ),
                        "source": source,
                        "lines": [
                            f"Container '{name}' not found in any Docker data-root"
                        ],
                    }
                ],
                "status": "violated",
                "managed": True,
            }
            alert_count += 1

    # ---- Phase 2: orphaned containers (found on disk but NOT in systemd) ----
    for name in sorted(on_disk):
        if name in containers:
            continue  # already processed in Phase 1
        cfg_path, host_path, runtime_mode = on_disk[name]
        vios, status = _analyze_container(
            name,
            cfg_path,
            host_path,
            runtime_mode,
            context,
            rules,
            mount_path,
            daemon_data=daemon_data,
        )
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
        "docker_scanned": len(containers),
        "alerts": alert_count,
        "warnings": warn_count,
        "elapsed": round(time.time() - start_ts, 3),
    }

    return {
        "scanner": "docker",
        "summary": summary,
        "results": list(containers.values()),
    }

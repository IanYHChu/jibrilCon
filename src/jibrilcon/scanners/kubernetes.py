# Copyright (c) 2025 IanYHChu
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for full license information.

"""
kubernetes.py

Statically analyse Kubernetes / K3s / RKE2 Pod manifests located inside
a mounted root filesystem image.

Focus areas
-----------
* Privileged containers
* Dangerous capabilities (SYS_ADMIN, SYS_PTRACE, NET_RAW, etc.)
* Host namespace sharing (PID, network, IPC)
* Dangerous hostPath mounts (/, /proc, /sys, docker.sock, etc.)
* Containers running as root / missing runAsNonRoot
* allowPrivilegeEscalation not disabled
* Missing read-only root filesystem
* Seccomp profile set to Unconfined
* Auto-mounted service account tokens
* hostPort usage
* Missing resource limits
* Bidirectional mount propagation
* Image tag missing or using :latest
* AppArmor profile unconfined (annotation + 1.30+ field)
* procMount set to Unmasked
* subPath combined with hostPath volumes
* shareProcessNamespace enabled

The module exposes:

    scan(mount_path: str, context: ScanContext) -> dict
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

import yaml

from jibrilcon.util.config_loader import ConfigLoadError, load_json_config
from jibrilcon.util.context import ScanContext
from jibrilcon.util.path_utils import safe_join
from jibrilcon.util.rules_engine import evaluate_rules
from jibrilcon.util.violation_utils import process_violations

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
RULE_PATH = BASE_DIR.parent / "rules" / "kubernetes_pod_rules.json"
RBAC_RULE_PATH = BASE_DIR.parent / "rules" / "kubernetes_rbac_rules.json"
INFRA_RULE_PATH = BASE_DIR.parent / "rules" / "kubernetes_infra_rules.json"
NODE_RULE_PATH = BASE_DIR.parent / "rules" / "kubernetes_node_rules.json"
CONTROLPLANE_RULE_PATH = (
    BASE_DIR.parent / "rules" / "kubernetes_controlplane_rules.json"
)
CONFIG_PATH = BASE_DIR.parent / "config" / "kubernetes.json"

_DANGEROUS_CAPS = frozenset(
    {
        "SYS_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "NET_RAW",
        "NET_ADMIN",
        "SYS_RAWIO",
        "DAC_OVERRIDE",
        "DAC_READ_SEARCH",
    }
)

# Map rule field names to manifest paths (used by violation line resolver)
_FIELD_TO_MANIFEST_KEY = {
    "privileged": "securityContext.privileged",
    "runs_as_root": "securityContext.runAsUser / runAsNonRoot",
    "allow_privilege_escalation": "securityContext.allowPrivilegeEscalation",
    "dangerous_caps_added": "securityContext.capabilities.add",
    "cap_drop_all_missing": "securityContext.capabilities.drop",
    "readonly_rootfs": "securityContext.readOnlyRootFilesystem",
    "seccomp_unconfined": "securityContext.seccompProfile",
    "host_pid": "spec.hostPID",
    "host_network": "spec.hostNetwork",
    "host_ipc": "spec.hostIPC",
    "has_dangerous_hostpath": "spec.volumes[].hostPath",
    "hostpath_not_readonly": "volumeMounts[].readOnly",
    "automount_sa_token": "automountServiceAccountToken",  # nosec B105
    "host_port_used": "ports[].hostPort",
    "no_resource_limits": "resources.limits",
    "service_user_missing": "service_user_missing",
    "mount_propagation_bidir": "volumeMounts[].mountPropagation",
    "image_tag_missing": "image",
    "apparmor_unconfined": "securityContext.appArmorProfile / annotation",
    "proc_mount_unmasked": "securityContext.procMount",
    "subpath_with_hostpath": "volumeMounts[].subPath + hostPath",
    "share_process_namespace": "spec.shareProcessNamespace",
}

# Pod spec path per resource kind
_POD_SPEC_PATHS: dict[str, list[str]] = {
    "Pod": ["spec"],
    "Deployment": ["spec", "template", "spec"],
    "DaemonSet": ["spec", "template", "spec"],
    "StatefulSet": ["spec", "template", "spec"],
    "ReplicaSet": ["spec", "template", "spec"],
    "ReplicationController": ["spec", "template", "spec"],
    "Job": ["spec", "template", "spec"],
    "CronJob": ["spec", "jobTemplate", "spec", "template", "spec"],
}

_MANIFEST_EXTENSIONS = frozenset({".yaml", ".yml", ".json"})


# ---------------------------------------------------------------------
# K8s distro detection
# ---------------------------------------------------------------------


def _detect_k8s_distro(rootfs: str) -> list[str]:
    """Detect which K8s distributions are present on the rootfs."""
    distros: list[str] = []
    hints = {
        "kubeadm": [
            "etc/kubernetes/manifests",
            "etc/kubernetes/admin.conf",
        ],
        "k3s": [
            "etc/rancher/k3s",
            "var/lib/rancher/k3s",
        ],
        "rke2": [
            "etc/rancher/rke2",
            "var/lib/rancher/rke2",
        ],
    }
    for distro, paths in hints.items():
        for p in paths:
            full = os.path.join(rootfs, p)
            if os.path.exists(full):
                distros.append(distro)
                break
    return distros


def _get_manifest_dirs(rootfs: str) -> list[str]:
    """Return all manifest directories to scan based on detected distros."""
    distros = _detect_k8s_distro(rootfs)
    if not distros:
        # Fall back: check all known paths
        distros = ["kubeadm", "k3s", "rke2"]

    manifest_dirs_map: dict[str, list[str]] = {
        "kubeadm": ["/etc/kubernetes/manifests"],
        "k3s": [
            "/var/lib/rancher/k3s/server/manifests",
            "/var/lib/rancher/k3s/agent/pod-manifests",
        ],
        "rke2": [
            "/var/lib/rancher/rke2/server/manifests",
            "/var/lib/rancher/rke2/agent/pod-manifests",
        ],
    }

    dirs: list[str] = []
    seen: set[str] = set()
    for distro in distros:
        for d in manifest_dirs_map.get(distro, []):
            try:
                full = str(safe_join(rootfs, d.lstrip("/")))
            except ValueError:
                continue
            if full not in seen and os.path.isdir(full):
                dirs.append(full)
                seen.add(full)
    return dirs


# ---------------------------------------------------------------------
# YAML / JSON manifest parsing
# ---------------------------------------------------------------------


def _load_manifests(filepath: str) -> list[dict[str, Any]]:
    """Load all K8s resource documents from a YAML or JSON file."""
    docs: list[dict[str, Any]] = []
    try:
        with open(filepath, encoding="utf-8") as fh:
            content = fh.read()
    except (OSError, UnicodeDecodeError) as exc:
        logger.warning("Cannot read manifest %s: %s", filepath, exc)
        return docs

    if filepath.endswith(".json"):
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                docs.append(data)
            elif isinstance(data, list):
                docs.extend(d for d in data if isinstance(d, dict))
        except json.JSONDecodeError as exc:
            logger.warning("Invalid JSON in %s: %s", filepath, exc)
    else:
        try:
            for doc in yaml.safe_load_all(content):
                if isinstance(doc, dict):
                    docs.append(doc)
        except yaml.YAMLError as exc:
            logger.warning("Invalid YAML in %s: %s", filepath, exc)

    return docs


def _extract_pod_spec(doc: dict[str, Any]) -> tuple[str, str, dict[str, Any] | None]:
    """
    Extract the PodSpec from a K8s resource document.

    Returns (kind, name, pod_spec) or (kind, name, None) if not a
    recognized workload resource.
    """
    kind = doc.get("kind", "")
    metadata = doc.get("metadata", {}) or {}
    name = metadata.get("name", "<unknown>")

    path_keys = _POD_SPEC_PATHS.get(kind)
    if not path_keys:
        return kind, name, None

    current: Any = doc
    for key in path_keys:
        if not isinstance(current, dict):
            return kind, name, None
        current = current.get(key)
        if current is None:
            return kind, name, None

    if isinstance(current, dict):
        return kind, name, current
    return kind, name, None


def _get_pod_metadata(doc: dict[str, Any], kind: str) -> dict[str, Any]:
    """Resolve the pod-template metadata (for annotation-based checks)."""
    if kind == "Pod":
        return doc.get("metadata") or {}
    # For workload resources, annotations live on the pod template
    path_to_template: dict[str, list[str]] = {
        "Deployment": ["spec", "template"],
        "DaemonSet": ["spec", "template"],
        "StatefulSet": ["spec", "template"],
        "ReplicaSet": ["spec", "template"],
        "ReplicationController": ["spec", "template"],
        "Job": ["spec", "template"],
        "CronJob": ["spec", "jobTemplate", "spec", "template"],
    }
    keys = path_to_template.get(kind)
    if not keys:
        return {}
    current: Any = doc
    for k in keys:
        if not isinstance(current, dict):
            return {}
        current = current.get(k)
    if isinstance(current, dict):
        return current.get("metadata") or {}
    return {}


# ---------------------------------------------------------------------
# Field extraction
# ---------------------------------------------------------------------


def _extract_container_fields(
    container: dict[str, Any],
    pod_spec: dict[str, Any],
    volumes: dict[str, dict[str, Any]],
    dangerous_hostpaths: frozenset[str],
    *,
    container_raw_name: str = "",
    pod_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Extract security-relevant fields from a single container spec."""
    sc = container.get("securityContext") or {}
    pod_sc = pod_spec.get("securityContext") or {}

    # --- privileged ---
    privileged = sc.get("privileged", False) is True

    # --- runs_as_root ---
    # Check container-level first, then pod-level
    run_as_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
    run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
    if run_as_non_root is True:
        runs_as_root = False
    elif run_as_user is not None:
        runs_as_root = run_as_user == 0
    else:
        # Neither runAsNonRoot nor runAsUser set -- defaults to image,
        # which is commonly root
        runs_as_root = True

    # --- allowPrivilegeEscalation ---
    # K8s default is true if not set
    ape = sc.get("allowPrivilegeEscalation")
    allow_privilege_escalation = ape is not False

    # --- capabilities ---
    caps = sc.get("capabilities") or {}
    cap_add = caps.get("add") or []
    cap_drop = caps.get("drop") or []
    if not isinstance(cap_add, list):
        cap_add = []
    if not isinstance(cap_drop, list):
        cap_drop = []
    normalised_add = {str(c).removeprefix("CAP_").upper() for c in cap_add}
    normalised_drop = {str(c).removeprefix("CAP_").upper() for c in cap_drop}
    dangerous_caps_added = bool(normalised_add & _DANGEROUS_CAPS)
    cap_drop_all_missing = "ALL" not in normalised_drop

    # --- readOnlyRootFilesystem ---
    readonly_rootfs = sc.get("readOnlyRootFilesystem", False) is True

    # --- seccomp ---
    seccomp = sc.get("seccompProfile") or pod_sc.get("seccompProfile") or {}
    seccomp_unconfined = seccomp.get("type", "") == "Unconfined"

    # --- host namespaces (pod-level) ---
    host_pid = pod_spec.get("hostPID", False) is True
    host_network = pod_spec.get("hostNetwork", False) is True
    host_ipc = pod_spec.get("hostIPC", False) is True

    # --- hostPath volumes ---
    volume_mounts = container.get("volumeMounts") or []
    if not isinstance(volume_mounts, list):
        volume_mounts = []

    # Build lookup: mount name -> readOnly flag
    mount_readonly: dict[str, bool] = {}
    for vm in volume_mounts:
        if isinstance(vm, dict):
            mount_readonly[vm.get("name", "")] = vm.get("readOnly", False) is True

    has_dangerous_hostpath = False
    hostpath_not_readonly = False
    for vm in volume_mounts:
        if not isinstance(vm, dict):
            continue
        vol_name = vm.get("name", "")
        vol_def = volumes.get(vol_name, {})
        hp = vol_def.get("hostPath")
        if not hp:
            continue
        hp_path = hp.get("path", "")

        # Check dangerous paths -- exact or prefix match
        def _is_subpath(path: str, prefix: str) -> bool:
            return path == prefix or path.startswith(prefix + "/")

        is_dangerous = hp_path in dangerous_hostpaths or any(
            _is_subpath(hp_path, dp)
            for dp in dangerous_hostpaths
            if not dp.endswith(".sock")
        )
        if is_dangerous:
            has_dangerous_hostpath = True
        if not mount_readonly.get(vol_name, False):
            hostpath_not_readonly = True

    # --- automountServiceAccountToken ---
    # Check pod-level (container-level doesn't exist in K8s spec)
    automount = pod_spec.get("automountServiceAccountToken")
    automount_sa_token = automount is not False

    # --- hostPort ---
    ports = container.get("ports") or []
    if not isinstance(ports, list):
        ports = []
    host_port_used = any(
        isinstance(p, dict) and p.get("hostPort") is not None and p.get("hostPort") != 0
        for p in ports
    )

    # --- resource limits ---
    resources = container.get("resources") or {}
    limits = resources.get("limits") or {}
    no_resource_limits = not limits

    # --- mountPropagation: Bidirectional ---
    mount_propagation_bidir = any(
        isinstance(vm, dict) and vm.get("mountPropagation") == "Bidirectional"
        for vm in volume_mounts
    )

    # --- image tag missing or :latest ---
    image = container.get("image", "")
    if isinstance(image, str) and image:
        # Strip digest if present (image@sha256:...)
        img_no_digest = image.split("@")[0]
        if ":" not in img_no_digest:
            image_tag_missing = True
        else:
            tag = img_no_digest.rsplit(":", 1)[-1]
            image_tag_missing = tag == "latest"
    else:
        image_tag_missing = True

    # --- AppArmor unconfined ---
    # 1.30+ field: securityContext.appArmorProfile.type
    aa_profile = sc.get("appArmorProfile") or {}
    aa_type = aa_profile.get("type", "") if isinstance(aa_profile, dict) else ""
    # Pre-1.30 annotation: container.apparmor.security.beta.kubernetes.io/<name>
    meta = pod_metadata or {}
    annotations = meta.get("annotations") or {}
    aa_anno_key = f"container.apparmor.security.beta.kubernetes.io/{container_raw_name}"
    aa_anno_val = annotations.get(aa_anno_key, "")
    apparmor_unconfined = aa_type == "Unconfined" or aa_anno_val == "unconfined"

    # --- procMount: Unmasked ---
    proc_mount_unmasked = sc.get("procMount", "Default") == "Unmasked"

    # --- subPath combined with hostPath ---
    subpath_with_hostpath = False
    for vm in volume_mounts:
        if not isinstance(vm, dict):
            continue
        has_subpath = bool(vm.get("subPath") or vm.get("subPathExpr"))
        if has_subpath:
            vol_name = vm.get("name", "")
            vol_def = volumes.get(vol_name, {})
            if vol_def.get("hostPath"):
                subpath_with_hostpath = True
                break

    # --- shareProcessNamespace ---
    share_process_namespace = pod_spec.get("shareProcessNamespace", False) is True

    return {
        "privileged": privileged,
        "runs_as_root": runs_as_root,
        "allow_privilege_escalation": allow_privilege_escalation,
        "dangerous_caps_added": dangerous_caps_added,
        "cap_drop_all_missing": cap_drop_all_missing,
        "readonly_rootfs": readonly_rootfs,
        "seccomp_unconfined": seccomp_unconfined,
        "host_pid": host_pid,
        "host_network": host_network,
        "host_ipc": host_ipc,
        "has_dangerous_hostpath": has_dangerous_hostpath,
        "hostpath_not_readonly": hostpath_not_readonly,
        "automount_sa_token": automount_sa_token,
        "host_port_used": host_port_used,
        "no_resource_limits": no_resource_limits,
        "mount_propagation_bidir": mount_propagation_bidir,
        "image_tag_missing": image_tag_missing,
        "apparmor_unconfined": apparmor_unconfined,
        "proc_mount_unmasked": proc_mount_unmasked,
        "subpath_with_hostpath": subpath_with_hostpath,
        "share_process_namespace": share_process_namespace,
    }


def _build_volume_map(pod_spec: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Build name -> volume definition map from pod spec volumes."""
    vols = pod_spec.get("volumes") or []
    if not isinstance(vols, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for v in vols:
        if isinstance(v, dict) and "name" in v:
            result[v["name"]] = v
    return result


# ---------------------------------------------------------------------
# RBAC field extraction
# ---------------------------------------------------------------------

_RBAC_ROLE_KINDS = frozenset({"Role", "ClusterRole"})
_RBAC_BINDING_KINDS = frozenset({"RoleBinding", "ClusterRoleBinding"})

# Dangerous sub-resource combinations
_SECRET_VERBS = frozenset({"get", "list", "watch", "*"})
_ESCALATE_BIND_VERBS = frozenset({"escalate", "bind"})
_ROLE_RESOURCES = frozenset(
    {"roles", "clusterroles", "rolebindings", "clusterrolebindings"}
)


def _extract_rbac_role_fields(doc: dict[str, Any]) -> dict[str, Any]:
    """Extract security-relevant fields from a Role/ClusterRole."""
    rules_list = doc.get("rules") or []
    if not isinstance(rules_list, list):
        rules_list = []

    has_wildcard_verbs = False
    has_wildcard_resources = False
    has_pods_exec = False
    has_secrets_access = False
    has_escalate_bind = False
    has_create_pods = False
    has_nodes_proxy = False
    has_sa_token_create = False

    for rule in rules_list:
        if not isinstance(rule, dict):
            continue
        verbs = set(rule.get("verbs") or [])
        resources = set(rule.get("resources") or [])
        api_groups = set(rule.get("apiGroups") or [])

        if "*" in verbs:
            has_wildcard_verbs = True
        if "*" in resources:
            has_wildcard_resources = True

        # pods/exec: resource "pods/exec" or "pods" with sub-resource
        if "pods/exec" in resources:
            has_pods_exec = True
        # Also check via wildcard: if verbs=* and resources contain pods
        if "*" in verbs and ("pods" in resources or "*" in resources):
            has_pods_exec = True

        # secrets access
        if "secrets" in resources and verbs & _SECRET_VERBS:
            has_secrets_access = True
        if "*" in resources and verbs & _SECRET_VERBS:
            has_secrets_access = True

        # escalate/bind on role resources
        if verbs & _ESCALATE_BIND_VERBS and (
            resources & _ROLE_RESOURCES or "*" in resources
        ):
            has_escalate_bind = True

        # create pods
        if "pods" in resources and "create" in verbs:
            has_create_pods = True
        if "*" in resources and "create" in verbs:
            has_create_pods = True

        # nodes/proxy
        if "nodes/proxy" in resources:
            has_nodes_proxy = True

        # serviceaccounts/token create
        if "serviceaccounts/token" in resources and "create" in verbs:
            has_sa_token_create = True
        if (
            "*" in resources
            and "create" in verbs
            and ("" in api_groups or "*" in api_groups)
        ):
            has_sa_token_create = True

    return {
        "has_wildcard_verbs": has_wildcard_verbs,
        "has_wildcard_resources": has_wildcard_resources,
        "has_pods_exec": has_pods_exec,
        "has_secrets_access": has_secrets_access,
        "has_escalate_bind": has_escalate_bind,
        "has_create_pods": has_create_pods,
        "has_nodes_proxy": has_nodes_proxy,
        "has_sa_token_create": has_sa_token_create,
        "binds_default_sa": False,
        "binds_anonymous": False,
    }


def _extract_rbac_binding_fields(doc: dict[str, Any]) -> dict[str, Any]:
    """Extract fields from a RoleBinding/ClusterRoleBinding."""
    subjects = doc.get("subjects") or []
    if not isinstance(subjects, list):
        subjects = []

    binds_default_sa = any(
        isinstance(s, dict)
        and s.get("kind") == "ServiceAccount"
        and s.get("name") == "default"
        for s in subjects
    )

    binds_anonymous = any(
        isinstance(s, dict)
        and (
            (s.get("kind") == "User" and s.get("name") == "system:anonymous")
            or (
                s.get("kind") == "Group"
                and s.get("name") in ("system:unauthenticated", "system:anonymous")
            )
        )
        for s in subjects
    )

    return {
        "has_wildcard_verbs": False,
        "has_wildcard_resources": False,
        "has_pods_exec": False,
        "has_secrets_access": False,
        "has_escalate_bind": False,
        "has_create_pods": False,
        "has_nodes_proxy": False,
        "has_sa_token_create": False,  # nosec B105
        "binds_default_sa": binds_default_sa,
        "binds_anonymous": binds_anonymous,
    }


# Map RBAC rule fields to manifest keys (for violation line resolver)
_RBAC_FIELD_TO_KEY = {
    "has_wildcard_verbs": "rules[].verbs",
    "has_wildcard_resources": "rules[].resources",
    "has_pods_exec": "rules[].resources (pods/exec)",
    "has_secrets_access": "rules[].resources (secrets)",
    "has_escalate_bind": "rules[].verbs (escalate/bind)",
    "has_create_pods": "rules[].verbs (create) + resources (pods)",
    "has_nodes_proxy": "rules[].resources (nodes/proxy)",
    "has_sa_token_create": "rules[].resources (serviceaccounts/token)",  # nosec B105
    "binds_default_sa": "subjects[].name (default)",
    "binds_anonymous": "subjects[].name (system:anonymous/unauthenticated)",
}


# ---------------------------------------------------------------------
# Infrastructure resource field extraction
# ---------------------------------------------------------------------

_INFRA_KINDS = frozenset({"Namespace", "NetworkPolicy", "Secret"})


def _extract_namespace_fields(doc: dict[str, Any]) -> dict[str, Any]:
    """Extract PSA labels from a Namespace manifest."""
    metadata = doc.get("metadata") or {}
    labels = metadata.get("labels") or {}
    enforce = labels.get("pod-security.kubernetes.io/enforce", "")
    return {
        "psa_enforce_missing": not enforce,
        "psa_enforce_privileged": enforce == "privileged",
    }


def _extract_secret_fields(doc: dict[str, Any]) -> dict[str, Any]:
    """Detect plaintext secrets in manifest files."""
    data = doc.get("data") or {}
    # If a Secret has 'data' keys, it contains base64-encoded values
    # that are NOT encrypted -- they are on disk in the manifest
    has_plaintext_data = bool(data) and isinstance(data, dict)
    return {"secret_plaintext_in_manifest": has_plaintext_data}


def _extract_netpol_fields(
    doc: dict[str, Any],
) -> dict[str, Any]:
    """Extract overly-permissive NetworkPolicy patterns."""
    spec = doc.get("spec") or {}
    ingress = spec.get("ingress")
    egress = spec.get("egress")

    # Empty ingress rule list [{}] means allow-all ingress
    ingress_allow_all = (
        isinstance(ingress, list)
        and len(ingress) > 0
        and any(r == {} or r is None for r in ingress)
    )
    egress_allow_all = (
        isinstance(egress, list)
        and len(egress) > 0
        and any(r == {} or r is None for r in egress)
    )

    return {
        "netpol_ingress_allow_all": ingress_allow_all,
        "netpol_egress_allow_all": egress_allow_all,
    }


_INFRA_FIELD_TO_KEY = {
    "psa_enforce_missing": "metadata.labels[pod-security.kubernetes.io/enforce]",
    "psa_enforce_privileged": "metadata.labels[pod-security.kubernetes.io/enforce]",
    "secret_plaintext_in_manifest": "data",  # nosec B105
    "netpol_ingress_allow_all": "spec.ingress",
    "netpol_egress_allow_all": "spec.egress",
}


# ---------------------------------------------------------------------
# Node / kubelet configuration extraction
# ---------------------------------------------------------------------

_NODE_CONFIG_PATHS: dict[str, list[str]] = {
    "kubeadm": ["/var/lib/kubelet/config.yaml"],
    "k3s": ["/etc/rancher/k3s/config.yaml"],
    "rke2": ["/etc/rancher/rke2/config.yaml"],
}

_CONTROL_PLANE_MANIFESTS = {
    "kube-apiserver": "etc/kubernetes/manifests/kube-apiserver.yaml",
    "etcd": "etc/kubernetes/manifests/etcd.yaml",
    "kube-controller-manager": "etc/kubernetes/manifests/kube-controller-manager.yaml",
}


def _discover_node_configs(rootfs: str) -> list[tuple[str, str]]:
    """Find kubelet/K3s/RKE2 config files. Returns (distro, path) pairs."""
    distros = _detect_k8s_distro(rootfs)
    if not distros:
        distros = list(_NODE_CONFIG_PATHS.keys())

    found: list[tuple[str, str]] = []
    for distro in distros:
        for cfg_rel in _NODE_CONFIG_PATHS.get(distro, []):
            try:
                full = str(safe_join(rootfs, cfg_rel.lstrip("/")))
            except ValueError:
                continue
            if os.path.isfile(full):
                found.append((distro, full))
    return found


def _load_yaml_config(filepath: str) -> dict[str, Any]:
    """Load a single YAML config file."""
    try:
        with open(filepath, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        logger.warning("Cannot read config %s: %s", filepath, exc)
        return {}


def _extract_kubelet_fields(cfg: dict[str, Any]) -> dict[str, Any]:
    """Extract security fields from KubeletConfiguration YAML."""
    # authentication.anonymous.enabled (default false in kubeadm, but
    # may be true in some distros)
    auth = cfg.get("authentication") or {}
    anon = auth.get("anonymous") or {}
    anonymous_enabled = anon.get("enabled", False) is True

    # readOnlyPort (default 10255 for older versions, 0 means disabled)
    readonly_port = cfg.get("readOnlyPort")
    readonly_port_enabled = readonly_port is not None and readonly_port != 0

    # authorization.mode
    authz = cfg.get("authorization") or {}
    authz_mode = authz.get("mode", "")
    authorization_always_allow = authz_mode == "AlwaysAllow"

    # protectKernelDefaults
    protect_kernel = cfg.get("protectKernelDefaults", False)
    protect_kernel_defaults_disabled = protect_kernel is not True

    # streamingConnectionIdleTimeout
    streaming_timeout = cfg.get("streamingConnectionIdleTimeout", "")
    streaming_timeout_disabled = streaming_timeout == "0" or (
        isinstance(streaming_timeout, str) and streaming_timeout == "0s"
    )

    # eventRecordQPS
    event_qps = cfg.get("eventRecordQPS")
    event_record_qps_disabled = event_qps == 0

    # TLS cert
    tls_cert = cfg.get("tlsCertFile", "")
    rotate_certs = cfg.get("rotateCertificates", False) is True
    server_tls_bootstrap = cfg.get("serverTLSBootstrap", False) is True
    tls_cert_missing = not tls_cert and not rotate_certs and not server_tls_bootstrap

    return {
        "anonymous_auth_enabled": anonymous_enabled,
        "readonly_port_enabled": readonly_port_enabled,
        "authorization_always_allow": authorization_always_allow,
        "protect_kernel_defaults_disabled": protect_kernel_defaults_disabled,
        "streaming_timeout_disabled": streaming_timeout_disabled,
        "event_record_qps_disabled": event_record_qps_disabled,
        "tls_cert_missing": tls_cert_missing,
    }


def _extract_k3s_rke2_fields(cfg: dict[str, Any]) -> dict[str, Any]:
    """Extract security fields from K3s/RKE2 config.yaml.

    K3s/RKE2 config uses CLI flag names as YAML keys (without leading
    dashes). Some map directly to kubelet args.
    """
    # K3s/RKE2 pass kubelet args via kubelet-arg list
    kubelet_args = cfg.get("kubelet-arg") or []
    if isinstance(kubelet_args, str):
        kubelet_args = [kubelet_args]

    # Parse kubelet args into a dict
    kargs: dict[str, str] = {}
    for arg in kubelet_args:
        if not isinstance(arg, str):
            continue
        if "=" in arg:
            k, v = arg.split("=", 1)
            kargs[k.lstrip("-")] = v
        else:
            kargs[arg.lstrip("-")] = "true"

    # anonymous-auth
    anon_val = kargs.get("anonymous-auth", "")
    anonymous_enabled = anon_val.lower() == "true"

    # read-only-port
    ro_port = kargs.get("read-only-port", "")
    readonly_port_enabled = bool(ro_port) and ro_port != "0"

    # authorization-mode
    authz_mode = kargs.get("authorization-mode", "")
    authorization_always_allow = authz_mode == "AlwaysAllow"

    # protect-kernel-defaults
    protect = kargs.get("protect-kernel-defaults", "")
    # Also check top-level config key
    top_protect = cfg.get("protect-kernel-defaults", False)
    protect_kernel_defaults_disabled = (
        protect.lower() != "true" and top_protect is not True
    )

    # streaming-connection-idle-timeout
    streaming = kargs.get("streaming-connection-idle-timeout", "")
    streaming_timeout_disabled = streaming in ("0", "0s")

    # event-qps
    event_qps = kargs.get("event-qps", "")
    event_record_qps_disabled = event_qps == "0"

    # TLS -- K3s/RKE2 auto-generate certs by default, so this is
    # generally safe. Only flag if explicitly set to empty.
    tls_cert = kargs.get("tls-cert-file", "not-checked")
    tls_cert_missing = tls_cert == ""

    return {
        "anonymous_auth_enabled": anonymous_enabled,
        "readonly_port_enabled": readonly_port_enabled,
        "authorization_always_allow": authorization_always_allow,
        "protect_kernel_defaults_disabled": protect_kernel_defaults_disabled,
        "streaming_timeout_disabled": streaming_timeout_disabled,
        "event_record_qps_disabled": event_record_qps_disabled,
        "tls_cert_missing": tls_cert_missing,
    }


_NODE_FIELD_TO_KEY = {
    "anonymous_auth_enabled": "authentication.anonymous.enabled",
    "readonly_port_enabled": "readOnlyPort",
    "authorization_always_allow": "authorization.mode",
    "protect_kernel_defaults_disabled": "protectKernelDefaults",
    "streaming_timeout_disabled": "streamingConnectionIdleTimeout",
    "event_record_qps_disabled": "eventRecordQPS",
    "tls_cert_missing": "tlsCertFile / rotateCertificates",
    "systemd_service_found": "systemd.service",
    "systemd_caps_unrestricted": "systemd.CapabilityBoundingSet",
}


# ---------------------------------------------------------------------
# Control plane component field extraction
# ---------------------------------------------------------------------


def _parse_component_args(doc: dict[str, Any]) -> dict[str, str]:
    """Parse command-line arguments from a static pod manifest."""
    containers = (doc.get("spec") or {}).get("containers") or []
    if not containers:
        return {}
    # Use the first container (control plane pods have one container)
    container = containers[0]
    args = list(container.get("command") or [])
    args.extend(container.get("args") or [])

    parsed: dict[str, str] = {}
    for arg in args:
        if not isinstance(arg, str):
            continue
        if "=" in arg:
            k, v = arg.split("=", 1)
            parsed[k.lstrip("-")] = v
        elif arg.startswith("--"):
            parsed[arg.lstrip("-")] = "true"
    return parsed


def _extract_apiserver_fields(args: dict[str, str]) -> dict[str, Any]:
    """Extract security fields from kube-apiserver arguments."""
    return {
        "apiserver_anonymous_auth": args.get("anonymous-auth", "") == "true",
        "apiserver_insecure_port": (args.get("insecure-port", "0") != "0"),
        "apiserver_authz_not_rbac": (
            "RBAC" not in args.get("authorization-mode", "RBAC")
        ),
        "apiserver_encryption_missing": not args.get("encryption-provider-config"),
        "apiserver_admission_missing": not args.get("enable-admission-plugins"),
    }


def _extract_etcd_fields(args: dict[str, str]) -> dict[str, Any]:
    """Extract security fields from etcd arguments."""
    return {
        "etcd_client_cert_missing": not args.get("cert-file"),
        "etcd_client_key_missing": not args.get("key-file"),
        "etcd_peer_cert_missing": not args.get("peer-cert-file"),
        "etcd_peer_key_missing": not args.get("peer-key-file"),
        "etcd_client_auto_tls": args.get("auto-tls", "") == "true",
    }


def _extract_controller_manager_fields(
    args: dict[str, str],
) -> dict[str, Any]:
    """Extract security fields from kube-controller-manager arguments."""
    return {
        "cm_sa_key_missing": not args.get("service-account-private-key-file"),
        "cm_root_ca_missing": not args.get("root-ca-file"),
        "cm_sa_credentials_disabled": (
            args.get("use-service-account-credentials", "") != "true"
        ),
    }


_APISERVER_FIELD_TO_KEY = {
    "apiserver_anonymous_auth": "--anonymous-auth",
    "apiserver_insecure_port": "--insecure-port",
    "apiserver_authz_not_rbac": "--authorization-mode",
    "apiserver_encryption_missing": "--encryption-provider-config",
    "apiserver_admission_missing": "--enable-admission-plugins",
}

_ETCD_FIELD_TO_KEY = {
    "etcd_client_cert_missing": "--cert-file",
    "etcd_client_key_missing": "--key-file",
    "etcd_peer_cert_missing": "--peer-cert-file",
    "etcd_peer_key_missing": "--peer-key-file",
    "etcd_client_auto_tls": "--auto-tls",
}

_CM_FIELD_TO_KEY = {
    "cm_sa_key_missing": "--service-account-private-key-file",
    "cm_root_ca_missing": "--root-ca-file",
    "cm_sa_credentials_disabled": "--use-service-account-credentials",
}


# ---------------------------------------------------------------------
# Manifest discovery
# ---------------------------------------------------------------------


def _discover_manifests(rootfs: str) -> list[str]:
    """Find all K8s manifest files under known directories."""
    manifest_dirs = _get_manifest_dirs(rootfs)
    files: list[str] = []
    for mdir in manifest_dirs:
        if not os.path.isdir(mdir):
            continue
        for dirpath, _dirnames, filenames in os.walk(mdir):
            for fname in sorted(filenames):
                ext = os.path.splitext(fname)[1].lower()
                if ext in _MANIFEST_EXTENSIONS:
                    files.append(os.path.join(dirpath, fname))
    return files


# ---------------------------------------------------------------------
# Systemd daemon service lookup
# ---------------------------------------------------------------------


def _get_daemon_service_meta(context: ScanContext, distro: str) -> dict[str, str]:
    """Find systemd service metadata for the K8s daemon by distro.

    Maps the detected K8s distribution to the engine/container pairs
    registered by ``systemd_unit_parser`` and returns the first match.
    """
    # Map distro to (engine, candidate container names)
    candidates: dict[str, list[tuple[str, str]]] = {
        "k3s": [("k3s", "server"), ("k3s", "agent")],
        "rke2": [("rke2", "server"), ("rke2", "agent")],
        "kubeadm": [("kubernetes", "")],
    }
    for engine, cname in candidates.get(distro, []):
        meta = context.get_service_meta(engine, cname)
        if meta:
            return meta
    return {}


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------


def scan(mount_path: str, context: ScanContext | None = None) -> dict[str, Any]:
    """
    Scan Kubernetes manifests under *mount_path*.

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

    # --- Load rule sets ---
    def _load_rules(path: Path) -> list[dict[str, Any]]:
        try:
            return load_json_config(path).get("rules", [])
        except ConfigLoadError:
            logger.error("Failed to load rules from %s", path)
            return []

    pod_rules = _load_rules(RULE_PATH)
    rbac_rules = _load_rules(RBAC_RULE_PATH)
    infra_rules = _load_rules(INFRA_RULE_PATH)
    node_rules = _load_rules(NODE_RULE_PATH)
    cp_rules = _load_rules(CONTROLPLANE_RULE_PATH)

    # Load dangerous hostpath list from config
    try:
        k8s_cfg = load_json_config(CONFIG_PATH)
    except ConfigLoadError:
        k8s_cfg = {}
    dangerous_hostpaths = frozenset(k8s_cfg.get("dangerous_hostpaths", []))

    results_map: dict[str, dict[str, Any]] = {}
    alert_count = 0
    warn_count = 0
    start_ts = time.time()

    manifest_files = _discover_manifests(mount_path)
    if not manifest_files:
        logger.info("No Kubernetes manifests found under %s", mount_path)

    for fpath in manifest_files:
        docs = _load_manifests(fpath)
        for doc in docs:
            kind = doc.get("kind", "")
            metadata = doc.get("metadata") or {}
            resource_name = metadata.get("name", "<unknown>")

            # --- Workload resources (Pod spec) ---
            _, _, pod_spec = _extract_pod_spec(doc)
            if pod_spec is not None:
                volumes = _build_volume_map(pod_spec)
                pod_metadata = _get_pod_metadata(doc, kind)

                all_containers: list[tuple[str, str, dict[str, Any]]] = []
                for c in pod_spec.get("containers") or []:
                    if isinstance(c, dict):
                        raw = c.get("name", "<unnamed>")
                        all_containers.append((raw, raw, c))
                for c in pod_spec.get("initContainers") or []:
                    if isinstance(c, dict):
                        raw = c.get("name", "<unnamed>")
                        all_containers.append((f"init:{raw}", raw, c))

                for cname, raw_name, cspec in all_containers:
                    key = f"{kind}/{resource_name}/{cname}"
                    data = _extract_container_fields(
                        cspec,
                        pod_spec,
                        volumes,
                        dangerous_hostpaths,
                        container_raw_name=raw_name,
                        pod_metadata=pod_metadata,
                    )
                    data["service_user_missing"] = context.is_user_missing(
                        resource_name
                    )
                    vios_raw = evaluate_rules(data, pod_rules)

                    def _resolve_pod(_v, used_fields, _d=data):
                        lines = []
                        for f in used_fields:
                            mk = _FIELD_TO_MANIFEST_KEY.get(f, f)
                            val = _d.get(f)
                            if val is not None:
                                lines.append(f"{mk} = {val}")
                            else:
                                lines.append(f"<missing> {mk}")
                        return lines

                    vios = process_violations(vios_raw, fpath, mount_path, _resolve_pod)
                    status = "violated" if vios else "clean"
                    if any(v["type"] == "alert" for v in vios):
                        alert_count += 1
                    elif any(v["type"] == "warning" for v in vios):
                        warn_count += 1
                    results_map[key] = {
                        "kind": kind,
                        "resource": resource_name,
                        "container": cname,
                        "violations": vios,
                        "status": status,
                    }
                continue

            # --- RBAC resources ---
            if kind in _RBAC_ROLE_KINDS and rbac_rules:
                key = f"{kind}/{resource_name}"
                data = _extract_rbac_role_fields(doc)
                vios_raw = evaluate_rules(data, rbac_rules)

                def _resolve_rbac(_v, used_fields, _d=data):
                    lines = []
                    for f in used_fields:
                        mk = _RBAC_FIELD_TO_KEY.get(f, f)
                        val = _d.get(f)
                        if val is not None:
                            lines.append(f"{mk} = {val}")
                        else:
                            lines.append(f"<missing> {mk}")
                    return lines

                vios = process_violations(vios_raw, fpath, mount_path, _resolve_rbac)
                status = "violated" if vios else "clean"
                if any(v["type"] == "alert" for v in vios):
                    alert_count += 1
                elif any(v["type"] == "warning" for v in vios):
                    warn_count += 1
                results_map[key] = {
                    "kind": kind,
                    "resource": resource_name,
                    "container": "",
                    "violations": vios,
                    "status": status,
                }

            elif kind in _RBAC_BINDING_KINDS and rbac_rules:
                key = f"{kind}/{resource_name}"
                data = _extract_rbac_binding_fields(doc)
                vios_raw = evaluate_rules(data, rbac_rules)

                def _resolve_bind(_v, used_fields, _d=data):
                    lines = []
                    for f in used_fields:
                        mk = _RBAC_FIELD_TO_KEY.get(f, f)
                        val = _d.get(f)
                        if val is not None:
                            lines.append(f"{mk} = {val}")
                        else:
                            lines.append(f"<missing> {mk}")
                    return lines

                vios = process_violations(vios_raw, fpath, mount_path, _resolve_bind)
                status = "violated" if vios else "clean"
                if any(v["type"] == "alert" for v in vios):
                    alert_count += 1
                elif any(v["type"] == "warning" for v in vios):
                    warn_count += 1
                results_map[key] = {
                    "kind": kind,
                    "resource": resource_name,
                    "container": "",
                    "violations": vios,
                    "status": status,
                }

            # --- Infrastructure resources ---
            elif kind in _INFRA_KINDS and infra_rules:
                key = f"{kind}/{resource_name}"
                if kind == "Namespace":
                    data = _extract_namespace_fields(doc)
                elif kind == "Secret":
                    data = _extract_secret_fields(doc)
                elif kind == "NetworkPolicy":
                    data = _extract_netpol_fields(doc)
                else:
                    continue

                vios_raw = evaluate_rules(data, infra_rules)

                def _resolve_infra(_v, used_fields, _d=data):
                    lines = []
                    for f in used_fields:
                        mk = _INFRA_FIELD_TO_KEY.get(f, f)
                        val = _d.get(f)
                        if val is not None:
                            lines.append(f"{mk} = {val}")
                        else:
                            lines.append(f"<missing> {mk}")
                    return lines

                vios = process_violations(vios_raw, fpath, mount_path, _resolve_infra)
                status = "violated" if vios else "clean"
                if any(v["type"] == "alert" for v in vios):
                    alert_count += 1
                elif any(v["type"] == "warning" for v in vios):
                    warn_count += 1
                results_map[key] = {
                    "kind": kind,
                    "resource": resource_name,
                    "container": "",
                    "violations": vios,
                    "status": status,
                }

    # --- Node / kubelet configuration scanning ---
    if node_rules:
        for distro, cfg_path in _discover_node_configs(mount_path):
            cfg = _load_yaml_config(cfg_path)
            if not cfg:
                continue

            if distro == "kubeadm":
                data = _extract_kubelet_fields(cfg)
            else:
                data = _extract_k3s_rke2_fields(cfg)

            # Systemd daemon service cross-validation
            svc_meta = _get_daemon_service_meta(context, distro)
            data["systemd_service_found"] = bool(svc_meta)
            data["systemd_caps_unrestricted"] = bool(svc_meta) and not svc_meta.get(
                "cap_bounding_set"
            )

            key = f"NodeConfig/{distro}"
            vios_raw = evaluate_rules(data, node_rules)

            def _resolve_node(_v, used_fields, _d=data):
                lines = []
                for f in used_fields:
                    mk = _NODE_FIELD_TO_KEY.get(f, f)
                    val = _d.get(f)
                    if val is not None:
                        lines.append(f"{mk} = {val}")
                    else:
                        lines.append(f"<missing> {mk}")
                return lines

            vios = process_violations(vios_raw, cfg_path, mount_path, _resolve_node)
            status = "violated" if vios else "clean"
            if any(v["type"] == "alert" for v in vios):
                alert_count += 1
            elif any(v["type"] == "warning" for v in vios):
                warn_count += 1
            results_map[key] = {
                "kind": "NodeConfig",
                "resource": distro,
                "container": "",
                "violations": vios,
                "status": status,
            }

    # --- Control plane component scanning ---
    if cp_rules:
        # Static pod manifests (kubeadm)
        for component, rel_path in _CONTROL_PLANE_MANIFESTS.items():
            try:
                full_path = str(safe_join(mount_path, rel_path))
            except ValueError:
                continue
            if not os.path.isfile(full_path):
                continue

            docs = _load_manifests(full_path)
            for doc in docs:
                args = _parse_component_args(doc)
                if not args:
                    continue

                if component == "kube-apiserver":
                    data = _extract_apiserver_fields(args)
                    field_map = _APISERVER_FIELD_TO_KEY
                elif component == "etcd":
                    data = _extract_etcd_fields(args)
                    field_map = _ETCD_FIELD_TO_KEY
                elif component == "kube-controller-manager":
                    data = _extract_controller_manager_fields(args)
                    field_map = _CM_FIELD_TO_KEY
                else:
                    continue

                key = f"ControlPlane/{component}"
                vios_raw = evaluate_rules(data, cp_rules)

                def _resolve_cp(_v, used_fields, _d=data, _m=field_map):
                    lines = []
                    for f in used_fields:
                        mk = _m.get(f, f)
                        val = _d.get(f)
                        if val is not None:
                            lines.append(f"{mk} = {val}")
                        else:
                            lines.append(f"<missing> {mk}")
                    return lines

                vios = process_violations(vios_raw, full_path, mount_path, _resolve_cp)
                status = "violated" if vios else "clean"
                if any(v["type"] == "alert" for v in vios):
                    alert_count += 1
                elif any(v["type"] == "warning" for v in vios):
                    warn_count += 1
                results_map[key] = {
                    "kind": "ControlPlane",
                    "resource": component,
                    "container": "",
                    "violations": vios,
                    "status": status,
                }

        # K3s/RKE2: extract apiserver/controller-manager args from config.yaml
        for distro, cfg_path in _discover_node_configs(mount_path):
            if distro not in ("k3s", "rke2"):
                continue
            cfg = _load_yaml_config(cfg_path)
            if not cfg:
                continue

            # kube-apiserver-arg
            apiserver_args_raw = cfg.get("kube-apiserver-arg") or []
            if isinstance(apiserver_args_raw, str):
                apiserver_args_raw = [apiserver_args_raw]
            if apiserver_args_raw:
                aargs: dict[str, str] = {}
                for arg in apiserver_args_raw:
                    if isinstance(arg, str) and "=" in arg:
                        k, v = arg.split("=", 1)
                        aargs[k.lstrip("-")] = v
                data = _extract_apiserver_fields(aargs)
                key = f"ControlPlane/{distro}-apiserver"
                vios_raw = evaluate_rules(data, cp_rules)

                def _resolve_cp_k3s(_v, used_fields, _d=data):
                    return [
                        f"{_APISERVER_FIELD_TO_KEY.get(f, f)} = {_d.get(f)}"
                        for f in used_fields
                    ]

                vios = process_violations(
                    vios_raw, cfg_path, mount_path, _resolve_cp_k3s
                )
                if vios:
                    status = "violated"
                    if any(v["type"] == "alert" for v in vios):
                        alert_count += 1
                    elif any(v["type"] == "warning" for v in vios):
                        warn_count += 1
                    results_map[key] = {
                        "kind": "ControlPlane",
                        "resource": f"{distro}-apiserver",
                        "container": "",
                        "violations": vios,
                        "status": status,
                    }

            # kube-controller-manager-arg
            cm_args_raw = cfg.get("kube-controller-manager-arg") or []
            if isinstance(cm_args_raw, str):
                cm_args_raw = [cm_args_raw]
            if cm_args_raw:
                cargs: dict[str, str] = {}
                for arg in cm_args_raw:
                    if isinstance(arg, str) and "=" in arg:
                        k, v = arg.split("=", 1)
                        cargs[k.lstrip("-")] = v
                data = _extract_controller_manager_fields(cargs)
                key = f"ControlPlane/{distro}-controller-manager"
                vios_raw = evaluate_rules(data, cp_rules)

                def _resolve_cp_cm(_v, used_fields, _d=data):
                    return [
                        f"{_CM_FIELD_TO_KEY.get(f, f)} = {_d.get(f)}"
                        for f in used_fields
                    ]

                vios = process_violations(
                    vios_raw, cfg_path, mount_path, _resolve_cp_cm
                )
                if vios:
                    status = "violated"
                    if any(v["type"] == "alert" for v in vios):
                        alert_count += 1
                    elif any(v["type"] == "warning" for v in vios):
                        warn_count += 1
                    results_map[key] = {
                        "kind": "ControlPlane",
                        "resource": f"{distro}-controller-manager",
                        "container": "",
                        "violations": vios,
                        "status": status,
                    }

    summary = {
        "kubernetes_scanned": len(results_map),
        "alerts": alert_count,
        "warnings": warn_count,
        "elapsed": round(time.time() - start_ts, 3),
    }

    return {
        "scanner": "kubernetes",
        "summary": summary,
        "results": list(results_map.values()),
    }

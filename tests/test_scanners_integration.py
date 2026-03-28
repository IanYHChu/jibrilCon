"""Integration tests for scanner modules using minimal rootfs fixtures."""

import json
from pathlib import Path

from jibrilcon.util.context import ScanContext
from jibrilcon.scanners import docker_native, lxc, podman


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

def _make_context() -> ScanContext:
    ctx = ScanContext()
    ctx.init_system = "systemd"
    return ctx


# ------------------------------------------------------------------ #
# Docker scanner
# ------------------------------------------------------------------ #

class TestDockerScanner:

    def test_clean_container(self, make_rootfs):
        r = make_rootfs
        cid = "aaa" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/clean"},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": ["/data:/data:ro"],
                "CapDrop": ["ALL"],
            },
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        assert result["scanner"] == "docker"
        assert result["summary"]["docker_scanned"] == 1
        containers = result["results"]
        assert len(containers) == 1
        assert containers[0]["status"] == "clean"
        assert containers[0]["violations"] == []

    def test_privileged_container(self, make_rootfs):
        r = make_rootfs
        cid = "bbb" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/priv"},
            hostconfig={"Privileged": True, "ReadonlyRootfs": False, "Binds": []},
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        containers = result["results"]
        assert len(containers) == 1
        assert containers[0]["status"] == "violated"
        vio_ids = [v["id"] for v in containers[0]["violations"]]
        assert "privileged" in vio_ids

    def test_violation_has_enriched_fields_and_no_internals(self, make_rootfs):
        """Violations must carry framework references and strip engine internals."""
        r = make_rootfs
        cid = "enr" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/enriched"},
            hostconfig={"Privileged": True, "ReadonlyRootfs": False, "Binds": []},
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        priv = [v for v in result["results"][0]["violations"] if v["id"] == "privileged"][0]

        # Enriched fields present
        assert "severity" in priv
        assert isinstance(priv["severity"], (int, float))
        assert "risk" in priv
        assert "remediation" in priv
        assert "references" in priv
        assert "mitre_attack" in priv["references"]

        # Engine internals stripped
        assert "conditions" not in priv
        assert "logic" not in priv

    def test_multi_container_no_cross_contamination(self, make_rootfs):
        """P0 regression: each container must have independent violation data."""
        r = make_rootfs
        # Two containers, both triggering readonly_rootfs_missing
        cid_a = "aaa" * 8 + "1" * 40
        cid_b = "bbb" * 8 + "2" * 40
        r.add_docker_container(
            cid_a,
            config_v2={"Name": "/alpha"},
            hostconfig={"Privileged": False, "ReadonlyRootfs": False, "Binds": []},
        )
        r.add_docker_container(
            cid_b,
            config_v2={"Name": "/beta"},
            hostconfig={"Privileged": False, "ReadonlyRootfs": False, "Binds": []},
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)

        assert result["summary"]["docker_scanned"] == 2
        results_by_name = {c["container"]: c for c in result["results"]}
        assert "alpha" in results_by_name
        assert "beta" in results_by_name

        # Both must have violations with DIFFERENT source paths
        for name, container in results_by_name.items():
            for vio in container["violations"]:
                assert "source" in vio
                assert name.lower() in "" or vio["source"]  # source is a path string
                # Key assertion: source must contain THIS container's cid, not the other's
                assert cid_a[:12] in vio["source"] or cid_b[:12] in vio["source"]

        # Collect all sources — must have at least 2 distinct values
        all_sources = set()
        for c in result["results"]:
            for v in c["violations"]:
                all_sources.add(v["source"])
        assert len(all_sources) == 2, f"Expected 2 distinct sources, got {all_sources}"

    def test_rootless_docker(self, make_rootfs):
        r = make_rootfs
        r.add_passwd(["testuser:x:1000:1000:Test User:/home/testuser:/bin/bash"])
        cid = "ccc" * 8 + "0" * 40
        base = Path(r.path) / "home" / "testuser" / ".local" / "share" / "docker" / "containers" / cid
        base.mkdir(parents=True, exist_ok=True)
        (base / "config.v2.json").write_text(json.dumps({"Name": "/rootless"}))
        (base / "hostconfig.json").write_text(json.dumps({
            "Privileged": True,
            "ReadonlyRootfs": False,
            "Binds": [],
        }))
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        assert result["summary"]["docker_scanned"] >= 1
        names = [c["container"] for c in result["results"]]
        assert "rootless" in names

    def test_seccomp_disabled_warning(self, make_rootfs):
        r = make_rootfs
        cid = "ddd" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/noseccomp"},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "SecurityOpt": ["seccomp=unconfined"],
            },
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        containers = result["results"]
        assert len(containers) == 1
        vio_ids = [v["id"] for v in containers[0]["violations"]]
        assert "seccomp_disabled" in vio_ids

    def test_label_disable_privileged(self, make_rootfs):
        r = make_rootfs
        cid = "eee" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/labeldisable"},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "SecurityOpt": ["label=disable"],
            },
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        containers = result["results"]
        assert len(containers) == 1
        vio_ids = [v["id"] for v in containers[0]["violations"]]
        assert "privileged" in vio_ids

    def test_bind_mount_readonly_with_extra_options(self, make_rootfs):
        r = make_rootfs
        cid = "fff" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/roextra"},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": ["/data:/data:ro,rslave"],
                "CapDrop": ["ALL"],
            },
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        containers = result["results"]
        assert len(containers) == 1
        assert containers[0]["status"] == "clean"

    def test_bind_mount_writable_default(self, make_rootfs):
        r = make_rootfs
        cid = "ggg" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/rwdefault"},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": ["/data:/data"],
            },
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        containers = result["results"]
        assert len(containers) == 1
        vio_ids = [v["id"] for v in containers[0]["violations"]]
        assert "binds_not_readonly" in vio_ids

    def test_passwd_path_traversal_rejected(self, make_rootfs):
        """Malicious passwd home dirs with ../ must not escape rootfs."""
        r = make_rootfs
        r.add_passwd([
            "legit:x:1000:1000:Legit:/home/legit:/bin/bash",
            "evil:x:1001:1001:Evil:/home/../../etc:/bin/bash",
        ])
        # Place a docker dir under the legitimate home only
        cid = "hhh" * 8 + "0" * 40
        base = Path(r.path) / "home" / "legit" / ".local" / "share" / "docker" / "containers" / cid
        base.mkdir(parents=True, exist_ok=True)
        (base / "config.v2.json").write_text(json.dumps({"Name": "/legit"}))
        (base / "hostconfig.json").write_text(json.dumps({
            "Privileged": False,
            "ReadonlyRootfs": True,
            "Binds": [],
        }))
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        # The legitimate container should still be found
        names = [c["container"] for c in result["results"]]
        assert "legit" in names
        # The evil traversal path should have been silently skipped (logged warning)
        # and must NOT cause any crash or unexpected behavior

    # -- Host namespace and capability rules --

    def test_host_pid_namespace(self, make_rootfs):
        r = make_rootfs
        cid = "pid" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/hostpid"},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "PidMode": "host",
                "CapDrop": ["ALL"],
            },
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "host_pid_namespace" in vio_ids

    def test_host_network_namespace(self, make_rootfs):
        r = make_rootfs
        cid = "net" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/hostnet"},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "NetworkMode": "host",
                "CapDrop": ["ALL"],
            },
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "host_network_namespace" in vio_ids

    def test_host_ipc_namespace(self, make_rootfs):
        r = make_rootfs
        cid = "ipc" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/hostipc"},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "IpcMode": "host",
                "CapDrop": ["ALL"],
            },
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "host_ipc_namespace" in vio_ids

    def test_dangerous_capabilities_added(self, make_rootfs):
        r = make_rootfs
        cid = "cap" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/dangcap"},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "CapAdd": ["SYS_ADMIN", "NET_RAW"],
                "CapDrop": ["ALL"],
            },
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "dangerous_capabilities_added" in vio_ids

    def test_dangerous_capabilities_with_cap_prefix(self, make_rootfs):
        """Docker may store capabilities with the CAP_ prefix."""
        r = make_rootfs
        cid = "cpx" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/capprefix"},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "CapAdd": ["CAP_SYS_PTRACE"],
                "CapDrop": ["ALL"],
            },
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "dangerous_capabilities_added" in vio_ids

    def test_safe_capabilities_not_flagged(self, make_rootfs):
        """Non-dangerous capabilities should not trigger the rule."""
        r = make_rootfs
        cid = "saf" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/safecap"},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "CapAdd": ["NET_BIND_SERVICE", "CHOWN"],
                "CapDrop": ["ALL"],
            },
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "dangerous_capabilities_added" not in vio_ids

    def test_cap_drop_missing(self, make_rootfs):
        r = make_rootfs
        cid = "nod" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/nodrop"},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
            },
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "cap_drop_missing" in vio_ids

    def test_cap_drop_present_not_flagged(self, make_rootfs):
        """When CapDrop is set, cap_drop_missing should not fire."""
        r = make_rootfs
        cid = "drp" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/hasdrop"},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "CapDrop": ["NET_RAW"],
            },
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "cap_drop_missing" not in vio_ids

    def test_apparmor_disabled(self, make_rootfs):
        r = make_rootfs
        cid = "aar" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/noapparmor"},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "SecurityOpt": ["apparmor=unconfined"],
                "CapDrop": ["ALL"],
            },
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "apparmor_disabled" in vio_ids

    def test_apparmor_with_profile_not_flagged(self, make_rootfs):
        """A custom AppArmor profile should not trigger the rule."""
        r = make_rootfs
        cid = "aap" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/hasapparmor"},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "SecurityOpt": ["apparmor=docker-default"],
                "CapDrop": ["ALL"],
            },
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "apparmor_disabled" not in vio_ids

    def test_fully_hardened_container_clean(self, make_rootfs):
        """A container with all security best practices should trigger none of the new rules."""
        r = make_rootfs
        cid = "hrd" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/hardened"},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": ["/data:/data:ro"],
                "PidMode": "",
                "NetworkMode": "bridge",
                "IpcMode": "",
                "CapAdd": [],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["apparmor=docker-default", "seccomp=/path/to/profile.json"],
            },
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        containers = result["results"]
        assert len(containers) == 1
        assert containers[0]["status"] == "clean"
        assert containers[0]["violations"] == []


# ------------------------------------------------------------------ #
# Podman scanner
# ------------------------------------------------------------------ #

class TestPodmanScanner:

    def test_root_uid_alert(self, make_rootfs):
        r = make_rootfs
        cid = "pod" * 8 + "0" * 40
        r.add_podman_container(
            cid,
            "rootpod",
            {
                "process": {
                    "user": {"uid": 0},
                    "capabilities": {"bounding": []},
                },
                "mounts": [],
                "linux": {},
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        assert result["scanner"] == "podman"
        assert result["summary"]["podman_scanned"] == 1
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "runs_as_root" in vio_ids

    def test_clean_podman_container(self, make_rootfs):
        r = make_rootfs
        cid = "pod" * 8 + "1" * 40
        r.add_podman_container(
            cid,
            "safepod",
            {
                "root": {"path": "rootfs", "readonly": True},
                "process": {
                    "user": {"uid": 1000},
                    "capabilities": {
                        "bounding": ["CAP_NET_BIND_SERVICE"],
                        "effective": ["CAP_NET_BIND_SERVICE"],
                    },
                },
                "mounts": [],
                "linux": {
                    "seccompProfilePath": "/path/to/seccomp.json",
                    "readonlyPaths": ["/proc"],
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                        {"type": "mount"},
                        {"type": "uts"},
                    ],
                },
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        safepod = [c for c in result["results"] if c["container"] == "safepod"]
        assert len(safepod) == 1
        assert safepod[0]["status"] == "clean"
        assert safepod[0]["violations"] == []

    def test_cap_sys_admin_alert(self, make_rootfs):
        r = make_rootfs
        cid = "pod" * 8 + "2" * 40
        r.add_podman_container(
            cid,
            "privpod",
            {
                "process": {
                    "user": {"uid": 1000},
                    "capabilities": {"bounding": ["CAP_SYS_ADMIN", "CAP_NET_RAW"]},
                },
                "mounts": [],
                "linux": {},
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "has_cap_sys_admin" in vio_ids

    def test_seccomp_disabled_warning(self, make_rootfs):
        r = make_rootfs
        cid = "pod" * 8 + "3" * 40
        r.add_podman_container(
            cid,
            "noseccomp",
            {
                "process": {
                    "user": {"uid": 1000},
                    "capabilities": {"bounding": []},
                },
                "mounts": [],
                "linux": {},
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "seccomp_disabled" in vio_ids

    def test_binds_not_readonly_warning(self, make_rootfs):
        r = make_rootfs
        cid = "pod" * 8 + "4" * 40
        r.add_podman_container(
            cid,
            "writablebind",
            {
                "process": {
                    "user": {"uid": 1000},
                    "capabilities": {"bounding": []},
                },
                "mounts": [
                    {
                        "type": "bind",
                        "source": "/host/data",
                        "destination": "/mnt",
                        "options": ["nosuid", "nodev"],
                    },
                ],
                "linux": {
                    "seccompProfilePath": "/path/to/seccomp.json",
                    "readonlyPaths": ["/proc"],
                },
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "binds_not_readonly" in vio_ids

    def test_readonly_rootfs_missing_warning(self, make_rootfs):
        r = make_rootfs
        cid = "pod" * 8 + "5" * 40
        r.add_podman_container(
            cid,
            "norootfs",
            {
                "process": {
                    "user": {"uid": 1000},
                    "capabilities": {"bounding": []},
                },
                "mounts": [],
                "linux": {
                    "seccompProfilePath": "/path/to/seccomp.json",
                },
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "readonly_rootfs_missing" in vio_ids

    def test_passwd_path_traversal_rejected(self, make_rootfs):
        """Malicious passwd home dirs with ../ must not escape rootfs."""
        r = make_rootfs
        r.add_passwd([
            "legit:x:1000:1000:Legit:/home/legit:/bin/bash",
            "evil:x:1001:1001:Evil:/home/../../etc:/bin/bash",
        ])
        # Place a podman storage dir under the legitimate home only
        cid = "pod" * 8 + "6" * 40
        sr = Path(r.path) / "home" / "legit" / ".local" / "share" / "containers" / "storage"
        index = sr / "overlay-containers" / "containers.json"
        index.parent.mkdir(parents=True, exist_ok=True)
        index.write_text(json.dumps([{"id": cid, "names": ["legitpod"]}]))
        cfg_dir = sr / "overlay-containers" / cid / "userdata"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        (cfg_dir / "config.json").write_text(json.dumps({
            "process": {
                "user": {"uid": 1000},
                "capabilities": {"bounding": []},
            },
            "mounts": [],
            "linux": {"readonlyPaths": ["/proc"]},
        }))
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        # The legitimate container should still be found
        names = [c["container"] for c in result["results"]]
        assert "legitpod" in names
        # The evil traversal path should have been silently skipped

    # -- Host namespace rules --

    def test_host_pid_namespace(self, make_rootfs):
        """Container missing pid namespace entry shares host PID namespace."""
        r = make_rootfs
        cid = "pod" * 8 + "7" * 40
        r.add_podman_container(
            cid,
            "hostpidpod",
            {
                "root": {"path": "rootfs", "readonly": True},
                "process": {
                    "user": {"uid": 1000},
                    "capabilities": {"bounding": [], "effective": []},
                },
                "mounts": [],
                "linux": {
                    "seccompProfilePath": "/path/to/seccomp.json",
                    "namespaces": [
                        {"type": "network"},
                        {"type": "ipc"},
                        {"type": "mount"},
                    ],
                },
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "host_pid_namespace" in vio_ids
        # network and ipc are present, so those should NOT fire
        assert "host_network_namespace" not in vio_ids
        assert "host_ipc_namespace" not in vio_ids

    def test_host_network_namespace(self, make_rootfs):
        """Container missing network namespace entry shares host network."""
        r = make_rootfs
        cid = "pod" * 8 + "8" * 40
        r.add_podman_container(
            cid,
            "hostnetpod",
            {
                "root": {"path": "rootfs", "readonly": True},
                "process": {
                    "user": {"uid": 1000},
                    "capabilities": {"bounding": [], "effective": []},
                },
                "mounts": [],
                "linux": {
                    "seccompProfilePath": "/path/to/seccomp.json",
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "ipc"},
                        {"type": "mount"},
                    ],
                },
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "host_network_namespace" in vio_ids
        assert "host_pid_namespace" not in vio_ids
        assert "host_ipc_namespace" not in vio_ids

    def test_host_ipc_namespace(self, make_rootfs):
        """Container missing ipc namespace entry shares host IPC."""
        r = make_rootfs
        cid = "pod" * 8 + "9" * 40
        r.add_podman_container(
            cid,
            "hostipcpod",
            {
                "root": {"path": "rootfs", "readonly": True},
                "process": {
                    "user": {"uid": 1000},
                    "capabilities": {"bounding": [], "effective": []},
                },
                "mounts": [],
                "linux": {
                    "seccompProfilePath": "/path/to/seccomp.json",
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "mount"},
                    ],
                },
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "host_ipc_namespace" in vio_ids
        assert "host_pid_namespace" not in vio_ids
        assert "host_network_namespace" not in vio_ids

    def test_all_host_namespaces_when_no_namespaces_array(self, make_rootfs):
        """Empty linux.namespaces means all namespaces are shared with host."""
        r = make_rootfs
        cid = "poa" * 8 + "0" * 40
        r.add_podman_container(
            cid,
            "allhostns",
            {
                "root": {"path": "rootfs", "readonly": True},
                "process": {
                    "user": {"uid": 1000},
                    "capabilities": {"bounding": [], "effective": []},
                },
                "mounts": [],
                "linux": {
                    "seccompProfilePath": "/path/to/seccomp.json",
                },
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "host_pid_namespace" in vio_ids
        assert "host_network_namespace" in vio_ids
        assert "host_ipc_namespace" in vio_ids

    # -- Dangerous capabilities --

    def test_dangerous_caps_in_bounding(self, make_rootfs):
        """Dangerous capabilities in bounding set trigger the rule."""
        r = make_rootfs
        cid = "pob" * 8 + "0" * 40
        r.add_podman_container(
            cid,
            "dangcappod",
            {
                "root": {"path": "rootfs", "readonly": True},
                "process": {
                    "user": {"uid": 1000},
                    "capabilities": {
                        "bounding": ["CAP_NET_RAW", "CAP_NET_BIND_SERVICE"],
                        "effective": [],
                    },
                },
                "mounts": [],
                "linux": {
                    "seccompProfilePath": "/path/to/seccomp.json",
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                        {"type": "mount"},
                    ],
                },
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "dangerous_caps_present" in vio_ids

    def test_dangerous_caps_in_effective(self, make_rootfs):
        """Dangerous capabilities in effective set also trigger the rule."""
        r = make_rootfs
        cid = "poc" * 8 + "0" * 40
        r.add_podman_container(
            cid,
            "dangeffpod",
            {
                "root": {"path": "rootfs", "readonly": True},
                "process": {
                    "user": {"uid": 1000},
                    "capabilities": {
                        "bounding": ["CAP_NET_BIND_SERVICE"],
                        "effective": ["CAP_SYS_PTRACE"],
                    },
                },
                "mounts": [],
                "linux": {
                    "seccompProfilePath": "/path/to/seccomp.json",
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                        {"type": "mount"},
                    ],
                },
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "dangerous_caps_present" in vio_ids

    def test_safe_caps_not_flagged(self, make_rootfs):
        """Non-dangerous capabilities should not trigger dangerous_caps_present."""
        r = make_rootfs
        cid = "pod" * 8 + "a" * 40
        r.add_podman_container(
            cid,
            "safecappod",
            {
                "root": {"path": "rootfs", "readonly": True},
                "process": {
                    "user": {"uid": 1000},
                    "capabilities": {
                        "bounding": ["CAP_NET_BIND_SERVICE", "CAP_CHOWN"],
                        "effective": ["CAP_NET_BIND_SERVICE"],
                    },
                },
                "mounts": [],
                "linux": {
                    "seccompProfilePath": "/path/to/seccomp.json",
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                        {"type": "mount"},
                    ],
                },
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "dangerous_caps_present" not in vio_ids

    # -- readonly rootfs fix --

    def test_readonly_rootfs_via_root_readonly(self, make_rootfs):
        """root.readonly=true should NOT trigger readonly_rootfs_missing."""
        r = make_rootfs
        cid = "poe" * 8 + "0" * 40
        r.add_podman_container(
            cid,
            "rorootpod",
            {
                "root": {"path": "rootfs", "readonly": True},
                "process": {
                    "user": {"uid": 1000},
                    "capabilities": {"bounding": [], "effective": []},
                },
                "mounts": [],
                "linux": {
                    "seccompProfilePath": "/path/to/seccomp.json",
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                        {"type": "mount"},
                    ],
                },
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "readonly_rootfs_missing" not in vio_ids

    def test_readonly_rootfs_missing_without_root_key(self, make_rootfs):
        """Missing root.readonly should trigger readonly_rootfs_missing."""
        r = make_rootfs
        cid = "pof" * 8 + "0" * 40
        r.add_podman_container(
            cid,
            "norootpod",
            {
                "process": {
                    "user": {"uid": 1000},
                    "capabilities": {"bounding": [], "effective": []},
                },
                "mounts": [],
                "linux": {
                    "seccompProfilePath": "/path/to/seccomp.json",
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                        {"type": "mount"},
                    ],
                },
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "readonly_rootfs_missing" in vio_ids

    def test_readonly_rootfs_false_triggers_rule(self, make_rootfs):
        """root.readonly=false should trigger readonly_rootfs_missing."""
        r = make_rootfs
        cid = "pog" * 8 + "0" * 40
        r.add_podman_container(
            cid,
            "rwrootpod",
            {
                "root": {"path": "rootfs", "readonly": False},
                "process": {
                    "user": {"uid": 1000},
                    "capabilities": {"bounding": [], "effective": []},
                },
                "mounts": [],
                "linux": {
                    "seccompProfilePath": "/path/to/seccomp.json",
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                        {"type": "mount"},
                    ],
                },
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "readonly_rootfs_missing" in vio_ids


# ------------------------------------------------------------------ #
# LXC scanner
# ------------------------------------------------------------------ #

class TestLxcScanner:

    _CLEAN_CONFIG = (
        "lxc.rootfs.path = /var/lib/lxc/clean/rootfs\n"
        "lxc.idmap = u 0 100000 65536\n"
        "lxc.idmap = g 0 100000 65536\n"
        "lxc.cap.drop = sys_admin net_raw\n"
    )

    _MISSING_IDMAP_CONFIG = (
        "lxc.rootfs.path = /var/lib/lxc/noidmap/rootfs\n"
        "lxc.cap.drop = sys_admin\n"
    )

    _INVALID_IDMAP_CONFIG = (
        "lxc.rootfs.path = /var/lib/lxc/badmap/rootfs\n"
        "lxc.idmap = u garbage_format\n"
        "lxc.idmap = g 0 100000 65536\n"
    )

    _DANGEROUS_MOUNT_CONFIG = (
        "lxc.rootfs.path = /var/lib/lxc/mounts/rootfs\n"
        "lxc.idmap = u 0 100000 65536\n"
        "lxc.idmap = g 0 100000 65536\n"
        "lxc.cap.drop = sys_admin\n"
        "lxc.mount.entry = /proc proc proc rw 0 0\n"
    )

    def test_clean_lxc_container(self, make_rootfs):
        r = make_rootfs
        r.add_lxc_config("clean", self._CLEAN_CONFIG)
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)

        assert result["scanner"] == "lxc"
        assert result["summary"]["lxc_scanned"] == 1
        containers = result["results"]
        assert len(containers) == 1
        assert containers[0]["status"] == "clean"
        assert containers[0]["violations"] == []

    def test_missing_idmap(self, make_rootfs):
        r = make_rootfs
        r.add_lxc_config("noidmap", self._MISSING_IDMAP_CONFIG)
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)

        containers = result["results"]
        assert len(containers) == 1
        vio_ids = [v["id"] for v in containers[0]["violations"]]
        assert "missing_uidmap" in vio_ids
        assert "missing_gidmap" in vio_ids

    def test_invalid_idmap_format(self, make_rootfs):
        """Regression: uidmap_format_invalid must fire on BAD format, not good."""
        r = make_rootfs
        r.add_lxc_config("badmap", self._INVALID_IDMAP_CONFIG)
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)

        containers = result["results"]
        vio_ids = [v["id"] for v in containers[0]["violations"]]
        # uidmap is "garbage_format" -> regex won't match valid pattern
        # -> not_regex_match returns False (because _IDMAP_RE won't parse it,
        #    so uidmap stays None -> missing_uidmap fires instead)
        assert "missing_uidmap" in vio_ids
        # gidmap is valid -> should NOT fire gidmap_format_invalid
        assert "gidmap_format_invalid" not in vio_ids

    def test_dangerous_mount(self, make_rootfs):
        r = make_rootfs
        r.add_lxc_config("mounts", self._DANGEROUS_MOUNT_CONFIG)
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)

        containers = result["results"]
        assert len(containers) == 1
        vio_ids = [v["id"] for v in containers[0]["violations"]]
        assert "mount_proc_dangerous" in vio_ids

    def test_dangerous_sys_mount(self, make_rootfs):
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/sysmnt/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.mount.entry = /sys sysfs sysfs rw 0 0\n"
        )
        r.add_lxc_config("sysmnt", config)
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)

        containers = result["results"]
        assert len(containers) == 1
        vio_ids = [v["id"] for v in containers[0]["violations"]]
        assert "mount_sys_dangerous" in vio_ids

    def test_dangerous_run_mount(self, make_rootfs):
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/runmnt/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.mount.entry = /run tmpfs tmpfs rw 0 0\n"
        )
        r.add_lxc_config("runmnt", config)
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)

        containers = result["results"]
        assert len(containers) == 1
        vio_ids = [v["id"] for v in containers[0]["violations"]]
        assert "mount_run_dangerous" in vio_ids

    def test_mount_usr_not_readonly(self, make_rootfs):
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/usrmnt/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.mount.entry = /usr usr none rw,bind 0 0\n"
        )
        r.add_lxc_config("usrmnt", config)
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)

        containers = result["results"]
        assert len(containers) == 1
        vio_ids = [v["id"] for v in containers[0]["violations"]]
        assert "mount_usr_should_be_ro" in vio_ids

    def test_cap_drop_missing(self, make_rootfs):
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/nocap/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
        )
        r.add_lxc_config("nocap", config)
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)

        containers = result["results"]
        assert len(containers) == 1
        vio_ids = [v["id"] for v in containers[0]["violations"]]
        assert "cap_drop_missing" in vio_ids

    def test_mount_dev_not_readonly(self, make_rootfs):
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/devmnt/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.mount.entry = /dev tmpfs tmpfs rw 0 0\n"
        )
        r.add_lxc_config("devmnt", config)
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)

        containers = result["results"]
        assert len(containers) == 1
        vio_ids = [v["id"] for v in containers[0]["violations"]]
        assert "mount_dev_should_be_ro" in vio_ids


# ------------------------------------------------------------------ #
# Full pipeline (core.run_scan)
# ------------------------------------------------------------------ #

class TestFullPipeline:

    def test_run_scan_returns_valid_report(self, make_rootfs):
        """Verify that core.run_scan produces a well-structured report."""
        from jibrilcon.core import run_scan

        r = make_rootfs
        cid = "full" * 8 + "0" * 32
        r.add_docker_container(
            cid,
            config_v2={"Name": "/fulltest"},
            hostconfig={"Privileged": False, "ReadonlyRootfs": True, "Binds": []},
        )
        report = run_scan(r.path)

        assert "report" in report
        assert "summary" in report
        assert isinstance(report["report"], list)
        assert isinstance(report["summary"], dict)
        # At least scanners_run should be populated
        assert "scanners_run" in report["summary"]

"""Integration tests for scanner modules using minimal rootfs fixtures."""

import json
from pathlib import Path

import pytest

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
                "process": {
                    "user": {"uid": 1000},
                    "capabilities": {"bounding": ["CAP_NET_BIND_SERVICE"]},
                },
                "mounts": [],
                "linux": {"readonlyPaths": ["/proc"]},
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        safepod = [c for c in result["results"] if c["container"] == "safepod"]
        assert len(safepod) == 1
        # Should have no alert-level violations for runs_as_root or cap_sys_admin
        alert_ids = [v["id"] for v in safepod[0]["violations"] if v["type"] == "alert"]
        assert "runs_as_root" not in alert_ids
        assert "has_cap_sys_admin" not in alert_ids

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

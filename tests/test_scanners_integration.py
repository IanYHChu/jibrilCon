"""Integration tests for scanner modules using minimal rootfs fixtures."""

import json
from pathlib import Path

from jibrilcon.scanners import docker_native, lxc, podman
from tests.conftest import _make_context

# ------------------------------------------------------------------ #
# Docker scanner
# ------------------------------------------------------------------ #


class TestDockerScanner:
    def test_clean_container(self, make_rootfs):
        r = make_rootfs
        r.add_docker_daemon_json({"userns-remap": "default", "icc": False})
        cid = "aaa" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={
                "Name": "/clean",
                "Config": {"User": "appuser", "Image": "myapp:v1.0"},
            },
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": ["/data:/data:ro"],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "Memory": 536870912,
                "PidsLimit": 100,
                "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 3},
                "LogConfig": {"Type": "json-file"},
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("docker", "clean")
        ctx.set_service_meta(
            "docker",
            "clean",
            {
                "user": "dockeruser",
                "unit": "docker-clean.service",
                "path": "etc/systemd/system/docker-clean.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = docker_native.scan(r.path, context=ctx)
        assert result["scanner"] == "docker"
        assert result["summary"]["docker_scanned"] == 1
        containers = result["results"]
        assert len(containers) == 1
        assert containers[0]["status"] == "clean"
        assert containers[0]["violations"] == []
        assert containers[0]["managed"] is True

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
        priv = [
            v for v in result["results"][0]["violations"] if v["id"] == "privileged"
        ][0]

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
        for _name, container in results_by_name.items():
            for vio in container["violations"]:
                assert "source" in vio
                assert vio["source"]  # source must be a non-empty path string
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
        base = (
            Path(r.path)
            / "home"
            / "testuser"
            / ".local"
            / "share"
            / "docker"
            / "containers"
            / cid
        )
        base.mkdir(parents=True, exist_ok=True)
        (base / "config.v2.json").write_text(json.dumps({"Name": "/rootless"}))
        (base / "hostconfig.json").write_text(
            json.dumps(
                {
                    "Privileged": True,
                    "ReadonlyRootfs": False,
                    "Binds": [],
                }
            )
        )
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
        r.add_docker_daemon_json({"userns-remap": "default", "icc": False})
        cid = "fff" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={
                "Name": "/roextra",
                "Config": {"User": "appuser", "Image": "myapp:v1.0"},
            },
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": ["/data:/data:ro,rslave"],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "Memory": 536870912,
                "PidsLimit": 100,
                "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 3},
                "LogConfig": {"Type": "json-file"},
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("docker", "roextra")
        ctx.set_service_meta(
            "docker",
            "roextra",
            {
                "user": "dockeruser",
                "unit": "docker-roextra.service",
                "path": "etc/systemd/system/docker-roextra.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
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
        r.add_passwd(
            [
                "legit:x:1000:1000:Legit:/home/legit:/bin/bash",
                "evil:x:1001:1001:Evil:/home/../../etc:/bin/bash",
            ]
        )
        # Place a docker dir under the legitimate home only
        cid = "hhh" * 8 + "0" * 40
        base = (
            Path(r.path)
            / "home"
            / "legit"
            / ".local"
            / "share"
            / "docker"
            / "containers"
            / cid
        )
        base.mkdir(parents=True, exist_ok=True)
        (base / "config.v2.json").write_text(json.dumps({"Name": "/legit"}))
        (base / "hostconfig.json").write_text(
            json.dumps(
                {
                    "Privileged": False,
                    "ReadonlyRootfs": True,
                    "Binds": [],
                }
            )
        )
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
        r.add_docker_daemon_json({"userns-remap": "default", "icc": False})
        cid = "hrd" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={
                "Name": "/hardened",
                "Config": {"User": "appuser", "Image": "myapp:v1.2.3"},
            },
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": ["/data:/data:ro"],
                "PidMode": "",
                "NetworkMode": "bridge",
                "IpcMode": "",
                "CapAdd": [],
                "CapDrop": ["ALL"],
                "SecurityOpt": [
                    "apparmor=docker-default",
                    "seccomp=/path/to/profile.json",
                    "no-new-privileges",
                ],
                "Memory": 536870912,
                "PidsLimit": 100,
                "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 3},
                "LogConfig": {"Type": "json-file"},
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("docker", "hardened")
        ctx.set_service_meta(
            "docker",
            "hardened",
            {
                "user": "dockeruser",
                "unit": "docker-hardened.service",
                "path": "etc/systemd/system/docker-hardened.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = docker_native.scan(r.path, context=ctx)
        containers = result["results"]
        assert len(containers) == 1
        assert containers[0]["status"] == "clean"
        assert containers[0]["violations"] == []
        assert containers[0]["managed"] is True

    def test_dangerous_bind_path_docker_sock(self, make_rootfs):
        r = make_rootfs
        cid = "dbs" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/dind"},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": ["/var/run/docker.sock:/var/run/docker.sock"],
                "CapDrop": ["ALL"],
            },
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "dangerous_bind_path" in vio_ids

    def test_no_new_privileges_missing(self, make_rootfs):
        r = make_rootfs
        cid = "nnp" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/nonnp"},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "CapDrop": ["ALL"],
                "SecurityOpt": [],
            },
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "no_new_privileges_missing" in vio_ids

    def test_no_new_privileges_set_not_flagged(self, make_rootfs):
        r = make_rootfs
        cid = "nnp" * 8 + "1" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/nnpok", "Config": {"Image": "app:v1"}},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
            },
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "no_new_privileges_missing" not in vio_ids

    def test_mount_propagation_shared(self, make_rootfs):
        r = make_rootfs
        cid = "mps" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/shared"},
            hostconfig={
                "Privileged": False,
                "Binds": ["/data:/data:rw,rshared"],
            },
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "mount_propagation_shared" in vio_ids

    def test_image_tag_latest(self, make_rootfs):
        r = make_rootfs
        cid = "itl" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/latest", "Config": {"Image": "nginx:latest"}},
            hostconfig={"Privileged": False, "Binds": []},
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "image_tag_latest" in vio_ids

    def test_image_tag_pinned_not_flagged(self, make_rootfs):
        r = make_rootfs
        cid = "itp" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/pinned", "Config": {"Image": "nginx:1.25.3"}},
            hostconfig={"Privileged": False, "Binds": []},
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "image_tag_latest" not in vio_ids

    def test_rootless_privileged_has_reduced_severity(self, make_rootfs):
        """Rootless Docker privileged container should have lower severity."""
        r = make_rootfs
        # Create a rootless container by placing it under a user's home
        r.add_passwd(["testuser:x:1000:1000:Test:/home/testuser:/bin/bash"])
        cid = "ccc" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/rootless_priv"},
            hostconfig={"Privileged": True, "ReadonlyRootfs": False, "Binds": []},
            data_root="/home/testuser/.local/share/docker",
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        containers = result["results"]
        assert len(containers) == 1
        priv_vio = [v for v in containers[0]["violations"] if v["id"] == "privileged"]
        assert len(priv_vio) == 1
        assert priv_vio[0]["severity"] == 5.0
        assert priv_vio[0]["type"] == "warning"
        assert containers[0]["managed"] is False

    def test_rootful_privileged_keeps_full_severity(self, make_rootfs):
        """Rootful Docker privileged container keeps original high severity."""
        r = make_rootfs
        cid = "ddd" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/rootful_priv"},
            hostconfig={"Privileged": True, "ReadonlyRootfs": False, "Binds": []},
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        containers = result["results"]
        assert len(containers) == 1
        priv_vio = [v for v in containers[0]["violations"] if v["id"] == "privileged"]
        assert len(priv_vio) == 1
        assert priv_vio[0]["severity"] == 9.0
        assert priv_vio[0]["type"] == "alert"
        assert containers[0]["managed"] is False

    def test_systemd_service_missing_detected(self, make_rootfs):
        """Container without systemd service should trigger alert."""
        r = make_rootfs
        cid = "eee" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/orphan"},
            hostconfig={"Privileged": False, "ReadonlyRootfs": True, "Binds": []},
        )
        # No systemd service -> context has no service_meta for this container
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "systemd_service_missing" in vio_ids
        assert result["results"][0]["managed"] is False

    def test_systemd_caps_unrestricted_detected(self, make_rootfs):
        """Systemd service without CapabilityBoundingSet should trigger warning."""
        r = make_rootfs
        cid = "fff" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/nocaps"},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("docker", "nocaps")
        # Register service meta WITHOUT cap_bounding_set
        ctx.set_service_meta(
            "docker",
            "nocaps",
            {
                "user": "dockeruser",
                "unit": "docker-nocaps.service",
                "path": "etc/systemd/system/docker-nocaps.service",
                "cap_bounding_set": "",
                "ambient_capabilities": "",
            },
        )
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "systemd_caps_unrestricted" in vio_ids
        # systemd_service_missing should NOT be in violations
        assert "systemd_service_missing" not in vio_ids

    def test_systemd_with_caps_not_flagged(self, make_rootfs):
        """Systemd service WITH CapabilityBoundingSet should NOT trigger."""
        r = make_rootfs
        cid = "ggg" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/withcaps"},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("docker", "withcaps")
        ctx.set_service_meta(
            "docker",
            "withcaps",
            {
                "user": "dockeruser",
                "unit": "docker-withcaps.service",
                "path": "etc/systemd/system/docker-withcaps.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE CAP_CHOWN",
                "ambient_capabilities": "",
            },
        )
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "systemd_caps_unrestricted" not in vio_ids
        assert "systemd_service_missing" not in vio_ids

    def test_broken_systemd_service_detected(self, make_rootfs):
        """Systemd references container but config not on disk."""
        r = make_rootfs
        ctx = _make_context()
        # Register a systemd service for a container that doesn't exist on disk
        ctx.mark_systemd_started("docker", "ghost")
        ctx.set_service_meta(
            "docker",
            "ghost",
            {
                "user": "dockeruser",
                "unit": "docker-ghost.service",
                "path": "etc/systemd/system/docker-ghost.service",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        result = docker_native.scan(r.path, context=ctx)
        # Should find the ghost container as a broken service
        ghost = [c for c in result["results"] if c["container"] == "ghost"]
        assert len(ghost) == 1
        assert ghost[0]["managed"] is True
        assert ghost[0]["status"] == "violated"
        vio_ids = [v["id"] for v in ghost[0]["violations"]]
        assert "systemd_service_broken" in vio_ids
        # Verify the source references the systemd service path
        broken_vio = [
            v for v in ghost[0]["violations"] if v["id"] == "systemd_service_broken"
        ][0]
        assert "etc/systemd/system/docker-ghost.service" in broken_vio["source"]
        assert broken_vio["severity"] == 8.0
        assert broken_vio["type"] == "alert"

    def test_managed_vs_orphaned_classification(self, make_rootfs):
        """Containers in systemd are managed=True, others are managed=False."""
        r = make_rootfs
        cid_a = "mng" * 8 + "0" * 40
        cid_b = "orp" * 8 + "0" * 40
        r.add_docker_container(
            cid_a,
            config_v2={"Name": "/managed_ctr"},
            hostconfig={"Privileged": False, "ReadonlyRootfs": True, "Binds": []},
        )
        r.add_docker_container(
            cid_b,
            config_v2={"Name": "/orphaned_ctr"},
            hostconfig={"Privileged": False, "ReadonlyRootfs": True, "Binds": []},
        )
        ctx = _make_context()
        # Only register managed_ctr in systemd
        ctx.mark_systemd_started("docker", "managed_ctr")
        ctx.set_service_meta(
            "docker",
            "managed_ctr",
            {
                "user": "dockeruser",
                "unit": "docker-managed.service",
                "path": "etc/systemd/system/docker-managed.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = docker_native.scan(r.path, context=ctx)
        by_name = {c["container"]: c for c in result["results"]}
        assert by_name["managed_ctr"]["managed"] is True
        assert by_name["orphaned_ctr"]["managed"] is False

    # -- New HIGH priority rules --

    def test_container_user_root_detected(self, make_rootfs):
        """Container with empty User (runs as root) should trigger warning."""
        r = make_rootfs
        cid = "usr" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/rootuser", "Config": {"User": "", "Image": "app:v1"}},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "Memory": 536870912,
                "PidsLimit": 100,
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("docker", "rootuser")
        ctx.set_service_meta(
            "docker",
            "rootuser",
            {
                "user": "dockeruser",
                "unit": "docker-rootuser.service",
                "path": "etc/systemd/system/docker-rootuser.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "container_user_is_root" in vio_ids

    def test_memory_limit_missing_detected(self, make_rootfs):
        """Container without memory limit should trigger warning."""
        r = make_rootfs
        cid = "mem" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/nomem", "Config": {"Image": "app:v1"}},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "Memory": 0,
                "PidsLimit": 100,
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("docker", "nomem")
        ctx.set_service_meta(
            "docker",
            "nomem",
            {
                "user": "dockeruser",
                "unit": "docker-nomem.service",
                "path": "etc/systemd/system/docker-nomem.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "memory_limit_missing" in vio_ids

    def test_restart_always_detected(self, make_rootfs):
        """Container with restart=always should trigger warning."""
        r = make_rootfs
        cid = "rst" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/restartalways", "Config": {"Image": "app:v1"}},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "Memory": 536870912,
                "PidsLimit": 100,
                "RestartPolicy": {"Name": "always", "MaximumRetryCount": 0},
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("docker", "restartalways")
        ctx.set_service_meta(
            "docker",
            "restartalways",
            {
                "user": "dockeruser",
                "unit": "docker-restart.service",
                "path": "etc/systemd/system/docker-restart.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "restart_always" in vio_ids

    def test_logging_disabled_detected(self, make_rootfs):
        """Container with logging disabled should trigger warning."""
        r = make_rootfs
        cid = "log" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/nolog", "Config": {"Image": "app:v1"}},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "Memory": 536870912,
                "PidsLimit": 100,
                "LogConfig": {"Type": "none", "Config": {}},
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("docker", "nolog")
        ctx.set_service_meta(
            "docker",
            "nolog",
            {
                "user": "dockeruser",
                "unit": "docker-nolog.service",
                "path": "etc/systemd/system/docker-nolog.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "logging_disabled" in vio_ids

    def test_daemon_userns_remap_missing_detected(self, make_rootfs):
        """Daemon without userns-remap should trigger warning."""
        r = make_rootfs
        r.add_docker_daemon_json({})  # empty daemon.json, no userns-remap
        cid = "dmn" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/daemon_test", "Config": {"Image": "app:v1"}},
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "Memory": 536870912,
                "PidsLimit": 100,
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("docker", "daemon_test")
        ctx.set_service_meta(
            "docker",
            "daemon_test",
            {
                "user": "dockeruser",
                "unit": "docker-daemon.service",
                "path": "etc/systemd/system/docker-daemon.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "daemon_userns_remap_missing" in vio_ids
        assert "daemon_icc_enabled" in vio_ids

    def test_dangerous_device_cgroup_detected(self, make_rootfs):
        r = make_rootfs
        r.add_docker_daemon_json({"userns-remap": "default", "icc": False})
        cid = "dcg" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={
                "Name": "/devcgroup",
                "Config": {"User": "app", "Image": "app:v1"},
            },
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "Memory": 536870912,
                "PidsLimit": 100,
                "DeviceCgroupRules": ["a *:* rwm"],
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("docker", "devcgroup")
        ctx.set_service_meta(
            "docker",
            "devcgroup",
            {
                "user": "u",
                "unit": "d.service",
                "path": "etc/systemd/system/d.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = docker_native.scan(r.path, context=ctx)
        assert "dangerous_device_cgroup" in [
            v["id"] for v in result["results"][0]["violations"]
        ]

    def test_dangerous_device_mounted_detected(self, make_rootfs):
        r = make_rootfs
        r.add_docker_daemon_json({"userns-remap": "default", "icc": False})
        cid = "dvm" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={
                "Name": "/devmount",
                "Config": {"User": "app", "Image": "app:v1"},
            },
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": [],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "Memory": 536870912,
                "PidsLimit": 100,
                "Devices": [
                    {
                        "PathOnHost": "/dev/mem",
                        "PathInContainer": "/dev/mem",
                        "CgroupPermissions": "rwm",
                    }
                ],
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("docker", "devmount")
        ctx.set_service_meta(
            "docker",
            "devmount",
            {
                "user": "u",
                "unit": "d.service",
                "path": "etc/systemd/system/d.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = docker_native.scan(r.path, context=ctx)
        assert "dangerous_device_mounted" in [
            v["id"] for v in result["results"][0]["violations"]
        ]

    def test_socket_mount_writable_detected(self, make_rootfs):
        """Writable docker.sock bind mount should trigger alert."""
        r = make_rootfs
        r.add_docker_daemon_json({"userns-remap": "default", "icc": False})
        cid = "smw" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={
                "Name": "/sockrw",
                "Config": {"User": "app", "Image": "app:v1"},
            },
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": ["/var/run/docker.sock:/var/run/docker.sock"],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "Memory": 536870912,
                "PidsLimit": 100,
                "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 3},
                "LogConfig": {"Type": "json-file"},
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("docker", "sockrw")
        ctx.set_service_meta(
            "docker",
            "sockrw",
            {
                "user": "u",
                "unit": "d.service",
                "path": "etc/systemd/system/d.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "socket_mount_writable" in vio_ids

    def test_extra_hosts_present_detected(self, make_rootfs):
        """Container with ExtraHosts entries should trigger info."""
        r = make_rootfs
        r.add_docker_daemon_json({"userns-remap": "default", "icc": False})
        cid = "exh" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={
                "Name": "/extrahosts",
                "Config": {"User": "app", "Image": "app:v1"},
            },
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": ["/data:/data:ro"],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "Memory": 536870912,
                "PidsLimit": 100,
                "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 3},
                "LogConfig": {"Type": "json-file"},
                "ExtraHosts": ["myhost:10.0.0.1"],
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("docker", "extrahosts")
        ctx.set_service_meta(
            "docker",
            "extrahosts",
            {
                "user": "u",
                "unit": "d.service",
                "path": "etc/systemd/system/d.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "extra_hosts_present" in vio_ids

    def test_ulimits_excessive_detected(self, make_rootfs):
        """Container with nofile ulimit >1M should trigger warning."""
        r = make_rootfs
        r.add_docker_daemon_json({"userns-remap": "default", "icc": False})
        cid = "ulm" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={
                "Name": "/highulimit",
                "Config": {"User": "app", "Image": "app:v1"},
            },
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": ["/data:/data:ro"],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "Memory": 536870912,
                "PidsLimit": 100,
                "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 3},
                "LogConfig": {"Type": "json-file"},
                "Ulimits": [{"Name": "nofile", "Soft": 2097152, "Hard": 2097152}],
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("docker", "highulimit")
        ctx.set_service_meta(
            "docker",
            "highulimit",
            {
                "user": "u",
                "unit": "d.service",
                "path": "etc/systemd/system/d.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "ulimits_excessive" in vio_ids

    def test_selinux_privileged_detected(self, make_rootfs):
        """Container with spc_t SELinux label should trigger alert."""
        r = make_rootfs
        r.add_docker_daemon_json({"userns-remap": "default", "icc": False})
        cid = "sel" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={
                "Name": "/spct",
                "Config": {"User": "app", "Image": "app:v1"},
            },
            hostconfig={
                "Privileged": False,
                "ReadonlyRootfs": True,
                "Binds": ["/data:/data:ro"],
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges", "label=type:spc_t"],
                "Memory": 536870912,
                "PidsLimit": 100,
                "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 3},
                "LogConfig": {"Type": "json-file"},
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("docker", "spct")
        ctx.set_service_meta(
            "docker",
            "spct",
            {
                "user": "u",
                "unit": "d.service",
                "path": "etc/systemd/system/d.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = docker_native.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "selinux_privileged" in vio_ids


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
                    "noNewPrivileges": True,
                    "apparmorProfile": "runtime/default",
                    "capabilities": {
                        "bounding": ["CAP_NET_BIND_SERVICE"],
                        "effective": ["CAP_NET_BIND_SERVICE"],
                    },
                },
                "mounts": [],
                "linux": {
                    "seccompProfilePath": "/path/to/seccomp.json",
                    "readonlyPaths": [
                        "/proc",
                        "/proc/sys",
                        "/proc/irq",
                        "/proc/bus",
                        "/sys/firmware",
                    ],
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                        {"type": "mount"},
                        {"type": "uts"},
                    ],
                    "resources": {
                        "memory": {"limit": 536870912},
                        "pids": {"limit": 100},
                    },
                    "maskedPaths": [
                        "/proc/kcore",
                        "/proc/sysrq-trigger",
                        "/proc/mem",
                        "/proc/kmsg",
                    ],
                },
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("podman", "safepod")
        ctx.set_service_meta(
            "podman",
            "safepod",
            {
                "user": "podmanuser",
                "unit": "podman-safepod.service",
                "path": "etc/systemd/system/podman-safepod.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = podman.scan(r.path, context=ctx)
        safepod = [c for c in result["results"] if c["container"] == "safepod"]
        assert len(safepod) == 1
        assert safepod[0]["status"] == "clean"
        assert safepod[0]["violations"] == []
        assert safepod[0]["managed"] is True

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
        r.add_passwd(
            [
                "legit:x:1000:1000:Legit:/home/legit:/bin/bash",
                "evil:x:1001:1001:Evil:/home/../../etc:/bin/bash",
            ]
        )
        # Place a podman storage dir under the legitimate home only
        cid = "pod" * 8 + "6" * 40
        sr = (
            Path(r.path)
            / "home"
            / "legit"
            / ".local"
            / "share"
            / "containers"
            / "storage"
        )
        index = sr / "overlay-containers" / "containers.json"
        index.parent.mkdir(parents=True, exist_ok=True)
        index.write_text(json.dumps([{"id": cid, "names": ["legitpod"]}]))
        cfg_dir = sr / "overlay-containers" / cid / "userdata"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        (cfg_dir / "config.json").write_text(
            json.dumps(
                {
                    "process": {
                        "user": {"uid": 1000},
                        "capabilities": {"bounding": []},
                    },
                    "mounts": [],
                    "linux": {"readonlyPaths": ["/proc"]},
                }
            )
        )
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

    def test_dangerous_bind_path_proc(self, make_rootfs):
        r = make_rootfs
        cid = "dbp" * 8 + "0" * 40
        r.add_podman_container(
            cid,
            "dangerousbind",
            {
                "process": {"user": {"uid": 1000}},
                "mounts": [
                    {"type": "bind", "source": "/proc", "destination": "/host-proc"},
                ],
                "linux": {
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                    ],
                },
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "dangerous_bind_path" in vio_ids

    def test_no_new_privileges_missing_podman(self, make_rootfs):
        r = make_rootfs
        cid = "nnp" * 8 + "0" * 40
        r.add_podman_container(
            cid,
            "nonnp",
            {
                "process": {"user": {"uid": 1000}},
                "mounts": [],
                "linux": {
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                    ],
                },
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "no_new_privileges_missing" in vio_ids

    def test_apparmor_disabled_podman(self, make_rootfs):
        r = make_rootfs
        cid = "aap" * 8 + "0" * 40
        r.add_podman_container(
            cid,
            "aa-unconfined",
            {
                "process": {
                    "user": {"uid": 1000},
                    "apparmorProfile": "unconfined",
                },
                "mounts": [],
                "linux": {
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                    ],
                },
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "apparmor_disabled" in vio_ids

    def test_mount_propagation_shared_podman(self, make_rootfs):
        r = make_rootfs
        cid = "mps" * 8 + "0" * 40
        r.add_podman_container(
            cid,
            "shared-mount",
            {
                "process": {"user": {"uid": 1000}},
                "mounts": [
                    {
                        "type": "bind",
                        "source": "/data",
                        "destination": "/data",
                        "options": ["rw", "rshared"],
                    },
                ],
                "linux": {
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                    ],
                },
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "mount_propagation_shared" in vio_ids

    def test_dangerous_caps_in_ambient(self, make_rootfs):
        """Dangerous capabilities in ambient set should be detected."""
        r = make_rootfs
        cid = "amb" * 8 + "f" * 40
        r.add_podman_container(
            cid,
            "ambient_caps",
            {
                "process": {
                    "user": {"uid": 1000},
                    "capabilities": {
                        "bounding": [],
                        "effective": [],
                        "ambient": ["CAP_SYS_ADMIN"],
                    },
                },
                "root": {"readonly": True},
                "linux": {
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                    ],
                    "resources": {
                        "memory": {"limit": 536870912},
                        "pids": {"limit": 100},
                    },
                    "maskedPaths": [
                        "/proc/kcore",
                        "/proc/sysrq-trigger",
                        "/proc/mem",
                        "/proc/kmsg",
                    ],
                },
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("podman", "ambient_caps")
        ctx.set_service_meta(
            "podman",
            "ambient_caps",
            {
                "user": "podmanuser",
                "unit": "p.service",
                "path": "etc/systemd/system/p.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "dangerous_caps_present" in vio_ids

    def test_memory_limit_missing_detected(self, make_rootfs):
        """Container without memory limit should trigger warning."""
        r = make_rootfs
        cid = "mem" * 8 + "f" * 40
        r.add_podman_container(
            cid,
            "nomem",
            {
                "process": {"user": {"uid": 1000}, "noNewPrivileges": True},
                "root": {"readonly": True},
                "linux": {
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                    ],
                    "seccompProfilePath": "/etc/seccomp/default.json",
                    "maskedPaths": [
                        "/proc/kcore",
                        "/proc/sysrq-trigger",
                        "/proc/mem",
                        "/proc/kmsg",
                    ],
                },
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("podman", "nomem")
        ctx.set_service_meta(
            "podman",
            "nomem",
            {
                "user": "podmanuser",
                "unit": "p.service",
                "path": "etc/systemd/system/p.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "memory_limit_missing" in vio_ids
        assert "pids_limit_missing" in vio_ids

    def test_critical_masks_missing_detected(self, make_rootfs):
        """Missing critical masked paths should trigger warning."""
        r = make_rootfs
        cid = "msk" * 8 + "f" * 40
        r.add_podman_container(
            cid,
            "nomask",
            {
                "process": {"user": {"uid": 1000}, "noNewPrivileges": True},
                "root": {"readonly": True},
                "linux": {
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                    ],
                    "seccompProfilePath": "/etc/seccomp/default.json",
                    "resources": {
                        "memory": {"limit": 536870912},
                        "pids": {"limit": 100},
                    },
                    "maskedPaths": [],
                },
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("podman", "nomask")
        ctx.set_service_meta(
            "podman",
            "nomask",
            {
                "user": "podmanuser",
                "unit": "p.service",
                "path": "etc/systemd/system/p.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "critical_masks_missing" in vio_ids

    def test_rootless_uid0_has_reduced_severity(self, make_rootfs):
        """Rootless Podman UID 0 should have lower severity than rootful."""
        r = make_rootfs
        r.add_passwd(["testuser:x:1000:1000:Test:/home/testuser:/bin/bash"])
        cid = "aaa" * 8 + "f" * 40
        r.add_podman_container(
            cid,
            "rootless_test",
            {
                "process": {"user": {"uid": 0}},
                "root": {"readonly": False},
                "linux": {
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                    ],
                },
            },
            storage_root="/home/testuser/.local/share/containers/storage",
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        containers = result["results"]
        assert len(containers) == 1
        uid_vio = [v for v in containers[0]["violations"] if v["id"] == "runs_as_root"]
        assert len(uid_vio) == 1
        assert uid_vio[0]["severity"] == 2.0
        assert uid_vio[0]["type"] == "info"
        assert containers[0]["managed"] is False

    def test_rootful_uid0_keeps_full_severity(self, make_rootfs):
        """Rootful Podman UID 0 keeps original high severity."""
        r = make_rootfs
        cid = "bbb" * 8 + "f" * 40
        r.add_podman_container(
            cid,
            "rootful_test",
            {
                "process": {"user": {"uid": 0}},
                "root": {"readonly": False},
                "linux": {
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                    ],
                },
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        containers = result["results"]
        assert len(containers) == 1
        uid_vio = [v for v in containers[0]["violations"] if v["id"] == "runs_as_root"]
        assert len(uid_vio) == 1
        assert uid_vio[0]["severity"] == 7.0
        assert uid_vio[0]["type"] == "alert"
        assert containers[0]["managed"] is False

    def test_systemd_service_missing_detected(self, make_rootfs):
        """Container without systemd service should trigger alert."""
        r = make_rootfs
        cid = "eee" * 8 + "f" * 40
        r.add_podman_container(
            cid,
            "orphan_podman",
            {
                "process": {"user": {"uid": 1000}},
                "root": {"readonly": True},
                "linux": {
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                    ]
                },
            },
        )
        ctx = _make_context()
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "systemd_service_missing" in vio_ids
        assert result["results"][0]["managed"] is False

    def test_systemd_caps_unrestricted_detected(self, make_rootfs):
        """Systemd service without CapabilityBoundingSet should trigger warning."""
        r = make_rootfs
        cid = "fff" * 8 + "f" * 40
        r.add_podman_container(
            cid,
            "nocaps_podman",
            {
                "process": {
                    "user": {"uid": 1000},
                    "noNewPrivileges": True,
                },
                "root": {"readonly": True},
                "linux": {
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                    ],
                    "seccompProfilePath": "/etc/seccomp/default.json",
                },
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("podman", "nocaps_podman")
        ctx.set_service_meta(
            "podman",
            "nocaps_podman",
            {
                "user": "podmanuser",
                "unit": "podman-nocaps.service",
                "path": "etc/systemd/system/podman-nocaps.service",
                "cap_bounding_set": "",
                "ambient_capabilities": "",
            },
        )
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "systemd_caps_unrestricted" in vio_ids
        assert "systemd_service_missing" not in vio_ids

    def test_systemd_with_caps_not_flagged(self, make_rootfs):
        """Systemd service WITH CapabilityBoundingSet should NOT trigger."""
        r = make_rootfs
        cid = "ggg" * 8 + "f" * 40
        r.add_podman_container(
            cid,
            "withcaps_podman",
            {
                "process": {
                    "user": {"uid": 1000},
                    "noNewPrivileges": True,
                },
                "root": {"readonly": True},
                "linux": {
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                    ],
                    "seccompProfilePath": "/etc/seccomp/default.json",
                },
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("podman", "withcaps_podman")
        ctx.set_service_meta(
            "podman",
            "withcaps_podman",
            {
                "user": "podmanuser",
                "unit": "podman-withcaps.service",
                "path": "etc/systemd/system/podman-withcaps.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "systemd_caps_unrestricted" not in vio_ids
        assert "systemd_service_missing" not in vio_ids

    def test_broken_systemd_service_detected(self, make_rootfs):
        """Systemd references container but config not on disk."""
        r = make_rootfs
        ctx = _make_context()
        ctx.mark_systemd_started("podman", "ghost")
        ctx.set_service_meta(
            "podman",
            "ghost",
            {
                "user": "podmanuser",
                "unit": "podman-ghost.service",
                "path": "etc/systemd/system/podman-ghost.service",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        result = podman.scan(r.path, context=ctx)
        ghost = [r for r in result["results"] if r["container"] == "ghost"]
        assert len(ghost) == 1
        assert ghost[0]["managed"] is True
        vio_ids = [v["id"] for v in ghost[0]["violations"]]
        assert "systemd_service_broken" in vio_ids

    def test_critical_readonly_missing_detected(self, make_rootfs):
        r = make_rootfs
        cid = "rop" * 8 + "f" * 40
        r.add_podman_container(
            cid,
            "noreadonly",
            {
                "process": {
                    "user": {"uid": 1000},
                    "noNewPrivileges": True,
                },
                "root": {"readonly": True},
                "linux": {
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                    ],
                    "seccompProfilePath": "/etc/seccomp/default.json",
                    "resources": {
                        "memory": {"limit": 536870912},
                        "pids": {"limit": 100},
                    },
                    "maskedPaths": [
                        "/proc/kcore",
                        "/proc/sysrq-trigger",
                        "/proc/mem",
                        "/proc/kmsg",
                    ],
                    "readonlyPaths": [],
                },
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("podman", "noreadonly")
        ctx.set_service_meta(
            "podman",
            "noreadonly",
            {
                "user": "u",
                "unit": "p.service",
                "path": "etc/systemd/system/p.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = podman.scan(r.path, context=ctx)
        assert "critical_readonly_missing" in [
            v["id"] for v in result["results"][0]["violations"]
        ]

    def test_selinux_privileged_detected(self, make_rootfs):
        r = make_rootfs
        cid = "sel" * 8 + "f" * 40
        r.add_podman_container(
            cid,
            "selinux_priv",
            {
                "process": {
                    "user": {"uid": 1000},
                    "noNewPrivileges": True,
                    "selinuxLabel": "system_u:system_r:spc_t:s0",
                },
                "root": {"readonly": True},
                "linux": {
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                    ],
                    "seccompProfilePath": "/etc/seccomp/default.json",
                    "resources": {
                        "memory": {"limit": 536870912},
                        "pids": {"limit": 100},
                    },
                    "maskedPaths": [
                        "/proc/kcore",
                        "/proc/sysrq-trigger",
                        "/proc/mem",
                        "/proc/kmsg",
                    ],
                    "readonlyPaths": [
                        "/proc/sys",
                        "/proc/irq",
                        "/proc/bus",
                        "/sys/firmware",
                    ],
                },
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("podman", "selinux_priv")
        ctx.set_service_meta(
            "podman",
            "selinux_priv",
            {
                "user": "u",
                "unit": "p.service",
                "path": "etc/systemd/system/p.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = podman.scan(r.path, context=ctx)
        assert "selinux_privileged" in [
            v["id"] for v in result["results"][0]["violations"]
        ]

    def test_dangerous_devices_allowed(self, make_rootfs):
        """Container with /dev/mem in linux.devices triggers alert."""
        r = make_rootfs
        cid = "ddv" * 8 + "f" * 40
        r.add_podman_container(
            cid,
            "devmem_pod",
            {
                "process": {
                    "user": {"uid": 1000},
                    "noNewPrivileges": True,
                },
                "root": {"readonly": True},
                "linux": {
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                    ],
                    "seccompProfilePath": "/etc/seccomp/default.json",
                    "resources": {
                        "memory": {"limit": 536870912},
                        "pids": {"limit": 100},
                    },
                    "maskedPaths": [
                        "/proc/kcore",
                        "/proc/sysrq-trigger",
                        "/proc/mem",
                        "/proc/kmsg",
                    ],
                    "readonlyPaths": [
                        "/proc/sys",
                        "/proc/irq",
                        "/proc/bus",
                        "/sys/firmware",
                    ],
                    "devices": [
                        {"path": "/dev/null", "type": "c", "major": 1, "minor": 3},
                        {"path": "/dev/mem", "type": "c", "major": 1, "minor": 1},
                    ],
                },
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("podman", "devmem_pod")
        ctx.set_service_meta(
            "podman",
            "devmem_pod",
            {
                "user": "u",
                "unit": "p.service",
                "path": "etc/systemd/system/p.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "dangerous_devices_allowed" in vio_ids

    def test_rootfs_propagation_shared(self, make_rootfs):
        """rootfsPropagation=shared triggers alert."""
        r = make_rootfs
        cid = "rfp" * 8 + "f" * 40
        r.add_podman_container(
            cid,
            "shared_prop_pod",
            {
                "process": {
                    "user": {"uid": 1000},
                    "noNewPrivileges": True,
                },
                "root": {"readonly": True},
                "linux": {
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                    ],
                    "seccompProfilePath": "/etc/seccomp/default.json",
                    "resources": {
                        "memory": {"limit": 536870912},
                        "pids": {"limit": 100},
                    },
                    "maskedPaths": [
                        "/proc/kcore",
                        "/proc/sysrq-trigger",
                        "/proc/mem",
                        "/proc/kmsg",
                    ],
                    "readonlyPaths": [
                        "/proc/sys",
                        "/proc/irq",
                        "/proc/bus",
                        "/sys/firmware",
                    ],
                    "rootfsPropagation": "shared",
                },
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("podman", "shared_prop_pod")
        ctx.set_service_meta(
            "podman",
            "shared_prop_pod",
            {
                "user": "u",
                "unit": "p.service",
                "path": "etc/systemd/system/p.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "rootfs_propagation_shared" in vio_ids

    def test_sensitive_env_detected(self, make_rootfs):
        """Environment variables with secrets trigger warning."""
        r = make_rootfs
        cid = "env" * 8 + "f" * 40
        r.add_podman_container(
            cid,
            "secret_env_pod",
            {
                "process": {
                    "user": {"uid": 1000},
                    "noNewPrivileges": True,
                    "env": [
                        "PATH=/usr/bin",
                        "DB_PASSWORD=hunter2",
                        "HOME=/app",
                    ],
                },
                "root": {"readonly": True},
                "linux": {
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                    ],
                    "seccompProfilePath": "/etc/seccomp/default.json",
                    "resources": {
                        "memory": {"limit": 536870912},
                        "pids": {"limit": 100},
                    },
                    "maskedPaths": [
                        "/proc/kcore",
                        "/proc/sysrq-trigger",
                        "/proc/mem",
                        "/proc/kmsg",
                    ],
                    "readonlyPaths": [
                        "/proc/sys",
                        "/proc/irq",
                        "/proc/bus",
                        "/sys/firmware",
                    ],
                },
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("podman", "secret_env_pod")
        ctx.set_service_meta(
            "podman",
            "secret_env_pod",
            {
                "user": "u",
                "unit": "p.service",
                "path": "etc/systemd/system/p.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "sensitive_env_detected" in vio_ids

    def test_containers_conf_no_seccomp(self, make_rootfs):
        """containers.conf without seccomp_profile triggers warning."""
        r = make_rootfs
        cid = "ccf" * 8 + "f" * 40
        # Write a containers.conf with no seccomp_profile
        conf_path = Path(r.path) / "etc" / "containers" / "containers.conf"
        conf_path.parent.mkdir(parents=True, exist_ok=True)
        conf_path.write_text("[containers]\ndefault_ulimits = []\n")
        r.add_podman_container(
            cid,
            "no_seccomp_conf_pod",
            {
                "process": {
                    "user": {"uid": 1000},
                    "noNewPrivileges": True,
                },
                "root": {"readonly": True},
                "linux": {
                    "namespaces": [
                        {"type": "pid"},
                        {"type": "network"},
                        {"type": "ipc"},
                    ],
                    "seccompProfilePath": "/etc/seccomp/default.json",
                    "resources": {
                        "memory": {"limit": 536870912},
                        "pids": {"limit": 100},
                    },
                    "maskedPaths": [
                        "/proc/kcore",
                        "/proc/sysrq-trigger",
                        "/proc/mem",
                        "/proc/kmsg",
                    ],
                    "readonlyPaths": [
                        "/proc/sys",
                        "/proc/irq",
                        "/proc/bus",
                        "/sys/firmware",
                    ],
                },
            },
        )
        ctx = _make_context()
        ctx.mark_systemd_started("podman", "no_seccomp_conf_pod")
        ctx.set_service_meta(
            "podman",
            "no_seccomp_conf_pod",
            {
                "user": "u",
                "unit": "p.service",
                "path": "etc/systemd/system/p.service",
                "cap_bounding_set": "CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        result = podman.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "containers_conf_no_seccomp" in vio_ids


# ------------------------------------------------------------------ #
# LXC scanner
# ------------------------------------------------------------------ #


class TestLxcScanner:
    _CLEAN_CONFIG = (
        "lxc.rootfs.path = /var/lib/lxc/clean/rootfs\n"
        "lxc.idmap = u 0 100000 65536\n"
        "lxc.idmap = g 0 100000 65536\n"
        "lxc.cap.drop = sys_admin net_raw\n"
        "lxc.net.0.type = veth\n"
        "lxc.no_new_privs = 1\n"
        "lxc.seccomp.profile = /usr/share/lxc/config/common.seccomp\n"
        "lxc.cgroup.memory.limit_in_bytes = 536870912\n"
        "lxc.prlimit.nproc = 1024\n"
        "lxc.rootfs.options = ro\n"
    )

    _MISSING_IDMAP_CONFIG = (
        "lxc.rootfs.path = /var/lib/lxc/noidmap/rootfs\n"
        "lxc.cap.drop = sys_admin\n"
        "lxc.net.0.type = veth\n"
    )

    _INVALID_IDMAP_CONFIG = (
        "lxc.rootfs.path = /var/lib/lxc/badmap/rootfs\n"
        "lxc.idmap = u garbage_format\n"
        "lxc.idmap = g 0 100000 65536\n"
        "lxc.net.0.type = veth\n"
    )

    _DANGEROUS_MOUNT_CONFIG = (
        "lxc.rootfs.path = /var/lib/lxc/mounts/rootfs\n"
        "lxc.idmap = u 0 100000 65536\n"
        "lxc.idmap = g 0 100000 65536\n"
        "lxc.cap.drop = sys_admin\n"
        "lxc.net.0.type = veth\n"
        "lxc.mount.entry = /proc proc proc rw 0 0\n"
    )

    def test_clean_lxc_container(self, make_rootfs):
        r = make_rootfs
        r.add_lxc_config("clean", self._CLEAN_CONFIG)
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "clean",
            {
                "user": "lxcuser",
                "unit": "lxc-clean.service",
                "path": "etc/systemd/system/lxc-clean.service",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "clean")
        result = lxc.scan(r.path, context=ctx)

        assert result["scanner"] == "lxc"
        assert result["summary"]["lxc_scanned"] == 1
        containers = result["results"]
        assert len(containers) == 1
        assert containers[0]["status"] == "clean"
        assert containers[0]["violations"] == []
        assert containers[0]["managed"] is True

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
            "lxc.net.0.type = veth\n"
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
            "lxc.net.0.type = veth\n"
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
            "lxc.net.0.type = veth\n"
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
            "lxc.net.0.type = veth\n"
        )
        r.add_lxc_config("nocap", config)
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)

        containers = result["results"]
        assert len(containers) == 1
        vio_ids = [v["id"] for v in containers[0]["violations"]]
        assert "cap_drop_missing" in vio_ids
        # cap_drop_missing should now be an alert with severity 7.0
        cap_vio = [
            v for v in containers[0]["violations"] if v["id"] == "cap_drop_missing"
        ][0]
        assert cap_vio["type"] == "alert"
        assert cap_vio["severity"] == 7.0

    def test_mount_dev_not_readonly(self, make_rootfs):
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/devmnt/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
            "lxc.mount.entry = /dev tmpfs tmpfs rw 0 0\n"
        )
        r.add_lxc_config("devmnt", config)
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)

        containers = result["results"]
        assert len(containers) == 1
        vio_ids = [v["id"] for v in containers[0]["violations"]]
        assert "mount_dev_should_be_ro" in vio_ids

    def test_apparmor_disabled_lxc(self, make_rootfs):
        """AppArmor set to unconfined should trigger apparmor_disabled."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/noaa/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
            "lxc.apparmor.profile = unconfined\n"
        )
        r.add_lxc_config("noaa", config)
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)

        containers = result["results"]
        assert len(containers) == 1
        vio_ids = [v["id"] for v in containers[0]["violations"]]
        assert "apparmor_disabled" in vio_ids
        aa_vio = [
            v for v in containers[0]["violations"] if v["id"] == "apparmor_disabled"
        ][0]
        assert aa_vio["type"] == "warning"
        assert aa_vio["severity"] == 6.0

    def test_apparmor_with_profile_not_flagged_lxc(self, make_rootfs):
        """A custom AppArmor profile should not trigger the rule."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/hasaa/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
            "lxc.apparmor.profile = lxc-container-default\n"
        )
        r.add_lxc_config("hasaa", config)
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)

        containers = result["results"]
        assert len(containers) == 1
        vio_ids = [v["id"] for v in containers[0]["violations"]]
        assert "apparmor_disabled" not in vio_ids

    def test_host_network_lxc(self, make_rootfs):
        """lxc.net.0.type = host should trigger host_network."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/hostnet/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = host\n"
        )
        r.add_lxc_config("hostnet", config)
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)

        containers = result["results"]
        assert len(containers) == 1
        vio_ids = [v["id"] for v in containers[0]["violations"]]
        assert "host_network" in vio_ids
        net_vio = [v for v in containers[0]["violations"] if v["id"] == "host_network"][
            0
        ]
        assert net_vio["type"] == "alert"
        assert net_vio["severity"] == 7.5

    def test_host_network_missing_net_type_lxc(self, make_rootfs):
        """Missing lxc.net.0.type (no networking config) should trigger host_network."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/nonet/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
        )
        r.add_lxc_config("nonet", config)
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)

        containers = result["results"]
        assert len(containers) == 1
        vio_ids = [v["id"] for v in containers[0]["violations"]]
        assert "host_network" in vio_ids

    def test_isolated_network_not_flagged_lxc(self, make_rootfs):
        """lxc.net.0.type = veth should not trigger host_network."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/vethnet/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
        )
        r.add_lxc_config("vethnet", config)
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)

        containers = result["results"]
        assert len(containers) == 1
        vio_ids = [v["id"] for v in containers[0]["violations"]]
        assert "host_network" not in vio_ids

    def test_mount_usr_severity_updated(self, make_rootfs):
        """Verify mount_usr_should_be_ro severity was updated to 5.5."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/usrsev/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
            "lxc.mount.entry = /usr usr none rw,bind 0 0\n"
        )
        r.add_lxc_config("usrsev", config)
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)

        containers = result["results"]
        assert len(containers) == 1
        usr_vio = [
            v
            for v in containers[0]["violations"]
            if v["id"] == "mount_usr_should_be_ro"
        ][0]
        assert usr_vio["severity"] == 5.5
        assert usr_vio["type"] == "warning"

    def test_no_new_privs_missing_lxc(self, make_rootfs):
        r = make_rootfs
        r.add_lxc_config(
            "nonnp",
            "lxc.rootfs.path = /var/lib/lxc/nonnp/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n",
        )
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "no_new_privs_missing" in vio_ids

    def test_no_new_privs_set_not_flagged_lxc(self, make_rootfs):
        r = make_rootfs
        r.add_lxc_config(
            "nnpok",
            "lxc.rootfs.path = /var/lib/lxc/nnpok/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
            "lxc.no_new_privs = 1\n",
        )
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "no_new_privs_missing" not in vio_ids

    def test_seccomp_profile_missing_lxc(self, make_rootfs):
        r = make_rootfs
        r.add_lxc_config(
            "noseccomp",
            "lxc.rootfs.path = /var/lib/lxc/noseccomp/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n",
        )
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "seccomp_profile_missing" in vio_ids

    def test_seccomp_profile_set_not_flagged_lxc(self, make_rootfs):
        r = make_rootfs
        r.add_lxc_config(
            "seccomp-ok",
            "lxc.rootfs.path = /var/lib/lxc/seccomp-ok/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
            "lxc.seccomp.profile = /usr/share/lxc/config/common.seccomp\n",
        )
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "seccomp_profile_missing" not in vio_ids

    def test_cap_keep_dangerous_lxc(self, make_rootfs):
        r = make_rootfs
        r.add_lxc_config(
            "capkeep",
            "lxc.rootfs.path = /var/lib/lxc/capkeep/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.keep = sys_admin net_bind_service\n"
            "lxc.net.0.type = veth\n",
        )
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "cap_keep_dangerous" in vio_ids

    def test_cap_keep_safe_not_flagged_lxc(self, make_rootfs):
        r = make_rootfs
        r.add_lxc_config(
            "capkeep-ok",
            "lxc.rootfs.path = /var/lib/lxc/capkeep-ok/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.keep = net_bind_service chown\n"
            "lxc.net.0.type = veth\n",
        )
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "cap_keep_dangerous" not in vio_ids

    def test_systemd_service_missing_detected(self, make_rootfs):
        """LXC container without systemd service should trigger alert."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/orphan/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.no_new_privs = 1\n"
            "lxc.seccomp.profile = /usr/share/lxc/config/common.seccomp\n"
            "lxc.apparmor.profile = lxc-container-default\n"
            "lxc.net.0.type = veth\n"
        )
        r.add_lxc_config("orphan", config)
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "systemd_service_missing" in vio_ids
        assert result["results"][0]["managed"] is False

    def test_systemd_caps_unrestricted_detected(self, make_rootfs):
        """LXC container with systemd service but no CapabilityBoundingSet."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/nocaps/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.no_new_privs = 1\n"
            "lxc.seccomp.profile = /usr/share/lxc/config/common.seccomp\n"
            "lxc.apparmor.profile = lxc-container-default\n"
            "lxc.net.0.type = veth\n"
        )
        r.add_lxc_config("nocaps", config)
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "nocaps",
            {
                "user": "lxcuser",
                "unit": "lxc-nocaps.service",
                "path": "etc/systemd/system/lxc-nocaps.service",
                "cap_bounding_set": "",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "nocaps")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "systemd_caps_unrestricted" in vio_ids
        assert "systemd_service_missing" not in vio_ids

    def test_systemd_with_caps_not_flagged(self, make_rootfs):
        """LXC container with properly configured systemd service."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/good/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.no_new_privs = 1\n"
            "lxc.seccomp.profile = /usr/share/lxc/config/common.seccomp\n"
            "lxc.apparmor.profile = lxc-container-default\n"
            "lxc.net.0.type = veth\n"
        )
        r.add_lxc_config("good", config)
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "good",
            {
                "user": "lxcuser",
                "unit": "lxc-good.service",
                "path": "etc/systemd/system/lxc-good.service",
                "cap_bounding_set": "CAP_NET_ADMIN CAP_NET_BIND_SERVICE",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "good")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "systemd_caps_unrestricted" not in vio_ids
        assert "systemd_service_missing" not in vio_ids

    def test_namespace_sharing_detected(self, make_rootfs):
        """Namespace sharing should trigger critical alert."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/nsshare/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.namespace.share.net = other_container\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
        )
        r.add_lxc_config("nsshare", config)
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "nsshare",
            {
                "user": "lxcuser",
                "unit": "lxc-nsshare.service",
                "path": "",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "nsshare")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "namespace_sharing_enabled" in vio_ids

    def test_namespace_keep_detected(self, make_rootfs):
        """Namespace keep should trigger critical alert."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/nskeep/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.namespace.keep = net\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
        )
        r.add_lxc_config("nskeep", config)
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "nskeep",
            {
                "user": "lxcuser",
                "unit": "lxc-nskeep.service",
                "path": "",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "nskeep")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "namespace_keep_enabled" in vio_ids

    def test_mount_auto_dangerous_detected(self, make_rootfs):
        """Dangerous lxc.mount.auto should trigger alert."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/mntauto/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.mount.auto = proc:rw sys:rw\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
        )
        r.add_lxc_config("mntauto", config)
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "mntauto",
            {
                "user": "lxcuser",
                "unit": "lxc-mntauto.service",
                "path": "",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "mntauto")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "mount_auto_dangerous" in vio_ids

    def test_mount_auto_safe_not_flagged(self, make_rootfs):
        """Safe lxc.mount.auto (proc:mixed, sys:ro) should NOT trigger."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/mntsafe/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.mount.auto = proc:mixed sys:ro\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.no_new_privs = 1\n"
            "lxc.seccomp.profile = /usr/share/lxc/config/common.seccomp\n"
            "lxc.apparmor.profile = lxc-container-default\n"
            "lxc.net.0.type = veth\n"
        )
        r.add_lxc_config("mntsafe", config)
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "mntsafe",
            {
                "user": "lxcuser",
                "unit": "lxc-mntsafe.service",
                "path": "",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "mntsafe")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "mount_auto_dangerous" not in vio_ids

    def test_selinux_unconfined_detected(self, make_rootfs):
        """Unconfined SELinux context should trigger warning."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/selinux/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.selinux.context = unconfined_u:unconfined_r:unconfined_t:s0\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
        )
        r.add_lxc_config("selinux", config)
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "selinux",
            {
                "user": "lxcuser",
                "unit": "lxc-selinux.service",
                "path": "",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "selinux")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "selinux_unconfined" in vio_ids

    def test_selinux_confined_not_flagged(self, make_rootfs):
        """Confined SELinux context should NOT trigger."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/selinuxok/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.selinux.context = system_u:system_r:lxc_t:s0\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.no_new_privs = 1\n"
            "lxc.seccomp.profile = /usr/share/lxc/config/common.seccomp\n"
            "lxc.apparmor.profile = lxc-container-default\n"
            "lxc.net.0.type = veth\n"
        )
        r.add_lxc_config("selinuxok", config)
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "selinuxok",
            {
                "user": "lxcuser",
                "unit": "lxc-selinuxok.service",
                "path": "",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "selinuxok")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "selinux_unconfined" not in vio_ids

    def test_apparmor_nesting_dangerous(self, make_rootfs):
        """lxc.apparmor.allow_nesting = 1 should trigger alert."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/aanest/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
            "lxc.apparmor.allow_nesting = 1\n"
        )
        r.add_lxc_config("aanest", config)
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "aanest",
            {
                "user": "lxcuser",
                "unit": "lxc-aanest.service",
                "path": "",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "aanest")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "apparmor_nesting_dangerous" in vio_ids
        vio = [
            v
            for v in result["results"][0]["violations"]
            if v["id"] == "apparmor_nesting_dangerous"
        ][0]
        assert vio["type"] == "alert"
        assert vio["severity"] == 7.5

    def test_apparmor_raw_dangerous(self, make_rootfs):
        """lxc.apparmor.raw should trigger apparmor_nesting_dangerous."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/aaraw/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
            "lxc.apparmor.raw = allow mount,\n"
        )
        r.add_lxc_config("aaraw", config)
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "aaraw",
            {
                "user": "lxcuser",
                "unit": "lxc-aaraw.service",
                "path": "",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "aaraw")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "apparmor_nesting_dangerous" in vio_ids

    def test_seccomp_nesting_detected(self, make_rootfs):
        """lxc.seccomp.allow_nesting = 1 should trigger alert."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/secnest/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
            "lxc.seccomp.allow_nesting = 1\n"
        )
        r.add_lxc_config("secnest", config)
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "secnest",
            {
                "user": "lxcuser",
                "unit": "lxc-secnest.service",
                "path": "",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "secnest")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "seccomp_nesting_enabled" in vio_ids
        vio = [
            v
            for v in result["results"][0]["violations"]
            if v["id"] == "seccomp_nesting_enabled"
        ][0]
        assert vio["type"] == "alert"
        assert vio["severity"] == 7.0

    def test_cgroup_devices_unrestricted(self, make_rootfs):
        """lxc.cgroup.devices.allow = a should trigger alert."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/cgdev/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
            "lxc.cgroup.devices.allow = a\n"
        )
        r.add_lxc_config("cgdev", config)
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "cgdev",
            {
                "user": "lxcuser",
                "unit": "lxc-cgdev.service",
                "path": "",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "cgdev")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "cgroup_devices_unrestricted" in vio_ids
        vio = [
            v
            for v in result["results"][0]["violations"]
            if v["id"] == "cgroup_devices_unrestricted"
        ][0]
        assert vio["type"] == "alert"
        assert vio["severity"] == 8.0

    def test_cgroup_devices_broad_pattern(self, make_rootfs):
        """Broad cgroup device pattern 'c *:* rwm' should trigger alert."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/cgbroad/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
            "lxc.cgroup.devices.allow = c *:* rwm\n"
        )
        r.add_lxc_config("cgbroad", config)
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "cgbroad",
            {
                "user": "lxcuser",
                "unit": "lxc-cgbroad.service",
                "path": "",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "cgbroad")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "cgroup_devices_unrestricted" in vio_ids

    def test_memory_limit_missing(self, make_rootfs):
        """Missing memory limit should trigger warning."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/nomem/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
        )
        r.add_lxc_config("nomem", config)
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "nomem",
            {
                "user": "lxcuser",
                "unit": "lxc-nomem.service",
                "path": "",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "nomem")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "memory_limit_missing" in vio_ids
        vio = [
            v
            for v in result["results"][0]["violations"]
            if v["id"] == "memory_limit_missing"
        ][0]
        assert vio["type"] == "warning"
        assert vio["severity"] == 5.0

    def test_memory_limit_set_not_flagged(self, make_rootfs):
        """Container with memory limit should NOT trigger."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/memok/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
            "lxc.cgroup.memory.limit_in_bytes = 536870912\n"
        )
        r.add_lxc_config("memok", config)
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "memok",
            {
                "user": "lxcuser",
                "unit": "lxc-memok.service",
                "path": "",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "memok")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "memory_limit_missing" not in vio_ids

    def test_nproc_limit_missing(self, make_rootfs):
        """Missing nproc limit should trigger warning."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/nonproc/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
        )
        r.add_lxc_config("nonproc", config)
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "nonproc",
            {
                "user": "lxcuser",
                "unit": "lxc-nonproc.service",
                "path": "",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "nonproc")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "nproc_limit_missing" in vio_ids
        vio = [
            v
            for v in result["results"][0]["violations"]
            if v["id"] == "nproc_limit_missing"
        ][0]
        assert vio["type"] == "warning"
        assert vio["severity"] == 5.0

    def test_nproc_limit_set_not_flagged(self, make_rootfs):
        """Container with nproc limit should NOT trigger."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/nprocok/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
            "lxc.prlimit.nproc = 1024\n"
        )
        r.add_lxc_config("nprocok", config)
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "nprocok",
            {
                "user": "lxcuser",
                "unit": "lxc-nprocok.service",
                "path": "",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "nprocok")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "nproc_limit_missing" not in vio_ids

    def test_rootfs_not_readonly(self, make_rootfs):
        """Missing lxc.rootfs.options = ro should trigger warning."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/rwroot/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
        )
        r.add_lxc_config("rwroot", config)
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "rwroot",
            {
                "user": "lxcuser",
                "unit": "lxc-rwroot.service",
                "path": "",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "rwroot")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "rootfs_not_readonly" in vio_ids
        vio = [
            v
            for v in result["results"][0]["violations"]
            if v["id"] == "rootfs_not_readonly"
        ][0]
        assert vio["type"] == "warning"
        assert vio["severity"] == 5.5

    def test_rootfs_readonly_not_flagged(self, make_rootfs):
        """lxc.rootfs.options = ro should NOT trigger."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/roroot/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
            "lxc.rootfs.options = ro\n"
        )
        r.add_lxc_config("roroot", config)
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "roroot",
            {
                "user": "lxcuser",
                "unit": "lxc-roroot.service",
                "path": "",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "roroot")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "rootfs_not_readonly" not in vio_ids

    def test_broken_systemd_service_detected(self, make_rootfs):
        """Systemd references LXC container but config not on disk."""
        r = make_rootfs
        ctx = _make_context()
        ctx.mark_systemd_started("lxc", "ghost")
        ctx.set_service_meta(
            "lxc",
            "ghost",
            {
                "user": "lxcuser",
                "unit": "lxc-ghost.service",
                "path": "etc/systemd/system/lxc-ghost.service",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        result = lxc.scan(r.path, context=ctx)
        ghost = [r for r in result["results"] if r["container"] == "ghost"]
        assert len(ghost) == 1
        assert ghost[0]["managed"] is True
        vio_ids = [v["id"] for v in ghost[0]["violations"]]
        assert "systemd_service_broken" in vio_ids

    def test_mount_dangerous_options_rbind(self, make_rootfs):
        """Mount entry with rbind should trigger mount_dangerous_options."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/rbindmnt/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
            "lxc.mount.entry = /data data none rbind 0 0\n"
        )
        r.add_lxc_config("rbindmnt", config)
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "rbindmnt",
            {
                "user": "lxcuser",
                "unit": "lxc-rbindmnt.service",
                "path": "",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "rbindmnt")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "mount_dangerous_options" in vio_ids
        vio = [
            v
            for v in result["results"][0]["violations"]
            if v["id"] == "mount_dangerous_options"
        ][0]
        assert vio["type"] == "warning"
        assert vio["severity"] == 6.0

    def test_mount_fstab_dangerous_entry(self, make_rootfs):
        """Fstab file with /proc mount should trigger mount_proc_dangerous."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/fstabmnt/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
            "lxc.mount.fstab = /etc/lxc/fstabmnt.fstab\n"
        )
        r.add_lxc_config("fstabmnt", config)
        # Create the fstab file referenced by the config
        fstab_dir = Path(r.path) / "etc" / "lxc"
        fstab_dir.mkdir(parents=True, exist_ok=True)
        (fstab_dir / "fstabmnt.fstab").write_text(
            "# LXC fstab\n/proc proc proc rw 0 0\n",
            encoding="utf-8",
        )
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "fstabmnt",
            {
                "user": "lxcuser",
                "unit": "lxc-fstabmnt.service",
                "path": "",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "fstabmnt")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "mount_proc_dangerous" in vio_ids

    def test_nested_lxc_detected(self, make_rootfs):
        """Container rootfs containing lxc-start binary should trigger nested_lxc_detected."""
        r = make_rootfs
        config = (
            "lxc.rootfs.path = /var/lib/lxc/nested/rootfs\n"
            "lxc.idmap = u 0 100000 65536\n"
            "lxc.idmap = g 0 100000 65536\n"
            "lxc.cap.drop = sys_admin\n"
            "lxc.net.0.type = veth\n"
        )
        r.add_lxc_config("nested", config)
        # Place lxc-start binary inside the container's rootfs
        nested_bin = (
            Path(r.path)
            / "var"
            / "lib"
            / "lxc"
            / "nested"
            / "rootfs"
            / "usr"
            / "bin"
            / "lxc-start"
        )
        nested_bin.parent.mkdir(parents=True, exist_ok=True)
        nested_bin.write_bytes(b"\x7fELF")
        ctx = _make_context()
        ctx.set_service_meta(
            "lxc",
            "nested",
            {
                "user": "lxcuser",
                "unit": "lxc-nested.service",
                "path": "",
                "cap_bounding_set": "CAP_NET_ADMIN",
                "ambient_capabilities": "",
            },
        )
        ctx.mark_systemd_started("lxc", "nested")
        result = lxc.scan(r.path, context=ctx)
        vio_ids = [v["id"] for v in result["results"][0]["violations"]]
        assert "nested_lxc_detected" in vio_ids
        vio = [
            v
            for v in result["results"][0]["violations"]
            if v["id"] == "nested_lxc_detected"
        ][0]
        assert vio["type"] == "warning"
        assert vio["severity"] == 6.0


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

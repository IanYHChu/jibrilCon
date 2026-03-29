"""Tests for scanner internal helper functions and edge cases."""

from pathlib import Path

from tests.conftest import _make_context, _write_text

from jibrilcon.scanners import docker_native, lxc, podman
from jibrilcon.scanners.docker_native import _extract_fields, _to_bool
from jibrilcon.util.context import ScanContext


# ------------------------------------------------------------------ #
# Docker _to_bool() tests
# ------------------------------------------------------------------ #


class TestToBool:
    def test_bool_true(self):
        assert _to_bool(True) is True

    def test_bool_false(self):
        assert _to_bool(False) is False

    def test_string_true(self):
        assert _to_bool("true") is True

    def test_string_True_uppercase(self):
        assert _to_bool("True") is True

    def test_string_TRUE_allcaps(self):
        assert _to_bool("TRUE") is True

    def test_string_false(self):
        assert _to_bool("false") is False

    def test_string_False_uppercase(self):
        assert _to_bool("False") is False

    def test_int_zero(self):
        assert _to_bool(0) is False

    def test_int_one(self):
        assert _to_bool(1) is True

    def test_none(self):
        assert _to_bool(None) is False

    def test_empty_string(self):
        assert _to_bool("") is False

    def test_arbitrary_string(self):
        assert _to_bool("yes") is False

    def test_float_zero(self):
        assert _to_bool(0.0) is False

    def test_float_nonzero(self):
        assert _to_bool(1.5) is True


# ------------------------------------------------------------------ #
# Docker _extract_fields() edge cases
# ------------------------------------------------------------------ #


class TestDockerExtractFields:
    def test_empty_config_and_hostconfig(self):
        """Empty config.v2.json and hostconfig.json should produce safe defaults."""
        fields = _extract_fields({}, {})
        assert fields["privileged"] is False
        assert fields["readonly_rootfs"] is False
        assert fields["binds_not_readonly"] is False
        assert fields["seccomp_disabled"] is False
        assert fields["pid_mode_is_host"] is False
        assert fields["network_mode_is_host"] is False
        assert fields["ipc_mode_is_host"] is False
        assert fields["dangerous_caps_added"] is False
        assert fields["cap_drop_missing"] is True  # no CapDrop = missing

    def test_security_opt_not_a_list(self, caplog):
        """SecurityOpt as a non-list value should be handled gracefully."""
        fields = _extract_fields({}, {"SecurityOpt": "not-a-list"})
        assert fields["seccomp_disabled"] is False
        assert any("SecurityOpt is not a list" in r.message for r in caplog.records)

    def test_binds_not_a_list(self, caplog):
        """Binds as a non-list value should be handled gracefully."""
        fields = _extract_fields({}, {"Binds": "not-a-list"})
        assert fields["binds_not_readonly"] is False
        assert any("Binds is not a list" in r.message for r in caplog.records)

    def test_cap_add_not_a_list(self, caplog):
        """CapAdd as a non-list value should be handled gracefully."""
        fields = _extract_fields({}, {"CapAdd": "SYS_ADMIN"})
        assert fields["dangerous_caps_added"] is False
        assert any("CapAdd is not a list" in r.message for r in caplog.records)


# ------------------------------------------------------------------ #
# Docker scanner with malformed input files
# ------------------------------------------------------------------ #


class TestDockerMalformedInput:
    def test_empty_config_v2_json(self, make_rootfs):
        """An empty config.v2.json (valid JSON {}) should not crash the scanner."""
        r = make_rootfs
        cid = "emp" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={},
            hostconfig={"Privileged": False, "ReadonlyRootfs": True, "Binds": []},
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        assert result["scanner"] == "docker"
        assert result["summary"]["docker_scanned"] == 1

    def test_empty_hostconfig_json(self, make_rootfs):
        """An empty hostconfig.json (valid JSON {}) should not crash the scanner."""
        r = make_rootfs
        cid = "emh" * 8 + "0" * 40
        r.add_docker_container(
            cid,
            config_v2={"Name": "/emptyhost"},
            hostconfig={},
        )
        ctx = _make_context()
        result = docker_native.scan(r.path, context=ctx)
        assert result["scanner"] == "docker"
        assert result["summary"]["docker_scanned"] == 1
        containers = result["results"]
        assert len(containers) == 1
        # With empty hostconfig, some rules will fire (e.g., cap_drop_missing)
        assert containers[0]["container"] == "emptyhost"


# ------------------------------------------------------------------ #
# Podman with missing process.user key
# ------------------------------------------------------------------ #


class TestPodmanMissingProcessUser:
    def test_missing_process_key(self, make_rootfs):
        """Config with no 'process' key at all should default uid to 0."""
        r = make_rootfs
        cid = "nop" * 8 + "0" * 40
        r.add_podman_container(
            cid,
            name="no_process",
            config_json={
                "root": {"path": "rootfs", "readonly": True},
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
        assert result["scanner"] == "podman"
        assert result["summary"]["podman_scanned"] == 1

    def test_missing_user_key(self, make_rootfs):
        """Config with 'process' but no 'user' sub-key should default uid to 0."""
        r = make_rootfs
        cid = "nou" * 8 + "0" * 40
        r.add_podman_container(
            cid,
            name="no_user",
            config_json={
                "process": {"args": ["/bin/sh"]},
                "root": {"path": "rootfs", "readonly": True},
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
        assert result["scanner"] == "podman"
        containers = result["results"]
        assert len(containers) == 1


# ------------------------------------------------------------------ #
# LXC with empty config content
# ------------------------------------------------------------------ #


class TestLxcEmptyConfig:
    def test_empty_config_file(self, make_rootfs):
        """An LXC config file with no content should not crash the scanner."""
        r = make_rootfs
        # Create an empty config file (no lxc.rootfs.path, so it won't be picked up)
        _write_text(
            Path(r.path) / "var" / "lib" / "lxc" / "empty" / "config",
            "",
        )
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)
        assert result["scanner"] == "lxc"
        # Empty config has no lxc.rootfs.path, so 0 containers scanned
        assert result["summary"]["lxc_scanned"] == 0

    def test_config_with_only_comments(self, make_rootfs):
        """An LXC config file with only comments should not crash."""
        r = make_rootfs
        _write_text(
            Path(r.path) / "var" / "lib" / "lxc" / "commented" / "config",
            "# This is a comment\n# Another comment\n",
        )
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)
        assert result["scanner"] == "lxc"
        assert result["summary"]["lxc_scanned"] == 0

    def test_config_with_rootfs_but_minimal(self, make_rootfs):
        """A minimal LXC config with only lxc.rootfs.path should be scanned without crash."""
        r = make_rootfs
        _write_text(
            Path(r.path) / "var" / "lib" / "lxc" / "minimal" / "config",
            "lxc.rootfs.path = /var/lib/lxc/minimal/rootfs\n",
        )
        ctx = _make_context()
        result = lxc.scan(r.path, context=ctx)
        assert result["scanner"] == "lxc"
        # Should find and scan the container
        assert result["summary"]["lxc_scanned"] == 1
        containers = result["results"]
        assert len(containers) == 1
        assert containers[0]["container"] == "minimal"


# ------------------------------------------------------------------ #
# Scanner loader narrowed exception types
# ------------------------------------------------------------------ #


class TestScannerLoaderNarrowedExceptions:
    def test_type_error_caught(self):
        """TypeError from a scanner should be caught by the narrowed handler."""
        from types import ModuleType
        from unittest.mock import patch

        from jibrilcon.util.scanner_loader import run_scanners

        def type_error_scan(mount_path, *, context=None):
            raise TypeError("bad argument type")

        def good_scan(mount_path, *, context=None):
            return {"scanner": "ok"}

        mod_bad = ModuleType("jibrilcon.scanners.bad")
        mod_bad.scan = type_error_scan
        mod_good = ModuleType("jibrilcon.scanners.good")
        mod_good.scan = good_scan

        with patch(
            "jibrilcon.util.scanner_loader._iter_scanner_modules",
            return_value=[mod_bad, mod_good],
        ):
            results = run_scanners("/fake", context=ScanContext())

        assert len(results) == 1
        assert results[0]["scanner"] == "ok"

    def test_value_error_caught(self):
        """ValueError from a scanner should be caught by the narrowed handler."""
        from types import ModuleType
        from unittest.mock import patch

        from jibrilcon.util.scanner_loader import run_scanners

        def value_error_scan(mount_path, *, context=None):
            raise ValueError("bad value")

        def good_scan(mount_path, *, context=None):
            return {"scanner": "ok"}

        mod_bad = ModuleType("jibrilcon.scanners.bad2")
        mod_bad.scan = value_error_scan
        mod_good = ModuleType("jibrilcon.scanners.good2")
        mod_good.scan = good_scan

        with patch(
            "jibrilcon.util.scanner_loader._iter_scanner_modules",
            return_value=[mod_bad, mod_good],
        ):
            results = run_scanners("/fake", context=ScanContext())

        assert len(results) == 1
        assert results[0]["scanner"] == "ok"

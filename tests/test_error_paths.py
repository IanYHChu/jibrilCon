"""Error path and edge case tests for modules that lack coverage."""

import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest.mock import patch

import pytest

from jibrilcon.util.config_loader import (
    ConfigLoadError,
    clear_cache,
    load_json_config,
)
from jibrilcon.util.context import ScanContext

# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _make_context() -> ScanContext:
    ctx = ScanContext()
    ctx.init_system = "systemd"
    return ctx


# ------------------------------------------------------------------ #
# 1. CLI: run_scan raises RuntimeError -> sys.exit(1)
# ------------------------------------------------------------------ #


class TestCliScanFailure:
    def test_cli_scan_failure_exits_nonzero(self, tmp_path):
        """If run_scan raises RuntimeError, main() must call sys.exit(1)."""
        # Create a valid directory so argparse path validation passes
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()

        with (
            patch("sys.argv", ["jibrilcon", str(rootfs)]),
            patch(
                "jibrilcon.cli.run_scan",
                side_effect=RuntimeError("scan exploded"),
            ),
        ):
            from jibrilcon.cli import main

            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1


# ------------------------------------------------------------------ #
# 2. config_loader: thread-safety of load_json_config
# ------------------------------------------------------------------ #


class TestConfigLoaderThreadSafety:
    @pytest.fixture(autouse=True)
    def _fresh_cache(self):
        clear_cache()
        yield
        clear_cache()

    def test_config_loader_thread_safety(self, tmp_path):
        """Concurrent loads of the same valid file must all return the
        correct data without corruption."""
        cfg_file = tmp_path / "thread_safe.json"
        payload = {"rules": [{"id": "r1"}], "meta": "hello"}
        cfg_file.write_text(json.dumps(payload), encoding="utf-8")

        results = []
        errors = []

        def _load():
            try:
                return load_json_config(cfg_file)
            except Exception as exc:
                errors.append(exc)
                return None

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(_load) for _ in range(32)]
            for f in as_completed(futures):
                results.append(f.result())

        assert not errors, f"Unexpected errors: {errors}"
        for r in results:
            assert r == payload

    def test_config_loader_clear_cache_is_threadsafe(self, tmp_path):
        """Calling clear_cache while other threads are loading must not
        crash or corrupt state."""
        cfg_file = tmp_path / "clear_safe.json"
        cfg_file.write_text(json.dumps({"v": 1}), encoding="utf-8")

        errors = []
        stop = threading.Event()

        def _load_loop():
            while not stop.is_set():
                try:
                    load_json_config(cfg_file)
                except ConfigLoadError:
                    pass  # acceptable if cache was cleared mid-flight
                except Exception as exc:
                    errors.append(exc)

        def _clear_loop():
            while not stop.is_set():
                try:
                    clear_cache()
                except Exception as exc:
                    errors.append(exc)

        threads = []
        for _ in range(4):
            threads.append(threading.Thread(target=_load_loop))
        threads.append(threading.Thread(target=_clear_loop))

        for t in threads:
            t.start()

        # Let them race for a short period
        stop.wait(timeout=0.5)
        stop.set()

        for t in threads:
            t.join(timeout=5)

        assert not errors, f"Thread errors: {errors}"


# ------------------------------------------------------------------ #
# 3. systemd_unit_parser: missing config graceful handling
# ------------------------------------------------------------------ #


class TestSystemdCollectGraceful:
    def test_systemd_collect_graceful_on_missing_config(self, tmp_path):
        """collect_systemd_containers must not crash when the systemd.json
        config file is missing; it should return normally with no side
        effects on the context."""
        from jibrilcon.util.systemd_unit_parser import collect_systemd_containers

        rootfs = tmp_path / "empty_rootfs"
        rootfs.mkdir()
        ctx = _make_context()

        # Point at a nonexistent filter file
        bogus_filter = tmp_path / "nonexistent_systemd.json"

        # Must not raise
        collect_systemd_containers(str(rootfs), ctx, filters_path=bogus_filter)

        # Context should remain empty
        assert not ctx.is_systemd_started("docker", "any")
        assert not ctx.is_user_missing("any")


# ------------------------------------------------------------------ #
# 4. LXC: include depth limit
# ------------------------------------------------------------------ #


class TestLxcIncludeDepthLimit:
    def test_lxc_include_depth_limit(self, tmp_path):
        """A chain of >20 lxc.include files must not stack-overflow;
        _file_contains_rootfs should return False at the depth limit."""
        from jibrilcon.scanners.lxc import _file_contains_rootfs, _is_text_file

        # Clear the _is_text_file cache so our fresh temp files are recognised
        _is_text_file.cache_clear()

        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()
        conf_dir = rootfs / "etc" / "lxc"
        conf_dir.mkdir(parents=True)

        # Build a chain: file_00 includes file_01, ..., file_21 includes file_22
        # None of them defines lxc.rootfs.path, so the answer is False.
        chain_length = 25
        for i in range(chain_length):
            f = conf_dir / f"chain_{i:02d}.conf"
            if i < chain_length - 1:
                next_f = conf_dir / f"chain_{i + 1:02d}.conf"
                # Use rootfs-relative absolute path for the include
                rel = str(next_f.relative_to(rootfs))
                f.write_text(
                    f"lxc.include = /{rel}\n",
                    encoding="utf-8",
                )
            else:
                # Terminal file: no rootfs.path, no include
                f.write_text("# end of chain\n", encoding="utf-8")

        first = conf_dir / "chain_00.conf"
        # Must not raise RecursionError; must return False
        result = _file_contains_rootfs(first, str(rootfs))
        assert result is False

        _is_text_file.cache_clear()


# ------------------------------------------------------------------ #
# 5. LXC: rules load failure
# ------------------------------------------------------------------ #


class TestLxcRulesLoadFailure:
    def test_lxc_rules_load_failure(self, make_rootfs):
        """If load_json_config raises ConfigLoadError for the LXC rule
        file, scan() must return a valid result dict, not crash."""
        from jibrilcon.scanners import lxc

        r = make_rootfs
        ctx = _make_context()

        with patch.object(
            lxc,
            "load_json_config",
            side_effect=ConfigLoadError("disk on fire"),
        ):
            result = lxc.scan(r.path, context=ctx)

        assert isinstance(result, dict)
        assert result["scanner"] == "lxc"
        assert "summary" in result
        assert "results" in result
        assert isinstance(result["results"], list)


# ------------------------------------------------------------------ #
# 6. Docker: rules load failure
# ------------------------------------------------------------------ #


class TestDockerRulesLoadFailure:
    def test_docker_rules_load_failure(self, make_rootfs):
        """If load_json_config raises ConfigLoadError for the Docker rule
        file, scan() must return a valid result dict, not crash."""
        from jibrilcon.scanners import docker_native

        r = make_rootfs
        ctx = _make_context()

        with patch.object(
            docker_native,
            "load_json_config",
            side_effect=ConfigLoadError("disk on fire"),
        ):
            result = docker_native.scan(r.path, context=ctx)

        assert isinstance(result, dict)
        assert result["scanner"] == "docker"
        assert "summary" in result
        assert "results" in result
        assert isinstance(result["results"], list)


# ------------------------------------------------------------------ #
# 7. Podman: rules load failure
# ------------------------------------------------------------------ #


class TestPodmanRulesLoadFailure:
    def test_podman_rules_load_failure(self, make_rootfs):
        """If load_json_config raises ConfigLoadError for the Podman rule
        file, scan() must return a valid result dict, not crash."""
        from jibrilcon.scanners import podman

        r = make_rootfs
        ctx = _make_context()

        with patch.object(
            podman,
            "load_json_config",
            side_effect=ConfigLoadError("disk on fire"),
        ):
            result = podman.scan(r.path, context=ctx)

        assert isinstance(result, dict)
        assert result["scanner"] == "podman"
        assert "summary" in result
        assert "results" in result
        assert isinstance(result["results"], list)

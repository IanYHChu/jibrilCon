"""Shared pytest fixtures for jibrilcon tests."""

import json
from pathlib import Path

import pytest

from jibrilcon.util.config_loader import clear_cache
from jibrilcon.util.context import ScanContext

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def rule_dir():
    """Return the path to the rules/ directory."""
    return PROJECT_ROOT / "src" / "jibrilcon" / "rules"


@pytest.fixture
def fixtures_dir():
    """Return the path to tests/fixtures/ if it exists, else skip."""
    d = PROJECT_ROOT / "tests" / "fixtures"
    if not d.is_dir():
        pytest.skip("tests/fixtures/ directory not available")
    return d


@pytest.fixture(autouse=False)
def fresh_cache():
    """Ensure each test starts with a clean LRU cache."""
    clear_cache()
    yield
    clear_cache()


# ------------------------------------------------------------------ #
# Helpers for building minimal rootfs layouts in tmp_path
# ------------------------------------------------------------------ #

_FAKE_SYSTEMD = b"\x7fELF\x02" + b"\x00" * 11 + b"systemd"


def _make_context() -> ScanContext:
    """Create a ScanContext pre-set for systemd."""
    ctx = ScanContext()
    ctx.init_system = "systemd"
    return ctx


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_binary(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


@pytest.fixture
def make_rootfs(tmp_path):
    """Factory fixture that returns a rootfs builder."""

    class RootfsBuilder:
        def __init__(self, base: Path):
            self.base = base
            # Always place a fake systemd binary so init detection works
            _write_binary(base / "sbin" / "init", _FAKE_SYSTEMD)

        @property
        def path(self) -> str:
            return str(self.base)

        def add_systemd_service(self, name: str, content: str) -> None:
            _write_text(
                self.base / "etc" / "systemd" / "system" / name,
                content,
            )

        def add_docker_container(
            self,
            cid: str,
            config_v2: dict,
            hostconfig: dict,
            *,
            data_root: str = "/var/lib/docker",
        ) -> None:
            base_dir = self.base / data_root.lstrip("/") / "containers" / cid
            _write_json(base_dir / "config.v2.json", config_v2)
            _write_json(base_dir / "hostconfig.json", hostconfig)

        def add_docker_daemon_json(self, data: dict) -> None:
            _write_json(self.base / "etc" / "docker" / "daemon.json", data)

        def add_podman_container(
            self,
            cid: str,
            name: str,
            config_json: dict,
            *,
            storage_root: str = "/var/lib/containers/storage",
        ) -> None:
            sr = self.base / storage_root.lstrip("/")
            index = sr / "overlay-containers" / "containers.json"

            # Read existing index or start fresh
            existing = []
            if index.exists():
                existing = json.loads(index.read_text())
            existing.append({"id": cid, "names": [name]})
            _write_json(index, existing)

            _write_json(
                sr / "overlay-containers" / cid / "userdata" / "config.json",
                config_json,
            )

        def add_lxc_config(self, container_name: str, content: str) -> None:
            _write_text(
                self.base / "var" / "lib" / "lxc" / container_name / "config",
                content,
            )

        def add_passwd(self, lines: list[str]) -> None:
            _write_text(self.base / "etc" / "passwd", "\n".join(lines) + "\n")

    return RootfsBuilder(tmp_path)

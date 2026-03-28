"""Tests for util/systemd_unit_parser.py."""

from jibrilcon.util.context import ScanContext
from jibrilcon.util.systemd_unit_parser import (
    _parse_unit_lines,
    _is_container_service,
    _guess_engine_and_container,
    scan_systemd_container_units,
    collect_systemd_containers,
)


# ------------------------------------------------------------------ #
# _parse_unit_lines
# ------------------------------------------------------------------ #

def test_parse_unit_lines_basic():
    lines = [
        "[Service]",
        "ExecStart=/usr/bin/docker run --name web01",
        "User=root",
        "# comment line",
        "",
        "ExecStartPre=/usr/bin/docker pull nginx",
    ]
    result = _parse_unit_lines(lines)
    assert result["ExecStart"] == ["/usr/bin/docker run --name web01"]
    assert result["ExecStartPre"] == ["/usr/bin/docker pull nginx"]
    assert result["User"] == ["root"]


def test_parse_unit_lines_duplicate_keys():
    lines = [
        "ExecStartPre=/bin/cmd1",
        "ExecStartPre=/bin/cmd2",
    ]
    result = _parse_unit_lines(lines)
    assert result["ExecStartPre"] == ["/bin/cmd1", "/bin/cmd2"]


# ------------------------------------------------------------------ #
# _is_container_service
# ------------------------------------------------------------------ #

def test_is_container_service_docker():
    assert _is_container_service(
        ["/usr/bin/docker run --name web"],
        ["docker", "podman", "lxc-start"],
    )


def test_is_container_service_no_match():
    assert not _is_container_service(
        ["/usr/bin/nginx -g daemon off"],
        ["docker", "podman", "lxc-start"],
    )


# ------------------------------------------------------------------ #
# _guess_engine_and_container
# ------------------------------------------------------------------ #

ENGINE_MAP = {
    "docker": {"keyword": "docker", "container_regex": "--name\\s+([^\\s]+)"},
    "podman": {"keyword": "podman", "container_regex": "--name\\s+([^\\s]+)"},
    "lxc": {"keyword": "lxc-start", "container_regex": "-n\\s+([^\\s]+)"},
}


def test_guess_docker():
    engine, cname = _guess_engine_and_container(
        ["/usr/bin/docker run --name web01"], ENGINE_MAP
    )
    assert engine == "docker"
    assert cname == "web01"


def test_guess_lxc():
    engine, cname = _guess_engine_and_container(
        ["/usr/bin/lxc-start -n mycontainer -d"], ENGINE_MAP
    )
    assert engine == "lxc"
    assert cname == "mycontainer"


def test_guess_unknown():
    engine, cname = _guess_engine_and_container(
        ["/usr/bin/nginx"], ENGINE_MAP
    )
    assert engine == ""
    assert cname == ""


# ------------------------------------------------------------------ #
# scan_systemd_container_units (integration with fixture rootfs)
# ------------------------------------------------------------------ #

def test_scan_finds_container_units(tmp_path):
    """Build a minimal rootfs with a docker service unit and verify parsing."""
    unit_dir = tmp_path / "etc" / "systemd" / "system"
    unit_dir.mkdir(parents=True)
    (unit_dir / "docker-web.service").write_text(
        "[Service]\n"
        "ExecStart=/usr/bin/docker run --name web01 nginx\n"
        "User=appuser\n"
    )

    rows = scan_systemd_container_units(tmp_path)
    assert len(rows) == 1
    assert rows[0]["engine"] == "docker"
    assert rows[0]["container"] == "web01"
    assert rows[0]["user"] == "appuser"


# ------------------------------------------------------------------ #
# collect_systemd_containers: caches both ExecStart and ExecStartPre
# ------------------------------------------------------------------ #

def test_collect_caches_execstartpre(tmp_path):
    """Regression test: ExecStartPre lines must be cached in ScanContext."""
    unit_dir = tmp_path / "etc" / "systemd" / "system"
    unit_dir.mkdir(parents=True)
    (unit_dir / "lxc-myct.service").write_text(
        "[Service]\n"
        "ExecStartPre=/usr/bin/lxc-start -n myct -f /custom/config\n"
        "ExecStart=/usr/bin/lxc-start -n myct -d\n"
    )

    ctx = ScanContext()
    collect_systemd_containers(tmp_path, ctx)

    lines = ctx.get_exec_lines("lxc", "myct")
    # Both ExecStart and ExecStartPre must be present
    assert any("-f /custom/config" in line for line in lines), (
        "ExecStartPre lines should be cached"
    )
    assert any("-d" in line for line in lines), (
        "ExecStart lines should be cached"
    )

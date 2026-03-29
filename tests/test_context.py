"""Tests for util/context.py."""

from jibrilcon.util.context import ScanContext


def test_mark_and_query_systemd_started():
    ctx = ScanContext()
    ctx.mark_systemd_started("docker", "web01")
    assert ctx.is_systemd_started("docker", "web01")
    assert not ctx.is_systemd_started("docker", "web02")
    assert not ctx.is_systemd_started("podman", "web01")


def test_mark_user_missing():
    ctx = ScanContext()
    assert not ctx.is_user_missing("web01")
    ctx.mark_user_missing("web01")
    assert ctx.is_user_missing("web01")
    assert not ctx.is_user_missing("web02")


def test_exec_lines_round_trip():
    ctx = ScanContext()
    lines = ["/usr/bin/docker start --name web01", "/usr/bin/docker stop web01"]
    ctx.add_exec_lines("docker", "web01", lines)
    got = ctx.get_exec_lines("docker", "web01")
    assert got == lines
    # Must be a copy, not a reference
    assert got is not lines
    # Mutating the returned list must NOT affect cached data
    got.append("extra")
    got2 = ctx.get_exec_lines("docker", "web01")
    assert got2 == lines


def test_exec_lines_missing_returns_empty():
    ctx = ScanContext()
    assert ctx.get_exec_lines("docker", "nonexistent") == []


def test_multiple_engines():
    ctx = ScanContext()
    ctx.mark_systemd_started("docker", "app")
    ctx.mark_systemd_started("podman", "db")
    assert ctx.is_systemd_started("docker", "app")
    assert ctx.is_systemd_started("podman", "db")
    assert not ctx.is_systemd_started("docker", "db")


def test_init_system_default_none():
    ctx = ScanContext()
    assert ctx.init_system is None


def test_init_system_settable():
    ctx = ScanContext()
    ctx.init_system = "systemd"
    assert ctx.init_system == "systemd"

"""Tests for init_manager_finder.py."""

import pytest

from jibrilcon.init_manager_finder import detect_init_system
from jibrilcon.util.path_utils import resolve_path


# A minimal fake ELF binary that contains "systemd" in its payload.
_FAKE_SYSTEMD_ELF = b"\x7fELF\x02" + b"\x00" * 11 + b"systemd"

# A minimal fake ELF binary that contains "sysvinit" in its payload.
_FAKE_SYSVINIT_ELF = b"\x7fELF\x02" + b"\x00" * 11 + b"sysvinit"


@pytest.fixture(autouse=True)
def _clear_resolve_cache():
    """Clear the resolve_path LRU cache before each test."""
    resolve_path.cache_clear()
    yield
    resolve_path.cache_clear()


# ------------------------------------------------------------------ #
# Binary-based detection
# ------------------------------------------------------------------ #

def test_detect_systemd_by_binary(tmp_path):
    """Direct /sbin/init binary containing 'systemd' -> 'systemd'."""
    sbin = tmp_path / "sbin"
    sbin.mkdir()
    (sbin / "init").write_bytes(_FAKE_SYSTEMD_ELF)

    result = detect_init_system(tmp_path)
    assert result == "systemd"


def test_detect_systemd_by_symlink(tmp_path):
    """
    /sbin/init is a symlink to a real binary that contains 'systemd'.
    The symlink target name does not matter; the *content* is checked.
    """
    sbin = tmp_path / "sbin"
    sbin.mkdir()
    real_bin = sbin / "real-init"
    real_bin.write_bytes(_FAKE_SYSTEMD_ELF)
    (sbin / "init").symlink_to("real-init")

    result = detect_init_system(tmp_path)
    assert result == "systemd"


def test_detect_sysvinit_by_binary(tmp_path):
    """Direct /sbin/init binary containing 'sysvinit' -> 'sysvinit'."""
    sbin = tmp_path / "sbin"
    sbin.mkdir()
    (sbin / "init").write_bytes(_FAKE_SYSVINIT_ELF)

    result = detect_init_system(tmp_path)
    assert result == "sysvinit"


def test_detect_systemd_via_usr_lib_path(tmp_path):
    """
    /usr/lib/systemd/systemd candidate binary containing 'systemd' is
    checked when /sbin/init is absent.
    """
    target = tmp_path / "usr" / "lib" / "systemd"
    target.mkdir(parents=True)
    (target / "systemd").write_bytes(_FAKE_SYSTEMD_ELF)

    result = detect_init_system(tmp_path)
    assert result == "systemd"


# ------------------------------------------------------------------ #
# Directory-based fallback detection
# ------------------------------------------------------------------ #

def test_detect_systemd_by_directory(tmp_path):
    """/etc/systemd/ directory present -> fallback to 'systemd'."""
    (tmp_path / "etc" / "systemd").mkdir(parents=True)

    result = detect_init_system(tmp_path)
    assert result == "systemd"


def test_detect_sysvinit_by_directory(tmp_path):
    """/etc/init.d/ directory present -> fallback to 'sysvinit'."""
    (tmp_path / "etc" / "init.d").mkdir(parents=True)

    result = detect_init_system(tmp_path)
    assert result == "sysvinit"


def test_detect_openrc_by_directory(tmp_path):
    """/etc/runlevels/ directory present -> fallback to 'openrc'."""
    (tmp_path / "etc" / "runlevels").mkdir(parents=True)

    result = detect_init_system(tmp_path)
    assert result == "openrc"


def test_directory_priority_systemd_over_sysvinit(tmp_path):
    """When both /etc/systemd and /etc/init.d exist, systemd wins."""
    (tmp_path / "etc" / "systemd").mkdir(parents=True)
    (tmp_path / "etc" / "init.d").mkdir(parents=True)

    result = detect_init_system(tmp_path)
    assert result == "systemd"


def test_directory_priority_sysvinit_over_openrc(tmp_path):
    """When both /etc/init.d and /etc/runlevels exist, sysvinit wins."""
    (tmp_path / "etc" / "init.d").mkdir(parents=True)
    (tmp_path / "etc" / "runlevels").mkdir(parents=True)

    result = detect_init_system(tmp_path)
    assert result == "sysvinit"


# ------------------------------------------------------------------ #
# Unknown / empty rootfs
# ------------------------------------------------------------------ #

def test_detect_unknown_empty_rootfs(tmp_path):
    """Empty rootfs with no binaries or directories -> empty string."""
    result = detect_init_system(tmp_path)
    assert result == ""


# ------------------------------------------------------------------ #
# Edge cases and robustness
# ------------------------------------------------------------------ #

def test_truncated_elf_header(tmp_path):
    """
    /sbin/init is only 3 bytes (too short for ELF).
    Should not crash; falls through to directory fallback or empty string.
    """
    sbin = tmp_path / "sbin"
    sbin.mkdir()
    (sbin / "init").write_bytes(b"\x7fEL")

    result = detect_init_system(tmp_path)
    # File exists but is not a valid ELF and does not contain init markers
    # in the raw bytes either -> falls to directory hints -> returns ""
    assert result == ""


def test_nonexistent_rootfs():
    """Passing a nonexistent path should return empty string, not crash."""
    result = detect_init_system("/nonexistent/rootfs/path")
    assert result == ""


def test_non_elf_binary_containing_systemd_string(tmp_path):
    """
    /sbin/init is not ELF but raw bytes contain 'systemd'.
    _bytes_contains should still match it.
    """
    sbin = tmp_path / "sbin"
    sbin.mkdir()
    (sbin / "init").write_bytes(b"not-elf-but-contains-systemd-string")

    result = detect_init_system(tmp_path)
    assert result == "systemd"


def test_symlink_escaping_rootfs(tmp_path):
    """
    /sbin/init is a symlink that points outside the rootfs boundary.
    Should be skipped gracefully and fall through.
    """
    sbin = tmp_path / "sbin"
    sbin.mkdir()
    # Absolute symlink pointing outside rootfs
    (sbin / "init").symlink_to("/usr/bin/systemd")

    result = detect_init_system(tmp_path)
    # Symlink escapes rootfs -> skipped; no directory hints -> ""
    assert result == ""


def test_binary_priority_over_directory(tmp_path):
    """
    Binary detection should take priority over directory hints.
    Place a sysvinit binary AND an /etc/systemd directory -- binary wins.
    """
    sbin = tmp_path / "sbin"
    sbin.mkdir()
    (sbin / "init").write_bytes(_FAKE_SYSVINIT_ELF)
    (tmp_path / "etc" / "systemd").mkdir(parents=True)

    result = detect_init_system(tmp_path)
    assert result == "sysvinit"


def test_init_binary_is_directory_not_file(tmp_path):
    """
    /sbin/init exists but is a directory (not a file).
    Should be skipped gracefully.
    """
    (tmp_path / "sbin" / "init").mkdir(parents=True)

    result = detect_init_system(tmp_path)
    assert result == ""


def test_string_path_argument(tmp_path):
    """detect_init_system accepts str in addition to Path."""
    (tmp_path / "etc" / "runlevels").mkdir(parents=True)

    result = detect_init_system(str(tmp_path))
    assert result == "openrc"


def test_sysv_fixture(fixtures_dir):
    """
    Integration: the rootfs_sysv fixture should be detected as sysvinit.
    The fixture has /sbin/init as a symlink to /sbin/init.sysvinit which
    contains the sysvinit marker.
    """
    rootfs = fixtures_dir / "rootfs_sysv"
    if not rootfs.is_dir():
        pytest.skip("rootfs_sysv fixture not available")

    result = detect_init_system(rootfs)
    assert result == "sysvinit"

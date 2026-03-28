"""Tests for util/path_utils.py."""

import pytest

from jibrilcon.util.path_utils import resolve_path, safe_join


# ------------------------------------------------------------------ #
# safe_join
# ------------------------------------------------------------------ #

def test_safe_join_normal_subpath(tmp_path):
    child = tmp_path / "a" / "b"
    child.mkdir(parents=True)
    result = safe_join(tmp_path, "a", "b")
    assert result == child


def test_safe_join_escape_raises(tmp_path):
    with pytest.raises(ValueError, match="Unsafe path escape"):
        safe_join(tmp_path, "..", "..", "etc", "passwd")


def test_safe_join_dotdot_within_boundary(tmp_path):
    (tmp_path / "a" / "b").mkdir(parents=True)
    result = safe_join(tmp_path, "a", "b", "..", "b")
    assert result == tmp_path / "a" / "b"


def test_safe_join_root_equals_candidate(tmp_path):
    result = safe_join(tmp_path, ".")
    assert result == tmp_path.resolve()


# ------------------------------------------------------------------ #
# resolve_path
# ------------------------------------------------------------------ #

def test_resolve_path_non_symlink(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("hello")
    result = resolve_path(str(f), str(tmp_path))
    assert result == str(f)


def test_resolve_path_symlink_inside_rootfs(tmp_path):
    real = tmp_path / "real.txt"
    real.write_text("hello")
    link = tmp_path / "link.txt"
    # Use relative symlink so resolver follows within rootfs
    link.symlink_to("real.txt")

    resolve_path.cache_clear()

    result = resolve_path(str(link), str(tmp_path))
    assert result == str(real)


def test_resolve_path_symlink_escape_raises(tmp_path):
    # Create a relative symlink that escapes rootfs via ../
    subdir = tmp_path / "sub"
    subdir.mkdir()
    link = subdir / "escape_link"
    link.symlink_to("../../escape_target")

    resolve_path.cache_clear()

    with pytest.raises(RuntimeError, match="outside rootfs"):
        resolve_path(str(link), str(tmp_path))


def test_resolve_path_symlink_loop_raises(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    # Use relative symlinks to create a real loop
    a.symlink_to("b")
    b.symlink_to("a")

    resolve_path.cache_clear()

    with pytest.raises(RuntimeError, match="symlink loop"):
        resolve_path(str(a), str(tmp_path))
